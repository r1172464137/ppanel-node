package panel

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	serverv1 "github.com/perfect-panel/ppanel-node/api/server/v1"
	"github.com/perfect-panel/ppanel-node/conf"
	"google.golang.org/protobuf/proto"
)

func TestObservedABACommitAnd304Concurrent(t *testing.T) {
	var mu sync.Mutex
	rev := 1
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		current := rev
		mu.Unlock()
		etag := fmt.Sprintf(`"%d"`, current)
		w.Header().Set("ETag", etag)
		if r.Header.Get("If-None-Match") == etag {
			w.WriteHeader(304)
			return
		}
		fmt.Fprintf(w, `{"code":200,"data":{"protocols":[],"routing":{"version":1,"outbounds":[],"rules":[],"default_outbound_id":"direct","mode":"ordered-v1-inherited","source":"global","source_revision":%d}}}`, current)
	}))
	defer srv.Close()
	c := NewServerClient(&conf.ServerApiConfig{ApiHost: srv.URL, ServerId: 7})
	fetch := func() *ServerConfigResponse {
		t.Helper()
		v, err := GetServerConfig(context.Background(), c)
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
	a := fetch()
	c.Commit(a)
	mu.Lock()
	rev = 2
	mu.Unlock()
	b := fetch()
	inFlight, resume, committed := make(chan struct{}), make(chan struct{}), make(chan struct{})
	go func() { close(inFlight); <-resume; c.Commit(b); close(committed) }()
	<-inFlight
	mu.Lock()
	rev = 1
	mu.Unlock()
	if latest := fetch(); latest != nil {
		t.Fatal("A is still applied before B switches")
	}
	close(resume)
	<-committed
	if !c.HasPending() || c.State.Snapshot().Pending.SourceRevision != 1 || c.State.Snapshot().Applied.SourceRevision != 2 {
		t.Fatalf("ABA lost: %+v", c.State.Snapshot())
	}
	pending := fetch() // server returns 304 for the most recently observed A
	if pending == nil || pending.Data.Routing.SourceRevision != 1 {
		t.Fatalf("304 swallowed observed A: %+v", pending)
	}
	c.Commit(pending)
	if c.HasPending() || c.State.Snapshot().Applied.SourceRevision != 1 {
		t.Fatalf("A was not reapplied: %+v", c.State.Snapshot())
	}
}

func TestConfigJSONStrictPresenceAndProtocolNull(t *testing.T) {
	valid := []string{`{"protocols":null}`, `{"protocols":[]}`}
	for _, raw := range valid {
		var d Data
		if err := json.Unmarshal([]byte(raw), &d); err != nil || d.Protocols == nil || len(*d.Protocols) != 0 {
			t.Fatalf("empty protocols %s: %+v %v", raw, d, err)
		}
	}
	var absent Data
	if err := json.Unmarshal([]byte(`{}`), &absent); err != nil || absent.Protocols != nil {
		t.Fatalf("missing protocol presence: %+v %v", absent, err)
	}
	bad := []string{
		`{"protocols":{}}`, `{"protocols":""}`, `{"Routing":null,"protocols":[]}`,
		`{"routing":null,"protocols":[]}`, `{"routing":{},"routing":null,"protocols":[]}`,
		`{"routing":{},"Routing":null,"protocols":[]}`, `{"future_route":{},"protocols":[]}`,
		`{"routing":{"Version":1},"protocols":[]}`,
		`{"routing":{"version":1,"version":2},"protocols":[]}`,
		`{"routing":{"rules":[{"enabled":true,"Enabled":false}]},"protocols":[]}`,
		`{"routing":{"outbounds":[{"id":"x","ID":"y"}]},"protocols":[]}`,
		`{"protocols":[],"protocols":null}`,
		`{"protocols":[{"type":"future","enable":true,"Enable":false}]}`,
		`{"protocols":[{"Type":"future","enable":true}]}`,
		`{"dns":[{"Address":"1.1.1.1"}]}`,
	}
	for _, raw := range bad {
		var d Data
		if err := json.Unmarshal([]byte(raw), &d); err == nil {
			t.Errorf("accepted ambiguous JSON: %s", raw)
		}
	}
	for _, raw := range []string{`{"code":200,"Data":{"protocols":[]}}`, `{"code":200,"data":{"protocols":[]},"data":null}`, `{"code":200,"data":{"protocols":[]},"extra":1}`} {
		var response ServerConfigResponse
		if err := json.Unmarshal([]byte(raw), &response); err == nil {
			t.Errorf("accepted ambiguous envelope: %s", raw)
		}
	}
}

func TestCutoverRejectsOldWireAndAcceptsExplicitEmptyProtocols(t *testing.T) {
	for _, binary := range []bool{false, true} {
		for _, ordered := range []bool{false, true} {
			t.Run(fmt.Sprintf("proto=%v/ordered=%v", binary, ordered), func(t *testing.T) {
				srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if binary {
						w.Header().Set("Content-Type", "application/protobuf")
						data := &serverv1.QueryServerProtocolConfigData{}
						if ordered {
							data.Routing = &serverv1.RoutingPolicy{Version: 1, DefaultOutboundId: "direct", Mode: "ordered-v1-inherited", Source: "global", SourceRevision: 1}
						}
						b, _ := proto.Marshal(&serverv1.QueryServerProtocolConfigResponse{Code: 200, Data: data})
						w.Write(b)
						return
					}
					if ordered {
						fmt.Fprint(w, `{"code":200,"data":{"protocols":null,"routing":{"version":1,"outbounds":[],"rules":[],"default_outbound_id":"direct","mode":"ordered-v1-inherited","source":"global","source_revision":1}}}`)
					} else {
						fmt.Fprint(w, `{"code":200,"data":{"protocols":[],"block":["legacy.example"]}}`)
					}
				}))
				defer srv.Close()
				client := NewServerClient(&conf.ServerApiConfig{ApiHost: srv.URL, ServerId: 7})
				got, err := GetServerConfig(context.Background(), client)
				if !ordered {
					if err == nil {
						t.Fatal("legacy response accepted")
					}
					return
				}
				if err != nil || got.Data.Protocols == nil || len(*got.Data.Protocols) != 0 {
					t.Fatalf("ordered empty protocols: %+v %v", got, err)
				}
			})
		}
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"code":200,"data":{"routing":{"version":1,"outbounds":[],"rules":[],"default_outbound_id":"direct","mode":"ordered-v1-inherited","source":"global","source_revision":1}}}`)
	}))
	defer server.Close()
	if _, err := GetServerConfig(context.Background(), NewServerClient(&conf.ServerApiConfig{ApiHost: server.URL})); err == nil {
		t.Fatal("missing protocols accepted")
	}
}

func TestInstanceIdentityAndRejectForeignLocalStatus(t *testing.T) {
	if os.Getenv("PPNODE_INSTANCE_TEST_CHILD") == "1" {
		fmt.Println("INSTANCE=" + ProcessInstanceID())
		return
	}
	a := NewServerClient(&conf.ServerApiConfig{ServerId: 7})
	b := NewServerClient(&conf.ServerApiConfig{ServerId: 7})
	id := a.State.Snapshot().InstanceID
	if id == "" || id != b.State.Snapshot().InstanceID {
		t.Fatal("client recreation changed process identity")
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestInstanceIdentityAndRejectForeignLocalStatus$")
	cmd.Env = append(os.Environ(), "PPNODE_INSTANCE_TEST_CHILD=1")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("child: %v %s", err, out)
	}
	match := regexp.MustCompile(`INSTANCE=([0-9a-f-]{36})`).FindStringSubmatch(string(out))
	if len(match) != 2 || match[1] == id {
		t.Fatalf("restart did not change instance ID: %q %s", id, out)
	}
	bad := &ServerConfigResponse{Data: &Data{Routing: &RoutingPolicy{RoutingIdentity: RoutingIdentity{Mode: "ordered-v1-local", Source: "server", SourceServerID: 8, SourceRevision: 1, LocalTransitionRevision: 1}}}}
	a.State.setPending(identityOf(bad, a.ServerId))
	a.State.RecordFailure(bad, "validate")
	status := a.State.Snapshot()
	if status.Pending != nil || status.Error.Identity != nil || status.InstanceID != id {
		t.Fatalf("foreign identity polluted heartbeat: %+v", status)
	}
	body, err := json.Marshal(status)
	if err != nil || strings.Contains(string(body), `"source_server_id":8`) {
		t.Fatalf("foreign identity serialized: %s %v", body, err)
	}
	if err := a.ActivateStatusPublisher(); err != nil {
		t.Fatal(err)
	}
	payload, err := a.statusPayloadAt(&NodeStatus{}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	pb := statusToProtobuf(payload)
	if pb.InstanceId != id {
		t.Fatal("protobuf instance ID missing")
	}
	a.State.RecordFailure(bad, "bind")
	a.State.RecordFailure(nil, "fetch")
	if a.State.Snapshot().Error.Stage != "fetch" {
		t.Fatal("fetch failure was not reported")
	}
	a.State.ClearFetchFailure()
	if a.State.Snapshot().Error.Stage != "bind" {
		t.Fatal("fetch recovery lost previous apply failure")
	}
}

package cmd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/perfect-panel/ppanel-node/api/panel"
	"github.com/perfect-panel/ppanel-node/conf"
)

func TestOrderedCandidateRetryReplacementAndZeroProtocolStatus(t *testing.T) {
	var mu sync.Mutex
	revision, version := 1, 1
	statuses := []panel.ServerPushStatusRequest{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		switch r.URL.Path {
		case "/v2/server/7":
			etag := fmt.Sprintf(`"%d"`, revision)
			w.Header().Set("ETag", etag)
			if r.Header.Get("If-None-Match") == etag {
				w.WriteHeader(304)
				return
			}
			fmt.Fprintf(w, `{"code":200,"data":{"pull_interval":3600,"push_interval":3600,"protocols":[],"routing":{"version":%d,"outbounds":[],"rules":[],"default_outbound_id":"direct","mode":"ordered-v1-inherited","source":"global","source_server_id":0,"source_revision":%d,"local_transition_revision":0}}}`, version, revision)
		case "/v1/server/status":
			if r.URL.Query().Get("protocol") != "" {
				t.Error("status was not server scoped")
			}
			var status panel.ServerPushStatusRequest
			if err := json.NewDecoder(r.Body).Decode(&status); err != nil {
				t.Error(err)
			}
			statuses = append(statuses, status)
			fmt.Fprint(w, `{"code":200}`)
		default:
			t.Errorf("unexpected path %s", r.URL.Path)
		}
	}))
	defer server.Close()
	cfg := conf.New()
	cfg.LogConfig.Level = "error"
	cfg.ApiConfig = conf.ServerApiConfig{ApiHost: server.URL, ServerId: 7, Timeout: 1}
	path := filepath.Join(t.TempDir(), "config.yml")
	if err := os.WriteFile(path, []byte(fmt.Sprintf("Log:\n  Level: error\nApi:\n  ApiHost: %q\n  ServerID: 7\n  Timeout: 1\n", server.URL)), 0600); err != nil {
		t.Fatal(err)
	}
	client := panel.NewServerClient(&cfg.ApiConfig)
	ch := make(chan struct{}, 1)
	nodes, x, _, err := startInitial(context.Background(), cfg, client, ch)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { nodes.Close(); x.Close() }()
	reporter := newServerReporter(client, time.Hour)
	if err := reporter.report(context.Background()); err != nil {
		t.Fatal(err)
	}
	oldNodes, oldCore := nodes, x
	mu.Lock()
	revision, version = 2, 2
	mu.Unlock()
	for i := 0; i < 2; i++ {
		if _, err := reload(path, &nodes, &x, nil); err == nil || !strings.Contains(err.Error(), "version") {
			t.Fatalf("attempt %d: %v", i, err)
		}
		if nodes != oldNodes || x != oldCore {
			t.Fatal("bad candidate displaced old core")
		}
		status := client.State.Snapshot()
		if status.Applied.SourceRevision != 1 || status.Pending.SourceRevision != 2 || status.Error.Stage != "validate" {
			t.Fatalf("status after failure = %+v", status)
		}
	}
	if client.ServerConfigEtag != `"1"` {
		t.Fatal("failed candidate advanced applied ETag")
	}
	if err := reporter.report(context.Background()); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	revision, version = 3, 1
	mu.Unlock()
	h, err := reload(path, &nodes, &x, nil)
	if err != nil {
		t.Fatal(err)
	}
	if h != nil {
		defer h.Close()
	}
	if x == oldCore || nodes == oldNodes {
		t.Fatal("replacement was not switched")
	}
	status := client.State.Snapshot()
	if status.Applied.SourceRevision != 3 || status.Pending != nil || status.Error.Identity.SourceRevision != 2 {
		t.Fatalf("status after replacement = %+v", status)
	}
	if err := reporter.report(context.Background()); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(statuses) != 3 || statuses[0].Version != 1 || statuses[0].Applied.SourceRevision != 1 || statuses[1].Pending.SourceRevision != 2 || statuses[2].Applied.SourceRevision != 3 {
		t.Fatalf("zero-protocol heartbeat states = %+v", statuses)
	}
}

func TestServerReporterRunsWithoutAnyCore(t *testing.T) {
	reports := make(chan panel.ServerPushStatusRequest, 4)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var status panel.ServerPushStatusRequest
		if err := json.NewDecoder(r.Body).Decode(&status); err != nil {
			t.Error(err)
		}
		reports <- status
		fmt.Fprint(w, `{"code":200}`)
	}))
	defer server.Close()
	client := panel.NewServerClient(&conf.ServerApiConfig{ApiHost: server.URL, ServerId: 7, Timeout: 1})
	reporter := newServerReporter(client, time.Hour)
	reporter.start()
	defer reporter.close()
	select {
	case status := <-reports:
		if status.RoutingStatus == nil || status.Version != 1 || status.Applied != nil {
			t.Fatalf("initial capability: %+v", status)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("server reporter did not run before core startup")
	}
	client.State.RecordFailure(nil, "restore")
	reporter.reportSoon()
	select {
	case status := <-reports:
		if status.Error == nil || status.Error.Stage != "restore" {
			t.Fatalf("failure status: %+v", status)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("server reporter did not report failure")
	}
}

func TestMultipleLiveProtocolsDoNotOverwriteServerRoutingStatus(t *testing.T) {
	reserve := func() int {
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer l.Close()
		return l.Addr().(*net.TCPAddr).Port
	}
	p1, p2 := reserve(), reserve()
	for p2 == p1 {
		p2 = reserve()
	}
	var mu sync.Mutex
	var reports []panel.ServerPushStatusRequest
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v2/server/7":
			fmt.Fprintf(w, `{"code":200,"data":{"push_interval":1,"pull_interval":3600,"protocols":[{"type":"vless","enable":true,"port":%d,"transport":"tcp"},{"type":"vmess","enable":true,"port":%d,"transport":"tcp"}],"total":2,"routing":{"version":1,"outbounds":[],"rules":[],"default_outbound_id":"direct","mode":"ordered-v1-inherited","source":"global","source_revision":4}}}`, p1, p2)
		case "/v1/server/user":
			fmt.Fprint(w, `{"code":200,"data":{"users":[]}}`)
		case "/v1/server/status":
			var status panel.ServerPushStatusRequest
			if err := json.NewDecoder(r.Body).Decode(&status); err != nil {
				t.Error(err)
			}
			mu.Lock()
			reports = append(reports, status)
			mu.Unlock()
			fmt.Fprint(w, `{"code":200}`)
		default:
			fmt.Fprint(w, `{"code":200}`)
		}
	}))
	defer server.Close()
	cfg := conf.New()
	cfg.LogConfig.Level = "error"
	cfg.ApiConfig = conf.ServerApiConfig{ApiHost: server.URL, ServerId: 7, Timeout: 1}
	client := panel.NewServerClient(&cfg.ApiConfig)
	n, x, _, err := startInitial(context.Background(), cfg, client, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer x.Close()
	defer n.Close()
	reporter := newServerReporter(client, time.Hour)
	if err := reporter.report(context.Background()); err != nil {
		t.Fatal(err)
	}
	time.Sleep(1400 * time.Millisecond) // let both live controllers' periodic report run
	mu.Lock()
	defer mu.Unlock()
	if len(reports) != 1 || reports[0].RoutingStatus == nil || reports[0].Applied == nil || reports[0].Applied.SourceRevision != 4 {
		t.Fatalf("protocol reports overwrote server receipt: %+v", reports)
	}
}

func TestRestorePreviousDoesNotClaimAvailabilityOnDoubleFailure(t *testing.T) {
	order := []string{}
	ok, err := restorePrevious("bind", errors.New("new bind"), func() { order = append(order, "cleanup") }, func() error { order = append(order, "restore"); return errors.New("old bind") })
	if ok || err == nil || !strings.Contains(err.Error(), "new bind") || !strings.Contains(err.Error(), "old bind") || strings.Contains(err.Error(), "previous nodes restored") {
		t.Fatalf("dual failure: restored=%v err=%v", ok, err)
	}
	if strings.Join(order, ",") != "cleanup,restore" {
		t.Fatalf("wrong rollback order: %v", order)
	}
	ok, err = restorePrevious("bind", errors.New("new bind"), func() {}, func() error { return nil })
	if !ok || err == nil || !strings.Contains(err.Error(), "previous nodes restored") {
		t.Fatalf("successful rollback: %v %v", ok, err)
	}
	ok, err = restorePrevious("stop", errors.New("remove failed"), func() {}, func() error { return nil })
	if ok || err == nil || !strings.Contains(err.Error(), "unverified") {
		t.Fatalf("ambiguous stop claimed availability: %v %v", ok, err)
	}
}

func TestInitialBadCandidateRemainsPendingAndRecovers(t *testing.T) {
	var mu sync.Mutex
	version, rev := 99, 1
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		etag := fmt.Sprintf(`"%d"`, rev)
		w.Header().Set("ETag", etag)
		if r.Header.Get("If-None-Match") == etag {
			w.WriteHeader(304)
			return
		}
		fmt.Fprintf(w, `{"code":200,"data":{"protocols":[],"routing":{"version":%d,"outbounds":[],"rules":[],"default_outbound_id":"direct","mode":"ordered-v1-inherited","source":"global","source_revision":%d}}}`, version, rev)
	}))
	defer server.Close()
	cfg := conf.New()
	cfg.ApiConfig = conf.ServerApiConfig{ApiHost: server.URL, ServerId: 7, Timeout: 1}
	client := panel.NewServerClient(&cfg.ApiConfig)
	for i := 0; i < 2; i++ {
		if _, _, _, err := startInitial(context.Background(), cfg, client, nil); err == nil {
			t.Fatal("bad initial candidate accepted")
		}
	}
	if s := client.State.Snapshot(); s.Applied != nil || s.Pending.SourceRevision != 1 || s.Error.Stage != "validate" {
		t.Fatalf("startup status %+v", s)
	}
	mu.Lock()
	version, rev = 1, 2
	mu.Unlock()
	n, x, _, err := startInitial(context.Background(), cfg, client, nil)
	if err != nil {
		t.Fatal(err)
	}
	n.Close()
	x.Close()
	if s := client.State.Snapshot(); s.Applied.SourceRevision != 2 || s.Pending != nil {
		t.Fatalf("startup recovery %+v", s)
	}
}

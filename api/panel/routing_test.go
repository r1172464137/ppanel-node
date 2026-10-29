package panel

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"

	serverv1 "github.com/perfect-panel/ppanel-node/api/server/v1"
	"github.com/perfect-panel/ppanel-node/conf"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/known/structpb"
)

func TestAllOutboundFieldsJSONProtobufGolden(t *testing.T) {
	options, err := structpb.NewValue(map[string]any{"mode": "websocket", "nested": []any{true, "x", float64(42)}})
	if err != nil {
		t.Fatal(err)
	}
	pb := &serverv1.Outbound{
		Id: "ob_11111111-1111-4111-8111-111111111111", Name: "gold", Protocol: "shadowsocks", Address: "host", Port: 443,
		User: "u", Password: "p", Uuid: "uuid", Cipher: "cipher", Plugin: "plugin", PluginOptions: options,
		Security: "tls", Sni: "sni", Alpn: []string{"h2", "http/1.1"}, AllowInsecure: true, Fingerprint: "fp",
		Transport: "xhttp", Host: "example", Path: "/path", ServiceName: "svc", XhttpMode: "stream-up", XhttpExtra: `{"nested":{"v":false}}`,
		Flow: "flow", Encryption: "enc", EncryptionMode: "mode", EncryptionRtt: "rtt", EncryptionTicket: "ticket", EncryptionClientPadding: "pad", EncryptionPassword: "ep",
		Multiplex: `{"enabled":false}`, Uot: true, UotVersion: 2, CongestionController: "bbr", UdpStream: true, ReduceRtt: true, Heartbeat: 17,
		RealityPublicKey: "pk", RealityShortId: "short", SpiderX: "/", Settings: `{"x":false}`, StreamSettings: `{"x":[]}`,
		Rules: []string{}, IpRules: []string{}, ProtocolRules: []string{},
	}
	const golden = `{"id":"ob_11111111-1111-4111-8111-111111111111","name":"gold","protocol":"shadowsocks","address":"host","port":443,"user":"u","password":"p","uuid":"uuid","cipher":"cipher","plugin":"plugin","plugin_opts":{"mode":"websocket","nested":[true,"x",42]},"security":"tls","sni":"sni","alpn":["h2","http/1.1"],"allow_insecure":true,"fingerprint":"fp","transport":"xhttp","host":"example","path":"/path","service_name":"svc","xhttp_mode":"stream-up","xhttp_extra":"{\"nested\":{\"v\":false}}","flow":"flow","encryption":"enc","encryption_mode":"mode","encryption_rtt":"rtt","encryption_ticket":"ticket","encryption_client_padding":"pad","encryption_password":"ep","multiplex":"{\"enabled\":false}","uot":true,"uot_version":2,"congestion_controller":"bbr","udp_stream":true,"reduce_rtt":true,"heartbeat":17,"reality_public_key":"pk","reality_short_id":"short","spider_x":"/","settings":"{\"x\":false}","stream_settings":"{\"x\":[]}","rules":[],"ip_rules":[],"protocol_rules":[]}`
	var expected Outbound
	decoder := json.NewDecoder(strings.NewReader(golden))
	decoder.UseNumber()
	if err := decoder.Decode(&expected); err != nil {
		t.Fatal(err)
	}
	wire, err := proto.Marshal(pb)
	if err != nil {
		t.Fatal(err)
	}
	decoded := &serverv1.Outbound{}
	if err := proto.Unmarshal(wire, decoded); err != nil {
		t.Fatal(err)
	}
	actual := outboundFromProtobuf(decoded)
	if !reflect.DeepEqual(actual, expected) {
		t.Fatalf("all-field projection mismatch:\nJSON: %#v\nprotobuf: %#v", expected, actual)
	}
	body, err := json.Marshal(actual)
	if err != nil {
		t.Fatal(err)
	}
	var round Outbound
	roundDecoder := json.NewDecoder(bytes.NewReader(body))
	roundDecoder.UseNumber()
	if err := roundDecoder.Decode(&round); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(round, expected) {
		t.Fatalf("JSON round-trip lost fields: %#v", round)
	}
	var jsonData Data
	if err := json.Unmarshal([]byte(`{"outbound":[{"plugin_opts":{"n":9007199254740993}}]}`), &jsonData); err != nil {
		t.Fatal(err)
	}
	optionMap := (*jsonData.Outbound)[0].PluginOptions.(map[string]any)
	if optionMap["n"] != json.Number("9007199254740993") {
		t.Fatalf("large JSON number rounded: %#v", optionMap["n"])
	}
	for _, option := range []any{"sip003-string", map[string]any{"enabled": false}, nil} {
		value, err := structpb.NewValue(option)
		if err != nil {
			t.Fatal(err)
		}
		decoded := outboundFromProtobuf(&serverv1.Outbound{PluginOptions: value})
		if !reflect.DeepEqual(decoded.PluginOptions, option) {
			t.Fatalf("plugin options: %#v != %#v", decoded.PluginOptions, option)
		}
	}
}

func TestRoutingWirePresenceAndTags(t *testing.T) {
	for _, tc := range []struct {
		name    string
		enabled *bool
	}{{"missing", nil}, {"false", proto.Bool(false)}, {"true", proto.Bool(true)}} {
		t.Run(tc.name, func(t *testing.T) {
			p := &serverv1.RoutingPolicy{Version: 1, DefaultOutboundId: "direct", Mode: "ordered-v1-inherited", Source: "global", SourceRevision: 42,
				Rules: []*serverv1.RouteRule{{Id: "rr_11111111-1111-4111-8111-111111111111", Enabled: tc.enabled, Kind: serverv1.RouteKind_ROUTE_KIND_DOMAIN, Values: []string{"test.example"}, OutboundId: "direct"}}}
			b, err := proto.Marshal(&serverv1.QueryServerProtocolConfigResponse{Data: &serverv1.QueryServerProtocolConfigData{Routing: p}})
			if err != nil {
				t.Fatal(err)
			}
			m := &serverv1.QueryServerProtocolConfigResponse{}
			if err := proto.Unmarshal(b, m); err != nil {
				t.Fatal(err)
			}
			got := serverConfigResponseFromProtobuf(m).Data.Routing.Rules[0].Enabled
			if (got == nil) != (tc.enabled == nil) || got != nil && *got != *tc.enabled {
				t.Fatalf("enabled = %v, want %v", got, tc.enabled)
			}
		})
	}
	for _, text := range []string{`{"routing":{"version":1,"outbounds":[],"rules":[{"enabled":false}],"default_outbound_id":"direct"}}`} {
		var data Data
		if err := json.Unmarshal([]byte(text), &data); err != nil {
			t.Fatal(err)
		}
		if !data.RoutingPresent {
			t.Fatal("routing presence lost")
		}
		if data.Routing != nil && (data.Routing.Rules[0].Enabled == nil || *data.Routing.Rules[0].Enabled) {
			t.Fatal("explicit false lost")
		}
	}
	var data Data
	if err := json.Unmarshal([]byte(`{"routing":null}`), &data); err == nil {
		t.Fatal("null routing accepted")
	}
	if err := json.Unmarshal([]byte(`{"routing":{"version":1,"unexpected":"future"}}`), &data); err == nil {
		t.Fatal("unknown policy field accepted")
	}
	unknown := protowire.AppendTag(nil, 99, protowire.VarintType)
	unknown = protowire.AppendVarint(unknown, 1)
	policy := &serverv1.RoutingPolicy{Rules: []*serverv1.RouteRule{{}}}
	policy.Rules[0].ProtoReflect().SetUnknown(unknown)
	if err := rejectUnknownRoutingFields(policy.ProtoReflect()); err == nil {
		t.Fatal("unknown protobuf policy field was ignored")
	}
	dataFields := (&serverv1.QueryServerProtocolConfigData{}).ProtoReflect().Descriptor().Fields()
	if dataFields.ByName("routing").Number() != 12 {
		t.Fatal("routing tag changed")
	}
	if (&serverv1.Outbound{}).ProtoReflect().Descriptor().Fields().ByName("id").Number() != 44 {
		t.Fatal("outbound id tag changed")
	}
	fields := (&serverv1.PushServerStatusRequest{}).ProtoReflect().Descriptor().Fields()
	for name, tag := range map[string]int{"routing_version": 5, "routing_applied": 6, "routing_pending": 7, "routing_error": 8, "instance_id": 9, "routing_sequence": 10} {
		if int(fields.ByName(protoreflect.Name(name)).Number()) != tag {
			t.Fatalf("status %s tag changed", name)
		}
	}
}

func TestCandidateETagCommitRetryAndReplacement(t *testing.T) {
	var mu sync.Mutex
	revision := 1
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get(RoutingVersionHeader) != "1" {
			t.Errorf("missing routing capability header")
		}
		mu.Lock()
		current := revision
		mu.Unlock()
		etag := fmt.Sprintf(`"r%d"`, current)
		w.Header().Set("ETag", etag)
		if r.Header.Get("If-None-Match") == etag {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		fmt.Fprintf(w, `{"code":200,"data":{"protocols":[],"routing":{"version":1,"outbounds":[],"rules":[],"default_outbound_id":"direct","mode":"ordered-v1-inherited","source":"global","source_server_id":0,"source_revision":%d,"local_transition_revision":0}}}`, current)
	}))
	defer server.Close()
	client := NewServerClient(&conf.ServerApiConfig{ApiHost: server.URL, ServerId: 7})
	fetch := func() *ServerConfigResponse {
		t.Helper()
		p, err := GetServerConfig(t.Context(), client)
		if err != nil {
			t.Fatal(err)
		}
		return p
	}
	first := fetch()
	if first == nil || client.ServerConfigEtag != "" {
		t.Fatal("observation was prematurely committed")
	}
	client.Commit(first)
	if client.ServerConfigEtag != `"r1"` || fetch() != nil {
		t.Fatal("applied configuration was not cached")
	}
	mu.Lock()
	revision = 2
	mu.Unlock()
	bad := fetch()
	if bad == nil {
		t.Fatal("new candidate not observed")
	}
	client.State.RecordFailure(bad, "build")
	if again := fetch(); again != bad {
		t.Fatal("304 swallowed pending candidate")
	}
	if client.ServerConfigEtag != `"r1"` || client.State.Snapshot().Applied.SourceRevision != 1 {
		t.Fatal("failed candidate was committed")
	}
	mu.Lock()
	revision = 3
	mu.Unlock()
	newer := fetch()
	if newer == nil || newer == bad {
		t.Fatal("new candidate did not replace pending")
	}
	client.Commit(bad) // A newer observation arrived during the switch.
	status := client.State.Snapshot()
	if status.Applied.SourceRevision != 2 || status.Pending.SourceRevision != 3 {
		t.Fatalf("lost concurrent candidate: %+v", status)
	}
	client.Commit(newer)
	status = client.State.Snapshot()
	if status.Applied.SourceRevision != 3 || status.Pending != nil || status.Error == nil || status.Error.Identity.SourceRevision != 2 {
		t.Fatalf("wrong committed state: %+v", status)
	}
}

func TestProtobufHTTPErrorAndResponseLimit(t *testing.T) {
	for _, tc := range []struct {
		name    string
		handler http.HandlerFunc
		want    string
	}{
		{"protobuf error", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", protobufContentType)
			w.WriteHeader(426)
			b, _ := proto.Marshal(&serverv1.Result{Code: 426, Message: "upgrade required"})
			w.Write(b)
		}, "upgrade required"},
		{"too large", func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprint(w, strings.Repeat("x", MaxServerConfigResponseBytes+1))
		}, "超过"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(tc.handler)
			defer srv.Close()
			c := NewServerClient(&conf.ServerApiConfig{ApiHost: srv.URL, ServerId: 1})
			if _, err := GetServerConfig(t.Context(), c); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v", err)
			}
		})
	}
}

func TestServerStatusWithoutProtocolJSONAndProtobuf(t *testing.T) {
	for _, binary := range []bool{false, true} {
		t.Run(fmt.Sprint(binary), func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Query().Get("server_id") != "7" || r.URL.Query().Get("protocol") != "" {
					t.Errorf("not server-scoped: %s", r.URL.RawQuery)
				}
				if binary {
					var msg serverv1.PushServerStatusRequest
					if err := proto.Unmarshal(readRequestBody(t, r), &msg); err != nil {
						t.Fatal(err)
					}
					if msg.RoutingVersion != 1 || msg.InstanceId != ProcessInstanceID() || msg.RoutingSequence == 0 || msg.RoutingApplied.SourceRevision != 7 || msg.RoutingPending.SourceRevision != 8 || msg.RoutingError.Stage != "bind" {
						t.Fatalf("protobuf status: %+v", &msg)
					}
					writeProtobuf(t, w, &serverv1.Result{Code: 200})
					return
				}
				var msg ServerPushStatusRequest
				if err := json.NewDecoder(r.Body).Decode(&msg); err != nil {
					t.Fatal(err)
				}
				if msg.RoutingStatus == nil || msg.Version != 1 || msg.InstanceID != ProcessInstanceID() || msg.Sequence == 0 || msg.Applied.SourceRevision != 7 || msg.Pending.SourceRevision != 8 || msg.Error.Stage != "bind" {
					t.Fatalf("JSON status: %+v", msg)
				}
				fmt.Fprint(w, `{"code":200}`)
			}))
			defer server.Close()
			c := NewServerClient(&conf.ServerApiConfig{ApiHost: server.URL, ServerId: 7})
			if err := c.ActivateStatusPublisher(); err != nil {
				t.Fatal(err)
			}
			c.UseProtobuf = binary
			c.State.commit(&RoutingIdentity{Mode: "ordered-v1-inherited", Source: "global", SourceRevision: 7}, &RoutingIdentity{Mode: "ordered-v1-inherited", Source: "global", SourceRevision: 8})
			c.State.RecordFailure(nil, "bind")
			if err := c.ReportServerStatus(t.Context(), &NodeStatus{CPU: 0.5}); err != nil {
				t.Fatal(err)
			}
		})
	}
}

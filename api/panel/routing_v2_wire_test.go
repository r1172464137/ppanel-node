package panel

import (
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
)

func v2WireFixture() *serverv1.QueryServerProtocolConfigResponse {
	const out = "ob_11111111-1111-4111-8111-111111111111"
	return &serverv1.QueryServerProtocolConfigResponse{Code: 200, Data: &serverv1.QueryServerProtocolConfigData{
		Total: 1, Protocols: []*serverv1.ServerProtocol{{Type: "vless", Enable: true, Port: 443, Transport: "tcp"}},
		Routing: &serverv1.RoutingPolicy{Version: 2, Mode: "ordered-v2-inherited", Source: "global", SourceRevision: 7, DefaultOutboundId: "direct",
			Outbounds:    []*serverv1.Outbound{{Id: out, Name: "exit", Protocol: "socks", Address: "127.0.0.1", Port: 1080}},
			Rules:        []*serverv1.RouteRule{{Id: "rr_11111111-1111-4111-8111-111111111111", Enabled: proto.Bool(false), Kind: serverv1.RouteKind_ROUTE_KIND_DOMAIN, Values: []string{"geosite:github"}, OutboundId: out, UserIds: []int64{42}}},
			UserDefaults: []*serverv1.UserDefault{{UserId: 42, OutboundId: out}},
			DnsPolicy:    &serverv1.DNSPolicy{QueryStrategy: "UseIPv4", Resolvers: []*serverv1.PolicyDNSResolver{{Id: "dns_11111111-1111-4111-8111-111111111111", Protocol: "udp", Address: "resolver.test:53", BootstrapIp: "127.0.0.1", OutboundId: out}}},
		},
		IdentitySnapshot: &serverv1.IdentitySnapshot{SnapshotId: strings.Repeat("a", 64), Protocols: []*serverv1.ProtocolUserSnapshot{{Protocol: "vless", Users: []*serverv1.ServerUser{{Id: 9, Uuid: "00000000-0000-0000-0000-000000000001", SpeedLimit: 12, DeviceLimit: 3, AccountId: 42}}}}},
	}}
}

func TestV2JSONProtobufSnapshotAndStatus(t *testing.T) {
	var first []byte
	for _, binary := range []bool{false, true} {
		t.Run(fmt.Sprint(binary), func(t *testing.T) {
			pb := v2WireFixture()
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get(RoutingVersionHeader) != SupportedRoutingVersion {
					t.Error("capability header missing")
				}
				w.Header().Set("ETag", `"identity-a"`)
				if r.Header.Get("If-None-Match") == `"identity-a"` {
					w.WriteHeader(304)
					return
				}
				var body []byte
				if binary {
					w.Header().Set("Content-Type", protobufContentType)
					body, _ = proto.Marshal(pb)
				} else {
					w.Header().Set("Content-Type", "application/json")
					body, _ = json.Marshal(serverConfigResponseFromProtobuf(pb))
				}
				_, _ = w.Write(body)
			}))
			defer srv.Close()
			client := NewServerClient(&conf.ServerApiConfig{ApiHost: srv.URL, ServerId: 7})
			candidate, err := GetServerConfig(t.Context(), client)
			if err != nil {
				t.Fatal(err)
			}
			encoded, err := json.Marshal(candidate.Data)
			if err != nil {
				t.Fatal(err)
			}
			if first == nil {
				first = encoded
			} else if !reflect.DeepEqual(encoded, first) {
				t.Fatal("JSON/protobuf effective data differs")
			}
			if candidate.Data.Routing.Rules[0].Enabled == nil || *candidate.Data.Routing.Rules[0].Enabled {
				t.Fatal("false rule presence lost")
			}
			client.RecordFailure(candidate, StageBuild)
			again, err := GetServerConfig(t.Context(), client)
			if err != nil || again != candidate {
				t.Fatal("304 swallowed snapshot candidate")
			}
			if err := client.Commit(candidate); err != nil {
				t.Fatal(err)
			}
			status := client.State.Snapshot()
			if status.Version != 2 || status.Applied == nil || status.Applied.SnapshotID != strings.Repeat("a", 64) {
				t.Fatalf("snapshot receipt not paired: %+v", status)
			}
		})
	}
}

func TestV2ClientNegotiatesOldPanelWithoutStrippingPolicy(t *testing.T) {
	var headers []string
	var mu sync.Mutex
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		version := r.Header.Get(RoutingVersionHeader)
		mu.Lock()
		headers = append(headers, version)
		mu.Unlock()
		if version != "1" {
			w.WriteHeader(426)
			return
		}
		fmt.Fprint(w, `{"code":200,"data":{"total":0,"protocols":[],"routing":{"version":1,"outbounds":[],"rules":[],"default_outbound_id":"direct","mode":"ordered-v1-inherited","source":"global","source_revision":1}}}`)
	}))
	defer srv.Close()
	client := NewServerClient(&conf.ServerApiConfig{ApiHost: srv.URL, ServerId: 7})
	candidate, err := GetServerConfig(t.Context(), client)
	mu.Lock()
	defer mu.Unlock()
	if err != nil || candidate == nil || candidate.Data.Routing.Version != 1 || !reflect.DeepEqual(headers, []string{"2", "1"}) {
		t.Fatalf("old panel negotiation: %v %v", headers, err)
	}
}

func TestV2SnapshotUnknownWireFieldsAreRejected(t *testing.T) {
	pb := v2WireFixture()
	unknown := protowire.AppendTag(nil, 99, protowire.VarintType)
	unknown = protowire.AppendVarint(unknown, 1)
	pb.Data.IdentitySnapshot.Protocols[0].Users[0].ProtoReflect().SetUnknown(unknown)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", protobufContentType)
		body, _ := proto.Marshal(pb)
		_, _ = w.Write(body)
	}))
	defer srv.Close()
	if _, err := GetServerConfig(t.Context(), NewServerClient(&conf.ServerApiConfig{ApiHost: srv.URL, ServerId: 7})); err == nil {
		t.Fatal("unknown identity field ignored")
	}
	var data Data
	if err := json.Unmarshal([]byte(`{"protocols":[],"identity_snapshot":{"snapshot_id":"a","protocols":[{"protocol":"vless","users":[{"id":1,"uuid":"x","account_id":2,"unexpected":true}]}]}}`), &data); err == nil {
		t.Fatal("unknown JSON identity field ignored")
	}
}

package panel

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	serverv1 "github.com/perfect-panel/ppanel-node/api/server/v1"
	"github.com/perfect-panel/ppanel-node/conf"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
)

func readRequestBody(t *testing.T, request *http.Request) []byte {
	t.Helper()
	body, err := io.ReadAll(request.Body)
	if err != nil {
		t.Fatalf("read request body: %v", err)
	}
	return body
}

func writeProtobuf(t *testing.T, writer http.ResponseWriter, message proto.Message) {
	t.Helper()
	body, err := proto.Marshal(message)
	if err != nil {
		t.Fatalf("proto.Marshal() error = %v", err)
	}
	writer.Header().Set("Content-Type", protobufContentType)
	_, _ = writer.Write(body)
}

func testPanelRouting() *RoutingPolicy {
	return &RoutingPolicy{Version: RoutingVersion, Outbounds: []Outbound{}, Rules: []RouteRule{}, DefaultOutboundID: "direct",
		UserDefaults: []UserDefault{}, TargetIPPreference: "none",
		DNS:             &DNSPolicy{QueryStrategy: "UseIP", Resolvers: []DNSResolverPolicy{{ID: "dns_00000000-0000-4000-8000-000000000001", Protocol: "system", Domains: []string{}, OutboundID: "direct"}}},
		RoutingIdentity: RoutingIdentity{Mode: "inherited", Source: "global", SourceRevision: 1}}
}

const testSnapshotID = "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd"

// testIdentity is an identity snapshot covering the given protocol types,
// each with no users.
func testIdentity(protocols ...string) *IdentitySnapshot {
	s := &IdentitySnapshot{SnapshotID: testSnapshotID, Protocols: []ProtocolIdentity{}}
	for _, p := range protocols {
		s.Protocols = append(s.Protocols, ProtocolIdentity{Protocol: p, Users: []IdentityUser{}})
	}
	return s
}

func TestServerClientUsesProtobuf(t *testing.T) {
	server := httptest.NewTestServer(t, http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/v2/server/7" {
			t.Fatalf("path = %q", request.URL.Path)
		}
		if got := request.Header.Get("Accept"); got != protobufContentType {
			t.Fatalf("Accept = %q, want %q", got, protobufContentType)
		}
		if got := request.Header.Get(RoutingVersionHeader); got != "3" {
			t.Fatalf("routing capability = %q", got)
		}
		writer.Header().Set("ETag", `"protobuf-config"`)
		writeProtobuf(t, writer, &serverv1.QueryServerProtocolConfigResponse{
			Code:    http.StatusOK,
			Message: "success",
			Data: &serverv1.QueryServerProtocolConfigData{
				PushInterval:     60,
				Total:            1,
				Routing:          &serverv1.RoutingPolicy{Version: 3, DefaultOutboundId: "direct", Mode: "inherited", Source: "global", SourceRevision: 1},
				IdentitySnapshot: &serverv1.IdentitySnapshot{SnapshotId: testSnapshotID, Protocols: []*serverv1.ProtocolIdentity{{Protocol: "vless"}}},
				Protocols: []*serverv1.ServerProtocol{{
					Type: "vless", Port: 443, Enable: true, Transport: "tcp",
				}},
			},
		})
	}))
	httpClient := server.Client()

	client := NewServerClient(&conf.ServerApiConfig{
		ApiHost: server.URL, ServerId: 7,
	})
	client.Client.SetTransport(httpClient.Transport)
	response, err := GetServerConfig(t.Context(), client)
	if err != nil {
		t.Fatalf("GetServerConfig() error = %v", err)
	}
	if response.Data.PushInterval != 60 || len(*response.Data.Protocols) != 1 || (*response.Data.Protocols)[0].Port != 443 {
		t.Fatalf("response data = %+v, want converted protobuf configuration", response.Data)
	}
	if response.Data.Routing == nil || response.Data.Routing.Version != 3 || response.Data.IdentitySnapshot == nil {
		t.Fatal("ordered policy missing")
	}
	if client.ServerConfigEtag != "" {
		t.Fatalf("observed ETag was committed before application: %q", client.ServerConfigEtag)
	}
	client.Commit(response)
	if client.ServerConfigEtag != `"protobuf-config"` {
		t.Fatalf("applied ETag = %q", client.ServerConfigEtag)
	}
	if !response.UseProtobuf || !client.UseProtobuf {
		t.Fatalf("protobuf negotiation = response:%v client:%v, want true", response.UseProtobuf, client.UseProtobuf)
	}
}

func TestServerClientFallsBackToJSON(t *testing.T) {
	server := httptest.NewTestServer(t, http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if got := request.Header.Get("Accept"); got != protobufContentType {
			t.Fatalf("Accept = %q, want Protobuf preference", got)
		}
		_ = json.NewEncoder(writer).Encode(&ServerConfigResponse{
			Code: http.StatusOK,
			Msg:  "success",
			Data: &Data{Protocols: &[]Protocol{{Type: "vless", Port: 443, Enable: true, Transport: "tcp"}}, Total: 1, Routing: testPanelRouting(), IdentitySnapshot: testIdentity("vless")},
		})
	}))
	httpClient := server.Client()

	client := NewServerClient(&conf.ServerApiConfig{ApiHost: server.URL, ServerId: 7})
	client.Client.SetTransport(httpClient.Transport)
	response, err := GetServerConfig(t.Context(), client)
	if err != nil {
		t.Fatalf("GetServerConfig() error = %v", err)
	}
	if response.UseProtobuf {
		t.Fatal("UseProtobuf = true, want JSON fallback")
	}
}

func TestNodeClientUsesProtobuf(t *testing.T) {
	const certificateSHA256 = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
	server := httptest.NewTestServer(t, http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if got := request.Header.Get(CertificateSHA256Header); got != certificateSHA256 {
			t.Fatalf("%s = %q, want %q", CertificateSHA256Header, got, certificateSHA256)
		}
		if got := request.Header.Get("Accept"); got != protobufContentType {
			t.Fatalf("Accept = %q, want %q", got, protobufContentType)
		}
		if request.Method == http.MethodPost && request.Header.Get("Content-Type") != protobufContentType {
			t.Fatalf("Content-Type = %q, want %q", request.Header.Get("Content-Type"), protobufContentType)
		}
		switch request.URL.Path {
		case "/v1/server/user":
			writeProtobuf(t, writer, &serverv1.GetServerUserListResponse{
				Code: http.StatusOK, Message: "success",
				Data: &serverv1.ServerUserListData{Users: []*serverv1.ServerUser{{
					Id: 1, Uuid: "user-1", SpeedLimit: 10, DeviceLimit: 2,
				}}},
			})
		case "/v1/server/online":
			message := &serverv1.PushOnlineUsersRequest{}
			if err := proto.Unmarshal(readRequestBody(t, request), message); err != nil {
				t.Fatalf("online request: %v", err)
			}
			if len(message.Users) != 1 || message.Users[0].UserId != 1 {
				t.Fatalf("online users = %+v", message.Users)
			}
			writeProtobuf(t, writer, &serverv1.Result{Code: http.StatusOK, Message: "success"})
		case "/v1/server/push":
			message := &serverv1.PushUserTrafficRequest{}
			if err := proto.Unmarshal(readRequestBody(t, request), message); err != nil {
				t.Fatalf("traffic request: %v", err)
			}
			if len(message.Traffic) != 1 || message.Traffic[0].Download != 20 {
				t.Fatalf("traffic = %+v", message.Traffic)
			}
			writeProtobuf(t, writer, &serverv1.Result{Code: http.StatusOK, Message: "success"})
		case "/v1/server/status":
			message := &serverv1.PushServerStatusRequest{}
			if err := proto.Unmarshal(readRequestBody(t, request), message); err != nil {
				t.Fatalf("status request: %v", err)
			}
			if message.Cpu != 0.5 {
				t.Fatalf("status = %+v", message)
			}
			writeProtobuf(t, writer, &serverv1.Result{Code: http.StatusOK, Message: "success"})
		default:
			t.Fatalf("unexpected path %q", request.URL.Path)
		}
	}))
	httpClient := server.Client()

	client, err := NewNodeClient(&conf.NodeApiConfig{
		APIHost: server.URL, NodeID: 7, NodeType: "vless", UseProtobuf: true,
	})
	if err != nil {
		t.Fatalf("NewNodeClient() error = %v", err)
	}
	client.Client.SetTransport(httpClient.Transport)
	client.SetCertificateSHA256(strings.ToUpper(certificateSHA256))
	if err := client.ReportNodeOnlineUsers(context.Background(), &[]OnlineUser{{UID: 1, IP: "203.0.113.1"}}); err != nil {
		t.Fatalf("ReportNodeOnlineUsers() error = %v", err)
	}
	if err := client.ReportUserTraffic(context.Background(), &[]UserTraffic{{UID: 1, Upload: 10, Download: 20}}); err != nil {
		t.Fatalf("ReportUserTraffic() error = %v", err)
	}
	statusClient := NewServerClient(&conf.ServerApiConfig{ApiHost: server.URL, ServerId: 7})
	if err := statusClient.ActivateStatusPublisher(); err != nil {
		t.Fatal(err)
	}
	if err := statusClient.BindNodeClient(client); err != nil {
		t.Fatal(err)
	}
	if err := statusClient.ReportCertificateStatus(context.Background(), client, &NodeStatus{CPU: 0.5, Mem: 0.6, Disk: 0.7}); err != nil {
		t.Fatalf("ReportCertificateStatus() error = %v", err)
	}
}

// One format 3 candidate decoded from JSON and from protobuf yields the same
// model, including account scopes, account defaults, DNS, chains and the
// identity snapshot.
func TestFormat3JSONAndProtobufMappingMatch(t *testing.T) {
	const snap = "abababababababababababababababababababababababababababababababab"
	raw := `{"code":200,"data":{"pull_interval":60,"push_interval":60,"total":1,
		"protocols":[{"type":"vless","enable":true,"port":443,"transport":"tcp"}],
		"routing":{"version":3,"default_outbound_id":"direct","target_ip_preference":"prefer_ipv4",
			"mode":"inherited","source":"global","source_server_id":0,"source_revision":4,"local_transition_revision":0,
			"outbounds":[{"id":"ob_11111111-1111-4111-8111-111111111111","name":"A","protocol":"socks","address":"192.0.2.1","port":1080,"rules":[],"ip_rules":[],"protocol_rules":[]},
				{"id":"ob_22222222-2222-4222-8222-222222222222","name":"B","protocol":"socks","address":"192.0.2.2","port":1080,"via_outbound_id":"ob_11111111-1111-4111-8111-111111111111","rules":[],"ip_rules":[],"protocol_rules":[]}],
			"rules":[{"id":"rr_33333333-3333-4333-8333-333333333333","enabled":true,"remark":"","kind":"domain","values":["domain:example.com"],"outbound_id":"ob_22222222-2222-4222-8222-222222222222","user_ids":[42]}],
			"user_defaults":[{"user_id":42,"outbound_id":"block"}],
			"dns":{"query_strategy":"UseIPv4","resolvers":[{"id":"dns_44444444-4444-4444-8444-444444444444","protocol":"system","address":"","domains":[],"outbound_id":"direct"}]}},
		"identity_snapshot":{"snapshot_id":"` + snap + `","protocols":[{"protocol":"vless","users":[{"id":7,"uuid":"00000000-0000-4000-8000-000000000007","speed_limit":5,"device_limit":2,"account_id":42}]}]}}}`
	var fromJSON ServerConfigResponse
	if err := json.Unmarshal([]byte(raw), &fromJSON); err != nil {
		t.Fatal(err)
	}
	enabled := true
	fromProto := serverConfigResponseFromProtobuf(&serverv1.QueryServerProtocolConfigResponse{Code: 200, Data: &serverv1.QueryServerProtocolConfigData{
		PullInterval: 60, PushInterval: 60, Total: 1,
		Protocols: []*serverv1.ServerProtocol{{Type: "vless", Enable: true, Port: 443, Transport: "tcp"}},
		Routing: &serverv1.RoutingPolicy{Version: 3, DefaultOutboundId: "direct", TargetIpPreference: "prefer_ipv4",
			Mode: "inherited", Source: "global", SourceRevision: 4,
			Outbounds: []*serverv1.Outbound{
				{Id: "ob_11111111-1111-4111-8111-111111111111", Name: "A", Protocol: "socks", Address: "192.0.2.1", Port: 1080},
				{Id: "ob_22222222-2222-4222-8222-222222222222", Name: "B", Protocol: "socks", Address: "192.0.2.2", Port: 1080, ViaOutboundId: "ob_11111111-1111-4111-8111-111111111111"}},
			Rules: []*serverv1.RouteRule{{Id: "rr_33333333-3333-4333-8333-333333333333", Enabled: &enabled, Kind: serverv1.RouteKind_ROUTE_KIND_DOMAIN,
				Values: []string{"domain:example.com"}, OutboundId: "ob_22222222-2222-4222-8222-222222222222", UserIds: []int64{42}}},
			UserDefaults: []*serverv1.UserDefault{{UserId: 42, OutboundId: "block"}},
			Dns:          &serverv1.DNSPolicy{QueryStrategy: "UseIPv4", Resolvers: []*serverv1.DNSResolverPolicy{{Id: "dns_44444444-4444-4444-8444-444444444444", Protocol: "system", OutboundId: "direct"}}}},
		IdentitySnapshot: &serverv1.IdentitySnapshot{SnapshotId: snap, Protocols: []*serverv1.ProtocolIdentity{{Protocol: "vless",
			Users: []*serverv1.IdentityUser{{Id: 7, Uuid: "00000000-0000-4000-8000-000000000007", SpeedLimit: 5, DeviceLimit: 2, AccountId: 42}}}}},
	}})
	j, p := fromJSON.Data, fromProto.Data
	if !reflect.DeepEqual(j.Routing, p.Routing) {
		t.Fatalf("routing differs:\nJSON  %+v\nproto %+v", j.Routing, p.Routing)
	}
	if !reflect.DeepEqual(j.IdentitySnapshot, p.IdentitySnapshot) {
		t.Fatalf("identity differs:\nJSON  %+v\nproto %+v", j.IdentitySnapshot, p.IdentitySnapshot)
	}
	if p.LegacyPresent || j.LegacyPresent {
		t.Fatal("format 3 candidate marked legacy")
	}
}

func TestStructuredRouteRuleProtoFieldNumbers(t *testing.T) {
	dataFields := (&serverv1.QueryServerProtocolConfigData{}).ProtoReflect().Descriptor().Fields()
	for name, want := range map[string]int{"block": 6, "total": 9, "block_ips": 10, "block_protocols": 11} {
		field := dataFields.ByName(protoreflect.Name(name))
		if field == nil || int(field.Number()) != want {
			t.Errorf("QueryServerProtocolConfigData.%s tag = %v, want %d", name, field, want)
		}
	}
	outboundFields := (&serverv1.Outbound{}).ProtoReflect().Descriptor().Fields()
	for name, want := range map[string]int{"rules": 41, "ip_rules": 42, "protocol_rules": 43} {
		field := outboundFields.ByName(protoreflect.Name(name))
		if field == nil || int(field.Number()) != want {
			t.Errorf("Outbound.%s tag = %v, want %d", name, field, want)
		}
	}
}

// Repeated protobuf fields carry no presence: any non-empty removed legacy
// field marks the candidate, which validation then rejects.
func TestProtobufLegacyFieldsMarkCandidate(t *testing.T) {
	for name, data := range map[string]*serverv1.QueryServerProtocolConfigData{
		"ip_strategy": {IpStrategy: "prefer_ipv4"},
		"dns":         {Dns: []*serverv1.DNSResolver{{Address: "1.1.1.1"}}},
		"block":       {Block: []string{"geosite:cn"}},
		"block_ips":   {BlockIps: []string{"10.0.0.0/8"}},
		"protocols":   {BlockProtocols: []string{"bittorrent"}},
		"outbound":    {Outbound: []*serverv1.Outbound{{Name: "x", Protocol: "direct"}}},
	} {
		if got := serverConfigResponseFromProtobuf(&serverv1.QueryServerProtocolConfigResponse{Code: 200, Data: data}); !got.Data.LegacyPresent {
			t.Errorf("%s not marked legacy", name)
		}
	}
	if got := serverConfigResponseFromProtobuf(&serverv1.QueryServerProtocolConfigResponse{Code: 200, Data: &serverv1.QueryServerProtocolConfigData{}}); got.Data.LegacyPresent {
		t.Error("empty candidate marked legacy")
	}
}

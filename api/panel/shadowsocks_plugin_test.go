package panel

import (
	"encoding/json"
	"reflect"
	"testing"

	serverv1 "github.com/perfect-panel/ppanel-node/api/server/v1"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/structpb"
)

func TestShadowsocksInboundPluginJSONAndProtobufProjection(t *testing.T) {
	for _, option := range []any{"obfs=http", map[string]any{"mode": "http", "tls": false}, nil} {
		pbOption, err := structpb.NewValue(option)
		if err != nil {
			t.Fatal(err)
		}
		message := &serverv1.QueryServerProtocolConfigResponse{Code: 200, Data: &serverv1.QueryServerProtocolConfigData{
			Routing:   &serverv1.RoutingPolicy{Version: 1, DefaultOutboundId: "direct", Mode: "ordered-v1-inherited", Source: "global", SourceRevision: 1},
			Protocols: []*serverv1.ServerProtocol{{Type: "shadowsocks", Enable: true, Port: 443, Cipher: "aes-128-gcm", Plugin: "obfs", PluginOptions: pbOption}},
		}}
		wire, err := proto.Marshal(message)
		if err != nil {
			t.Fatal(err)
		}
		var decoded serverv1.QueryServerProtocolConfigResponse
		if err := proto.Unmarshal(wire, &decoded); err != nil {
			t.Fatal(err)
		}
		fromProto := (*serverConfigResponseFromProtobuf(&decoded).Data.Protocols)[0]
		body, err := json.Marshal(map[string]any{"protocols": []any{map[string]any{"type": "shadowsocks", "enable": true, "port": 443, "cipher": "aes-128-gcm", "plugin": "obfs", "plugin_opts": option}}})
		if err != nil {
			t.Fatal(err)
		}
		var data Data
		if err := json.Unmarshal(body, &data); err != nil {
			t.Fatal(err)
		}
		fromJSON := (*data.Protocols)[0]
		if fromProto.Plugin != "obfs" || !reflect.DeepEqual(fromProto.PluginOptions, fromJSON.PluginOptions) {
			t.Fatalf("plugin lost: JSON=%+v protobuf=%+v", fromJSON, fromProto)
		}
		if err := ValidateShadowsocksInboundPlugin(fromProto); err == nil {
			t.Fatal("unsupported plugin accepted")
		}
	}
}
func TestShadowsocksPluginDefaultAndNondefault(t *testing.T) {
	for _, p := range []Protocol{{}, {Plugin: "none"}, {PluginOptions: ""}, {PluginOptions: map[string]any{}}} {
		if err := ValidateShadowsocksInboundPlugin(p); err != nil {
			t.Fatalf("default plugin rejected: %+v %v", p, err)
		}
	}
	for _, p := range []Protocol{{Plugin: "v2ray-plugin"}, {PluginOptions: "tls"}, {PluginOptions: map[string]any{"mode": "http"}}, {PluginOptions: false}, {PluginOptions: []any{}}} {
		if err := ValidateShadowsocksInboundPlugin(p); err == nil {
			t.Fatalf("plugin semantics ignored: %+v", p)
		}
	}
}

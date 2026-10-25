package inbound

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/perfect-panel/ppanel-node/api/panel"
	serverv1 "github.com/perfect-panel/ppanel-node/api/server/v1"
	"github.com/perfect-panel/ppanel-node/conf"
	"github.com/xtls/xray-core/app/proxyman"
	"github.com/xtls/xray-core/transport/internet/reality"
	"google.golang.org/protobuf/proto"
)

type realityConfigTransport struct {
	body        []byte
	contentType string
}

func (transport realityConfigTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": {transport.contentType}}, Body: io.NopCloser(strings.NewReader(string(transport.body))), Request: request}, nil
}

// All HTTP responses are in-memory: no core instance, listener, target dial or process.
func TestRealityXverPanelDeliveryToBuiltConfig(t *testing.T) {
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	privateKey := base64.RawURLEncoding.EncodeToString(key.Bytes())
	for _, format := range []string{"json", "protobuf"} {
		for _, xver := range []int{0, 1, 2, -1, 3} {
			t.Run(fmt.Sprintf("%s/%d", format, xver), func(t *testing.T) {
				var body []byte
				contentType := "application/json"
				if format == "protobuf" {
					contentType = "application/protobuf"
					body, err = proto.Marshal(&serverv1.QueryServerProtocolConfigResponse{Code: 200, Data: &serverv1.QueryServerProtocolConfigData{Protocols: []*serverv1.ServerProtocol{{Type: "vless", Port: 20100, Enable: true, Transport: "tcp", Security: "reality", Sni: "example.com", RealityServerAddr: "127.0.0.1", RealityServerPort: 8443, RealityPrivateKey: privateKey, RealityShortId: "0123456789abcdef", RealityXver: uint32(xver), AcceptProxyProtocol: true}}}})
				} else {
					// Zero is deliberately absent to cover old panel responses.
					p := map[string]any{"type": "vless", "port": 20100, "enable": true, "transport": "tcp", "security": "reality", "sni": "example.com", "reality_server_addr": "127.0.0.1", "reality_server_port": 8443, "reality_private_key": privateKey, "reality_short_id": "0123456789abcdef", "accept_proxy_protocol": true}
					if xver != 0 {
						p["reality_xver"] = xver
					}
					body, err = json.Marshal(map[string]any{"code": 200, "data": map[string]any{"protocols": []any{p}}})
				}
				if err != nil {
					t.Fatal(err)
				}
				client := panel.NewServerClient(&conf.ServerApiConfig{ApiHost: "http://panel.invalid", ServerId: 1})
				client.Client.SetTransport(realityConfigTransport{body: body, contentType: contentType})
				response, err := panel.GetServerConfig(t.Context(), client)
				if err != nil {
					t.Fatal(err)
				}
				p := (*response.Data.Protocols)[0]
				built, err := Build(&panel.NodeInfo{Id: 1, Type: p.Type, Protocol: &p}, "delivery-test")
				if xver < 0 || xver > 2 {
					if err == nil {
						t.Fatalf("invalid %d reached built config", xver)
					}
					return
				}
				if err != nil {
					t.Fatal(err)
				}
				receiver, err := built.ReceiverSettings.GetInstance()
				if err != nil {
					t.Fatal(err)
				}
				security, err := receiver.(*proxyman.ReceiverConfig).StreamSettings.GetEffectiveSecuritySettings()
				if err != nil {
					t.Fatal(err)
				}
				if got := security.(*reality.Config).Xver; got != uint64(xver) {
					t.Fatalf("built Xver = %d, want %d", got, xver)
				}
			})
		}
	}
}

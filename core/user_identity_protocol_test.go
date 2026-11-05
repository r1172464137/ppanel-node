package core

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"testing"
	"time"

	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/serial"
	xray "github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/outbound"
	"github.com/xtls/xray-core/features/routing"
	coreConf "github.com/xtls/xray-core/infra/conf"
)

// Exercise the authenticated context, rather than trusting constructors that
// assign Email. A missing or different user identity must reach the block rule.
func TestAuthenticatedUserRoutingAcrossSupportedInbounds(t *testing.T) {
	for _, name := range []string{"vless", "vmess", "shadowsocks", "trojan", "anytls", "hysteria2", "tuic"} {
		t.Run(name, func(t *testing.T) {
			server, port, _, user, pin := protocolServer(t, name)
			socks := startControlledSOCKSServer(t)
			settings, _ := json.Marshal(map[string]any{"address": "127.0.0.1", "port": socks.port()})
			raw := json.RawMessage(settings)
			cfg, err := (&coreConf.OutboundDetourConfig{Tag: "identity-proof", Protocol: "socks", Settings: &raw}).Build()
			if err != nil {
				t.Fatal(err)
			}
			object, err := xray.CreateObject(server.Server, cfg)
			if err != nil {
				t.Fatal(err)
			}
			if err = server.ohm.AddHandler(context.Background(), object.(outbound.Handler)); err != nil {
				t.Fatal(err)
			}
			setUser := func(email string) {
				t.Helper()
				match, _ := json.Marshal(map[string]any{"user": []string{email}, "ip": []string{"203.0.113.42"}, "outboundTag": "identity-proof"})
				block := json.RawMessage(`{"network":"tcp,udp","outboundTag":"block"}`)
				rules, err := (&coreConf.RouterConfig{RuleList: []json.RawMessage{match, block}}).Build()
				if err != nil {
					t.Fatal(err)
				}
				if err = server.Server.GetFeature(routing.RouterType()).(routing.Router).AddRule(serial.ToTypedMessage(rules), false); err != nil {
					t.Fatal(err)
				}
			}
			setUser("protocol-test|" + user.Uuid)
			var client *xray.Instance
			if name != "tuic" {
				client = protocolClient(t, name, port, pin)
			}
			probe := func() error {
				ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
				defer cancel()
				target := xnet.TCPDestination(xnet.ParseAddress("203.0.113.42"), 443)
				var conn io.ReadWriteCloser
				if name == "tuic" {
					conn = dialTUIC(t, ctx, port, target)
				} else {
					var err error
					conn, err = xray.Dial(ctx, client, target)
					if err != nil {
						return err
					}
				}
				defer conn.Close()
				if _, err := conn.Write([]byte("identity")); err != nil {
					return err
				}
				buf := make([]byte, 8)
				_, err := io.ReadFull(conn, buf)
				if err == nil && string(buf) != "identity" {
					return fmt.Errorf("unexpected relay response")
				}
				return err
			}
			if err := probe(); err != nil {
				t.Fatalf("authenticated identity not matched: %v", err)
			}
			select {
			case e := <-socks.evidence:
				if e.host != "203.0.113.42" {
					t.Fatalf("wrong target: %+v", e)
				}
			case <-time.After(time.Second):
				t.Fatal("user route did not reach SOCKS")
			}
			setUser("different-authenticated-identity")
			if err := probe(); err == nil {
				t.Fatal("different user condition was ignored")
			}
			select {
			case e := <-socks.evidence:
				t.Fatalf("wrong identity reached SOCKS: %+v", e)
			default:
			}
		})
	}
}

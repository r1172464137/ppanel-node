package inbound

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"testing"

	"github.com/perfect-panel/ppanel-node/api/panel"
	"github.com/xtls/xray-core/app/proxyman"
	"github.com/xtls/xray-core/transport/internet/reality"
	"github.com/xtls/xray-core/transport/internet/tcp"
	"google.golang.org/protobuf/proto"
)

func TestRealityXverBuild(t *testing.T) {
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{"vless", "vmess", "trojan", "anytls"} {
		for _, xver := range []int{0, 1, 2} {
			for _, accept := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/%d/accept=%v", kind, xver, accept), func(t *testing.T) {
					p := &panel.Protocol{Port: 20100, Transport: "tcp", Security: "reality", SNI: "example.com", RealityServerAddr: "127.0.0.1", RealityServerPort: 8443,
						RealityPrivateKey: base64.RawURLEncoding.EncodeToString(key.Bytes()), RealityShortID: "0123456789abcdef", RealityXver: xver, AcceptProxyProtocol: accept}
					built, err := Build(&panel.NodeInfo{Id: 1, Type: kind, Protocol: p}, "reality-xver-test")
					if err != nil {
						t.Fatal(err)
					}
					value, err := built.ReceiverSettings.GetInstance()
					if err != nil {
						t.Fatal(err)
					}
					receiver := value.(*proxyman.ReceiverConfig)
					security, err := receiver.StreamSettings.GetEffectiveSecuritySettings()
					if err != nil {
						t.Fatal(err)
					}
					config := security.(*reality.Config)
					if config.Xver != uint64(xver) || config.Dest != "127.0.0.1:8443" {
						t.Fatalf("REALITY config = %v", config)
					}
					if native := config.GetREALITYConfig(); native.Xver != byte(xver) {
						t.Fatalf("native REALITY Xver = %d, want %d", native.Xver, xver)
					}
					if len(receiver.PortList.Range) != 1 || receiver.PortList.Range[0].From != 20100 || receiver.PortList.Range[0].To != 20100 {
						t.Fatalf("listener ports changed: %v", receiver.PortList)
					}
					if kind != "anytls" {
						transport, err := receiver.StreamSettings.TransportSettings[0].Settings.GetInstance()
						if err != nil {
							t.Fatal(err)
						}
						if transport.(*tcp.Config).AcceptProxyProtocol != accept {
							t.Fatalf("PROXY reception changed: %v", transport)
						}
					}
				})
			}
		}
	}
	for _, xver := range []int{-1, 3, int(^uint(0) >> 1)} {
		_, err := Build(&panel.NodeInfo{Type: "vless", Protocol: &panel.Protocol{Transport: "tcp", Security: "reality", RealityXver: xver}}, "invalid")
		if err == nil {
			t.Fatalf("accepted invalid xver %d", xver)
		}
	}
}

func TestRealityXverNonRealityAndProxyReceptionUnchanged(t *testing.T) {
	for _, transport := range []string{"tcp", "ws", "httpupgrade"} {
		for _, accept := range []bool{false, true} {
			base := &panel.NodeInfo{Type: "vless", Protocol: &panel.Protocol{Port: 20100, Transport: transport, AcceptProxyProtocol: accept}}
			before, err := Build(base, "non-reality")
			if err != nil {
				t.Fatal(err)
			}
			base.Protocol.RealityXver = 2
			after, err := Build(base, "non-reality")
			if err != nil {
				t.Fatal(err)
			}
			if !proto.Equal(before, after) {
				t.Fatalf("non-REALITY config changed for %s accept=%v", transport, accept)
			}
		}
	}
}

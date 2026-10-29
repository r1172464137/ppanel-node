package outbound

import (
	"encoding/base64"
	"fmt"
	"strings"
	"testing"

	"github.com/perfect-panel/ppanel-node/api/panel"
)

func TestOrderedOutboundCapabilityMatrixFailsBeforeBuild(t *testing.T) {
	cases := []struct {
		name   string
		change func(*panel.Outbound)
		want   string
	}{
		{"tuic", func(o *panel.Outbound) { o.Protocol = "tuic" }, "TUIC outbound"},
		{"tuic-raw-settings", func(o *panel.Outbound) {
			o.Protocol = "tuic"
			o.Settings = `{"address":"127.0.0.1","port":443,"id":"00000000-0000-0000-0000-000000000001","password":"password"}`
		}, "TUIC outbound"},
		{"tuic-transport", func(o *panel.Outbound) { o.Protocol = "vless"; o.Transport = "tuic" }, "TUIC"},
		{"tuic-raw-network", func(o *panel.Outbound) { o.Protocol = "vless"; o.StreamSettings = `{"network":"tuic"}` }, "TUIC"},
		{"tuic-raw-method", func(o *panel.Outbound) { o.Protocol = "vless"; o.StreamSettings = `{"network":"tcp","method":"tuic"}` }, "TUIC"},
		{"tuic-xhttp-download", func(o *panel.Outbound) {
			o.Protocol = "vless"
			o.Transport = "xhttp"
			o.XHTTPExtra = `{"downloadSettings":{"network":"tuic"}}`
		}, "TUIC"},
		{"wireguard-raw", func(o *panel.Outbound) { o.Protocol = "wireguard"; o.Settings = `{}` }, "unsupported"},
		{"custom-dns-raw", func(o *panel.Outbound) { o.Protocol = "dns"; o.Settings = `{}` }, "unsupported"},
		{"loopback-raw", func(o *panel.Outbound) { o.Protocol = "loopback"; o.Settings = `{}` }, "unsupported"},
		{"orphan-plugin-options", func(o *panel.Outbound) { o.PluginOptions = map[string]any{"mode": "http"} }, "plugin"},
		{"raw-plugin", func(o *panel.Outbound) {
			o.Protocol = "shadowsocks"
			o.Settings = `{"address":"127.0.0.1","port":443,"method":"aes-128-gcm","password":"x","plugin":"obfs"}`
		}, "plugin"},
		{"hysteria-wrong-transport", func(o *panel.Outbound) { o.Protocol = "hysteria2"; o.StreamSettings = `{"network":"tcp"}` }, "requires Hysteria"},
		{"vless-hysteria-transport", func(o *panel.Outbound) { o.Protocol = "vless"; o.Transport = "hysteria" }, "requires Hysteria"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := orderedFixture()
			tc.change(&cfg.Data.Routing.Outbounds[0])
			if err := ValidateOrdered(cfg.Data); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("ValidateOrdered = %v, want %q", err, tc.want)
			}
			if _, err := Build(cfg, false); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Build = %v, want %q", err, tc.want)
			}
		})
	}
	// Unsupported connections cannot hide just because no enabled rule or
	// default references them.
	cfg := orderedFixture()
	cfg.Data.Routing.DefaultOutboundID = "direct"
	cfg.Data.Routing.Rules = []panel.RouteRule{}
	cfg.Data.Routing.Outbounds[0].Protocol = "tuic"
	if err := ValidateOrdered(cfg.Data); err == nil {
		t.Fatal("unreferenced TUIC accepted")
	}
}

func TestAllOrderedOutboundsRejectNondefaultUOT(t *testing.T) {
	for _, protocol := range []string{"direct", "block", "socks", "http", "shadowsocks", "vless", "vmess", "trojan", "anytls", "hysteria2", "tuic"} {
		for _, mutation := range []struct {
			name  string
			apply func(*panel.Outbound)
		}{
			{"uot", func(o *panel.Outbound) { o.UoT = true }},
			{"version", func(o *panel.Outbound) { o.UoTVersion = 2 }},
			{"settings", func(o *panel.Outbound) { o.Settings = `{"nested":[{"udp_over_tcp":true}]}` }},
			{"stream", func(o *panel.Outbound) { o.StreamSettings = `{"nested":{"UoTVersion":2}}` }},
			{"unicode-fold", func(o *panel.Outbound) { o.Settings = `{"uotVer\u017fion":2}` }},
			{"xhttp-extra", func(o *panel.Outbound) { o.XHTTPExtra = `{"downloadSettings":{"nested":{"UDP-OVER-TCP":true}}}` }},
		} {
			t.Run(protocol+"/"+mutation.name, func(t *testing.T) {
				cfg := orderedFixture()
				ob := &cfg.Data.Routing.Outbounds[0]
				ob.Protocol = protocol
				mutation.apply(ob)
				if err := ValidateOrdered(cfg.Data); err == nil {
					t.Fatal("nondefault UoT accepted")
				}
			})
		}
	}
}

func TestRawCaseFoldConflictsRejectedBeforeBuild(t *testing.T) {
	for _, tc := range []struct {
		name  string
		apply func(*panel.Outbound)
	}{
		{"settings", func(o *panel.Outbound) { o.Settings = `{"domainStrategy":"UseIPv4","DomainStrategy":"UseIPv6"}` }},
		{"stream-security", func(o *panel.Outbound) { o.StreamSettings = `{"security":"tls","Security":"reality"}` }},
		{"nested-tls", func(o *panel.Outbound) {
			o.StreamSettings = `{"security":"tls","tlsSettings":{"serverName":"a","ServerName":"b"}}`
		}},
		{"xhttp-nested", func(o *panel.Outbound) { o.XHTTPExtra = `{"downloadSettings":{"security":"tls","Security":"reality"}}` }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := orderedFixture()
			tc.apply(&cfg.Data.Routing.Outbounds[0])
			if err := ValidateOrdered(cfg.Data); err == nil {
				t.Fatal("fold collision accepted")
			}
			if _, err := Build(cfg, false); err == nil {
				t.Fatal("fold collision built")
			}
		})
	}
}

func realityOutbound() panel.Outbound {
	return panel.Outbound{ID: testOutboundID, Name: "reality", Protocol: "vless", Address: "example.com", Port: 443, UUID: "00000000-0000-0000-0000-000000000001", Transport: "tcp", Security: "reality", SNI: "example.com", RealityPublicKey: base64.RawURLEncoding.EncodeToString(make([]byte, 32)), Fingerprint: "chrome"}
}
func TestMalformedURIsRejectedBeforeXrayBuild(t *testing.T) {
	key := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	cases := []struct {
		name   string
		change func(*panel.Outbound)
	}{
		{"spider-escape", func(o *panel.Outbound) { o.SpiderX = "/%" }},
		{"spider-query", func(o *panel.Outbound) { o.SpiderX = "/?p=%" }},
		{"spider-escaped-control", func(o *panel.Outbound) { o.SpiderX = "/%00" }},
		{"spider-query-control", func(o *panel.Outbound) { o.SpiderX = "/?a=%0A" }},
		{"spider-padding-oom", func(o *panel.Outbound) { o.SpiderX = "/?p=9223372036854775807" }},
		{"spider-concurrency", func(o *panel.Outbound) { o.SpiderX = "/?c=1000000000" }},
		{"spider-worker-amplification", func(o *panel.Outbound) { o.SpiderX = "/?c=8&t=16" }},
		{"spider-duplicate", func(o *panel.Outbound) { o.SpiderX = "/?p=1&p=2" }},
		{"spider-network-path", func(o *panel.Outbound) { o.SpiderX = "//attacker.example/path" }},
		{"spider-fragment", func(o *panel.Outbound) { o.SpiderX = "/path#frag" }},
		{"spider-raw", func(o *panel.Outbound) {
			o.StreamSettings = fmt.Sprintf(`{"network":"tcp","security":"reality","realitySettings":{"fingerprint":"chrome","serverName":"example.com","publicKey":%q,"spiderX":"/%%"}}`, key)
		}},
		{"spider-nested-download", func(o *panel.Outbound) {
			o.Security = ""
			o.Transport = "xhttp"
			o.XHTTPExtra = `{"downloadSettings":{"network":"tcp","security":"reality","realitySettings":{"spiderX":"/%"}}}`
		}},
		{"spider-nested-padding", func(o *panel.Outbound) {
			o.Security = ""
			o.Transport = "xhttp"
			o.XHTTPExtra = `{"downloadSettings":{"network":"tcp","security":"reality","realitySettings":{"spiderX":"/?p=4097"}}}`
		}},
		{"websocket-path", func(o *panel.Outbound) { o.Security = ""; o.Transport = "ws"; o.Path = "/%" }},
		{"raw-ws-path", func(o *panel.Outbound) { o.StreamSettings = `{"network":"ws","wsSettings":{"path":"/bad?ed=%"}}` }},
		{"httpupgrade-path", func(o *panel.Outbound) { o.Security = ""; o.Transport = "httpupgrade"; o.Path = "/%" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := orderedFixture()
			cfg.Data.Routing.Outbounds[0] = realityOutbound()
			tc.change(&cfg.Data.Routing.Outbounds[0])
			if err := ValidateOrdered(cfg.Data); err == nil {
				t.Fatal("invalid URI passed validation")
			}
			defer func() {
				if v := recover(); v != nil {
					t.Fatalf("malformed URI panicked: %v", v)
				}
			}()
			if _, err := Build(cfg, false); err == nil {
				t.Fatal("invalid URI built successfully")
			}
		})
	}
	cfg := orderedFixture()
	ob := realityOutbound()
	ob.SpiderX = "/path?p=1-2&x=value"
	cfg.Data.Routing.Outbounds[0] = ob
	if _, err := Build(cfg, false); err != nil {
		t.Fatalf("valid REALITY URI rejected: %v", err)
	}
}

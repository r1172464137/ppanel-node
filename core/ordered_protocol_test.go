package core

import (
	"testing"

	"github.com/perfect-panel/ppanel-node/api/panel"
)

func TestAllInboundProtocolUOTFieldsFailClosed(t *testing.T) {
	for _, kind := range []string{"vless", "vmess", "trojan", "shadowsocks", "anytls", "hysteria2", "tuic", "future"} {
		for _, enabled := range []bool{false, true} {
			for _, mutation := range []func(*panel.Protocol){
				func(p *panel.Protocol) { p.UoT = true },
				func(p *panel.Protocol) { p.UoTVersion = 2 },
				func(p *panel.Protocol) { p.XHTTPExtra = `{"downloadSettings":{"nested":{"u_o_t":true}}}` },
				func(p *panel.Protocol) {
					p.PluginOptions = map[string]any{"nested": map[string]any{"UDPOverTCP": true}}
				},
				func(p *panel.Protocol) { p.PluginOptions = map[string]string{"uot": "true"} },
			} {
				cfg := orderedConfig([]panel.RouteRule{}, nil)
				cfg.Data.Total = 1
				p := panel.Protocol{Type: kind, Enable: enabled, Port: 443, Transport: "tcp", Cipher: "aes-128-gcm"}
				mutation(&p)
				*cfg.Data.Protocols = []panel.Protocol{p}
				if err := ValidateServerConfig(cfg); err == nil {
					t.Fatalf("%s enabled=%v UoT accepted", kind, enabled)
				}
			}
		}
	}
}

func TestShadowsocksPluginCannotBeApplied(t *testing.T) {
	cfg := orderedConfig([]panel.RouteRule{}, nil)
	cfg.Data.Total = 1
	for _, p := range []panel.Protocol{
		{Type: "shadowsocks", Enable: true, Port: 443, Cipher: "aes-128-gcm", Plugin: "obfs"},
		{Type: "shadowsocks", Enable: true, Port: 443, Cipher: "aes-128-gcm", PluginOptions: map[string]any{"mode": "http"}},
	} {
		*cfg.Data.Protocols = []panel.Protocol{p}
		if err := ValidateServerConfig(cfg); err == nil {
			t.Fatalf("plugin protocol accepted: %+v", p)
		}
		p.Enable = false
		*cfg.Data.Protocols = []panel.Protocol{p}
		if err := ValidateServerConfig(cfg); err != nil {
			t.Fatalf("disabled protocol rejected: %v", err)
		}
	}
	*cfg.Data.Protocols = []panel.Protocol{{Type: "vless", Enable: true, Port: 443, Transport: "tcp"}}
	if err := ValidateServerConfig(cfg); err != nil {
		t.Fatalf("ordinary VLESS rejected: %v", err)
	}
}

func TestOrderedRejectsUnsupportedEnabledProtocols(t *testing.T) {
	cfg := orderedConfig([]panel.RouteRule{}, nil)
	cfg.Data.Total = 1
	*cfg.Data.Protocols = []panel.Protocol{{Type: "future-protocol", Enable: true, Port: 443}}
	if err := ValidateServerConfig(cfg); err == nil {
		t.Fatal("enabled unsupported protocol accepted")
	}
	(*cfg.Data.Protocols)[0].Enable = false
	if err := ValidateServerConfig(cfg); err != nil {
		t.Fatalf("disabled unsupported protocol: %v", err)
	}
	cfg.Data.Routing = nil
	(*cfg.Data.Protocols)[0].Enable = true
	if err := ValidateServerConfig(cfg); err == nil {
		t.Fatal("legacy configuration accepted")
	}
	cfg = orderedConfig([]panel.RouteRule{}, nil)
	cfg.Data.Total = 1
	*cfg.Data.Protocols = []panel.Protocol{{Type: "vless", Enable: true, Port: 0, Transport: "tcp"}}
	if err := ValidateServerConfig(cfg); err == nil {
		t.Fatal("unstartable enabled protocol accepted")
	}
}

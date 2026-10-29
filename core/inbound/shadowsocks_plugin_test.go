package inbound

import (
	"strings"
	"testing"

	"github.com/perfect-panel/ppanel-node/api/panel"
)

func TestShadowsocksInboundRejectsUnsupportedPluginBeforeBuild(t *testing.T) {
	for _, p := range []panel.Protocol{
		{Port: 443, Cipher: "aes-128-gcm", Plugin: "obfs"},
		{Port: 443, Cipher: "aes-128-gcm", PluginOptions: map[string]any{"mode": "http"}},
	} {
		info := &panel.NodeInfo{Type: "shadowsocks", Protocol: &p}
		if _, err := Build(info, "ss-test"); err == nil || !strings.Contains(err.Error(), "plugin") {
			t.Fatalf("plugin accepted: %v", err)
		}
	}
	plain := panel.Protocol{Port: 443, Cipher: "aes-128-gcm"}
	if _, err := Build(&panel.NodeInfo{Type: "shadowsocks", Protocol: &plain}, "ss-test"); err != nil {
		t.Fatalf("ordinary Shadowsocks rejected: %v", err)
	}
}
func TestInboundRejectsMalformedTransportURI(t *testing.T) {
	for _, p := range []panel.Protocol{
		{Port: 443, Transport: "ws", Path: "/%"},
		{Port: 443, Transport: "httpupgrade", Path: "/x?ed=%"},
		{Port: 443, Transport: "xhttp", XHTTPExtra: `{"downloadSettings":{"network":"tcp","security":"reality","realitySettings":{"spiderX":"/%"}}}`},
		{Port: 443, Transport: "xhttp", XHTTPExtra: `{"downloadSettings":{"network":"tcp","security":"reality","realitySettings":{"spiderX":"/?c=9"}}}`},
	} {
		info := &panel.NodeInfo{Type: "vless", Protocol: &p}
		func() {
			defer func() {
				if v := recover(); v != nil {
					t.Fatalf("invalid URI panicked: %v", v)
				}
			}()
			if _, err := Build(info, "inbound-test"); err == nil {
				t.Fatal("invalid URI accepted")
			}
		}()
	}
}

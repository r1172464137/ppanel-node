package core

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/perfect-panel/ppanel-node/api/panel"
	"github.com/perfect-panel/ppanel-node/conf"
	outboundbuilder "github.com/perfect-panel/ppanel-node/core/outbound"
	"github.com/xtls/xray-core/app/proxyman"
	xnet "github.com/xtls/xray-core/common/net"
	xray "github.com/xtls/xray-core/core"
	reality "github.com/xtls/xray-core/transport/internet/reality"
)

const spiderFallbackChild = "PPNODE_SPIDER_FALLBACK_CHILD"

// The positive control reaches the pinned Xray REALITY fallback over an actual
// trusted local TLS/H2 server; unsafe policies must fail before any handshake.
func TestRealitySpiderBoundsWithRealFallback(t *testing.T) {
	if mode := os.Getenv(spiderFallbackChild); mode != "" {
		runSpiderFallbackChild(t, mode)
		return
	}
	var connections, requests atomic.Int32
	cookies := make(chan int, 4)
	target := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if c, err := r.Cookie("padding"); err == nil {
			select {
			case cookies <- len(c.Value):
			default:
			}
		}
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<html><a href="/next">next</a></html>`)
	}))
	target.EnableHTTP2 = true
	target.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			connections.Add(1)
		}
	}
	target.StartTLS()
	defer target.Close()
	if err := target.Certificate().VerifyHostname("example.com"); err != nil {
		t.Fatalf("fixture certificate: %v", err)
	}
	dir := t.TempDir()
	rootPath := filepath.Join(dir, "root.pem")
	if err := os.WriteFile(rootPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: target.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	run := func(mode string) {
		t.Helper()
		cmd := exec.Command(os.Args[0], "-test.run=^TestRealitySpiderBoundsWithRealFallback$", "-test.timeout=30s")
		for _, entry := range os.Environ() {
			key, _, _ := strings.Cut(entry, "=")
			if key != spiderFallbackChild && key != "PPNODE_SPIDER_TARGET" && key != "SSL_CERT_FILE" && key != "SSL_CERT_DIR" {
				cmd.Env = append(cmd.Env, entry)
			}
		}
		cmd.Env = append(cmd.Env, spiderFallbackChild+"="+mode, "PPNODE_SPIDER_TARGET="+target.Listener.Addr().String(), "SSL_CERT_FILE="+rootPath, "SSL_CERT_DIR="+dir)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("%s subprocess: %v\n%s", mode, err, out)
		}
	}
	for _, mode := range []string{"bad-padding", "bad-goroutines", "bad-duplicate", "bad-raw"} {
		before := connections.Load()
		run(mode)
		if connections.Load() != before {
			t.Fatalf("%s reached TLS server", mode)
		}
	}
	run("safe")
	if connections.Load() == 0 || requests.Load() == 0 {
		t.Fatalf("REALITY fallback did not reach HTTPS: connections=%d requests=%d", connections.Load(), requests.Load())
	}
	select {
	case n := <-cookies:
		if n != 64 {
			t.Fatalf("fallback cookie length=%d", n)
		}
	case <-time.After(time.Second):
		t.Fatal("no fallback padding receipt")
	}
}

func runSpiderFallbackChild(t *testing.T, mode string) {
	host, portText, err := net.SplitHostPort(os.Getenv("PPNODE_SPIDER_TARGET"))
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatal(err)
	}
	private, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub := base64.RawURLEncoding.EncodeToString(private.PublicKey().Bytes())
	ob := panel.Outbound{ID: orderedSOCKSID, Name: "reality-fallback", Protocol: "vless", Address: host, Port: port, UUID: "00000000-0000-0000-0000-000000000001", Transport: "tcp", Security: "reality", SNI: "example.com", Fingerprint: "chrome", RealityPublicKey: pub, SpiderX: "/proof?p=64&c=0&t=0&i=0&r=1000"}
	switch mode {
	case "bad-padding":
		ob.SpiderX = "/proof?p=9223372036854775807"
	case "bad-goroutines":
		ob.SpiderX = "/proof?c=8&t=16"
	case "bad-duplicate":
		ob.SpiderX = "/proof?p=1&p=4097"
	case "bad-raw":
		stream := map[string]any{"network": "tcp", "security": "reality", "realitySettings": map[string]any{"fingerprint": "chrome", "serverName": "example.com", "publicKey": pub, "spiderX": "/proof?r=9223372036854775807"}}
		raw, err := json.Marshal(stream)
		if err != nil {
			t.Fatal(err)
		}
		ob.StreamSettings = string(raw)
	case "safe":
	default:
		t.Fatal("unknown subprocess mode")
	}
	cfg := orderedConfig([]panel.RouteRule{}, []panel.Outbound{ob})
	cfg.Data.Routing.DefaultOutboundID = orderedSOCKSID
	if mode != "safe" {
		defer func() {
			if v := recover(); v != nil {
				t.Fatalf("unsafe spider panicked: %v", v)
			}
		}()
		if _, err := outboundbuilder.Build(cfg, false); err == nil {
			t.Fatal("unsafe REALITY spider was built")
		}
		return
	}
	built, err := outboundbuilder.Build(cfg, false)
	if err != nil {
		t.Fatal(err)
	}
	senderRaw, err := built.Outbounds[0].SenderSettings.GetInstance()
	if err != nil {
		t.Fatal(err)
	}
	security, err := senderRaw.(*proxyman.SenderConfig).StreamSettings.GetEffectiveSecuritySettings()
	if err != nil {
		t.Fatal(err)
	}
	rc, ok := security.(*reality.Config)
	if !ok || len(rc.SpiderY) != 10 || rc.SpiderY[0] != 64 || rc.SpiderY[1] != 64 || rc.SpiderY[8] != 1000 {
		t.Fatalf("bad compiled REALITY spider: %+v", security)
	}
	instance, err := getCore(conf.New(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := instance.Start(); err != nil {
		t.Fatal(err)
	}
	defer instance.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	defer cancel()
	conn, err := xray.Dial(ctx, instance, xnet.TCPDestination(xnet.DomainAddress("probe.example.com"), 443))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetWriteDeadline(time.Now().Add(3 * time.Second))
	_, _ = conn.Write([]byte("trigger REALITY handshake"))
	_ = conn.SetReadDeadline(time.Now().Add(4 * time.Second))
	var response [1]byte
	_, _ = conn.Read(response[:])
	// Xray launches the fallback goroutine before closing the failed VLESS flow.
	time.Sleep(1200 * time.Millisecond)
}

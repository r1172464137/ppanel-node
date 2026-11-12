package core

import (
	"context"
	"fmt"
	"io"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/perfect-panel/ppanel-node/api/panel"
	"github.com/perfect-panel/ppanel-node/conf"
	xnet "github.com/xtls/xray-core/common/net"
	xray "github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/infra/conf/serial"
)

const matrixUUID = "00000000-0000-4000-8000-0000000000aa"

// upstream starts an in-process Xray server with one inbound; its direct
// outbound may reach only the given loopback ports (the core blocks private
// targets by default).
func upstream(t *testing.T, inbound string, allowPorts ...int) int {
	t.Helper()
	port := reserveTCPUDPPort(t)
	allow := make([]string, len(allowPorts))
	for i, p := range allowPorts {
		allow[i] = fmt.Sprint(p)
	}
	body := fmt.Sprintf(`{"log":{"loglevel":"error"},"inbounds":[{"listen":"127.0.0.1","port":%d,%s}],
"outbounds":[{"protocol":"freedom","settings":{"finalRules":[{"action":"allow","ip":["127.0.0.1/32"],"port":"%s"}]}}]}`,
		port, inbound, strings.Join(allow, ","))
	cfg, err := serial.DecodeJSONConfig(strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	built, err := cfg.Build()
	if err != nil {
		t.Fatal(err)
	}
	server, err := xray.New(built)
	if err != nil {
		t.Fatal(err)
	}
	if err := server.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { server.Close() })
	return port
}

// countingRelay forwards TCP to target and counts accepted connections, proving a
// chain really passes through its front hop.
func countingRelay(t *testing.T, target int) (int, *atomic.Int32) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	var n atomic.Int32
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			n.Add(1)
			u, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", target))
			if err != nil {
				c.Close()
				continue
			}
			go func() { io.Copy(u, c); u.Close() }()
			go func() { io.Copy(c, u); c.Close() }()
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port, &n
}

func tcpEcho(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { io.Copy(c, c); c.Close() }()
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port
}

var matrixInbound = map[string]string{
	"vless":       `"protocol":"vless","settings":{"clients":[{"id":"` + matrixUUID + `"}],"decryption":"none"}`,
	"vmess":       `"protocol":"vmess","settings":{"clients":[{"id":"` + matrixUUID + `"}]}`,
	"trojan":      `"protocol":"trojan","settings":{"clients":[{"password":"matrix-pass"}]}`,
	"shadowsocks": `"protocol":"shadowsocks","settings":{"method":"aes-128-gcm","password":"matrix-pass","network":"tcp,udp"}`,
	"socks":       `"protocol":"socks","settings":{"auth":"noauth","udp":true}`,
	"http":        `"protocol":"http","settings":{}`,
}

func matrixOutbound(id, protocol string, port int) panel.Outbound {
	ob := panel.Outbound{ID: id, Name: id, Protocol: protocol, Address: "127.0.0.1", Port: port}
	switch protocol {
	case "vless", "vmess":
		ob.UUID = matrixUUID
	case "trojan":
		ob.Password = "matrix-pass"
	case "shadowsocks":
		ob.Cipher, ob.Password = "aes-128-gcm", "matrix-pass"
	}
	return ob
}

func startClient(t *testing.T, outbounds []panel.Outbound, defaultID string) *xray.Instance {
	t.Helper()
	cfg := orderedConfig([]panel.RouteRule{}, outbounds)
	cfg.Data.Routing.DefaultOutboundID = defaultID
	instance, err := getCore(conf.New(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := instance.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { instance.Close() })
	return instance
}

func echoThrough(t *testing.T, instance *xray.Instance, port int) error {
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	conn, err := xray.Dial(ctx, instance, xnet.TCPDestination(xnet.LocalHostIP, xnet.Port(port)))
	if err != nil {
		return err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(6 * time.Second))
	if _, err := conn.Write([]byte("matrix-evidence")); err != nil {
		return err
	}
	buf := make([]byte, len("matrix-evidence"))
	if _, err := io.ReadFull(conn, buf); err != nil {
		return err
	}
	if string(buf) != "matrix-evidence" {
		return fmt.Errorf("echo mismatch %q", buf)
	}
	return nil
}

// Every exit protocol the panel offers carries real TCP traffic.
func TestOrderedExitProtocolMatrix(t *testing.T) {
	for _, protocol := range []string{"vless", "vmess", "trojan", "shadowsocks", "socks", "http"} {
		t.Run(protocol, func(t *testing.T) {
			echo := tcpEcho(t)
			port := upstream(t, matrixInbound[protocol], echo)
			client := startClient(t, []panel.Outbound{matrixOutbound(orderedSOCKSID, protocol, port)}, orderedSOCKSID)
			if err := echoThrough(t, client, echo); err != nil {
				t.Fatalf("%s exit: %v", protocol, err)
			}
		})
	}
}

// node -> front -> exit -> target: the exit dials through the front hop.
func TestOrderedChainFrontHops(t *testing.T) {
	const front, exit = "ob_aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", "ob_bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
	for _, protocol := range []string{"socks", "shadowsocks", "vless"} {
		t.Run(protocol, func(t *testing.T) {
			echo := tcpEcho(t)
			exitPort := upstream(t, matrixInbound["vless"], echo)
			frontPort := upstream(t, matrixInbound[protocol], exitPort)
			via, seen := countingRelay(t, frontPort)
			exitOB := matrixOutbound(exit, "vless", exitPort)
			exitOB.ViaOutboundID = front
			client := startClient(t, []panel.Outbound{matrixOutbound(front, protocol, via), exitOB}, exit)
			if err := echoThrough(t, client, echo); err != nil {
				t.Fatalf("chain via %s: %v", protocol, err)
			}
			if seen.Load() == 0 {
				t.Fatalf("chain via %s bypassed the front hop", protocol)
			}
		})
	}
}

// HTTP CONNECT cannot carry UDP: UDP through an HTTP front hop fails and
// never leaks to the target directly.
func TestOrderedHTTPFrontHopFailsUDP(t *testing.T) {
	const front, exit = "ob_aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", "ob_bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
	target, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	targetPort := target.LocalAddr().(*net.UDPAddr).Port
	exitPort := upstream(t, matrixInbound["shadowsocks"], targetPort)
	// Control: without the HTTP front hop the same exit delivers UDP, so the
	// failure below is the front hop and not the harness.
	direct := startClient(t, []panel.Outbound{matrixOutbound(orderedSOCKSID, "shadowsocks", exitPort)}, orderedSOCKSID)
	dctx, dcancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer dcancel()
	dconn, err := xray.DialUDP(dctx, direct)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = dconn.WriteTo([]byte("control"), &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: targetPort})
	_ = target.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, _, err := target.ReadFromUDP(make([]byte, 64)); err != nil {
		t.Fatalf("control UDP through the Shadowsocks exit failed: %v", err)
	}
	dconn.Close()
	frontPort := upstream(t, matrixInbound["http"], exitPort)
	exitOB := matrixOutbound(exit, "shadowsocks", exitPort)
	exitOB.ViaOutboundID = front
	client := startClient(t, []panel.Outbound{matrixOutbound(front, "http", frontPort), exitOB}, exit)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := xray.DialUDP(ctx, client)
	if err != nil {
		return // refused outright: explicit failure
	}
	defer conn.Close()
	_, _ = conn.WriteTo([]byte("udp-via-http"), &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: targetPort})
	_ = target.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 64)
	if n, _, err := target.ReadFromUDP(buf); err == nil {
		t.Fatalf("UDP crossed an HTTP front hop or leaked: %q", buf[:n])
	}
}

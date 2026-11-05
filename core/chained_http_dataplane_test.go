package core

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/perfect-panel/ppanel-node/api/panel"
	"github.com/perfect-panel/ppanel-node/conf"
	xnet "github.com/xtls/xray-core/common/net"
	xray "github.com/xtls/xray-core/core"
)

// A local HTTP CONNECT hop relays only to the controlled SOCKS endpoint.
func TestDialerProxyHTTPToSOCKSTCPAndUDPFailure(t *testing.T) {
	b := startControlledSOCKSServer(t)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	receipt := make(chan string, 16)
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
				reader := bufio.NewReader(conn)
				req, err := http.ReadRequest(reader)
				if err != nil {
					return
				}
				receipt <- req.Method + " " + req.Host
				upstream, err := net.DialTimeout("tcp", b.tcp.Addr().String(), time.Second)
				if err != nil {
					return
				}
				defer upstream.Close()
				_, _ = io.WriteString(conn, "HTTP/1.1 200 Connection Established\r\n\r\n")
				go func() { _, _ = io.Copy(upstream, reader) }()
				_, _ = io.Copy(conn, upstream)
			}()
		}
	}()
	const bid = "ob_22222222-2222-4222-8222-222222222222"
	out := []panel.Outbound{
		{ID: orderedSOCKSID, Name: "http A", Protocol: "http", Address: "127.0.0.1", Port: listener.Addr().(*net.TCPAddr).Port},
		{ID: bid, Name: "socks B", Protocol: "socks", Address: "127.0.0.1", Port: b.port(), StreamSettings: fmt.Sprintf(`{"sockopt":{"dialerProxy":"routing_%s"}}`, orderedSOCKSID)},
	}
	cfg := orderedConfig([]panel.RouteRule{}, out)
	cfg.Data.Routing.DefaultOutboundID = bid
	instance, err := getCore(conf.New(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := instance.Start(); err != nil {
		t.Fatal(err)
	}
	defer instance.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := xray.Dial(ctx, instance, xnet.TCPDestination(xnet.DomainAddress("chain.example"), 443))
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := conn.Write([]byte("tcp")); err != nil {
		t.Fatal(err)
	}
	result := make([]byte, 3)
	if _, err := io.ReadFull(conn, result); err != nil || string(result) != "tcp" {
		t.Fatalf("TCP %q %v", result, err)
	}
	_ = conn.Close()
	select {
	case r := <-receipt:
		if r != fmt.Sprintf("CONNECT 127.0.0.1:%d", b.port()) {
			t.Fatal(r)
		}
	case <-ctx.Done():
		t.Fatal("missing A")
	}
	select {
	case e := <-b.evidence:
		if e.command != 1 || e.host != "chain.example" {
			t.Fatalf("B: %+v", e)
		}
	case <-ctx.Done():
		t.Fatal("missing B")
	}
	sink, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer sink.Close()
	udp, err := xray.DialUDP(ctx, instance)
	if err != nil {
		t.Fatal(err)
	}
	defer udp.Close()
	if _, err := udp.WriteTo([]byte("must-not-bypass"), sink.LocalAddr()); err != nil {
		t.Fatal(err)
	}
	// B may receive a SOCKS UDP-associate control, but HTTP A cannot carry the UDP datagram.
	deadline := time.NewTimer(1500 * time.Millisecond)
	defer deadline.Stop()
	for {
		select {
		case e := <-b.evidence:
			if e.transport == "udp-datagram" {
				t.Fatalf("UDP bypassed HTTP A: %+v", e)
			}
		case <-deadline.C:
			_ = sink.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
			if _, _, err := sink.ReadFrom(make([]byte, 64)); err == nil {
				t.Fatal("UDP reached target directly")
			}
			return
		}
	}
}

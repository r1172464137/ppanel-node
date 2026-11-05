package core

import (
	"context"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	"github.com/perfect-panel/ppanel-node/api/panel"
	"github.com/perfect-panel/ppanel-node/conf"
	xnet "github.com/xtls/xray-core/common/net"
	xray "github.com/xtls/xray-core/core"
)

// Exercise the pinned Xray's existing dialerProxy, independently of the new wire.
func TestDialerProxySOCKSTCPAndUDPDataPlane(t *testing.T) {
	b := startControlledSOCKSServer(t)
	a := startControlledSOCKSRelay(t, b.tcp.Addr().String())
	a.mu.Lock()
	a.udpRelayAddress = b.udp.LocalAddr().String()
	a.mu.Unlock()
	const bid = "ob_22222222-2222-4222-8222-222222222222"
	out := []panel.Outbound{
		{ID: orderedSOCKSID, Name: "A", Protocol: "socks", Address: "127.0.0.1", Port: a.port()},
		{ID: bid, Name: "B", Protocol: "socks", Address: "127.0.0.1", Port: b.port(), StreamSettings: fmt.Sprintf(`{"sockopt":{"dialerProxy":"routing_%s"}}`, orderedSOCKSID)},
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
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	tcp, err := xray.Dial(ctx, instance, xnet.TCPDestination(xnet.DomainAddress("chain.example"), 443))
	if err != nil {
		t.Fatal(err)
	}
	_ = tcp.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := tcp.Write([]byte("chain-tcp")); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len("chain-tcp"))
	if _, err := io.ReadFull(tcp, got); err != nil || string(got) != "chain-tcp" {
		t.Fatalf("TCP response %q: %v", got, err)
	}
	_ = tcp.Close()
	select {
	case x := <-a.evidence:
		if x.command != 1 || x.port != b.port() {
			t.Fatalf("A TCP: %+v", x)
		}
	case <-ctx.Done():
		t.Fatal("no A TCP")
	}
	select {
	case x := <-b.evidence:
		if x.command != 1 || x.host != "chain.example" {
			t.Fatalf("B TCP: %+v", x)
		}
	case <-ctx.Done():
		t.Fatal("no B TCP")
	}
	udp, err := xray.DialUDP(ctx, instance)
	if err != nil {
		t.Fatal(err)
	}
	defer udp.Close()
	if _, err := udp.WriteTo([]byte("chain-udp"), &net.UDPAddr{IP: net.ParseIP("198.51.100.42"), Port: 9999}); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 256)
	n, _, err := readPacketWithContext(ctx, udp, buf)
	if err != nil || string(buf[:n]) != "chain-udp" {
		t.Fatalf("UDP response %q: %v", buf[:n], err)
	}
	foundAUDP, foundBUDP := false, false
	for !foundAUDP || !foundBUDP {
		select {
		case x := <-a.evidence:
			if x.transport == "udp-datagram" {
				foundAUDP = true
			}
		case x := <-b.evidence:
			if x.transport == "udp-datagram" && x.host == "198.51.100.42" && x.port == 9999 {
				foundBUDP = true
			}
		case <-ctx.Done():
			t.Fatalf("missing UDP evidence A=%v B=%v", foundAUDP, foundBUDP)
		}
	}
}

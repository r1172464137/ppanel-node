package core

import (
	"context"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/perfect-panel/ppanel-node/api/panel"
	"github.com/perfect-panel/ppanel-node/conf"
	xnet "github.com/xtls/xray-core/common/net"
	xray "github.com/xtls/xray-core/core"
)

func TestV2StructuredChainSOCKSTCPUDP(t *testing.T) {
	b := startControlledSOCKSServer(t)
	a := startControlledSOCKSRelay(t, b.tcp.Addr().String())
	a.mu.Lock()
	a.udpRelayAddress = b.udp.LocalAddr().String()
	a.mu.Unlock()
	const bid = "ob_22222222-2222-4222-8222-222222222222"
	out := []panel.Outbound{{ID: orderedSOCKSID, Name: "A", Protocol: "socks", Address: "127.0.0.1", Port: a.port()}, {ID: bid, Name: "B", Protocol: "socks", Address: "127.0.0.1", Port: b.port(), ViaOutboundID: orderedSOCKSID}}
	cfg := orderedConfig([]panel.RouteRule{}, out)
	cfg.Data.Routing.Version = 2
	cfg.Data.Routing.Mode = "ordered-v2-inherited"
	cfg.Data.Routing.DefaultOutboundID = bid
	cfg.Data.Routing.UserDefaults = []panel.UserDefault{}
	cfg.Data.IdentitySnapshot = &panel.IdentitySnapshot{SnapshotID: strings.Repeat("a", 64), Protocols: []panel.ProtocolUserSnapshot{}}
	instance, err := getCore(conf.New(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err = instance.Start(); err != nil {
		t.Fatal(err)
	}
	defer instance.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, err := xray.Dial(ctx, instance, xnet.TCPDestination(xnet.DomainAddress("chain.example"), 443))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(3 * time.Second))
	_, _ = c.Write([]byte("tcp"))
	reply := make([]byte, 3)
	if _, err = io.ReadFull(c, reply); err != nil || string(reply) != "tcp" {
		t.Fatalf("TCP %q %v", reply, err)
	}
	select {
	case e := <-a.evidence:
		if e.command != 1 || e.port != b.port() {
			t.Fatalf("A %+v", e)
		}
	case <-ctx.Done():
		t.Fatal("A missing")
	}
	select {
	case e := <-b.evidence:
		if e.command != 1 || e.host != "chain.example" {
			t.Fatalf("B %+v", e)
		}
	case <-ctx.Done():
		t.Fatal("B missing")
	}
	udp, err := xray.DialUDP(ctx, instance)
	if err != nil {
		t.Fatal(err)
	}
	defer udp.Close()
	if _, err = udp.WriteTo([]byte("udp"), &net.UDPAddr{IP: net.ParseIP("198.51.100.1"), Port: 9999}); err != nil {
		t.Fatal(err)
	}
	packet := make([]byte, 64)
	n, _, err := readPacketWithContext(ctx, udp, packet)
	if err != nil || string(packet[:n]) != "udp" {
		t.Fatalf("UDP %q %v", packet[:n], err)
	}
	gotA, gotB := false, false
	for !gotA || !gotB {
		select {
		case e := <-a.evidence:
			if e.transport == "udp-datagram" {
				gotA = true
			}
		case e := <-b.evidence:
			if e.transport == "udp-datagram" {
				gotB = true
			}
		case <-ctx.Done():
			t.Fatalf("UDP evidence A=%v B=%v", gotA, gotB)
		}
	}
}

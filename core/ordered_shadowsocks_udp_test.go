package core

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/perfect-panel/ppanel-node/api/panel"
	"github.com/perfect-panel/ppanel-node/conf"
	xray "github.com/xtls/xray-core/core"
)

func TestOrderedShadowsocksDefaultUsesNativeUDPNotUOT(t *testing.T) {
	tcp, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer tcp.Close()
	port := tcp.Addr().(*net.TCPAddr).Port
	udp, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: port})
	if err != nil {
		t.Fatal(err)
	}
	defer udp.Close()
	ob := panel.Outbound{ID: orderedSOCKSID, Name: "ss-native-udp", Protocol: "shadowsocks", Address: "127.0.0.1", Port: port, Cipher: "aes-128-gcm", Password: "secret"}
	cfg := orderedConfig([]panel.RouteRule{}, []panel.Outbound{ob})
	cfg.Data.Routing.DefaultOutboundID = orderedSOCKSID
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
	conn, err := xray.DialUDP(ctx, instance)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := conn.WriteTo([]byte("udp-evidence"), &net.UDPAddr{IP: net.ParseIP("198.51.100.17"), Port: 9999}); err != nil {
		t.Fatal(err)
	}
	_ = udp.SetReadDeadline(time.Now().Add(4 * time.Second))
	buf := make([]byte, 2048)
	n, _, err := udp.ReadFromUDP(buf)
	if err != nil || n <= len("udp-evidence") {
		t.Fatalf("no encrypted native UDP datagram: n=%d err=%v", n, err)
	}
	_ = tcp.SetDeadline(time.Now().Add(200 * time.Millisecond))
	if c, err := tcp.Accept(); err == nil {
		c.Close()
		t.Fatal("UDP unexpectedly used a TCP connection (UoT)")
	}
}

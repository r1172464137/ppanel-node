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

func TestDialerProxyUnavailableHopDoesNotDirect(t *testing.T) {
	for _, dead := range []string{"A", "B"} {
		t.Run(dead, func(t *testing.T) {
			target, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer target.Close()
			b := startControlledSOCKSRelay(t, target.Addr().String())
			a := startControlledSOCKSRelay(t, b.tcp.Addr().String())
			ap, bp := a.port(), b.port()
			if dead == "A" {
				a.close()
			} else {
				b.close()
			}
			const bid = "ob_22222222-2222-4222-8222-222222222222"
			out := []panel.Outbound{
				{ID: orderedSOCKSID, Name: "A", Protocol: "socks", Address: "127.0.0.1", Port: ap},
				{ID: bid, Name: "B", Protocol: "socks", Address: "127.0.0.1", Port: bp, StreamSettings: fmt.Sprintf(`{"sockopt":{"dialerProxy":"routing_%s"}}`, orderedSOCKSID)},
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
			ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
			defer cancel()
			address := target.Addr().(*net.TCPAddr)
			conn, err := xray.Dial(ctx, instance, xnet.TCPDestination(xnet.IPAddress(address.IP), xnet.Port(address.Port)))
			if err == nil {
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
				_, _ = conn.Write([]byte("no-bypass"))
				_, err = io.ReadFull(conn, make([]byte, 1))
				if err == nil {
					t.Fatal("traffic succeeded with dead hop")
				}
			}
			_ = target.(*net.TCPListener).SetDeadline(time.Now().Add(200 * time.Millisecond))
			if c, err := target.Accept(); err == nil {
				c.Close()
				t.Fatal("target reached despite dead hop")
			}
		})
	}
}

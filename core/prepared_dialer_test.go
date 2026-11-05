package core

import (
	"context"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/perfect-panel/ppanel-node/api/panel"
	"github.com/perfect-panel/ppanel-node/conf"
	xnet "github.com/xtls/xray-core/common/net"
	xray "github.com/xtls/xray-core/core"
)

func TestPreparedCoreKeepsActiveChainAndRestoresDialer(t *testing.T) {
	b := startControlledSOCKSServer(t)
	a := startControlledSOCKSRelay(t, b.tcp.Addr().String())
	const bid = "ob_22222222-2222-4222-8222-222222222222"
	cfg := orderedConfig([]panel.RouteRule{}, []panel.Outbound{
		{ID: orderedSOCKSID, Name: "A", Protocol: "socks", Address: "127.0.0.1", Port: a.port()},
		{ID: bid, Name: "B", Protocol: "socks", Address: "127.0.0.1", Port: b.port(), ViaOutboundID: orderedSOCKSID},
	})
	cfg.Data.Routing.Version = 2
	cfg.Data.Routing.Mode = "ordered-v2-inherited"
	cfg.Data.Routing.UserDefaults = []panel.UserDefault{}
	cfg.Data.Routing.DefaultOutboundID = bid
	cfg.Data.IdentitySnapshot = &panel.IdentitySnapshot{SnapshotID: strings.Repeat("a", 64), Protocols: []panel.ProtocolUserSnapshot{}}
	old := New(conf.New(), nil)
	if err := old.StartPrepared(cfg); err != nil {
		t.Fatal(err)
	}
	defer old.Close()
	probe := func() io.ReadWriteCloser {
		t.Helper()
		ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
		t.Cleanup(cancel)
		conn, err := xray.Dial(ctx, old.Server, xnet.TCPDestination(xnet.DomainAddress("chain.unit.test"), 443))
		if err != nil {
			t.Fatal(err)
		}
		_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
		if _, err := conn.Write([]byte("proof")); err != nil {
			t.Fatal(err)
		}
		buf := make([]byte, 5)
		if _, err := io.ReadFull(conn, buf); err != nil || string(buf) != "proof" {
			t.Fatalf("old chain: %q %v", buf, err)
		}
		return conn
	}
	first := probe()
	first.Close()
	candidate := New(conf.New(), nil)
	defer candidate.Close()
	next := orderedConfig([]panel.RouteRule{}, nil)
	if err := candidate.Prepare(next); err != nil {
		t.Fatal(err)
	}
	// Compilation must not replace the process-wide manager used by old A/B.
	inflight := probe()
	defer inflight.Close()
	quiesced := make(chan struct{})
	go func() { old.Quiesce(); close(quiesced) }()
	select {
	case <-quiesced:
	case <-time.After(5 * time.Second):
		t.Fatal("old dispatches did not stop")
	}
	if _, err := inflight.Read(make([]byte, 1)); err == nil {
		t.Fatal("retired flow remained open")
	}
	if err := candidate.StartPrepared(next); err != nil {
		t.Fatal(err)
	}
	if err := candidate.Close(); err != nil {
		t.Fatal(err)
	}
	if err := old.RestoreDialer(); err != nil {
		t.Fatal(err)
	}
	restored := probe()
	restored.Close()
}

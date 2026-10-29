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

// The retained HTTP outbound forwards CONNECT/TCP; it does not support UDP.
func TestOrderedHTTPOutboundConnectDataPlane(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	receipts := make(chan string, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		r := bufio.NewReader(conn)
		request, err := http.ReadRequest(r)
		if err != nil {
			return
		}
		receipts <- fmt.Sprintf("%s %s", request.Method, request.Host)
		if _, err := io.WriteString(conn, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
			return
		}
		_, _ = io.Copy(conn, r)
	}()
	ob := panel.Outbound{ID: orderedSOCKSID, Name: "http", Protocol: "http", Address: "127.0.0.1", Port: listener.Addr().(*net.TCPAddr).Port}
	cfg := orderedConfig([]panel.RouteRule{orderedRule(0, "domain", "route.example", orderedSOCKSID, true)}, []panel.Outbound{ob})
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
	conn, err := xray.Dial(ctx, instance, xnet.TCPDestination(xnet.DomainAddress("route.example"), 443))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(4 * time.Second))
	payload := []byte("http-connect-receipt")
	if _, err := conn.Write(payload); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatal(err)
	}
	if string(got) != string(payload) {
		t.Fatalf("HTTP tunnel echo %q", got)
	}
	select {
	case receipt := <-receipts:
		if receipt != "CONNECT route.example:443" {
			t.Fatal(receipt)
		}
	case <-ctx.Done():
		t.Fatal("no HTTP CONNECT receipt")
	}
}

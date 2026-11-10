package core

import (
	"context"
	"io"
	"net"
	"testing"
	"time"

	"github.com/perfect-panel/ppanel-node/api/panel"
	"github.com/perfect-panel/ppanel-node/conf"
	xrayDNS "github.com/xtls/xray-core/app/dns"
	"github.com/xtls/xray-core/common/geodata"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/serial"
	xray "github.com/xtls/xray-core/core"
)

type ipv4OnlySOCKS struct {
	listener net.Listener
	evidence chan string
	done     chan struct{}
}

func startIPv4OnlySOCKS(t *testing.T) *ipv4OnlySOCKS {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := &ipv4OnlySOCKS{listener: listener, evidence: make(chan string, 8), done: make(chan struct{})}
	t.Cleanup(func() {
		close(server.done)
		_ = listener.Close()
	})
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go server.serve(conn)
		}
	}()
	return server
}

func (s *ipv4OnlySOCKS) port() int { return s.listener.Addr().(*net.TCPAddr).Port }

func (s *ipv4OnlySOCKS) record(host string) {
	select {
	case s.evidence <- host:
	case <-s.done:
	}
}

func (s *ipv4OnlySOCKS) serve(conn net.Conn) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	var greeting [2]byte
	if _, err := io.ReadFull(conn, greeting[:]); err != nil || greeting[0] != 5 {
		return
	}
	methods := make([]byte, int(greeting[1]))
	if _, err := io.ReadFull(conn, methods); err != nil {
		return
	}
	if _, err := conn.Write([]byte{5, 0}); err != nil {
		return
	}
	var request [4]byte
	if _, err := io.ReadFull(conn, request[:]); err != nil || request[0] != 5 || request[1] != 1 {
		return
	}
	host, _, err := readSOCKSAddress(conn, request[3])
	if err != nil {
		return
	}
	s.record(host)
	if net.ParseIP(host).To4() == nil {
		// IPv4-only exits cannot dial an IPv6 target. Fail the SOCKS request
		// instead of silently using the test relay target.
		_, _ = conn.Write([]byte{5, 4, 0, 1, 0, 0, 0, 0, 0, 0})
		return
	}
	if _, err := conn.Write([]byte{5, 0, 0, 1, 127, 0, 0, 1, 0, 0}); err != nil {
		return
	}
	_, _ = io.Copy(conn, conn)
}

func ipStrategyV2Config(strategy string, socks int) *panel.ServerConfigResponse {
	outbound := panel.Outbound{ID: orderedSOCKSID, Name: "ipv4-only", Protocol: "socks", Address: "127.0.0.1", Port: socks}
	rules := []panel.RouteRule{
		orderedRule(0, "ip", "192.0.2.0/24", "direct", true),
		orderedRule(1, "ip", "198.51.100.0/24", "block", true),
		orderedRule(2, "domain", "full:dual.example", orderedSOCKSID, true),
	}
	config := orderedConfig(rules, []panel.Outbound{outbound})
	config.Data.Routing.Version = 2
	config.Data.Routing.Mode = "ordered-v2-inherited"
	config.Data.Routing.DefaultOutboundID = orderedSOCKSID
	config.Data.Routing.UserDefaults = []panel.UserDefault{}
	config.Data.IdentitySnapshot = &panel.IdentitySnapshot{SnapshotID: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", Protocols: []panel.ProtocolUserSnapshot{}}
	config.Data.IPStrategy = strategy
	return config
}

func getCoreWithStaticHosts(t *testing.T, cfg *panel.ServerConfigResponse, host string, ips ...net.IP) *xray.Instance {
	t.Helper()
	c := conf.New()
	c.ApiConfig.ApiHost = "http://fixture.invalid"
	coreConfig, err := coreConfiguration(c, cfg)
	if err != nil {
		t.Fatal(err)
	}
	rule, err := geodata.ParseDomainRule("full:"+host, geodata.Domain_Full)
	if err != nil {
		t.Fatal(err)
	}
	mapping := &xrayDNS.Config_HostMapping{Domain: rule}
	for _, ip := range ips {
		if v4 := ip.To4(); v4 != nil {
			mapping.Ip = append(mapping.Ip, append([]byte(nil), v4...))
			continue
		}
		mapping.Ip = append(mapping.Ip, append([]byte(nil), ip.To16()...))
	}
	found := false
	for i, app := range coreConfig.App {
		instance, err := app.GetInstance()
		if err != nil {
			t.Fatal(err)
		}
		dnsConfig, ok := instance.(*xrayDNS.Config)
		if !ok {
			continue
		}
		// The fixture host may not expose public IPv6, but this test exercises
		// the dual-stack answer path explicitly.
		dnsConfig.QueryStrategy = xrayDNS.QueryStrategy_USE_IP
		for _, server := range dnsConfig.NameServer {
			server.QueryStrategy = xrayDNS.QueryStrategy_USE_IP
		}
		dnsConfig.StaticHosts = append(dnsConfig.StaticHosts, mapping)
		coreConfig.App[i] = serial.ToTypedMessage(dnsConfig)
		found = true
	}
	if !found {
		t.Fatal("DNS app config not found")
	}
	instance, err := newCoreInstance(coreConfig, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := instance.Start(); err != nil {
		_ = instance.Close()
		t.Fatal(err)
	}
	return instance
}

func TestPreferIPv4RealSOCKSPinsIPv4AndOldOrderFails(t *testing.T) {
	v4 := net.ParseIP("203.0.113.10")
	v6 := net.ParseIP("2607:6bc0::10")
	for _, test := range []struct {
		name     string
		strategy string
		wantHost string
		wantErr  bool
	}{
		{name: "legacy-first-address", wantHost: v6.String(), wantErr: true},
		{name: "prefer_ipv4", strategy: "prefer_ipv4", wantHost: v4.String()},
		{name: "prefer_ipv6", strategy: "prefer_ipv6", wantHost: v6.String(), wantErr: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			socks := startIPv4OnlySOCKS(t)
			instance := getCoreWithStaticHosts(t, ipStrategyV2Config(test.strategy, socks.port()), "dual.example", v6, v4)
			defer instance.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			conn, err := xray.Dial(ctx, instance, xnet.TCPDestination(xnet.DomainAddress("dual.example"), 443))
			if test.wantErr {
				if err == nil {
					_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
					_, writeErr := conn.Write([]byte("must-not-succeed"))
					buffer := make([]byte, 1)
					_, readErr := conn.Read(buffer)
					_ = conn.Close()
					if writeErr == nil && readErr == nil {
						t.Fatal("IPv4-only SOCKS unexpectedly served the selected IPv6 target")
					}
				}
				select {
				case host := <-socks.evidence:
					if host != test.wantHost {
						t.Fatalf("SOCKS target = %q, want %q", host, test.wantHost)
					}
				case <-time.After(time.Second):
					t.Fatal("SOCKS exit received no target")
				}
				return
			}
			if err != nil {
				t.Fatalf("real TCP through preferred IPv4 SOCKS: %v", err)
			}
			defer conn.Close()
			_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
			payload := []byte("ip-strategy-data-plane")
			if _, err := conn.Write(payload); err != nil {
				t.Fatal(err)
			}
			reply := make([]byte, len(payload))
			if _, err := io.ReadFull(conn, reply); err != nil || string(reply) != string(payload) {
				t.Fatalf("SOCKS echo = %q, err = %v", reply, err)
			}
			select {
			case host := <-socks.evidence:
				if host != test.wantHost {
					t.Fatalf("SOCKS target = %q, want %q", host, test.wantHost)
				}
			case <-time.After(time.Second):
				t.Fatal("SOCKS exit received no target")
			}
		})
	}
}

func TestPreferIPv4MixedBlockedAnswerFailsClosed(t *testing.T) {
	socks := startIPv4OnlySOCKS(t)
	instance := getCoreWithStaticHosts(t, ipStrategyV2Config("prefer_ipv4", socks.port()), "blocked.example",
		net.ParseIP("2607:6bc0::20"), net.ParseIP("198.51.100.20"))
	defer instance.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	conn, err := xray.Dial(ctx, instance, xnet.TCPDestination(xnet.DomainAddress("blocked.example"), 443))
	if err == nil {
		_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
		_, writeErr := conn.Write([]byte("must-not-succeed"))
		buffer := make([]byte, 1)
		_, readErr := conn.Read(buffer)
		_ = conn.Close()
		if writeErr == nil && readErr == nil {
			t.Fatal("mixed blocked answer reached an outbound")
		}
	}
	select {
	case host := <-socks.evidence:
		t.Fatalf("blocked mixed answer reached SOCKS with %s", host)
	case <-time.After(150 * time.Millisecond):
	}
}

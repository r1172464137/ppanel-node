package core

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/perfect-panel/ppanel-node/api/panel"
	"github.com/perfect-panel/ppanel-node/conf"
	featureDNS "github.com/xtls/xray-core/features/dns"
	"golang.org/x/net/dns/dnsmessage"
)

func dnsPolicyResponse(packet []byte, last byte) ([]byte, string, error) {
	var request dnsmessage.Message
	if err := request.Unpack(packet); err != nil {
		return nil, "", err
	}
	if len(request.Questions) != 1 {
		return nil, "", fmt.Errorf("unexpected DNS questions")
	}
	q := request.Questions[0]
	response := dnsmessage.Message{Header: dnsmessage.Header{ID: request.ID, Response: true, Authoritative: true, RecursionAvailable: true}, Questions: request.Questions}
	if strings.HasPrefix(q.Name.String(), "fail.") {
		response.RCode = dnsmessage.RCodeNameError
	} else if q.Type == dnsmessage.TypeA {
		response.Answers = []dnsmessage.Resource{{Header: dnsmessage.ResourceHeader{Name: q.Name, Type: q.Type, Class: dnsmessage.ClassINET, TTL: 60}, Body: &dnsmessage.AResource{A: [4]byte{203, 0, 113, last}}}}
	} else if q.Type == dnsmessage.TypeAAAA {
		response.Answers = []dnsmessage.Resource{{Header: dnsmessage.ResourceHeader{Name: q.Name, Type: q.Type, Class: dnsmessage.ClassINET, TTL: 60}, Body: &dnsmessage.AAAAResource{AAAA: [16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, last}}}}
	}
	body, err := response.Pack()
	return body, q.Name.String(), err
}

type policyDNSServer struct {
	udp  net.PacketConn
	tcp  net.Listener
	hits atomic.Int32
}

func policyDNSFixture(t *testing.T, last byte) *policyDNSServer {
	t.Helper()
	u, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		u.Close()
		t.Fatal(err)
	}
	s := &policyDNSServer{udp: u, tcp: l}
	t.Cleanup(func() { u.Close(); l.Close() })
	go func() {
		buf := make([]byte, 65535)
		for {
			n, peer, err := u.ReadFrom(buf)
			if err != nil {
				return
			}
			answer, _, err := dnsPolicyResponse(buf[:n], last)
			if err == nil {
				s.hits.Add(1)
				_, _ = u.WriteTo(answer, peer)
			}
		}
	}()
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(8 * time.Second))
				for {
					var length [2]byte
					if _, err := io.ReadFull(c, length[:]); err != nil {
						return
					}
					packet := make([]byte, binary.BigEndian.Uint16(length[:]))
					if _, err := io.ReadFull(c, packet); err != nil {
						return
					}
					answer, _, err := dnsPolicyResponse(packet, last)
					if err != nil {
						return
					}
					s.hits.Add(1)
					binary.BigEndian.PutUint16(length[:], uint16(len(answer)))
					if _, err = c.Write(append(length[:], answer...)); err != nil {
						return
					}
				}
			}()
		}
	}()
	return s
}

func forbidSystemDNS(t *testing.T) *atomic.Int32 {
	t.Helper()
	calls := &atomic.Int32{}
	previous := net.DefaultResolver
	net.DefaultResolver = &net.Resolver{PreferGo: true, Dial: func(context.Context, string, string) (net.Conn, error) {
		calls.Add(1)
		return nil, fmt.Errorf("system DNS forbidden in fixture")
	}}
	t.Cleanup(func() { net.DefaultResolver = previous })
	return calls
}

func policyV2Config(resolvers []panel.PolicyDNSResolver, outbounds []panel.Outbound) *panel.ServerConfigResponse {
	cfg := orderedConfig([]panel.RouteRule{}, outbounds)
	cfg.Data.Routing.Version = 2
	cfg.Data.Routing.Mode = "ordered-v2-inherited"
	cfg.Data.Routing.UserDefaults = []panel.UserDefault{}
	cfg.Data.IdentitySnapshot = &panel.IdentitySnapshot{SnapshotID: strings.Repeat("a", 64), Protocols: []panel.ProtocolUserSnapshot{}}
	cfg.Data.Routing.DNSPolicy = &panel.DNSPolicy{QueryStrategy: "UseIPv4", Resolvers: resolvers}
	return cfg
}
func dnsResolverID(i int) string { return fmt.Sprintf("dns_11111111-1111-4111-8111-%012x", i+1) }

func TestV2DNSPolicyUDPAndTCPThroughChain(t *testing.T) {
	systemCalls := forbidSystemDNS(t)
	target := policyDNSFixture(t, 42)
	fallback := policyDNSFixture(t, 99)
	b := startControlledSOCKSRelay(t, target.tcp.Addr().String())
	b.mu.Lock()
	b.udpRelayAddress = target.udp.LocalAddr().String()
	b.mu.Unlock()
	a := startControlledSOCKSRelay(t, b.tcp.Addr().String())
	a.mu.Lock()
	a.udpRelayAddress = b.udp.LocalAddr().String()
	a.mu.Unlock()
	const bid = "ob_22222222-2222-4222-8222-222222222222"
	outs := []panel.Outbound{{ID: orderedSOCKSID, Name: "A", Protocol: "socks", Address: "127.0.0.1", Port: a.port()}, {ID: bid, Name: "B", Protocol: "socks", Address: "127.0.0.1", Port: b.port(), ViaOutboundID: orderedSOCKSID}}
	cfg := policyV2Config([]panel.PolicyDNSResolver{
		{ID: dnsResolverID(0), Protocol: "udp", Address: target.udp.LocalAddr().String(), Domains: []string{"domain:udp.unit.test"}, OutboundID: bid},
		{ID: dnsResolverID(1), Protocol: "tcp", Address: target.tcp.Addr().String(), Domains: []string{"domain:tcp.unit.test"}, OutboundID: bid},
		{ID: dnsResolverID(2), Protocol: "udp", Address: fallback.udp.LocalAddr().String(), Domains: []string{}, OutboundID: "direct"},
	}, outs)
	instance, err := getCore(conf.New(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err = instance.Start(); err != nil {
		t.Fatal(err)
	}
	defer instance.Close()
	resolver := instance.GetFeature(featureDNS.ClientType()).(featureDNS.Client)
	for _, domain := range []string{"proof.udp.unit.test", "proof.tcp.unit.test"} {
		ips, _, err := resolver.LookupIP(domain, featureDNS.IPOption{IPv4Enable: true})
		if err != nil || len(ips) != 1 || !ips[0].Equal(net.ParseIP("203.0.113.42")) {
			t.Fatalf("%s: %v %v", domain, ips, err)
		}
	}
	if target.hits.Load() != 2 || fallback.hits.Load() != 0 {
		t.Fatalf("resolver hits %d / %d", target.hits.Load(), fallback.hits.Load())
	}
	if _, _, err := resolver.LookupIP("fail.udp.unit.test", featureDNS.IPOption{IPv4Enable: true}); err == nil {
		t.Fatal("NXDOMAIN accepted")
	}
	if fallback.hits.Load() != 0 {
		t.Fatal("failed matching query escaped to default resolver")
	}
	ips, _, err := resolver.LookupIP("default.unit.test", featureDNS.IPOption{IPv4Enable: true})
	if err != nil || len(ips) != 1 || !ips[0].Equal(net.ParseIP("203.0.113.99")) {
		t.Fatalf("default %v %v", ips, err)
	}
	if systemCalls.Load() != 0 {
		t.Fatalf("system DNS attempted %d times", systemCalls.Load())
	}
	for name, server := range map[string]*controlledSOCKSServer{"A": a, "B": b} {
		udp, tcp := false, false
		for len(server.evidence) > 0 {
			e := <-server.evidence
			if e.transport == "udp-datagram" {
				udp = true
			}
			if e.command == 1 {
				tcp = true
			}
		}
		if !udp || !tcp {
			t.Fatalf("%s missing UDP/TCP evidence", name)
		}
	}
}

func TestV2DNSPolicyDoHBootstrap(t *testing.T) {
	const child = "PPNODE_DOH_POLICY_CHILD"
	if os.Getenv(child) != "1" {
		cmd := exec.Command(os.Args[0], "-test.run=^TestV2DNSPolicyDoHBootstrap$", "-test.v")
		cmd.Env = append(os.Environ(), child+"=1", "GODEBUG=x509usefallbackroots=1")
		if output, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("isolated DoH test: %v\n%s", err, output)
		}
		return
	}
	systemCalls := forbidSystemDNS(t)
	certificate := protocolCertificate(t).Certs[0]
	pair, err := tls.X509KeyPair([]byte(strings.Join(certificate.CertStr, "\n")), []byte(strings.Join(certificate.KeyStr, "\n")))
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode([]byte(strings.Join(certificate.CertStr, "\n")))
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	x509.SetFallbackRoots(pool)
	var hits atomic.Int32
	httpServer := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Host != "localhost:"+strconv.Itoa(r.Context().Value(http.LocalAddrContextKey).(net.Addr).(*net.TCPAddr).Port) {
			t.Errorf("DoH authority changed: %s", r.Host)
		}
		packet, err := io.ReadAll(io.LimitReader(r.Body, 65536))
		if err != nil {
			w.WriteHeader(400)
			return
		}
		answer, _, err := dnsPolicyResponse(packet, 53)
		if err != nil {
			w.WriteHeader(400)
			return
		}
		hits.Add(1)
		w.Header().Set("Content-Type", "application/dns-message")
		_, _ = w.Write(answer)
	}))
	httpServer.TLS = &tls.Config{Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS12}
	httpServer.EnableHTTP2 = true
	httpServer.StartTLS()
	defer httpServer.Close()
	b := startControlledSOCKSRelay(t, httpServer.Listener.Addr().String())
	const bid = "ob_22222222-2222-4222-8222-222222222222"
	url := "https://localhost:" + strconv.Itoa(httpServer.Listener.Addr().(*net.TCPAddr).Port) + "/dns-query"
	cfg := policyV2Config([]panel.PolicyDNSResolver{{ID: dnsResolverID(0), Protocol: "https", Address: url, BootstrapIP: "127.0.0.1", Domains: []string{}, OutboundID: bid}}, []panel.Outbound{{ID: bid, Name: "DoH proxy", Protocol: "socks", Address: "127.0.0.1", Port: b.port()}})
	cfg.Data.Routing.DNSPolicy.QueryStrategy = "UseIPv6"
	instance, err := getCore(conf.New(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err = instance.Start(); err != nil {
		t.Fatal(err)
	}
	defer instance.Close()
	resolver := instance.GetFeature(featureDNS.ClientType()).(featureDNS.Client)
	ips, _, err := resolver.LookupIP("doh.unit.test", featureDNS.IPOption{IPv4Enable: true, IPv6Enable: true})
	if err != nil || len(ips) != 1 || !ips[0].Equal(net.ParseIP("2001:db8::35")) {
		t.Fatalf("DoH result %v %v", ips, err)
	}
	if hits.Load() != 1 || systemCalls.Load() != 0 {
		t.Fatalf("DoH hits=%d systemDNS=%d", hits.Load(), systemCalls.Load())
	}
	select {
	case evidence := <-b.evidence:
		if evidence.host != "127.0.0.1" {
			t.Fatalf("DoH bootstrap target not pinned: %+v", evidence)
		}
	case <-time.After(time.Second):
		t.Fatal("DoH did not use selected SOCKS")
	}
}

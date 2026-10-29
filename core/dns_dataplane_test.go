package core

import (
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/perfect-panel/ppanel-node/api/panel"
	"github.com/perfect-panel/ppanel-node/conf"
	featureDNS "github.com/xtls/xray-core/features/dns"
	"golang.org/x/net/dns/dnsmessage"
)

// Exercise Xray's actual DNS feature and its UDP dispatcher, not just config
// projection. Matching domains force the custom resolver ahead of system DNS.
func TestCustomUDPResolverRealDNSQuery(t *testing.T) {
	for _, tc := range []struct{ name, host, protocol string }{
		{"ipv4-default-proto", "127.0.0.1", ""},
		{"ipv4-explicit-udp", "127.0.0.1", "udp"},
		{"localhost-explicit-udp", "localhost", "udp"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
			if err != nil {
				t.Fatal(err)
			}
			defer server.Close()
			queries := make(chan string, 4)
			errors := make(chan error, 1)
			go func() {
				buf := make([]byte, 4096)
				for {
					n, client, err := server.ReadFromUDP(buf)
					if err != nil {
						return
					}
					var request dnsmessage.Message
					if err := request.Unpack(buf[:n]); err != nil {
						select {
						case errors <- err:
						default:
						}
						continue
					}
					if len(request.Questions) != 1 {
						select {
						case errors <- fmt.Errorf("unexpected question count %d", len(request.Questions)):
						default:
						}
						continue
					}
					question := request.Questions[0]
					select {
					case queries <- question.Name.String():
					default:
					}
					response := dnsmessage.Message{Header: dnsmessage.Header{ID: request.ID, Response: true, Authoritative: true, RecursionAvailable: true}, Questions: request.Questions}
					if question.Type == dnsmessage.TypeA {
						response.Answers = []dnsmessage.Resource{{Header: dnsmessage.ResourceHeader{Name: question.Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 60}, Body: &dnsmessage.AResource{A: [4]byte{203, 0, 113, 42}}}}
					}
					packet, err := response.Pack()
					if err != nil {
						select {
						case errors <- err:
						default:
						}
						continue
					}
					if _, err := server.WriteToUDP(packet, client); err != nil {
						return
					}
				}
			}()
			address := net.JoinHostPort(tc.host, fmt.Sprint(server.LocalAddr().(*net.UDPAddr).Port))
			cfg := orderedConfig([]panel.RouteRule{}, nil)
			cfg.Data.IPStrategy = "prefer_ipv4"
			cfg.Data.DNS = &[]panel.DNSItem{{Proto: tc.protocol, Address: address, Domains: []string{"full:ppnode-dns-proof.example.com"}}}
			instance, err := getCore(conf.New(), cfg)
			if err != nil {
				t.Fatalf("build DNS core: %v", err)
			}
			if err := instance.Start(); err != nil {
				t.Fatal(err)
			}
			defer instance.Close()
			resolver := instance.GetFeature(featureDNS.ClientType()).(featureDNS.Client)
			type lookup struct {
				ips []net.IP
				err error
			}
			result := make(chan lookup, 1)
			go func() {
				ips, _, err := resolver.LookupIP("ppnode-dns-proof.example.com", featureDNS.IPOption{IPv4Enable: true})
				result <- lookup{ips: ips, err: err}
			}()
			select {
			case out := <-result:
				if out.err != nil || len(out.ips) != 1 || !out.ips[0].Equal(net.ParseIP("203.0.113.42")) {
					t.Fatalf("DNS response=%v, err=%v", out.ips, out.err)
				}
			case err := <-errors:
				t.Fatalf("local DNS server: %v", err)
			case <-time.After(8 * time.Second):
				t.Fatal("custom UDP DNS lookup timed out")
			}
			select {
			case q := <-queries:
				if q != "ppnode-dns-proof.example.com." {
					t.Fatalf("query=%q", q)
				}
			case <-time.After(time.Second):
				t.Fatal("no UDP query reached custom resolver")
			}
		})
	}
}

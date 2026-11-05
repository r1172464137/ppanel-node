package core

import (
	"context"
	"io"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/perfect-panel/ppanel-node/api/panel"
	"github.com/perfect-panel/ppanel-node/conf"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/proxy/vless/encoding"
	"golang.org/x/net/dns/dnsmessage"
)

func TestV2UserFallbackChecksIPAndPinsSOCKSTarget(t *testing.T) {
	resolver, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer resolver.Close()
	previousResolver := net.DefaultResolver
	net.DefaultResolver = &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "udp", resolver.LocalAddr().String())
	}}
	defer func() { net.DefaultResolver = previousResolver }()
	go func() {
		buf := make([]byte, 4096)
		for {
			n, peer, err := resolver.ReadFromUDP(buf)
			if err != nil {
				return
			}
			var q dnsmessage.Message
			if q.Unpack(buf[:n]) != nil || len(q.Questions) != 1 {
				continue
			}
			question := q.Questions[0]
			r := dnsmessage.Message{Header: dnsmessage.Header{ID: q.ID, Response: true, RecursionAvailable: true}, Questions: q.Questions}
			host := question.Name.String()
			if host == "failure.example." {
				r.RCode = dnsmessage.RCodeNameError
			} else if question.Type == dnsmessage.TypeA {
				ip := [4]byte{203, 0, 113, 42}
				if host == "blocked.example." {
					ip = [4]byte{198, 51, 100, 42}
				}
				if host == "private.example." || host == "scoped.example." || host == "all.example." || host == "explicit.example." || host == "explicit-all.example." {
					ip = [4]byte{10, 55, 0, 1}
				}
				r.Answers = []dnsmessage.Resource{{Header: dnsmessage.ResourceHeader{Name: question.Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 60}, Body: &dnsmessage.AResource{A: ip}}}
				if host == "mixed.example." {
					r.Answers = append(r.Answers, dnsmessage.Resource{Header: dnsmessage.ResourceHeader{Name: question.Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 60}, Body: &dnsmessage.AResource{A: [4]byte{198, 51, 100, 42}}})
				}
			} else if question.Type == dnsmessage.TypeAAAA && host == "mixed6.example." {
				var ip [16]byte
				copy(ip[:], net.ParseIP("2001:db8:bad::1").To16())
				r.Answers = []dnsmessage.Resource{{Header: dnsmessage.ResourceHeader{Name: question.Name, Type: dnsmessage.TypeAAAA, Class: dnsmessage.ClassINET, TTL: 60}, Body: &dnsmessage.AAAAResource{AAAA: ip}}}
			}
			b, err := r.Pack()
			if err == nil {
				_, _ = resolver.WriteToUDP(b, peer)
			}
		}
	}()
	socks := startControlledSOCKSServer(t)
	out := panel.Outbound{ID: orderedSOCKSID, Name: "user exit", Protocol: "socks", Address: "127.0.0.1", Port: socks.port()}
	dnsDirect := orderedRule(0, "ip", "127.0.0.1/32", "direct", true)
	explicit := orderedRule(1, "domain", "full:explicit.example", orderedSOCKSID, true)
	explicit.UserIDs = []int64{42}
	private := orderedRule(2, "ip", "10.0.0.0/8", "block", true)
	block := orderedRule(3, "ip", "198.51.100.0/24", "block", true)
	ipv6 := orderedRule(4, "ip", "2001:db8:bad::/48", "block", true)
	scoped := orderedRule(5, "domain", "full:scoped.example", orderedSOCKSID, true)
	scoped.UserIDs = []int64{42}
	explicitAll := orderedRule(6, "domain", "full:explicit-all.example", orderedSOCKSID, true)
	all := orderedRule(7, "domain", "full:all.example", orderedSOCKSID, true)
	config := orderedConfig([]panel.RouteRule{dnsDirect, explicit, explicitAll, private, block, ipv6, scoped, all}, []panel.Outbound{out})
	config.Data.Routing.Version = 2
	config.Data.Routing.Mode = "ordered-v2-inherited"
	config.Data.Routing.DefaultOutboundID = "block"
	config.Data.Routing.UserDefaults = []panel.UserDefault{{UserID: 42, OutboundID: orderedSOCKSID}}
	u1 := panel.UserInfo{Id: 1, Uuid: "00000000-0000-0000-0000-000000000001", AccountID: 42}
	u2 := panel.UserInfo{Id: 2, Uuid: "00000000-0000-0000-0000-000000000002", AccountID: 43}
	config.Data.IdentitySnapshot = &panel.IdentitySnapshot{SnapshotID: strings.Repeat("a", 64), Protocols: []panel.ProtocolUserSnapshot{{Protocol: "vless", Users: []panel.UserInfo{u1, u2}}}}
	config.Data.Routing.DNSPolicy = &panel.DNSPolicy{QueryStrategy: "UseIP", Resolvers: []panel.PolicyDNSResolver{{ID: dnsResolverID(0), Protocol: "udp", Address: resolver.LocalAddr().String(), Domains: []string{}, OutboundID: "direct"}}}
	port := reserveTCPUDPPort(t)
	protocols := []panel.Protocol{{Type: "vless", Enable: true, Port: port, Transport: "tcp"}}
	config.Data.Protocols = &protocols
	config.Data.Total = 1
	c := conf.New()
	c.ApiConfig.ApiHost = "http://fixture.invalid"
	c.ApiConfig.ServerId = 7
	x := New(c, nil)
	if err := x.Start(config); err != nil {
		t.Fatal(err)
	}
	defer x.Close()
	tag := panel.InboundTag(c.ApiConfig.ApiHost, "vless", 7)
	info := &panel.NodeInfo{Id: 7, Type: "vless", Protocol: &protocols[0]}
	x.LimiterManager.Add(tag, []panel.UserInfo{u1, u2}, nil, "vless")
	if err := x.AddNode(tag, info); err != nil {
		t.Fatal(err)
	}
	if _, err := x.AddUsers(&AddUsersParams{Tag: tag, NodeInfo: info, Users: []panel.UserInfo{u1, u2}}); err != nil {
		t.Fatal(err)
	}
	request := func(u panel.UserInfo, domain string) (string, error) {
		conn, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), time.Second)
		if err != nil {
			return "", err
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
		mu, err := buildVlessUser(tag, &u, "").ToMemoryUser()
		if err != nil {
			return "", err
		}
		req := &protocol.RequestHeader{Version: 0, Command: protocol.RequestCommandTCP, Address: xnet.ParseAddress(domain), Port: 443, User: mu}
		if err = encoding.EncodeRequestHeader(conn, req, &encoding.Addons{}); err != nil {
			return "", err
		}
		if _, err = conn.Write([]byte("proof")); err != nil {
			return "", err
		}
		if _, err = encoding.DecodeResponseHeader(conn, req); err != nil {
			return "", err
		}
		buf := make([]byte, 5)
		_, err = io.ReadFull(conn, buf)
		return string(buf), err
	}
	if got, err := request(u1, "allowed.example"); err != nil || got != "proof" {
		t.Fatalf("fallback %q %v", got, err)
	}
	select {
	case evidence := <-socks.evidence:
		if evidence.host != "203.0.113.42" || evidence.port != 443 {
			t.Fatalf("not pinned: %+v", evidence)
		}
	case <-time.After(time.Second):
		t.Fatal("SOCKS missing")
	}
	if got, err := request(u1, "explicit.example"); err != nil || got != "proof" {
		t.Fatalf("explicit ordered exception changed: %q %v", got, err)
	}
	select {
	case e := <-socks.evidence:
		if e.host != "10.55.0.1" {
			t.Fatalf("explicit target not pinned: %+v", e)
		}
	case <-time.After(time.Second):
		t.Fatal("explicit exception missing")
	}
	if got, err := request(u1, "explicit-all.example"); err != nil || got != "proof" {
		t.Fatalf("all-user ordered exception changed: %q %v", got, err)
	}
	select {
	case e := <-socks.evidence:
		if e.host != "10.55.0.1" {
			t.Fatalf("all-user target not pinned: %+v", e)
		}
	case <-time.After(time.Second):
		t.Fatal("all-user exception missing")
	}
	for _, host := range []string{"blocked.example", "private.example", "scoped.example", "all.example", "mixed.example", "mixed6.example", "failure.example", "198.51.100.42", "10.55.0.1"} {
		if _, err := request(u1, host); err == nil {
			t.Fatalf("blocked or unresolved request succeeded: %s", host)
		}
	}
	if _, err := request(u2, "allowed.example"); err == nil {
		t.Fatal("unconfigured user bypassed global default")
	}
	select {
	case e := <-socks.evidence:
		t.Fatalf("blocked/unconfigured user reached SOCKS: %+v", e)
	case <-time.After(100 * time.Millisecond):
	}
}

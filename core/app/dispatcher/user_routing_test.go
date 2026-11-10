package dispatcher

import (
	"net"
	"testing"

	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/features/dns"
	"github.com/xtls/xray-core/features/routing"
)

type fixedDNSClient struct {
	ips   []net.IP
	calls int
}

func (*fixedDNSClient) Type() interface{} { return dns.ClientType() }
func (*fixedDNSClient) Start() error      { return nil }
func (*fixedDNSClient) Close() error      { return nil }
func (c *fixedDNSClient) LookupIP(string, dns.IPOption) ([]net.IP, uint32, error) {
	c.calls++
	return append([]net.IP(nil), c.ips...), 60, nil
}

type fixedRoute struct {
	routing.Context
	outbound string
	rule     string
}

func (r fixedRoute) GetOutboundTag() string         { return r.outbound }
func (r fixedRoute) GetOutboundGroupTags() []string { return nil }
func (r fixedRoute) GetRuleTag() string             { return r.rule }

type fixedRouter struct {
	pick func(routing.Context) (routing.Route, error)
}

func (fixedRouter) Type() interface{} { return routing.RouterType() }
func (fixedRouter) Start() error      { return nil }
func (fixedRouter) Close() error      { return nil }
func (r fixedRouter) PickRoute(ctx routing.Context) (routing.Route, error) {
	return r.pick(ctx)
}
func (fixedRouter) AddRule(*serial.TypedMessage, bool) error { return nil }
func (fixedRouter) RemoveRule(string) error                  { return nil }
func (fixedRouter) ListRule() []routing.Route                { return nil }

type emptyRoutingContext struct{ routing.Context }

func TestOrderCandidateIPsHonorsPanelStrategy(t *testing.T) {
	v4 := net.ParseIP("203.0.113.10")
	v6 := net.ParseIP("2607:6bc0::10")
	original := []net.IP{v6, v4}
	for _, test := range []struct {
		strategy string
		want     net.IP
	}{
		{"prefer_ipv4", v4},
		{"prefer_ipv6", v6},
		{"", v6},
		{"unknown", v6},
	} {
		t.Run(test.strategy, func(t *testing.T) {
			got := orderCandidateIPs(original, test.strategy)
			if len(got) != 2 || !got[0].Equal(test.want) {
				t.Fatalf("strategy %q order = %v, want first %v", test.strategy, got, test.want)
			}
		})
	}
	for _, test := range []struct {
		name     string
		ips      []net.IP
		strategy string
		want     net.IP
	}{
		{"ipv4-preference-falls-back-to-ipv6", []net.IP{v6}, "prefer_ipv4", v6},
		{"ipv6-preference-falls-back-to-ipv4", []net.IP{v4}, "prefer_ipv6", v4},
	} {
		t.Run(test.name, func(t *testing.T) {
			got := orderCandidateIPs(test.ips, test.strategy)
			if len(got) != 1 || !got[0].Equal(test.want) {
				t.Fatalf("order = %v, want %v", got, test.want)
			}
		})
	}
}

func TestCheckedDestinationAppliesStrategyAndFailClosesMixedBlocks(t *testing.T) {
	v4 := net.ParseIP("203.0.113.10")
	v4Blocked := net.ParseIP("198.51.100.10")
	v6 := net.ParseIP("2607:6bc0::10")
	router := fixedRouter{pick: func(ctx routing.Context) (routing.Route, error) {
		ips := ctx.GetTargetIPs()
		if len(ips) > 1 {
			return fixedRoute{outbound: "socks", rule: "domain-dual"}, nil
		}
		if ips[0].Equal(v4Blocked) {
			return fixedRoute{outbound: "routing_blocked", rule: "ip-blocked"}, nil
		}
		return fixedRoute{outbound: "socks", rule: "domain-dual"}, nil
	}}
	for _, test := range []struct {
		strategy string
		want     net.IP
	}{
		{"prefer_ipv4", v4},
		{"prefer_ipv6", v6},
		{"", v6},
	} {
		t.Run(test.strategy, func(t *testing.T) {
			d := &DefaultDispatcher{
				dnsClient:        &fixedDNSClient{ips: []net.IP{v6, v4}},
				router:           router,
				blockedOutbounds: map[string]bool{},
			}
			d.SetIPStrategy(test.strategy)
			route, ip, err := d.checkedDestination(emptyRoutingContext{}, "dual.example")
			if err != nil {
				t.Fatal(err)
			}
			if route == nil || route.GetOutboundTag() != "socks" || !ip.Equal(test.want) {
				t.Fatalf("strategy %q selected %v via %+v, want %v", test.strategy, ip, route, test.want)
			}
		})
	}

	d := &DefaultDispatcher{
		dnsClient:        &fixedDNSClient{ips: []net.IP{v6, v4Blocked, v4}},
		router:           router,
		blockedOutbounds: map[string]bool{"routing_blocked": true},
	}
	d.SetIPStrategy("prefer_ipv4")
	route, ip, err := d.checkedDestination(emptyRoutingContext{}, "mixed.example")
	if err != nil || route == nil || route.GetOutboundTag() != "routing_blocked" || !ip.Equal(v4Blocked) {
		t.Fatalf("mixed block did not fail closed: route=%+v ip=%v err=%v", route, ip, err)
	}
}

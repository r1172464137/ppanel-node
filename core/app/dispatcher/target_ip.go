package dispatcher

import (
	"fmt"

	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/features/dns"
	"github.com/xtls/xray-core/features/routing"
)

// blockTag is the built-in blackhole outbound (core/outbound.BlockTag).
const blockTag = "block"

// TargetIPPolicy controls domain targets when IP rules exist (CONTRACT 4.4).
type TargetIPPolicy struct {
	Recheck       bool
	Preference    string // none, prefer_ipv4, prefer_ipv6
	QueryStrategy string // UseIP, UseIPv4, UseIPv6
}

// ipCheckContext presents one resolved address for the original domain,
// identity, inbound and protocol, so the ordered rules are evaluated exactly
// as for the connection itself (domain rules still match first).
type ipCheckContext struct {
	routing.Context
	ip net.IP
}

func (c ipCheckContext) GetTargetIPs() []net.IP { return []net.IP{c.ip} }

// recheckTarget resolves a domain target with the DNS policy, evaluates the
// ordered rules for every answer, and pins the connection to one checked
// address. It fails closed when resolution fails, when any answer is
// blocked, or when answers would leave through different rules or outbounds.
// The returned route is nil when no rule matched (default/account default).
func (d *DefaultDispatcher) recheckTarget(rctx routing.Context, dest net.Destination) (routing.Route, net.Destination, error) {
	if d.DNS == nil {
		return nil, dest, fmt.Errorf("target IP check needs DNS")
	}
	qs := d.TargetIP.QueryStrategy
	ips, _, err := d.DNS.LookupIP(dest.Address.Domain(), dns.IPOption{IPv4Enable: qs != "UseIPv6", IPv6Enable: qs != "UseIPv4"})
	if err != nil {
		return nil, dest, fmt.Errorf("resolve %s: %w", dest.Address.Domain(), err)
	}
	if len(ips) == 0 {
		return nil, dest, fmt.Errorf("resolve %s: no address", dest.Address.Domain())
	}
	var first routing.Route
	firstKey := ""
	for i, ip := range ips {
		key := "no-rule"
		route, err := d.router.PickRoute(ipCheckContext{Context: rctx, ip: ip})
		if err == nil && route != nil {
			if route.GetOutboundTag() == blockTag {
				return nil, dest, fmt.Errorf("%s resolves to a blocked address", dest.Address.Domain())
			}
			key = route.GetRuleTag() + "|" + route.GetOutboundTag()
		} else {
			route = nil
		}
		if i == 0 {
			first, firstKey = route, key
		} else if key != firstKey {
			return nil, dest, fmt.Errorf("%s resolves to addresses with different routes", dest.Address.Domain())
		}
	}
	chosen := orderByPreference(ips, d.TargetIP.Preference)[0]
	return first, net.Destination{Network: dest.Network, Address: net.IPAddress(chosen), Port: dest.Port}, nil
}

// orderByPreference puts the preferred family first, keeping the resolver's
// order within each family. It never drops the other family.
func orderByPreference(ips []net.IP, preference string) []net.IP {
	if preference != "prefer_ipv4" && preference != "prefer_ipv6" {
		return ips
	}
	wantV4 := preference == "prefer_ipv4"
	out := make([]net.IP, 0, len(ips))
	for pass := 0; pass < 2; pass++ {
		for _, ip := range ips {
			isV4 := ip.To4() != nil
			if (pass == 0) == (isV4 == wantV4) {
				out = append(out, ip)
			}
		}
	}
	return out
}

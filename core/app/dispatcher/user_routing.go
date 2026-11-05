package dispatcher

import (
	stderrors "errors"
	"fmt"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/features/dns"
	"github.com/xtls/xray-core/features/routing"
)

func (d *DefaultDispatcher) SetIPRuleChecks(enabled bool, blocked map[string]bool) {
	d.guardIPRules, d.blockedOutbounds = enabled, blocked
}

// A user selector must not change how the destination predicates are checked.
// For v2 policies with IP conditions, re-evaluate with resolved addresses before
// dialing, retaining domain/user predicates and ordered explicit exceptions.
func (d *DefaultDispatcher) checkedDestination(ctx routing.Context, domain string) (routing.Route, net.IP, error) {
	if d.dnsClient == nil {
		return nil, nil, fmt.Errorf("DNS client unavailable")
	}
	ips, _, err := d.dnsClient.LookupIP(domain, dns.IPOption{IPv4Enable: true, IPv6Enable: true})
	if err != nil {
		return nil, nil, err
	}
	if len(ips) == 0 {
		return nil, nil, fmt.Errorf("target lookup returned no addresses")
	}
	selected, err := d.router.PickRoute(resolvedRoutingContext{Context: ctx, ips: ips})
	if err != nil && !stderrors.Is(err, common.ErrNoClue) {
		return nil, nil, err
	}
	var chosen net.IP
	for _, ip := range ips {
		route, err := d.router.PickRoute(resolvedRoutingContext{Context: ctx, ips: []net.IP{ip}})
		if err != nil && !stderrors.Is(err, common.ErrNoClue) {
			return nil, nil, err
		}
		if route != nil && (route.GetOutboundTag() == "block" || d.blockedOutbounds[route.GetOutboundTag()]) {
			return route, ip, nil
		}
		if chosen == nil && (selected == nil && route == nil || selected != nil && route != nil && selected.GetRuleTag() == route.GetRuleTag() && selected.GetOutboundTag() == route.GetOutboundTag()) {
			chosen = ip
		}
	}
	if chosen == nil {
		return nil, nil, fmt.Errorf("no address matches selected route")
	}
	return selected, chosen, nil
}

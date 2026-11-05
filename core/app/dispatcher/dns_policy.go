package dispatcher

import (
	"fmt"
	"strings"

	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/features/dns"
)

// DNSRouteTarget restricts an internal resolver tag to its configured peer.
// It is installed before listeners start and never changed on a live core.
type DNSRouteTarget struct {
	Host      string
	Port      net.Port
	Bootstrap net.Address
}

func (d *DefaultDispatcher) SetDNSTargets(targets map[string]DNSRouteTarget) {
	d.dnsTargets = targets
}

func (d *DefaultDispatcher) resolveDNSTarget(tag string, destination net.Destination) (net.Destination, error) {
	target, ok := d.dnsTargets[tag]
	if !ok {
		return destination, nil
	}
	if !strings.EqualFold(strings.TrimSuffix(destination.Address.String(), "."), strings.TrimSuffix(target.Host, ".")) || destination.Port != target.Port {
		return destination, fmt.Errorf("DNS resolver attempted a different endpoint")
	}
	if !destination.Address.Family().IsDomain() {
		return destination, nil
	}
	// Bootstrap describes the resolver transport, independent of whether the
	// resolver is configured to answer A or AAAA questions.
	if target.Bootstrap != nil {
		destination.Address = target.Bootstrap
		return destination, nil
	}
	if d.dnsClient == nil {
		return destination, fmt.Errorf("DNS client unavailable")
	}
	// Static bootstrap hosts and acyclic resolver dependencies use the same
	// configured DNS client. Never delegate resolver bootstrap to system DNS.
	ips, _, err := d.dnsClient.LookupIP(target.Host, dns.IPOption{IPv4Enable: true, IPv6Enable: true})
	if err != nil {
		return destination, err
	}
	if len(ips) == 0 {
		return destination, fmt.Errorf("DNS resolver bootstrap returned no addresses")
	}
	destination.Address = net.IPAddress(ips[0])
	return destination, nil
}

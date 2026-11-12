package outbound

import (
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"sort"
	"strings"

	"github.com/google/uuid"
	"github.com/perfect-panel/ppanel-node/api/panel"
	"github.com/perfect-panel/ppanel-node/common/format"
)

// Routing format 3 checks the node performs on every candidate, in addition
// to the backend's: a candidate the node cannot prove consistent is rejected
// as a whole and the applied configuration keeps serving.

const (
	maxUserIDsPerRule   = 1024
	maxUserIDs          = 8192
	maxUserDefaults     = 8192
	maxDNSResolvers     = 128
	maxDNSDomainsPerRes = 1024
)

var snapshotIDPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

var chainableProtocols = map[string]bool{
	"socks": true, "http": true, "shadowsocks": true, "vmess": true, "vless": true,
	"trojan": true, "anytls": true, "hysteria": true,
}

func validateAccountScopes(p *panel.RoutingPolicy, ids map[string]bool) error {
	total := 0
	for i, r := range p.Rules {
		if r.UserIDs == nil {
			return fmt.Errorf("routing rule %d user_ids must be an array", i+1)
		}
		if len(r.UserIDs) > maxUserIDsPerRule {
			return fmt.Errorf("routing rule %d has too many accounts", i+1)
		}
		total += len(r.UserIDs)
		seen := map[int64]bool{}
		for _, id := range r.UserIDs {
			if id <= 0 || seen[id] {
				return fmt.Errorf("routing rule %d has an invalid or duplicate account", i+1)
			}
			seen[id] = true
		}
	}
	if total > maxUserIDs {
		return fmt.Errorf("routing references too many accounts")
	}
	if p.UserDefaults == nil {
		return fmt.Errorf("routing user_defaults must be an array")
	}
	if len(p.UserDefaults) > maxUserDefaults {
		return fmt.Errorf("routing has too many account defaults")
	}
	seen := map[int64]bool{}
	for i, d := range p.UserDefaults {
		if d.UserID <= 0 || seen[d.UserID] {
			return fmt.Errorf("account default %d has an invalid or duplicate account", i+1)
		}
		seen[d.UserID] = true
		if !ids[d.OutboundID] {
			return fmt.Errorf("account default %d references unknown outbound %q", i+1, d.OutboundID)
		}
	}
	return nil
}

// rawDialerProxy reads sockopt.dialerProxy from raw stream settings; Xray's
// JSON decoding is case-insensitive, so the keys are matched the same way.
func rawDialerProxy(stream string) (string, error) {
	if strings.TrimSpace(stream) == "" {
		return "", nil
	}
	var top map[string]json.RawMessage
	if err := json.Unmarshal([]byte(stream), &top); err != nil {
		return "", err
	}
	for k, v := range top {
		if !strings.EqualFold(k, "sockopt") {
			continue
		}
		var sock map[string]json.RawMessage
		if json.Unmarshal(v, &sock) != nil {
			continue
		}
		for sk, sv := range sock {
			if strings.EqualFold(sk, "dialerProxy") {
				var s string
				if err := json.Unmarshal(sv, &s); err != nil {
					return "", fmt.Errorf("sockopt.dialerProxy must be a string")
				}
				return strings.TrimSpace(s), nil
			}
		}
	}
	return "", nil
}

// validateChains checks via_outbound_id and raw dialerProxy references: same
// policy, not direct/block, only dialing protocols, and no cycle.
func validateChains(p *panel.RoutingPolicy) error {
	byID := map[string]panel.Outbound{}
	for _, o := range p.Outbounds {
		byID[o.ID] = o
	}
	next := map[string]string{}
	for i, o := range p.Outbounds {
		via := strings.TrimSpace(o.ViaOutboundID)
		raw, err := rawDialerProxy(o.StreamSettings)
		if err != nil {
			return fmt.Errorf("routing outbound %d stream settings: %w", i+1, err)
		}
		if via != "" && raw != "" {
			return fmt.Errorf("routing outbound %d sets both via_outbound_id and dialerProxy", i+1)
		}
		target := via
		if raw != "" {
			if !strings.HasPrefix(raw, "routing_") {
				return fmt.Errorf("routing outbound %d dialerProxy must reference an outbound of this policy", i+1)
			}
			target = strings.TrimPrefix(raw, "routing_")
		}
		if target == "" {
			continue
		}
		if _, ok := byID[target]; !ok || target == o.ID {
			return fmt.Errorf("routing outbound %d has an invalid preceding outbound", i+1)
		}
		if !chainableProtocols[normalizeOutboundProtocol(o.Protocol)] {
			return fmt.Errorf("routing outbound %d cannot use a preceding outbound", i+1)
		}
		next[o.ID] = target
	}
	for start := range next {
		seen := map[string]bool{start: true}
		for cur := next[start]; cur != ""; cur = next[cur] {
			if seen[cur] {
				return fmt.Errorf("routing outbound chain contains a cycle")
			}
			seen[cur] = true
		}
	}
	return nil
}

// validateDNSPolicy checks the DNS policy's structure. Which resolver kinds
// this build can run is decided when compiling.
func validateDNSPolicy(p *panel.RoutingPolicy, customIDs map[string]bool) error {
	d := p.DNS
	if d == nil {
		return fmt.Errorf("routing dns must be an object")
	}
	switch d.QueryStrategy {
	case "UseIP", "UseIPv4", "UseIPv6":
	default:
		return fmt.Errorf("routing dns query_strategy %q is invalid", d.QueryStrategy)
	}
	if len(d.Resolvers) == 0 || len(d.Resolvers) > maxDNSResolvers {
		return fmt.Errorf("routing dns must have 1..%d resolvers", maxDNSResolvers)
	}
	last := len(d.Resolvers) - 1
	ids := map[string]bool{}
	bootstrap := map[string]string{}
	hasBootstrap := map[string]bool{}
	type hostRef struct{ host, bootstrap string }
	var hosts []hostRef
	for i, r := range d.Resolvers {
		if !orderedID(r.ID, "dns_") || ids[r.ID] {
			return fmt.Errorf("dns resolver %d has an invalid or duplicate ID", i+1)
		}
		ids[r.ID] = true
		if r.Domains == nil || len(r.Domains) > maxDNSDomainsPerRes {
			return fmt.Errorf("dns resolver %d domains must be an array of at most %d", i+1, maxDNSDomainsPerRes)
		}
		if len(r.Domains) > 0 {
			if _, err := buildDomainRules(r.Domains); err != nil {
				return fmt.Errorf("dns resolver %d domains: %w", i+1, err)
			}
		}
		if (i == last) != (len(r.Domains) == 0) {
			return fmt.Errorf("dns resolver %d: only the last resolver is the default and has no domains", i+1)
		}
		switch r.Protocol {
		case "system":
			if i != last || r.Address != "" || r.BootstrapIP != "" || r.OutboundID != "direct" {
				return fmt.Errorf("dns resolver %d: system is only the last default, without address, bootstrap or outbound", i+1)
			}
		case "udp", "tcp", "https":
			host, err := resolverHost(r.Protocol, r.Address)
			if err != nil {
				return fmt.Errorf("dns resolver %d address: %w", i+1, err)
			}
			if r.OutboundID != "direct" && !customIDs[r.OutboundID] {
				return fmt.Errorf("dns resolver %d references unknown or block outbound %q", i+1, r.OutboundID)
			}
			if net.ParseIP(host) != nil {
				if r.BootstrapIP != "" {
					return fmt.Errorf("dns resolver %d: bootstrap_ip is not allowed for an IP address", i+1)
				}
				continue
			}
			if r.BootstrapIP != "" {
				if net.ParseIP(r.BootstrapIP) == nil {
					return fmt.Errorf("dns resolver %d bootstrap_ip must be an IP address", i+1)
				}
				h := strings.ToLower(host)
				if prev, ok := bootstrap[h]; ok && prev != r.BootstrapIP {
					return fmt.Errorf("dns resolver %d bootstrap_ip conflicts for the same host", i+1)
				}
				bootstrap[h], hasBootstrap[h] = r.BootstrapIP, true
			}
			hosts = append(hosts, hostRef{strings.ToLower(host), r.BootstrapIP})
		default:
			return fmt.Errorf("dns resolver %d protocol %q is invalid", i+1, r.Protocol)
		}
	}
	for _, h := range hosts {
		if hasBootstrap[h.host] && h.bootstrap != bootstrap[h.host] {
			return fmt.Errorf("dns resolvers for the same host must use the same bootstrap_ip")
		}
	}
	switch p.TargetIPPreference {
	case "none", "prefer_ipv4", "prefer_ipv6":
	default:
		return fmt.Errorf("routing target_ip_preference %q is invalid", p.TargetIPPreference)
	}
	return nil
}

func resolverHost(protocol, address string) (string, error) {
	if address == "" || strings.Contains(address, "+local") {
		return "", fmt.Errorf("invalid resolver address")
	}
	if protocol == "https" {
		u, err := url.Parse(address)
		if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Fragment != "" || strings.Contains(address, "#") {
			return "", fmt.Errorf("must be an https:// URL without credentials or fragment")
		}
		host := u.Hostname()
		if net.ParseIP(host) == nil {
			if _, err := validateDNSHostname(host); err != nil {
				return "", err
			}
		}
		if p := u.Port(); p != "" {
			if _, err := parseDNSPort(p); err != nil {
				return "", err
			}
		}
		return host, nil
	}
	host, _, err := parseDNSAddress(address)
	if err != nil {
		return "", err
	}
	return host, nil
}

// validateIdentitySnapshot checks the identity snapshot against the delivered
// protocols: one entry per delivered protocol type in sorted order, users
// sorted by subscription ID, well-formed UUIDs, no duplicate UUID within a
// protocol, and one account per UUID.
func validateIdentitySnapshot(data *panel.Data) error {
	s := data.IdentitySnapshot
	if s == nil {
		return fmt.Errorf("identity snapshot is missing")
	}
	if !snapshotIDPattern.MatchString(s.SnapshotID) {
		return fmt.Errorf("identity snapshot ID is invalid")
	}
	delivered := map[string]bool{}
	if data.Protocols != nil {
		for _, p := range *data.Protocols {
			delivered[p.Type] = true
		}
	}
	if s.Protocols == nil || len(s.Protocols) != len(delivered) {
		return fmt.Errorf("identity snapshot does not cover the delivered protocols")
	}
	for i, p := range s.Protocols {
		if !delivered[p.Protocol] || (i > 0 && s.Protocols[i-1].Protocol >= p.Protocol) {
			return fmt.Errorf("identity snapshot protocols are not the sorted delivered protocols")
		}
		if p.Users == nil {
			return fmt.Errorf("identity snapshot users of %s must be an array", p.Protocol)
		}
		byUUID := map[string]int64{}
		for j, u := range p.Users {
			if u.ID <= 0 || u.AccountID <= 0 || u.SpeedLimit < 0 || u.DeviceLimit < 0 {
				return fmt.Errorf("identity %s user %d has invalid fields", p.Protocol, j+1)
			}
			if j > 0 && p.Users[j-1].ID >= u.ID {
				return fmt.Errorf("identity %s users are not sorted by unique ID", p.Protocol)
			}
			if _, err := uuid.Parse(u.UUID); err != nil {
				return fmt.Errorf("identity %s user %d has an invalid UUID", p.Protocol, j+1)
			}
			key := strings.ToLower(u.UUID)
			if _, dup := byUUID[key]; dup {
				return fmt.Errorf("identity %s has a duplicate UUID", p.Protocol)
			}
			byUUID[key] = u.AccountID
		}
	}
	return nil
}

// IdentityUsers returns the users of one protocol as the controller's user
// records.
func IdentityUsers(data *panel.Data, protocol string) []panel.UserInfo {
	users := []panel.UserInfo{}
	if data == nil || data.IdentitySnapshot == nil {
		return users
	}
	for _, p := range data.IdentitySnapshot.Protocols {
		if p.Protocol != protocol {
			continue
		}
		for _, u := range p.Users {
			users = append(users, panel.UserInfo{Id: int(u.ID), Uuid: u.UUID, SpeedLimit: int(u.SpeedLimit), DeviceLimit: int(u.DeviceLimit)})
		}
	}
	return users
}

// accountEmails returns the "inboundTag|UUID" identities of the given accounts
// across all delivered protocols, sorted for deterministic rules.
func accountEmails(data *panel.Data, inboundTag func(protocol string) string, accounts map[int64]bool) []string {
	var out []string
	if data.IdentitySnapshot == nil {
		return out
	}
	for _, p := range data.IdentitySnapshot.Protocols {
		tag := inboundTag(p.Protocol)
		for _, u := range p.Users {
			if accounts[u.AccountID] {
				out = append(out, format.UserTag(tag, u.UUID))
			}
		}
	}
	sort.Strings(out)
	return out
}

// ScopedAccounts returns every account referenced by enabled account-scoped
// rules or account defaults. Identity changes of these accounts change the
// compiled router, so they need a full switch instead of a hot update.
func ScopedAccounts(p *panel.RoutingPolicy) map[int64]bool {
	out := map[int64]bool{}
	if p == nil {
		return out
	}
	for _, r := range p.Rules {
		if r.Enabled != nil && *r.Enabled {
			for _, id := range r.UserIDs {
				out[id] = true
			}
		}
	}
	for _, d := range p.UserDefaults {
		out[d.UserID] = true
	}
	return out
}

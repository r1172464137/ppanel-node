package outbound

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/perfect-panel/ppanel-node/api/panel"
	"github.com/xtls/xray-core/app/dns"
	"github.com/xtls/xray-core/app/router"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/core"
	coreConf "github.com/xtls/xray-core/infra/conf"
)

const (
	DefaultTag = "Default"
	BlockTag   = "block"
	DNSTag     = "dns_out"
)

type BuildResult struct {
	DNS       *dns.Config
	Outbounds []*core.OutboundHandlerConfig
	Router    *router.Config
}

func Build(serverconfig *panel.ServerConfigResponse, hasIPv6 bool) (*BuildResult, error) {
	if err := validateRouteConfigRawLimits(serverconfig.Data); err != nil {
		return nil, err
	}
	globalBlockBudget := routeRuleBudget{
		scope: "global block", maxRules: MaxGlobalBlockAggregateRules, maxBytes: MaxGlobalBlockAggregateBytes,
	}
	outboundBudget := routeRuleBudget{
		scope: "outbound", maxRules: MaxOutboundAggregateRules, maxBytes: MaxOutboundAggregateBytes,
	}
	configBudget := routeRuleBudget{
		scope: "structured config", maxRules: MaxStructuredConfigAggregateRules, maxBytes: MaxStructuredConfigAggregateBytes,
	}

	var ipStrategy string
	if serverconfig.Data.IPStrategy != "" {
		switch serverconfig.Data.IPStrategy {
		case "prefer_ipv4":
			ipStrategy = "UseIPv4v6"
		case "prefer_ipv6":
			ipStrategy = "UseIPv6v4"
		default:
			ipStrategy = "UseIPv4v6"
		}
	} else {
		if hasIPv6 {
			ipStrategy = "UseIPv4v6"
		} else {
			ipStrategy = "UseIPv4"
		}
	}
	dnsConfig := serverconfig.Data.DNS
	blockDomains := serverconfig.Data.Block
	blockIPs := serverconfig.Data.BlockIPs
	blockProtocols := serverconfig.Data.BlockProtocols
	outboundList := serverconfig.Data.Outbound

	//default dns
	queryStrategy := "UseIPv4v6"
	if !hasIPv6 {
		queryStrategy = "UseIPv4"
	}
	coreDnsConfig := &coreConf.DNSConfig{
		Servers: []*coreConf.NameServerConfig{
			{
				Address: &coreConf.Address{
					Address: xnet.ParseAddress("localhost"),
				},
			},
		},
		QueryStrategy: queryStrategy,
	}

	//custom dns
	if dnsConfig != nil {
		for i, item := range *dnsConfig {
			domains, err := buildDomainRules(item.Domains)
			if err != nil {
				return nil, fmt.Errorf("invalid DNS resolver %d domain rules: %w", i+1, err)
			}
			/*switch item.Proto {
			case "udp":
				item.Address = item.Address
			case "tcp":
				item.Address = "tcp://" + item.Address
			case "tls":
				item.Address = "tls://" + item.Address
			case "https":
				item.Address = "https://" + item.Address
			case "quic":
				item.Address = "quic://" + item.Address
			}*/
			server := &coreConf.NameServerConfig{
				Address: &coreConf.Address{
					Address: xnet.ParseAddress(item.Address),
				},
				QueryStrategy: ipStrategy,
				Domains:       domains,
			}
			coreDnsConfig.Servers = append(coreDnsConfig.Servers, server)
		}
	}

	//default outbound
	defaultoutbound, _ := buildDefaultOutbound()
	coreOutboundConfig := append([]*core.OutboundHandlerConfig{}, defaultoutbound)
	block, _ := buildBlockOutbound()
	coreOutboundConfig = append(coreOutboundConfig, block)
	dns, _ := buildDnsOutbound()
	coreOutboundConfig = append(coreOutboundConfig, dns)

	//default route
	domainStrategy := "AsIs"
	dnsRule, _ := json.Marshal(map[string]interface{}{
		"port":        "53",
		"network":     "udp",
		"outboundTag": DNSTag,
	})
	coreRouterConfig := &coreConf.RouterConfig{
		RuleList:       []json.RawMessage{dnsRule},
		DomainStrategy: &domainStrategy,
	}

	// Global block categories are separate OR rules. Their fixed order also
	// guarantees that every block rule wins over every custom outbound rule.
	if blockProtocols != nil {
		protocols, err := buildProtocolRules(*blockProtocols)
		if err != nil {
			return nil, fmt.Errorf("invalid global block protocol rules: %w", err)
		}
		if err := globalBlockBudget.add("block_protocols", protocols); err != nil {
			return nil, err
		}
		if err := configBudget.add("block_protocols", protocols); err != nil {
			return nil, err
		}
		if err := appendRouteRule(coreRouterConfig, "protocol", protocols, BlockTag); err != nil {
			return nil, err
		}
	}
	if blockIPs != nil {
		ips, err := buildIPRules(*blockIPs)
		if err != nil {
			return nil, fmt.Errorf("invalid global block IP rules: %w", err)
		}
		if err := globalBlockBudget.add("block_ips", ips); err != nil {
			return nil, err
		}
		if err := configBudget.add("block_ips", ips); err != nil {
			return nil, err
		}
		if err := appendRouteRule(coreRouterConfig, "ip", ips, BlockTag); err != nil {
			return nil, err
		}
	}
	if blockDomains != nil {
		domains, err := buildDomainRules(*blockDomains)
		if err != nil {
			return nil, fmt.Errorf("invalid global block domain rules: %w", err)
		}
		if err := globalBlockBudget.add("block", domains); err != nil {
			return nil, err
		}
		if err := configBudget.add("block", domains); err != nil {
			return nil, err
		}
		if err := appendRouteRule(coreRouterConfig, "domain", domains, BlockTag); err != nil {
			return nil, err
		}
	}

	// Keep each outbound's three OR rules together, in panel list order.
	if outboundList != nil {
		for _, outbounditem := range *outboundList {
			// Parse every rule before protocol support is considered. This is
			// intentionally fail-closed: malformed rules on a legacy/unsupported
			// outbound must not be silently accepted and later become active.
			domains, err := buildDomainRules(outbounditem.Rules)
			if err != nil {
				return nil, fmt.Errorf("invalid outbound %q domain rules: %w", outbounditem.Name, err)
			}
			ips, err := buildIPRules(outbounditem.IPRules)
			if err != nil {
				return nil, fmt.Errorf("invalid outbound %q IP rules: %w", outbounditem.Name, err)
			}
			protocols, err := buildProtocolRules(outbounditem.ProtocolRules)
			if err != nil {
				return nil, fmt.Errorf("invalid outbound %q protocol rules: %w", outbounditem.Name, err)
			}
			for _, group := range []struct {
				field  string
				values []string
			}{
				{field: "rules", values: domains},
				{field: "ip_rules", values: ips},
				{field: "protocol_rules", values: protocols},
			} {
				field := fmt.Sprintf("outbound %q %s", outbounditem.Name, group.field)
				if err := outboundBudget.add(field, group.values); err != nil {
					return nil, err
				}
				if err := configBudget.add(field, group.values); err != nil {
					return nil, err
				}
			}

			protocol, rawSettings, err := buildOutboundSettings(outbounditem)
			if err != nil {
				return nil, err
			}
			if protocol == "" || rawSettings == nil {
				continue
			}
			streamSettings, err := buildOutboundStreamConfig(outbounditem)
			if err != nil {
				return nil, err
			}
			outbound := &coreConf.OutboundDetourConfig{
				Tag:           outbounditem.Name,
				Protocol:      protocol,
				Settings:      rawSettings,
				StreamSetting: streamSettings,
			}
			customOutbound, err := outbound.Build()
			if err != nil {
				return nil, fmt.Errorf("build outbound %q (%s): %w", outbounditem.Name, protocol, err)
			}
			for _, rule := range []struct {
				field  string
				values []string
			}{
				{field: "domain", values: domains},
				{field: "ip", values: ips},
				{field: "protocol", values: protocols},
			} {
				if err := appendRouteRule(coreRouterConfig, rule.field, rule.values, customOutbound.Tag); err != nil {
					return nil, err
				}
			}
			if hasOutboundWithTag(coreOutboundConfig, customOutbound.Tag) {
				continue
			}
			coreOutboundConfig = append(coreOutboundConfig, customOutbound)
		}
	}
	//build config
	DNSConfig, err := coreDnsConfig.Build()
	if err != nil {
		return nil, err
	}
	RouterConfig, err := coreRouterConfig.Build()
	if err != nil {
		return nil, err
	}
	return &BuildResult{
		DNS:       DNSConfig,
		Outbounds: coreOutboundConfig,
		Router:    RouterConfig,
	}, nil
}

func hasOutboundWithTag(list []*core.OutboundHandlerConfig, tag string) bool {
	for _, o := range list {
		if o != nil && o.Tag == tag {
			return true
		}
	}
	return false
}

const (
	// Canonical limits are shared with the backend/frontend contract.
	MaxRouteRules                     = 1024
	MaxRouteRuleBytes                 = 4096
	MaxNodeOutbounds                  = 128
	MaxOutboundAggregateRules         = 4096
	MaxOutboundAggregateBytes         = 48 * 1024
	MaxPersistedRouteJSONBytes        = 60 * 1024
	MaxGlobalBlockAggregateRules      = 3 * MaxRouteRules
	MaxGlobalBlockAggregateBytes      = 3 * MaxPersistedRouteJSONBytes
	MaxStructuredConfigAggregateRules = MaxGlobalBlockAggregateRules + MaxOutboundAggregateRules
	MaxStructuredConfigAggregateBytes = MaxGlobalBlockAggregateBytes + MaxOutboundAggregateBytes
	// Raw bounds are node-only pre-normalization DoS guards. They deliberately
	// permit duplicates above the canonical unique-value limits.
	MaxRawRouteEntriesPerCategory = 4096
	MaxRawStructuredRouteEntries  = 8192
)

var (
	geoIPLabelPattern   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]*$`)
	geoSiteLabelPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.!-]*(?:@[A-Za-z0-9_!-]+)*$`)
	domainLabelPattern  = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$`)
)

func appendRouteRule(config *coreConf.RouterConfig, field string, values []string, outboundTag string) error {
	if len(values) == 0 {
		return nil
	}
	rawRule, err := json.Marshal(map[string]interface{}{
		field:         values,
		"outboundTag": outboundTag,
	})
	if err != nil {
		return fmt.Errorf("marshal %s route rule for outbound %q: %w", field, outboundTag, err)
	}
	config.RuleList = append(config.RuleList, rawRule)
	return nil
}

type ruleNormalizer func(string) (string, error)

func normalizeRouteRules(category string, rules []string, normalize ruleNormalizer) ([]string, error) {
	if len(rules) > MaxRawRouteEntriesPerCategory {
		return nil, fmt.Errorf("%s rules contain more than %d raw entries", category, MaxRawRouteEntriesPerCategory)
	}
	capacity := len(rules)
	if capacity > MaxRouteRules {
		capacity = MaxRouteRules
	}
	result := make([]string, 0, capacity)
	seen := make(map[string]struct{}, capacity)
	for i, rawRule := range rules {
		rule := strings.TrimSpace(rawRule)
		if rule == "" {
			continue
		}
		if !utf8.ValidString(rule) {
			return nil, fmt.Errorf("%s rule %d is not valid UTF-8", category, i+1)
		}
		if strings.IndexFunc(rule, unicode.IsControl) >= 0 {
			return nil, fmt.Errorf("%s rule %d (%q) contains a control character or embedded newline", category, i+1, rawRule)
		}
		if len(rule) > MaxRouteRuleBytes {
			return nil, fmt.Errorf("%s rule %d exceeds %d raw bytes", category, i+1, MaxRouteRuleBytes)
		}

		canonical, err := normalize(rule)
		if err != nil {
			return nil, fmt.Errorf("%s rule %d (%q): %w", category, i+1, rawRule, err)
		}
		if len(canonical) > MaxRouteRuleBytes {
			return nil, fmt.Errorf("%s rule %d canonical value exceeds %d bytes", category, i+1, MaxRouteRuleBytes)
		}
		if _, ok := seen[canonical]; ok {
			continue
		}
		seen[canonical] = struct{}{}
		result = append(result, canonical)
		if len(result) > MaxRouteRules {
			return nil, fmt.Errorf("%s rules contain more than %d canonical unique values", category, MaxRouteRules)
		}
	}
	return result, nil
}

func buildDomainRules(rules []string) ([]string, error) {
	return normalizeRouteRules("domain", rules, normalizeDomainRule)
}

func normalizeDomainRule(rule string) (string, error) {
	// Detect bare IPv6 before interpreting its first colon as a rule prefix.
	if prefix, err := netip.ParsePrefix(rule); err == nil && prefix.IsValid() {
		return "", fmt.Errorf("%q is an IP prefix and belongs in an IP rule field", rule)
	}
	if address, err := netip.ParseAddr(rule); err == nil && address.IsValid() {
		return "", fmt.Errorf("%q is an IP address and belongs in an IP rule field", rule)
	}
	prefix, value, hasPrefix := strings.Cut(rule, ":")
	if !hasPrefix {
		canonical, err := normalizeDomainValue(rule, "exact domain")
		if err != nil {
			return "", err
		}
		return "full:" + canonical, nil
	}

	switch strings.ToLower(prefix) {
	case "full":
		canonical, err := normalizeDomainValue(value, "full domain")
		if err != nil {
			return "", err
		}
		return "full:" + canonical, nil
	case "keyword":
		if value == "" {
			return "", fmt.Errorf("keyword is empty")
		}
		if strings.IndexFunc(value, func(r rune) bool { return unicode.IsSpace(r) || unicode.IsControl(r) }) >= 0 {
			return "", fmt.Errorf("keyword must not contain whitespace or control characters")
		}
		return "keyword:" + value, nil
	case "suffix", "domain":
		canonical, err := normalizeDomainValue(value, "domain suffix")
		if err != nil {
			return "", err
		}
		return "domain:" + canonical, nil
	case "regex", "regexp":
		if value == "" {
			return "", fmt.Errorf("regular expression is empty")
		}
		if err := validateRE2(value); err != nil {
			return "", err
		}
		return "regexp:" + value, nil
	case "geosite":
		if len(value) > 253 || !geoSiteLabelPattern.MatchString(value) {
			return "", fmt.Errorf("unsafe geosite label %q", value)
		}
		return "geosite:" + value, nil
	default:
		return "", fmt.Errorf("unknown prefix %q", prefix)
	}
}

func normalizeDomainValue(value, kind string) (string, error) {
	original := value
	if value == "" {
		return "", fmt.Errorf("%s is empty", kind)
	}
	if strings.HasSuffix(value, ".") {
		value = strings.TrimSuffix(value, ".")
		if strings.HasSuffix(value, ".") {
			return "", fmt.Errorf("%q has repeated trailing DNS root dots", original)
		}
	}
	if value == "" {
		return "", fmt.Errorf("%s is empty after trimming the DNS root dot", kind)
	}
	if strings.EqualFold(value, "bittorrent") {
		return "", fmt.Errorf("bittorrent is a protocol and belongs in a protocol_rules/block_protocols field")
	}
	if prefix, err := netip.ParsePrefix(value); err == nil && prefix.IsValid() {
		return "", fmt.Errorf("%q is an IP prefix and belongs in an IP rule field", value)
	}
	if address, err := netip.ParseAddr(value); err == nil && address.IsValid() {
		return "", fmt.Errorf("%q is an IP address and belongs in an IP rule field", value)
	}
	if strings.Contains(value, "/") {
		return "", fmt.Errorf("%q looks like an IP prefix and belongs in an IP rule field", value)
	}
	if len(value) > 253 {
		return "", fmt.Errorf("%s exceeds 253 bytes", kind)
	}
	if strings.ContainsAny(value, " \t\r\n:#") {
		return "", fmt.Errorf("%q is not a valid %s", value, kind)
	}
	for _, label := range strings.Split(value, ".") {
		if !domainLabelPattern.MatchString(label) {
			return "", fmt.Errorf("domain label %q in %q is malformed", label, value)
		}
	}
	return value, nil
}

func validateRE2(expression string) error {
	if _, err := regexp.Compile(expression); err != nil {
		return fmt.Errorf("regular expression is not supported by RE2: %w", err)
	}
	return nil
}

func buildIPRules(rules []string) ([]string, error) {
	return normalizeRouteRules("IP", rules, normalizeIPRule)
}

func normalizeIPRule(rule string) (string, error) {
	if prefix, err := netip.ParsePrefix(rule); err == nil {
		if prefix.Addr().Zone() != "" {
			return "", fmt.Errorf("zoned IP prefixes are not supported")
		}
		return prefix.Masked().String(), nil
	}
	if address, err := netip.ParseAddr(rule); err == nil {
		if address.Zone() != "" {
			return "", fmt.Errorf("zoned IP addresses are not supported")
		}
		return address.String(), nil
	}

	prefix, value, hasPrefix := strings.Cut(rule, ":")
	if hasPrefix && strings.EqualFold(prefix, "geoip") {
		if len(value) > 253 || !geoIPLabelPattern.MatchString(value) {
			return "", fmt.Errorf("unsafe geoip label %q", value)
		}
		return "geoip:" + value, nil
	}
	if strings.Contains(rule, "/") {
		return "", fmt.Errorf("%q is not a valid CIDR prefix", rule)
	}
	if hasPrefix {
		return "", fmt.Errorf("unknown IP rule prefix %q", prefix)
	}
	return "", fmt.Errorf("%q is not a valid IP address or CIDR prefix", rule)
}

func buildProtocolRules(rules []string) ([]string, error) {
	return normalizeRouteRules("protocol", rules, normalizeProtocolRule)
}

func normalizeProtocolRule(rule string) (string, error) {
	canonical := strings.ToLower(rule)
	if canonical != "bittorrent" {
		return "", fmt.Errorf("unsupported protocol %q (allowed: bittorrent)", rule)
	}
	return canonical, nil
}

type routeRuleBudget struct {
	scope              string
	count, bytes       int
	maxRules, maxBytes int
}

func (b *routeRuleBudget) add(field string, canonical []string) error {
	for _, rule := range canonical {
		b.count++
		b.bytes += len(rule)
		if b.count > b.maxRules {
			return fmt.Errorf("%s route rules exceed %d canonical values at %s", b.scope, b.maxRules, field)
		}
		if b.bytes > b.maxBytes {
			return fmt.Errorf("%s route rules exceed %d canonical payload bytes at %s", b.scope, b.maxBytes, field)
		}
	}
	return nil
}

func validateRouteConfigRawLimits(data *panel.Data) error {
	if data == nil {
		return fmt.Errorf("server configuration data is empty")
	}
	if data.Outbound != nil && len(*data.Outbound) > MaxNodeOutbounds {
		return fmt.Errorf("structured configuration contains more than %d outbounds", MaxNodeOutbounds)
	}
	rawStructured := 0
	check := func(field string, rules []string, structured bool) error {
		if len(rules) > MaxRawRouteEntriesPerCategory {
			return fmt.Errorf("%s contains more than %d raw entries", field, MaxRawRouteEntriesPerCategory)
		}
		if structured {
			rawStructured += len(rules)
			if rawStructured > MaxRawStructuredRouteEntries {
				return fmt.Errorf("structured route configuration contains more than %d raw entries at %s", MaxRawStructuredRouteEntries, field)
			}
		}
		return nil
	}
	// DNS uses the shared domain parser but is intentionally excluded from the
	// structured block/outbound aggregate contract.
	if data.DNS != nil {
		for i, resolver := range *data.DNS {
			if err := check(fmt.Sprintf("dns[%d].domains", i), resolver.Domains, false); err != nil {
				return err
			}
		}
	}
	for _, group := range []struct {
		field string
		rules *[]string
	}{
		{field: "block", rules: data.Block},
		{field: "block_ips", rules: data.BlockIPs},
		{field: "block_protocols", rules: data.BlockProtocols},
	} {
		if group.rules != nil {
			if err := check(group.field, *group.rules, true); err != nil {
				return err
			}
		}
	}
	if data.Outbound != nil {
		for i, outbound := range *data.Outbound {
			for _, group := range []struct {
				field string
				rules []string
			}{
				{field: "rules", rules: outbound.Rules},
				{field: "ip_rules", rules: outbound.IPRules},
				{field: "protocol_rules", rules: outbound.ProtocolRules},
			} {
				if err := check(fmt.Sprintf("outbound[%d].%s", i, group.field), group.rules, true); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func normalizeOutboundProtocol(protocol string) string {
	switch strings.ToLower(strings.TrimSpace(protocol)) {
	case "direct":
		return "freedom"
	case "reject", "block":
		return "blackhole"
	case "hysteria2":
		return "hysteria"
	default:
		return strings.ToLower(strings.TrimSpace(protocol))
	}
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" {
			return value
		}
	}
	return ""
}

func rawJSONMessage(value string, field string) (*json.RawMessage, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil, nil
	}
	if !json.Valid([]byte(value)) {
		return nil, fmt.Errorf("invalid outbound %s json", field)
	}
	raw := json.RawMessage(value)
	return &raw, nil
}

func buildOutboundSettings(item panel.Outbound) (string, *json.RawMessage, error) {
	protocol := normalizeOutboundProtocol(item.Protocol)
	if raw, err := rawJSONMessage(item.Settings, "settings"); err != nil || raw != nil {
		return protocol, raw, err
	}

	settings := map[string]interface{}{}
	switch protocol {
	case "freedom", "blackhole":
	case "http", "socks":
		settings["address"] = strings.TrimSpace(item.Address)
		settings["port"] = item.Port
		if strings.TrimSpace(item.User) != "" {
			settings["user"] = strings.TrimSpace(item.User)
			settings["pass"] = item.Password
		}
	case "shadowsocks":
		settings["address"] = strings.TrimSpace(item.Address)
		settings["port"] = item.Port
		settings["method"] = firstNonEmpty(item.Cipher, "chacha20-ietf-poly1305")
		settings["password"] = item.Password
		settings["uot"] = true
		if item.UoT {
			settings["uot"] = item.UoT
		}
		uotVersion := item.UoTVersion
		if uotVersion == 0 {
			uotVersion = 2
		}
		settings["uotVersion"] = uotVersion
	case "trojan":
		settings["address"] = strings.TrimSpace(item.Address)
		settings["port"] = item.Port
		settings["password"] = item.Password
	case "vmess":
		settings["address"] = strings.TrimSpace(item.Address)
		settings["port"] = item.Port
		settings["id"] = firstNonEmpty(item.UUID, item.Password)
		settings["security"] = firstNonEmpty(item.Cipher, "auto")
	case "vless":
		settings["address"] = strings.TrimSpace(item.Address)
		settings["port"] = item.Port
		settings["id"] = firstNonEmpty(item.UUID, item.Password)
		settings["encryption"] = "none"
		if flow := strings.TrimSpace(item.Flow); flow != "" && flow != "none" {
			settings["flow"] = flow
		}
	case "anytls":
		settings["address"] = strings.TrimSpace(item.Address)
		settings["port"] = item.Port
		settings["password"] = item.Password
	case "tuic":
		settings["address"] = strings.TrimSpace(item.Address)
		settings["port"] = item.Port
		settings["id"] = firstNonEmpty(item.UUID, item.Password)
		settings["password"] = item.Password
		if congestion := strings.TrimSpace(item.CongestionController); congestion != "" {
			settings["congestionControl"] = congestion
		}
		settings["udpStream"] = item.UDPStream
		settings["zeroRttHandshake"] = item.ReduceRTT
		if item.Heartbeat > 0 {
			settings["heartbeat"] = item.Heartbeat
		}
	case "hysteria":
		settings["version"] = 2
		settings["address"] = strings.TrimSpace(item.Address)
		settings["port"] = item.Port
	case "wireguard":
		return "", nil, nil
	default:
		return "", nil, nil
	}

	data, err := json.Marshal(settings)
	if err != nil {
		return "", nil, err
	}
	raw := json.RawMessage(data)
	return protocol, &raw, nil
}

func buildOutboundStreamConfig(item panel.Outbound) (*coreConf.StreamConfig, error) {
	if raw := strings.TrimSpace(item.StreamSettings); raw != "" {
		var stream coreConf.StreamConfig
		if err := json.Unmarshal([]byte(raw), &stream); err != nil {
			return nil, fmt.Errorf("invalid outbound stream_settings json: %w", err)
		}
		return &stream, nil
	}

	protocol := normalizeOutboundProtocol(item.Protocol)
	transport := strings.ToLower(strings.TrimSpace(item.Transport))
	if transport == "" {
		switch protocol {
		case "vmess", "vless", "trojan", "anytls":
			transport = "tcp"
		case "tuic":
			transport = "tuic"
		case "hysteria":
			transport = "hysteria"
		}
	}
	security := strings.ToLower(strings.TrimSpace(item.Security))
	hasStreamField := transport != "" ||
		security != "" ||
		strings.TrimSpace(item.SNI) != "" ||
		strings.TrimSpace(item.Fingerprint) != "" ||
		strings.TrimSpace(item.Host) != "" ||
		strings.TrimSpace(item.Path) != "" ||
		strings.TrimSpace(item.ServiceName) != "" ||
		strings.TrimSpace(item.RealityPublicKey) != "" ||
		strings.TrimSpace(item.RealityShortID) != ""
	if !hasStreamField {
		return nil, nil
	}

	stream := &coreConf.StreamConfig{Security: security}
	if transport != "" {
		t := coreConf.TransportProtocol(transport)
		stream.Network = &t
	}
	switch security {
	case "", "none":
	case "tls":
		stream.TLSSettings = &coreConf.TLSConfig{
			ServerName:    strings.TrimSpace(item.SNI),
			AllowInsecure: item.AllowInsecure,
			Fingerprint:   firstNonEmpty(item.Fingerprint, "chrome"),
		}
	case "reality":
		stream.REALITYSettings = &coreConf.REALITYConfig{
			ServerName:  strings.TrimSpace(item.SNI),
			PublicKey:   strings.TrimSpace(item.RealityPublicKey),
			ShortId:     strings.TrimSpace(item.RealityShortID),
			Fingerprint: firstNonEmpty(item.Fingerprint, "chrome"),
			SpiderX:     firstNonEmpty(item.SpiderX, "/"),
		}
	default:
		return nil, fmt.Errorf("unsupported outbound security %q", item.Security)
	}

	switch transport {
	case "", "tcp", "raw":
		if transport != "" {
			stream.TCPSettings = &coreConf.TCPConfig{}
		}
	case "ws", "websocket":
		stream.WSSettings = &coreConf.WebSocketConfig{
			Host: strings.TrimSpace(item.Host),
			Path: strings.TrimSpace(item.Path),
		}
	case "grpc":
		stream.GRPCSettings = &coreConf.GRPCConfig{
			Authority:   strings.TrimSpace(item.Host),
			ServiceName: strings.TrimSpace(item.ServiceName),
		}
	case "httpupgrade":
		stream.HTTPUPGRADESettings = &coreConf.HttpUpgradeConfig{
			Host: strings.TrimSpace(item.Host),
			Path: strings.TrimSpace(item.Path),
		}
	case "splithttp", "xhttp":
		stream.SplitHTTPSettings = &coreConf.SplitHTTPConfig{
			Host: strings.TrimSpace(item.Host),
			Path: strings.TrimSpace(item.Path),
		}
	case "hysteria":
		stream.HysteriaSettings = &coreConf.HysteriaConfig{Version: 2, Auth: firstNonEmpty(item.Password, item.UUID)}
	case "tuic":
	default:
		return nil, fmt.Errorf("unsupported outbound transport %q", item.Transport)
	}

	return stream, nil
}

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
	if serverconfig == nil || serverconfig.Data == nil {
		return nil, fmt.Errorf("server configuration data is empty")
	}
	return buildOrdered(serverconfig, hasIPv6)
}

// buildBase builds only DNS, the built-in connections and the UDP/53 rule.
func buildBase(serverconfig *panel.ServerConfigResponse, hasIPv6 bool) (*BuildResult, error) {
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
			server, err := buildDNSResolver(item, ipStrategy)
			if err != nil {
				return nil, fmt.Errorf("DNS resolver %d: %w", i+1, err)
			}
			coreDnsConfig.Servers = append(coreDnsConfig.Servers, server)
		}
	}

	// Built-in outbounds retain the existing Freedom safety settings.
	defaultoutbound, err := buildDefaultOutbound()
	if err != nil {
		return nil, fmt.Errorf("build direct: %w", err)
	}
	block, err := buildBlockOutbound()
	if err != nil {
		return nil, fmt.Errorf("build block: %w", err)
	}
	dns, err := buildDnsOutbound()
	if err != nil {
		return nil, fmt.Errorf("build DNS outbound: %w", err)
	}
	coreOutboundConfig := []*core.OutboundHandlerConfig{defaultoutbound, block, dns}

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

const (
	MaxRouteRules                 = 1024
	MaxRouteRuleBytes             = 4096
	MaxNodeOutbounds              = 128
	MaxRawRouteEntriesPerCategory = 4096
)

var (
	geoIPLabelPattern   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]*$`)
	geoSiteLabelPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.!-]*(?:@[A-Za-z0-9_!-]+)*$`)
	domainLabelPattern  = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$`)
)

func appendRouteRule(config *coreConf.RouterConfig, field string, values []string, outboundTag, ruleID string) error {
	if len(values) == 0 {
		return nil
	}
	rawRule, err := json.Marshal(map[string]interface{}{
		field:         values,
		"outboundTag": outboundTag,
		"ruleTag":     ruleID,
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
	default:
		return nil, fmt.Errorf("unsupported outbound transport %q", item.Transport)
	}

	return stream, nil
}

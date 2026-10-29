package outbound

import (
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/perfect-panel/ppanel-node/api/panel"
	xnet "github.com/xtls/xray-core/common/net"
	coreConf "github.com/xtls/xray-core/infra/conf"
)

const defaultDNSPort = 53
const maxDNSAddressBytes = 260 // 253-byte hostname + root dot + ':' + 5-digit port

type udpDNSResolver struct {
	protocol string
	host     string
	port     uint16
	domains  []string
}

// parseDNSResolver validates the node wire before passing any address into
// Xray. An empty protocol has the canonical meaning "udp"; it never implies
// TLS, TCP, HTTPS, QUIC, or Xray's special local/fake resolver modes.
func parseDNSResolver(item panel.DNSItem) (udpDNSResolver, error) {
	if len(item.Proto) > 64 {
		return udpDNSResolver{}, fmt.Errorf("unsupported DNS protocol (only udp is supported)")
	}
	protocol := strings.ToLower(strings.TrimSpace(item.Proto))
	if protocol != "" && protocol != "udp" {
		return udpDNSResolver{}, fmt.Errorf("unsupported DNS protocol (only udp is supported)")
	}
	if item.ServerName != "" {
		return udpDNSResolver{}, fmt.Errorf("DNS server_name must be empty for udp")
	}
	host, port, err := parseDNSAddress(item.Address)
	if err != nil {
		return udpDNSResolver{}, err
	}
	domains, err := buildDomainRules(item.Domains)
	if err != nil {
		return udpDNSResolver{}, fmt.Errorf("invalid DNS domain rules: %w", err)
	}
	return udpDNSResolver{protocol: "udp", host: host, port: port, domains: domains}, nil
}

func parseDNSAddress(value string) (string, uint16, error) {
	if value == "" || len(value) > maxDNSAddressBytes || !utf8.ValidString(value) || value != strings.TrimSpace(value) || strings.ContainsAny(value, "@/?#\\%") {
		return "", 0, fmt.Errorf("invalid UDP DNS address")
	}
	port := uint16(defaultDNSPort)
	host := value
	if strings.HasPrefix(value, "[") {
		end := strings.IndexByte(value, ']')
		if end < 0 || strings.ContainsAny(value[1:end], "[]") {
			return "", 0, fmt.Errorf("invalid bracketed IPv6 DNS address")
		}
		host = value[1:end]
		ip, err := netip.ParseAddr(host)
		if err != nil || !ip.Is6() || ip.Zone() != "" {
			return "", 0, fmt.Errorf("invalid bracketed IPv6 DNS address")
		}
		tail := value[end+1:]
		if tail != "" {
			if !strings.HasPrefix(tail, ":") {
				return "", 0, fmt.Errorf("invalid IPv6 DNS port")
			}
			port, err = parseDNSPort(tail[1:])
			if err != nil {
				return "", 0, err
			}
		}
		return ip.String(), port, nil
	}
	if strings.ContainsAny(value, "[]") {
		return "", 0, fmt.Errorf("invalid DNS address brackets")
	}
	// An unbracketed valid IPv6 literal is always a host without a port.
	if ip, err := netip.ParseAddr(value); err == nil {
		if ip.Zone() != "" {
			return "", 0, fmt.Errorf("scoped DNS addresses are unsupported")
		}
		return ip.String(), port, nil
	}
	switch strings.Count(value, ":") {
	case 0:
	case 1:
		var rawPort string
		host, rawPort, _ = strings.Cut(value, ":")
		var err error
		port, err = parseDNSPort(rawPort)
		if err != nil {
			return "", 0, err
		}
	default:
		return "", 0, fmt.Errorf("invalid IPv6 DNS address (ports require brackets)")
	}
	if ip, err := netip.ParseAddr(host); err == nil {
		if ip.Zone() != "" {
			return "", 0, fmt.Errorf("scoped DNS addresses are unsupported")
		}
		return ip.String(), port, nil
	}
	canonical, err := validateDNSHostname(host)
	if err != nil {
		return "", 0, err
	}
	return canonical, port, nil
}

func parseDNSPort(value string) (uint16, error) {
	if value == "" {
		return 0, fmt.Errorf("DNS port is required after colon")
	}
	for _, r := range value {
		if r < '0' || r > '9' {
			return 0, fmt.Errorf("invalid DNS port")
		}
	}
	v, err := strconv.ParseUint(value, 10, 16)
	if err != nil || v == 0 {
		return 0, fmt.Errorf("DNS port must be 1..65535")
	}
	return uint16(v), nil
}

func validateDNSHostname(host string) (string, error) {
	if host == "" || strings.HasSuffix(host, "..") {
		return "", fmt.Errorf("invalid DNS hostname")
	}
	base := strings.TrimSuffix(host, ".")
	if len(base) == 0 || len(base) > 253 {
		return "", fmt.Errorf("invalid DNS hostname length")
	}
	// A four-component numeric value that looks like IPv4 must not be
	// reinterpreted as a hostname when malformed (e.g. 1.2.3.999).
	numericIPv4 := len(strings.Split(base, ".")) == 4
	if numericIPv4 {
		for _, r := range base {
			if r != '.' && (r < '0' || r > '9') {
				numericIPv4 = false
				break
			}
		}
		if numericIPv4 {
			if _, err := netip.ParseAddr(base); err != nil {
				return "", fmt.Errorf("invalid numeric DNS address")
			}
		}
	}
	for _, label := range strings.Split(base, ".") {
		if !domainLabelPattern.MatchString(label) {
			return "", fmt.Errorf("invalid DNS hostname label")
		}
	}
	canonical := strings.ToLower(host)
	// Xray treats these bare names as local/fake DNS instead of UDP. Their
	// absolute-DNS spelling is semantically equivalent as a hostname, but is
	// not interpreted as an Xray transport selector.
	if strings.EqualFold(canonical, "localhost") || strings.EqualFold(canonical, "fakedns") {
		canonical += "."
	}
	return canonical, nil
}

func buildDNSResolver(item panel.DNSItem, ipStrategy string) (*coreConf.NameServerConfig, error) {
	resolver, err := parseDNSResolver(item)
	if err != nil {
		return nil, err
	}
	return &coreConf.NameServerConfig{
		Address: &coreConf.Address{Address: xnet.ParseAddress(resolver.host)},
		Port:    resolver.port, QueryStrategy: ipStrategy, Domains: resolver.domains,
	}, nil
}

// ValidateDNS checks every resolver before a candidate can be applied, even
// when no listener protocols are enabled.
func ValidateDNS(data *panel.Data) error {
	if data == nil {
		return fmt.Errorf("server configuration data is empty")
	}
	if data.DNS == nil {
		return nil
	}
	for i, item := range *data.DNS {
		if _, err := parseDNSResolver(item); err != nil {
			return fmt.Errorf("DNS resolver %d: %w", i+1, err)
		}
	}
	return nil
}

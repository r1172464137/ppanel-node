package outbound

import (
	"encoding/json"
	"fmt"
	"reflect"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/perfect-panel/ppanel-node/api/panel"
	"github.com/xtls/xray-core/core"
	coreConf "github.com/xtls/xray-core/infra/conf"
)

const (
	MaxOrderedRules      = 512
	MaxOrderedValues     = 8192
	MaxOrderedMatchBytes = 256 * 1024
	MaxOrderedJSONBytes  = 1024 * 1024
)

var orderedUUID = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

func orderedID(id, prefix string) bool {
	return strings.HasPrefix(id, prefix) && orderedUUID.MatchString(strings.TrimPrefix(id, prefix))
}

func validText(s string, max int, empty bool) bool {
	return utf8.ValidString(s) && (empty || s != "") && utf8.RuneCountInString(s) <= max && strings.IndexFunc(s, unicode.IsControl) < 0
}

// ValidateOrdered checks even disabled rules and bounds raw input before
// normalizing or compiling. It never turns an invalid v1 policy into legacy.
func ValidateOrdered(data *panel.Data) error {
	if data == nil {
		return fmt.Errorf("server configuration data is empty")
	}
	p := data.Routing
	if p == nil {
		return fmt.Errorf("routing policy is null or missing")
	}
	if p.Version != 1 {
		return fmt.Errorf("unsupported routing version %d", p.Version)
	}
	if data.LegacyRoutingPresent || sliceLen(data.Block) != 0 || sliceLen(data.BlockIPs) != 0 || sliceLen(data.BlockProtocols) != 0 || outboundLen(data.Outbound) != 0 {
		return fmt.Errorf("ordered routing mixed with legacy routing")
	}
	if p.SourceRevision <= 0 || p.LocalTransitionRevision < 0 {
		return fmt.Errorf("invalid routing revision")
	}
	switch p.Mode {
	case "ordered-v1-local":
		if p.Source != "server" || p.SourceServerID <= 0 || p.SourceRevision != p.LocalTransitionRevision {
			return fmt.Errorf("invalid local routing identity")
		}
	case "ordered-v1-inherited":
		if p.Source != "global" || p.SourceServerID != 0 {
			return fmt.Errorf("invalid inherited routing identity")
		}
	default:
		return fmt.Errorf("unknown routing mode %q", p.Mode)
	}
	if p.Outbounds == nil || p.Rules == nil {
		return fmt.Errorf("routing outbounds and rules must be arrays")
	}
	if len(p.Outbounds) > MaxNodeOutbounds || len(p.Rules) > MaxOrderedRules {
		return fmt.Errorf("routing contains too many outbounds or rules")
	}
	rawCount := 0
	for i, r := range p.Rules {
		if len(r.Values) > MaxRouteRules {
			return fmt.Errorf("routing rule %d exceeds raw per-rule limit", i+1)
		}
		rawCount += len(r.Values)
		if rawCount > MaxOrderedValues {
			return fmt.Errorf("routing exceeds raw value limit")
		}
	}
	// Identity is not part of the persisted package's byte budget.
	copyOutbounds := append([]panel.Outbound{}, p.Outbounds...)
	for i := range copyOutbounds {
		// Proto repeated fields have no empty-list presence; use the backend's
		// canonical empty arrays when calculating the serialized budget.
		if copyOutbounds[i].Rules == nil {
			copyOutbounds[i].Rules = []string{}
		}
		if copyOutbounds[i].IPRules == nil {
			copyOutbounds[i].IPRules = []string{}
		}
		if copyOutbounds[i].ProtocolRules == nil {
			copyOutbounds[i].ProtocolRules = []string{}
		}
	}
	content := struct {
		Version   int               `json:"version"`
		Outbounds []panel.Outbound  `json:"outbounds"`
		Rules     []panel.RouteRule `json:"rules"`
		Default   string            `json:"default_outbound_id"`
	}{p.Version, copyOutbounds, p.Rules, p.DefaultOutboundID}
	encoded, err := json.Marshal(content)
	if err != nil || len(encoded) > MaxOrderedJSONBytes {
		return fmt.Errorf("routing package cannot be encoded or exceeds 1 MiB")
	}
	ids := map[string]bool{"direct": true, "block": true}
	names := map[string]bool{}
	for i, ob := range p.Outbounds {
		v := reflect.ValueOf(ob)
		for j := 0; j < v.NumField(); j++ {
			f := v.Field(j)
			if f.Kind() == reflect.String && !utf8.ValidString(f.String()) {
				return fmt.Errorf("routing outbound %d has invalid UTF-8", i+1)
			}
			if f.Kind() == reflect.Slice && f.Type().Elem().Kind() == reflect.String {
				for k := 0; k < f.Len(); k++ {
					if !utf8.ValidString(f.Index(k).String()) {
						return fmt.Errorf("routing outbound %d has invalid UTF-8", i+1)
					}
				}
			}
		}
		if !orderedID(ob.ID, "ob_") || ids[ob.ID] {
			return fmt.Errorf("routing outbound %d invalid or duplicate ID", i+1)
		}
		ids[ob.ID] = true
		name := strings.TrimSpace(ob.Name)
		if !validText(name, 200, false) || names[name] {
			return fmt.Errorf("routing outbound %d invalid or duplicate name", i+1)
		}
		names[name] = true
		copyOutbounds[i].Name = name
		copyOutbounds[i].Protocol = strings.TrimSpace(ob.Protocol)
		if !validText(strings.TrimSpace(ob.Protocol), 200, false) {
			return fmt.Errorf("routing outbound %d invalid protocol", i+1)
		}
		if len(ob.Rules)+len(ob.IPRules)+len(ob.ProtocolRules) != 0 {
			return fmt.Errorf("routing outbound %d contains legacy rules", i+1)
		}
		for _, raw := range []string{ob.Settings, ob.StreamSettings} {
			if strings.TrimSpace(raw) != "" {
				var obj map[string]json.RawMessage
				if !utf8.ValidString(raw) || panel.ValidateUniqueJSON([]byte(raw)) != nil || json.Unmarshal([]byte(raw), &obj) != nil || obj == nil {
					return fmt.Errorf("routing outbound %d raw settings must be a JSON object", i+1)
				}
			}
		}
		if err := validateOutboundCapability(ob); err != nil {
			return fmt.Errorf("routing outbound %d: %w", i+1, err)
		}
	}
	if !ids[p.DefaultOutboundID] {
		return fmt.Errorf("unknown default outbound %q", p.DefaultOutboundID)
	}
	seen := map[string]bool{}
	budget := routeRuleBudget{scope: "ordered", maxRules: MaxOrderedValues, maxBytes: MaxOrderedMatchBytes}
	canonicalRules := make([]panel.RouteRule, len(p.Rules))
	for i, r := range p.Rules {
		if !orderedID(r.ID, "rr_") || seen[r.ID] {
			return fmt.Errorf("routing rule %d invalid or duplicate ID", i+1)
		}
		seen[r.ID] = true
		if r.Enabled == nil {
			return fmt.Errorf("routing rule %d enabled is missing", i+1)
		}
		if !validText(r.Remark, 200, true) {
			return fmt.Errorf("routing rule %d invalid remark", i+1)
		}
		if !ids[r.OutboundID] {
			return fmt.Errorf("routing rule %d unknown outbound %q", i+1, r.OutboundID)
		}
		values, err := orderedValues(r)
		if err != nil {
			return fmt.Errorf("routing rule %d: %w", i+1, err)
		}
		if len(values) == 0 {
			return fmt.Errorf("routing rule %d has no matching values", i+1)
		}
		if err := budget.add(fmt.Sprintf("rule %d", i+1), values); err != nil {
			return err
		}
		canonicalRules[i] = r
		canonicalRules[i].Values = values
	}
	content.Rules = canonicalRules
	encoded, err = json.Marshal(content)
	if err != nil || len(encoded) > MaxOrderedJSONBytes {
		return fmt.Errorf("canonical routing package cannot be encoded or exceeds 1 MiB")
	}
	return nil
}

func sliceLen(v *[]string) int {
	if v == nil {
		return 0
	}
	return len(*v)
}
func outboundLen(v *[]panel.Outbound) int {
	if v == nil {
		return 0
	}
	return len(*v)
}

func orderedValues(r panel.RouteRule) ([]string, error) {
	switch r.Kind {
	case "domain":
		return buildDomainRules(r.Values)
	case "ip":
		return buildIPRules(r.Values)
	case "protocol":
		return buildProtocolRules(r.Values)
	default:
		return nil, fmt.Errorf("unknown route kind %q", r.Kind)
	}
}

func buildOrdered(config *panel.ServerConfigResponse, hasIPv6 bool) (*BuildResult, error) {
	if err := ValidateOrdered(config.Data); err != nil {
		return nil, err
	}
	p := config.Data.Routing
	// Only shared DNS and built-in system routes are built before v1 rules.
	base, err := buildBase(config, hasIPv6)
	if err != nil {
		return nil, err
	}
	tags := map[string]string{"direct": DefaultTag, "block": BlockTag}
	connections := map[string]*core.OutboundHandlerConfig{"direct": base.Outbounds[0], "block": base.Outbounds[1]}
	for _, item := range p.Outbounds {
		// Do not silently ignore settings that this node cannot consume.
		if strings.TrimSpace(item.Multiplex) != "" && item.Multiplex != "none" {
			return nil, fmt.Errorf("outbound %q uses unsupported multiplex", item.ID)
		}
		if strings.TrimSpace(item.Settings) == "" && ((item.Encryption != "" && item.Encryption != "none") || item.EncryptionMode != "" || item.EncryptionRTT != "" || item.EncryptionTicket != "" || item.EncryptionClientPadding != "" || item.EncryptionPassword != "") {
			return nil, fmt.Errorf("outbound %q uses unsupported encryption without raw settings", item.ID)
		}
		// Explicit raw settings take precedence over projected connection fields.
		protocol, settings, err := buildOutboundSettings(item)
		if err != nil {
			return nil, fmt.Errorf("outbound %q: %w", item.ID, err)
		}
		if protocol == "" || settings == nil {
			return nil, fmt.Errorf("outbound %q uses unsupported protocol %q", item.ID, item.Protocol)
		}
		stream, err := buildOutboundStreamConfig(item)
		if err != nil {
			return nil, fmt.Errorf("outbound %q: %w", item.ID, err)
		}
		if strings.TrimSpace(item.StreamSettings) == "" {
			if len(item.ALPN) != 0 {
				if stream == nil || stream.TLSSettings == nil {
					return nil, fmt.Errorf("outbound %q ALPN requires TLS", item.ID)
				}
				alpn := coreConf.StringList(append([]string(nil), item.ALPN...))
				stream.TLSSettings.ALPN = &alpn
			}
			if item.XHTTPMode != "" || item.XHTTPExtra != "" {
				if stream == nil || stream.SplitHTTPSettings == nil {
					return nil, fmt.Errorf("outbound %q XHTTP options require XHTTP transport", item.ID)
				}
				stream.SplitHTTPSettings.Mode = item.XHTTPMode
				if item.XHTTPExtra != "" {
					var extra map[string]json.RawMessage
					if panel.ValidateUniqueJSON([]byte(item.XHTTPExtra)) != nil || json.Unmarshal([]byte(item.XHTTPExtra), &extra) != nil || extra == nil {
						return nil, fmt.Errorf("outbound %q XHTTP extra must be a JSON object", item.ID)
					}
					stream.SplitHTTPSettings.Extra = json.RawMessage(item.XHTTPExtra)
				}
			}
		}
		tag := "routing_" + item.ID
		built, err := (&coreConf.OutboundDetourConfig{Tag: tag, Protocol: protocol, Settings: settings, StreamSetting: stream}).Build()
		if err != nil {
			return nil, fmt.Errorf("build outbound %q: %w", item.ID, err)
		}
		tags[item.ID], connections[item.ID] = tag, built
	}
	// Xray uses the first outbound as the fallback. DNS is never a selectable
	// default and the stable custom ID namespace cannot collide with it.
	result := []*core.OutboundHandlerConfig{connections[p.DefaultOutboundID]}
	for _, id := range []string{"direct", "block"} {
		if id != p.DefaultOutboundID {
			result = append(result, connections[id])
		}
	}
	for _, item := range p.Outbounds {
		if item.ID != p.DefaultOutboundID {
			result = append(result, connections[item.ID])
		}
	}
	result = append(result, base.Outbounds[2])
	base.Outbounds = result
	routes := &coreConf.RouterConfig{}
	for _, rule := range p.Rules {
		values, err := orderedValues(rule)
		if err != nil {
			return nil, err
		} // already validated, including disabled
		if *rule.Enabled {
			if err := appendRouteRule(routes, rule.Kind, values, tags[rule.OutboundID], rule.ID); err != nil {
				return nil, err
			}
		}
	}
	compiled, err := routes.Build()
	if err != nil {
		return nil, fmt.Errorf("build ordered router: %w", err)
	}
	base.Router.Rule = append(base.Router.Rule, compiled.Rule...)
	return base, nil
}

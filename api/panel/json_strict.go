package panel

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"reflect"
	"strings"
	"unicode"
)

// Duplicate keys are ambiguous even when encoding/json would silently choose
// the last one. Check every object before decoding any routing content.
func scanJSONValue(d *json.Decoder, depth int, foldKeys bool) error {
	if depth > 100 {
		return fmt.Errorf("JSON nesting limit exceeded")
	}
	token, err := d.Token()
	if err != nil {
		return err
	}
	delim, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delim {
	case '{':
		seen := map[string]bool{}
		for d.More() {
			keyToken, err := d.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok {
				return fmt.Errorf("invalid object key")
			}
			canonical := key
			if foldKeys {
				canonical = foldJSONKey(key)
			}
			if seen[canonical] {
				return fmt.Errorf("duplicate or case-folded JSON key %q", key)
			}
			seen[canonical] = true
			if err := scanJSONValue(d, depth+1, foldKeys); err != nil {
				return err
			}
		}
		_, err = d.Token()
		return err
	case '[':
		for d.More() {
			if err := scanJSONValue(d, depth+1, foldKeys); err != nil {
				return err
			}
		}
		_, err = d.Token()
		return err
	default:
		return fmt.Errorf("invalid JSON delimiter")
	}
}

// foldJSONKey matches encoding/json's Unicode simple-fold field matching.
func foldJSONKey(key string) string {
	var b strings.Builder
	for _, r := range key {
		for {
			next := unicode.SimpleFold(r)
			if next <= r {
				r = next
				break
			}
			r = next
		}
		b.WriteRune(r)
	}
	return b.String()
}

// Xray decodes raw settings into structs with case-insensitive field matching.
func ValidateUniqueJSON(data []byte) error { return validateJSONKeys(data, true) }
func checkDuplicateJSON(data []byte) error { return validateJSONKeys(data, false) }

func validateJSONKeys(data []byte, foldKeys bool) error {
	d := json.NewDecoder(bytes.NewReader(data))
	d.UseNumber()
	if err := scanJSONValue(d, 0, foldKeys); err != nil {
		return err
	}
	if _, err := d.Token(); err != io.EOF {
		return fmt.Errorf("trailing JSON data")
	}
	return nil
}
func exactObject(data []byte, allowed map[string]bool) (map[string]json.RawMessage, error) {
	if len(bytes.TrimSpace(data)) == 0 || bytes.TrimSpace(data)[0] != '{' {
		return nil, fmt.Errorf("expected JSON object")
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return nil, err
	}
	for key := range fields {
		if !allowed[key] {
			return nil, fmt.Errorf("unknown JSON field %q", key)
		}
	}
	return fields, nil
}
func names(values ...string) map[string]bool {
	m := make(map[string]bool, len(values))
	for _, v := range values {
		m[v] = true
	}
	return m
}
func typeJSONNames(t reflect.Type) map[string]bool {
	m := map[string]bool{}
	for i := 0; i < t.NumField(); i++ {
		tag := strings.Split(t.Field(i).Tag.Get("json"), ",")[0]
		if tag != "" && tag != "-" {
			m[tag] = true
		}
	}
	return m
}

var dataJSONNames = names("traffic_report_threshold", "push_interval", "pull_interval", "ip_strategy", "dns", "block", "block_ips", "block_protocols", "outbound", "protocols", "total", "routing")
var policyJSONNames = names("version", "outbounds", "rules", "default_outbound_id", "mode", "source", "source_server_id", "source_revision", "local_transition_revision")
var outboundJSONNames = typeJSONNames(reflect.TypeOf(Outbound{}))
var ruleJSONNames = typeJSONNames(reflect.TypeOf(RouteRule{}))
var dnsJSONNames = typeJSONNames(reflect.TypeOf(DNSItem{}))
var protocolJSONNames = func() map[string]bool {
	m := typeJSONNames(reflect.TypeOf(Protocol{}))
	// Existing panel protocol fields that the current inbound builder does not
	// consume remain valid on the wire, but their exact names are enforced.
	for _, key := range []string{"version", "mode", "network", "alpn", "heartbeat", "quic_congestion_control", "traffic_pattern", "user_hint_is_mandatory", "ssr_protocol", "protocol_param", "obfs_param"} {
		m[key] = true
	}
	return m
}()

func validateArrayObjects(raw []byte, allowed map[string]bool, field string) error {
	if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return nil
	}
	var items []json.RawMessage
	if err := json.Unmarshal(raw, &items); err != nil {
		return fmt.Errorf("%s: %w", field, err)
	}
	for i, item := range items {
		if _, err := exactObject(item, allowed); err != nil {
			return fmt.Errorf("%s[%d]: %w", field, i, err)
		}
	}
	return nil
}

func validatePolicyJSON(raw []byte) error {
	fields, err := exactObject(raw, policyJSONNames)
	if err != nil {
		return err
	}
	for _, entry := range []struct {
		name    string
		allowed map[string]bool
	}{{"outbounds", outboundJSONNames}, {"rules", ruleJSONNames}} {
		data, ok := fields[entry.name]
		if !ok || bytes.Equal(bytes.TrimSpace(data), []byte("null")) {
			continue
		}
		if err := validateArrayObjects(data, entry.allowed, "routing "+entry.name); err != nil {
			return err
		}
	}
	return nil
}

func (r *ServerConfigResponse) UnmarshalJSON(data []byte) error {
	if err := checkDuplicateJSON(data); err != nil {
		return err
	}
	if _, err := exactObject(data, names("code", "msg", "data")); err != nil {
		return err
	}
	type alias ServerConfigResponse
	var v alias
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if err := decoder.Decode(&v); err != nil {
		return err
	}
	*r = ServerConfigResponse(v)
	return nil
}

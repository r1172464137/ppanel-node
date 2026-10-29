package streamguard

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/perfect-panel/ppanel-node/api/panel"
	coreConf "github.com/xtls/xray-core/infra/conf"
)

// The pinned Xray REALITY builder ignores url.Parse errors before
// dereferencing the result. Validate every URI before invoking Xray builders.
func ValidateURI(field, value string, spider bool) error {
	if value == "" {
		return nil
	}
	if spider && len(value) > MaxSpiderURIBytes {
		return fmt.Errorf("%s URI exceeds size limit", field)
	}
	if value != strings.TrimSpace(value) {
		return fmt.Errorf("invalid %s URI", field)
	}
	u, err := url.Parse(value)
	if err != nil || u == nil {
		return fmt.Errorf("invalid %s URI", field)
	}
	query, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return fmt.Errorf("invalid %s URI query", field)
	}
	valid := func(s string) bool { return utf8.ValidString(s) && strings.IndexFunc(s, unicode.IsControl) < 0 }
	if !valid(u.Path) || !valid(u.Fragment) {
		return fmt.Errorf("invalid %s URI", field)
	}
	for key, values := range query {
		if !valid(key) {
			return fmt.Errorf("invalid %s URI query", field)
		}
		for _, v := range values {
			if !valid(v) {
				return fmt.Errorf("invalid %s URI query", field)
			}
		}
	}
	if spider {
		if !strings.HasPrefix(value, "/") || strings.HasPrefix(value, "//") || u.IsAbs() || u.Host != "" || u.Fragment != "" {
			return fmt.Errorf("invalid %s URI", field)
		}
		if err := validateSpiderQuery(query); err != nil {
			return fmt.Errorf("invalid %s: %w", field, err)
		}
	}
	return nil
}

const (
	MaxSpiderURIBytes          = 4096
	MaxSpiderQueryKeys         = 32
	MaxSpiderPadding           = 4096
	MaxSpiderConcurrency       = 8
	MaxSpiderRequestsPerWorker = 16
	MaxSpiderTotalRequests     = 64
	MaxSpiderIntervalMS        = 30000
	MaxSpiderReturnMS          = 5000
)

// Xray uses p in strings.Repeat, c for goroutine creation, t as each
// goroutine's loop count and i/r as milliseconds. Reject ambiguous values
// before their unchecked conversion and use conservative aggregate limits.
func validateSpiderQuery(query url.Values) error {
	if len(query) > MaxSpiderQueryKeys {
		return fmt.Errorf("too many query parameters")
	}
	limits := map[string]uint64{"p": MaxSpiderPadding, "c": MaxSpiderConcurrency, "t": MaxSpiderRequestsPerWorker, "i": MaxSpiderIntervalMS, "r": MaxSpiderReturnMS}
	var concurrency, times uint64
	for key, values := range query {
		if len(key) > 128 || len(values) != 1 || len(values[0]) > 1024 {
			return fmt.Errorf("invalid or duplicate query parameter")
		}
		for special, limit := range limits {
			if !strings.EqualFold(key, special) {
				continue
			}
			if key != special {
				return fmt.Errorf("ambiguous spider parameter name")
			}
			maximum, err := parseSpiderRange(values[0], limit)
			if err != nil {
				return fmt.Errorf("invalid spider parameter %s: %w", special, err)
			}
			if special == "c" {
				concurrency = maximum
			}
			if special == "t" {
				times = maximum
			}
		}
	}
	if concurrency*times > MaxSpiderTotalRequests {
		return fmt.Errorf("spider request budget exceeded")
	}
	return nil
}
func parseSpiderRange(raw string, limit uint64) (uint64, error) {
	parts := strings.Split(raw, "-")
	if len(parts) < 1 || len(parts) > 2 {
		return 0, fmt.Errorf("expected nonnegative integer or min-max")
	}
	var nums [2]uint64
	for i, part := range parts {
		if len(part) == 0 || len(part) > 20 {
			return 0, fmt.Errorf("invalid numeric length")
		}
		for _, r := range part {
			if r < '0' || r > '9' {
				return 0, fmt.Errorf("invalid numeric value")
			}
		}
		v, err := strconv.ParseUint(part, 10, 64)
		if err != nil || v > limit {
			return 0, fmt.Errorf("value exceeds %d", limit)
		}
		nums[i] = v
	}
	if len(parts) == 1 {
		return nums[0], nil
	}
	if nums[0] > nums[1] {
		return 0, fmt.Errorf("reversed range")
	}
	return nums[1], nil
}

type TransportCheck func(string) error

func ValidateStream(stream *coreConf.StreamConfig, check TransportCheck) error {
	return validateStream(stream, check, 0)
}
func validateStream(stream *coreConf.StreamConfig, check TransportCheck, depth int) error {
	if stream == nil {
		return nil
	}
	if depth > 32 {
		return fmt.Errorf("stream nesting exceeds limit")
	}
	if check != nil {
		for _, name := range []*coreConf.TransportProtocol{stream.Network, stream.Method} {
			if name != nil {
				if err := check(string(*name)); err != nil {
					return err
				}
			}
		}
	}
	if stream.REALITYSettings != nil {
		if err := ValidateURI("realitySettings.spiderX", stream.REALITYSettings.SpiderX, true); err != nil {
			return err
		}
	}
	if stream.WSSettings != nil {
		if err := ValidateURI("wsSettings.path", stream.WSSettings.Path, false); err != nil {
			return err
		}
	}
	if stream.HTTPUPGRADESettings != nil {
		if err := ValidateURI("httpupgradeSettings.path", stream.HTTPUPGRADESettings.Path, false); err != nil {
			return err
		}
	}
	for _, split := range []*coreConf.SplitHTTPConfig{stream.XHTTPSettings, stream.SplitHTTPSettings} {
		if err := validateSplit(split, check, depth+1); err != nil {
			return err
		}
	}
	return nil
}
func validateSplit(split *coreConf.SplitHTTPConfig, check TransportCheck, depth int) error {
	if split == nil {
		return nil
	}
	if depth > 32 {
		return fmt.Errorf("stream nesting exceeds limit")
	}
	if err := ValidateURI("xhttp.path", split.Path, false); err != nil {
		return err
	}
	if err := validateStream(split.DownloadSettings, check, depth+1); err != nil {
		return err
	}
	if len(split.Extra) != 0 {
		return validateXHTTPExtra(split.Extra, check, depth+1)
	}
	return nil
}
func ValidateXHTTPExtra(raw []byte, check TransportCheck) error {
	return validateXHTTPExtra(raw, check, 0)
}
func validateXHTTPExtra(raw []byte, check TransportCheck, depth int) error {
	if depth > 32 {
		return fmt.Errorf("stream nesting exceeds limit")
	}
	if err := panel.ValidateUniqueJSON(raw); err != nil {
		return fmt.Errorf("invalid XHTTP extra: %w", err)
	}
	var extra *coreConf.SplitHTTPConfig
	if err := json.Unmarshal(raw, &extra); err != nil || extra == nil {
		return fmt.Errorf("XHTTP extra must be a JSON object")
	}
	return validateSplit(extra, check, depth+1)
}

package streamguard

import (
	"encoding/json"
	"fmt"
	"strings"
	"unicode"

	"github.com/perfect-panel/ppanel-node/api/panel"
)

// ValidateNoUOTJSON rejects non-default UoT aliases recursively before a raw
// JSON object is decoded into an Xray struct.
func ValidateNoUOTJSON(raw []byte) error {
	if err := panel.ValidateUniqueJSON(raw); err != nil {
		return fmt.Errorf("invalid raw settings: %w", err)
	}
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return err
	}
	return ValidateNoUOTValue(value)
}

func ValidateNoUOTValue(value any) error {
	switch x := value.(type) {
	case map[string]any:
		for key, child := range x {
			var folded strings.Builder
			for _, r := range key {
				if r == '_' || r == '-' {
					continue
				}
				for {
					next := unicode.SimpleFold(r)
					if next <= r {
						r = next
						break
					}
					r = next
				}
				folded.WriteRune(unicode.ToLower(r))
			}
			normal := folded.String()
			switch normal {
			case "uot", "uotversion", "udpovertcp", "udpovertcpversion":
				switch v := child.(type) {
				case bool:
					if !v {
						continue
					}
				case json.Number:
					if v == "0" {
						continue
					}
				case float64:
					if v == 0 {
						continue
					}
				case int:
					if v == 0 {
						continue
					}
				case int64:
					if v == 0 {
						continue
					}
				case uint64:
					if v == 0 {
						continue
					}
				}
				return fmt.Errorf("configured UDP-over-TCP is unsupported")
			default:
				if err := ValidateNoUOTValue(child); err != nil {
					return err
				}
			}
		}
	case []any:
		for _, child := range x {
			if err := ValidateNoUOTValue(child); err != nil {
				return err
			}
		}
	case nil, string, bool, json.Number, float64, int, int64, uint64:
		return nil
	default:
		// Programmatic callers may supply typed maps/slices rather than the
		// JSON decoder's map[string]any; inspect them without a bypass.
		raw, err := json.Marshal(value)
		if err != nil {
			return fmt.Errorf("invalid UoT-bearing options: %w", err)
		}
		return ValidateNoUOTJSON(raw)
	}
	return nil
}

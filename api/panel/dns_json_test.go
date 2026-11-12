package panel

import (
	"encoding/json"
	"testing"
)

// The removed legacy delivery fields are unknown to format 3: a candidate
// carrying any of them is rejected as a whole, never read or converted.
func TestLegacyDeliveryFieldsRejected(t *testing.T) {
	for _, field := range []string{
		`"dns":[]`, `"dns":[{"proto":"udp","address":"1.1.1.1","domains":[]}]`, `"ip_strategy":"prefer_ipv4"`,
		`"block":[]`, `"block_ips":[]`, `"block_protocols":[]`, `"outbound":[]`,
	} {
		raw := `{"pull_interval":60,"push_interval":60,"protocols":[],"total":0,` + field + `}`
		var data Data
		if err := json.Unmarshal([]byte(raw), &data); err == nil {
			t.Errorf("candidate with %s accepted", field)
		}
	}
}

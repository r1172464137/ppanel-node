package panel

import (
	"encoding/json"
	"testing"
)

func TestDNSJSONFieldsHaveStringPresence(t *testing.T) {
	for _, raw := range []string{
		`{"dns":[{"proto":null,"address":"1.1.1.1"}]}`,
		`{"dns":[{"proto":"udp","address":null}]}`,
		`{"dns":[{"address":"1.1.1.1","server_name":null}]}`,
		`{"dns":[{"address":"1.1.1.1","Address":"8.8.8.8"}]}`,
	} {
		var data Data
		if err := json.Unmarshal([]byte(raw), &data); err == nil {
			t.Errorf("invalid DNS JSON accepted: %s", raw)
		}
	}
	var data Data
	if err := json.Unmarshal([]byte(`{"dns":[{"proto":"","address":"1.1.1.1","server_name":"","domains":null}]}`), &data); err != nil {
		t.Fatal(err)
	}
	if data.DNS == nil || len(*data.DNS) != 1 || (*data.DNS)[0].Address != "1.1.1.1" {
		t.Fatalf("valid DNS JSON lost: %+v", data.DNS)
	}
}

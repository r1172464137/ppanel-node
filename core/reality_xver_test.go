package core

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/perfect-panel/ppanel-node/api/panel"
	serverv1 "github.com/perfect-panel/ppanel-node/api/server/v1"
	"google.golang.org/protobuf/proto"
)

func TestRealityXverValidation(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		for _, xver := range []int{-1, 0, 1, 2, 3, int(^uint(0) >> 1)} {
			p := panel.Protocol{Type: "vless", Enable: enabled, Port: 20100, Transport: "tcp", Security: "reality", SNI: "example.com", RealityServerPort: 8443, RealityPrivateKey: "key", RealityShortID: "abcd", RealityXver: xver}
			for _, accept := range []bool{false, true} {
				p.AcceptProxyProtocol = accept
				err := ValidateServerConfig(&panel.ServerConfigResponse{Data: &panel.Data{Protocols: &[]panel.Protocol{p}, Total: 1, Routing: emptyTestRouting()}})
				if (err != nil) != (xver < 0 || xver > 2) {
					t.Fatalf("enabled=%v xver=%d accept=%v: %v", enabled, xver, accept, err)
				}
			}
		}
	}
	// Invalid values delivered by either transport cannot bypass semantic validation.
	for _, xver := range []int{-1, 3, int(^uint(0) >> 1)} {
		var jsonProtocol panel.Protocol
		if err := json.Unmarshal([]byte(fmt.Sprintf(`{"type":"vless","security":"reality","reality_xver":%d}`, xver)), &jsonProtocol); err != nil {
			t.Fatal(err)
		}
		if err := validateProtocol(jsonProtocol); err == nil {
			t.Fatalf("accepted JSON %d", xver)
		}
		wire, err := proto.Marshal(&serverv1.ServerProtocol{RealityXver: uint32(xver)})
		if err != nil {
			t.Fatal(err)
		}
		var decoded serverv1.ServerProtocol
		if err := proto.Unmarshal(wire, &decoded); err != nil {
			t.Fatal(err)
		}
		if err := validateProtocol(panel.Protocol{Security: "reality", RealityXver: int(decoded.RealityXver)}); err == nil {
			t.Fatalf("accepted protobuf %d", xver)
		}
	}
	if err := validateProtocol(panel.Protocol{Type: "vless", Enable: true, Port: 20100, Transport: "tcp", RealityXver: 2, AcceptProxyProtocol: true}); err != nil {
		t.Fatalf("non-REALITY behavior changed: %v", err)
	}
}

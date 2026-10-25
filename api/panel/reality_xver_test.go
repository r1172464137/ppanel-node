package panel

import (
	"encoding/json"
	"math"
	"testing"

	serverv1 "github.com/perfect-panel/ppanel-node/api/server/v1"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
)

func TestRealityXverJSONAndProtobufDelivery(t *testing.T) {
	field := (&serverv1.ServerProtocol{}).ProtoReflect().Descriptor().Fields().ByName("reality_xver")
	if field == nil || field.Number() != 66 || field.Kind() != protoreflect.Uint32Kind {
		t.Fatalf("wire contract = %v", field)
	}
	for _, xver := range []uint32{0, 1, 2, 3, math.MaxUint32} {
		message := &serverv1.QueryServerProtocolConfigResponse{Code: 200, Data: &serverv1.QueryServerProtocolConfigData{Protocols: []*serverv1.ServerProtocol{{Type: "vless", Security: "reality", RealityXver: xver, AcceptProxyProtocol: true}}}}
		wire, err := proto.Marshal(message)
		if err != nil {
			t.Fatal(err)
		}
		var decoded serverv1.QueryServerProtocolConfigResponse
		if err := proto.Unmarshal(wire, &decoded); err != nil {
			t.Fatal(err)
		}
		response := serverConfigResponseFromProtobuf(&decoded)
		p := (*response.Data.Protocols)[0]
		if p.RealityXver != int(xver) || !p.AcceptProxyProtocol {
			t.Fatalf("conversion = %+v", p)
		}
		// Out-of-range values must survive conversion so validation can reject them.
		body, err := json.Marshal(response)
		if err != nil {
			t.Fatal(err)
		}
		var received ServerConfigResponse
		if err := json.Unmarshal(body, &received); err != nil {
			t.Fatal(err)
		}
		if (*received.Data.Protocols)[0].RealityXver != int(xver) {
			t.Fatalf("JSON = %s", body)
		}
	}
	var omitted Protocol
	if err := json.Unmarshal([]byte(`{"accept_proxy_protocol":true}`), &omitted); err != nil {
		t.Fatal(err)
	}
	if omitted.RealityXver != 0 {
		t.Fatal("omitted xver must default to zero")
	}
	for _, raw := range []string{`1.5`, `"2"`, `true`, `18446744073709551616`} {
		var p Protocol
		if err := json.Unmarshal([]byte(`{"reality_xver":`+raw+`}`), &p); err == nil {
			t.Fatalf("accepted %s", raw)
		}
	}
}

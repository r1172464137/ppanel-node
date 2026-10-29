package panel

import (
	"encoding/json"
	"testing"
	"time"

	serverv1 "github.com/perfect-panel/ppanel-node/api/server/v1"
	"github.com/perfect-panel/ppanel-node/conf"
	"google.golang.org/protobuf/proto"
)

func TestFailureStagesMatchBackendInJSONAndProtobuf(t *testing.T) {
	stages := map[string]string{"fetch": "fetch", "validate": "validate", "build": "build", "core_start": "core_start", "prepare": "prepare", "stop": "stop", "bind": "bind", "restore": "restore", "config": "validate", "monitor": "prepare", "unrecognized": "validate"}
	for operation, want := range stages {
		t.Run(operation, func(t *testing.T) {
			c := NewServerClient(&conf.ServerApiConfig{ServerId: 8101})
			if err := c.ActivateStatusPublisher(); err != nil {
				t.Fatal(err)
			}
			c.RecordFailure(nil, StageForOperation(operation))
			payload, err := c.statusPayloadAt(&NodeStatus{}, time.Now())
			if err != nil {
				t.Fatal(err)
			}
			if payload.Error == nil || payload.Error.Stage != want || payload.Error.Message != "candidate failed during "+want {
				t.Fatalf("stage payload %+v", payload)
			}
			body, err := json.Marshal(payload)
			if err != nil {
				t.Fatal(err)
			}
			var jsonStatus ServerPushStatusRequest
			if err := json.Unmarshal(body, &jsonStatus); err != nil {
				t.Fatal(err)
			}
			if jsonStatus.Error == nil || jsonStatus.Error.Stage != want {
				t.Fatalf("JSON stage %+v", jsonStatus)
			}
			wire, err := proto.Marshal(statusToProtobuf(payload))
			if err != nil {
				t.Fatal(err)
			}
			var pb serverv1.PushServerStatusRequest
			if err := proto.Unmarshal(wire, &pb); err != nil {
				t.Fatal(err)
			}
			if pb.RoutingError == nil || pb.RoutingError.Stage != want {
				t.Fatalf("protobuf stage %+v", pb.RoutingError)
			}
		})
	}
}

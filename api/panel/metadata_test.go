package panel

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	serverv1 "github.com/perfect-panel/ppanel-node/api/server/v1"
	"github.com/perfect-panel/ppanel-node/conf"
	"google.golang.org/protobuf/proto"
)

func TestIntervalBoundsBeforeDurationConversion(t *testing.T) {
	for _, tc := range []struct {
		v    int
		want time.Duration
		bad  bool
	}{
		{0, time.Minute, false}, {1, time.Second, false}, {86400, 24 * time.Hour, false}, {-1, 0, true}, {86401, 0, true}, {int(^uint(0) >> 1), 0, true},
	} {
		got, err := IntervalDuration(tc.v)
		if (err != nil) != tc.bad || !tc.bad && got != tc.want {
			t.Fatalf("IntervalDuration(%d)=%v,%v", tc.v, got, err)
		}
	}
}

func TestLocalAPITimeoutBounds(t *testing.T) {
	for _, seconds := range []int{-1, 86401, int(^uint(0) >> 1)} {
		if err := ValidateAPITimeout(seconds); err == nil {
			t.Fatalf("invalid timeout %d accepted", seconds)
		}
		if got := NewServerClient(&conf.ServerApiConfig{Timeout: seconds}).Client.GetClient().Timeout; got != 30*time.Second {
			t.Fatalf("unsafe fallback timeout=%v", got)
		}
		if _, err := NewNodeClient(&conf.NodeApiConfig{NodeType: "vless", Timeout: seconds}); err == nil {
			t.Fatal("node client accepted invalid timeout")
		}
	}
	if err := ValidateAPITimeout(86400); err != nil {
		t.Fatal(err)
	}
}

func TestDeliveryTotalAndIntervalJSONProto(t *testing.T) {
	for _, binary := range []bool{false, true} {
		for _, tc := range []struct {
			name       string
			total      int64
			count      int
			pull, push int64
			null       bool
			ok         bool
		}{
			{"null-zero", 0, 0, 0, 0, true, true}, {"empty-mismatch", 1, 0, 0, 0, true, false},
			{"one-valid", 1, 1, 1, 86400, false, true}, {"one-mismatch", 0, 1, 1, 1, false, false},
			{"negative", 0, 0, -1, 1, false, false}, {"over-limit", 0, 0, 86401, 1, false, false}, {"overflow", 0, 0, math.MaxInt64, 1, false, false},
		} {
			t.Run(fmt.Sprintf("proto=%v/%s", binary, tc.name), func(t *testing.T) {
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if binary {
						w.Header().Set("Content-Type", "application/protobuf")
						p := make([]*serverv1.ServerProtocol, tc.count)
						for i := range p {
							p[i] = &serverv1.ServerProtocol{Type: "vless"}
						}
						body, _ := proto.Marshal(&serverv1.QueryServerProtocolConfigResponse{Code: 200, Data: &serverv1.QueryServerProtocolConfigData{Total: tc.total, Protocols: p, PullInterval: tc.pull, PushInterval: tc.push, Routing: &serverv1.RoutingPolicy{Version: 1, DefaultOutboundId: "direct", Mode: "ordered-v1-inherited", Source: "global", SourceRevision: 1}}})
						w.Write(body)
						return
					}
					var protocols any = make([]any, 0, tc.count)
					if tc.count == 1 {
						protocols = []any{map[string]any{"type": "vless"}}
					}
					if tc.null {
						protocols = nil
					}
					json.NewEncoder(w).Encode(map[string]any{"code": 200, "data": map[string]any{"total": tc.total, "protocols": protocols, "pull_interval": tc.pull, "push_interval": tc.push, "routing": map[string]any{"version": 1, "outbounds": []any{}, "rules": []any{}, "default_outbound_id": "direct", "mode": "ordered-v1-inherited", "source": "global", "source_revision": 1}}})
				}))
				defer server.Close()
				result, err := GetServerConfig(context.Background(), NewServerClient(&conf.ServerApiConfig{ApiHost: server.URL, ServerId: 7}))
				if (err == nil) != tc.ok {
					t.Fatalf("GetServerConfig = %+v, %v", result, err)
				}
				if tc.ok && (result.Data.Protocols == nil || len(*result.Data.Protocols) != tc.count) {
					t.Fatal("protocol count changed")
				}
			})
		}
	}
}

func TestProtoUOTRejectedBeforeNarrowingOn32Bit(t *testing.T) {
	for _, inbound := range []bool{false, true} {
		t.Run(fmt.Sprint(inbound), func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/protobuf")
				data := &serverv1.QueryServerProtocolConfigData{Routing: &serverv1.RoutingPolicy{Version: 1, DefaultOutboundId: "direct", Mode: "ordered-v1-inherited", Source: "global", SourceRevision: 1}}
				if inbound {
					data.Protocols = []*serverv1.ServerProtocol{{Type: "vless", UotVersion: 1 << 32}}
					data.Total = 1
				} else {
					data.Routing.Outbounds = []*serverv1.Outbound{{UotVersion: 1 << 32}}
				}
				body, _ := proto.Marshal(&serverv1.QueryServerProtocolConfigResponse{Code: 200, Data: data})
				w.Write(body)
			}))
			defer server.Close()
			if _, err := GetServerConfig(context.Background(), NewServerClient(&conf.ServerApiConfig{ApiHost: server.URL, ServerId: 7})); err == nil {
				t.Fatal("nonzero UoT hidden by narrowing")
			}
		})
	}
}

func TestRoutingSequenceIndependentOfClockAndClient(t *testing.T) {
	c1 := NewServerClient(&conf.ServerApiConfig{ServerId: 7})
	c2 := NewServerClient(&conf.ServerApiConfig{ServerId: 7})
	if c1.State.Snapshot().InstanceID != c2.State.Snapshot().InstanceID {
		t.Fatal("instance changed across clients")
	}
	t0 := time.UnixMilli(123456789)
	if err := c1.ActivateStatusPublisher(); err != nil {
		t.Fatal(err)
	}
	a, err := c1.statusPayloadAt(&NodeStatus{}, t0)
	if err != nil {
		t.Fatal(err)
	}
	if err := c2.ActivateStatusPublisher(); err != nil {
		t.Fatal(err)
	}
	b, err := c2.statusPayloadAt(&NodeStatus{}, t0)
	if err != nil {
		t.Fatal(err)
	}
	c, err := c2.statusPayloadAt(&NodeStatus{}, t0.Add(-time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c1.statusPayloadAt(&NodeStatus{}, t0); err != ErrRetiredClient {
		t.Fatalf("retired client: %v", err)
	}
	if a.UpdatedAt != b.UpdatedAt || c.UpdatedAt >= b.UpdatedAt || a.Sequence == 0 || a.Sequence >= b.Sequence || b.Sequence >= c.Sequence {
		t.Fatalf("clock-dependent sequence: %+v %+v %+v", a, b, c)
	}
	wire, err := proto.Marshal(statusToProtobuf(c))
	if err != nil {
		t.Fatal(err)
	}
	var decoded serverv1.PushServerStatusRequest
	if err := proto.Unmarshal(wire, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.RoutingSequence != c.Sequence {
		t.Fatal("protobuf sequence lost")
	}
	body, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	var projection map[string]any
	if err := json.Unmarshal(body, &projection); err != nil {
		t.Fatal(err)
	}
	if projection["routing_sequence"] == nil {
		t.Fatal("JSON sequence absent")
	}
	const count = 256
	seqs := make(chan uint64, count)
	var wg sync.WaitGroup
	for i := 0; i < count; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			payload, err := c2.statusPayloadAt(&NodeStatus{}, t0)
			if err != nil {
				t.Error(err)
				return
			}
			seqs <- payload.Sequence
		}()
	}
	wg.Wait()
	close(seqs)
	seen := map[uint64]bool{}
	for s := range seqs {
		if s <= c.Sequence || seen[s] {
			t.Fatalf("duplicate or reversed process sequence %d", s)
		}
		seen[s] = true
	}
}

func TestRawJSONCaseFoldCollisions(t *testing.T) {
	for _, raw := range []string{`{"security":"tls","Security":"reality"}`, `{"tlsSettings":{"serverName":"a","ServerName":"b"}}`, `{"x":[{"K":1,"\u212a":2}]}`} {
		if err := ValidateUniqueJSON([]byte(raw)); err == nil {
			t.Fatalf("case-folded collision accepted: %s", raw)
		}
	}
	if err := ValidateUniqueJSON([]byte(`{"security":"tls","tlsSettings":{"serverName":"x"}}`)); err != nil {
		t.Fatal(err)
	}
}

package cmd

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"

	"github.com/perfect-panel/ppanel-node/api/panel"
	serverv1 "github.com/perfect-panel/ppanel-node/api/server/v1"
)

// v3TestTag is the inbound tag function used by tests.
func v3TestTag(protocol string) string { return "test-" + protocol }

// completeV3 fills the format 3 fields a test does not exercise: version 3,
// empty account scopes and defaults, the system DNS default, no IP
// preference, and an identity snapshot covering the delivered protocols
// (users given per protocol type; others empty). The snapshot ID hashes the
// candidate so different candidates get different IDs.
func completeV3(sc *panel.ServerConfigResponse, users map[string][]panel.IdentityUser) *panel.ServerConfigResponse {
	if sc == nil || sc.Data == nil {
		return sc
	}
	d := sc.Data
	if p := d.Routing; p != nil {
		p.Version = panel.RoutingVersion
		if p.Outbounds == nil {
			p.Outbounds = []panel.Outbound{}
		}
		if p.Rules == nil {
			p.Rules = []panel.RouteRule{}
		}
		for i := range p.Rules {
			if p.Rules[i].UserIDs == nil {
				p.Rules[i].UserIDs = []int64{}
			}
		}
		if p.UserDefaults == nil {
			p.UserDefaults = []panel.UserDefault{}
		}
		if p.DNS == nil {
			p.DNS = &panel.DNSPolicy{QueryStrategy: "UseIP", Resolvers: []panel.DNSResolverPolicy{{ID: "dns_00000000-0000-4000-8000-000000000001", Protocol: "system", Domains: []string{}, OutboundID: "direct"}}}
		}
		if p.DefaultOutboundID == "" {
			p.DefaultOutboundID = "direct"
		}
		if p.TargetIPPreference == "" {
			p.TargetIPPreference = "none"
		}
		if p.Mode == "" {
			p.RoutingIdentity = panel.RoutingIdentity{Mode: "inherited", Source: "global", SourceRevision: 1}
		}
	}
	if d.IdentitySnapshot == nil || users != nil || !coversProtocols(d) {
		types := map[string]bool{}
		if d.Protocols != nil {
			for _, p := range *d.Protocols {
				types[p.Type] = true
			}
		}
		names := make([]string, 0, len(types))
		for t := range types {
			names = append(names, t)
		}
		sort.Strings(names)
		snap := &panel.IdentitySnapshot{Protocols: []panel.ProtocolIdentity{}}
		for _, t := range names {
			u := users[t]
			if u == nil {
				u = []panel.IdentityUser{}
			}
			snap.Protocols = append(snap.Protocols, panel.ProtocolIdentity{Protocol: t, Users: u})
		}
		body, _ := json.Marshal(struct {
			R *panel.RoutingPolicy
			P *[]panel.Protocol
			S *panel.IdentitySnapshot
		}{d.Routing, d.Protocols, snap})
		sum := sha256.Sum256(body)
		snap.SnapshotID = hex.EncodeToString(sum[:])
		d.IdentitySnapshot = snap
	}
	return sc
}

// coversProtocols reports whether the snapshot lists exactly the delivered
// protocol types (tests often change protocols after building a fixture).
func coversProtocols(d *panel.Data) bool {
	want := map[string]bool{}
	if d.Protocols != nil {
		for _, p := range *d.Protocols {
			want[p.Type] = true
		}
	}
	if len(want) != len(d.IdentitySnapshot.Protocols) {
		return false
	}
	for _, p := range d.IdentitySnapshot.Protocols {
		if !want[p.Protocol] {
			return false
		}
	}
	return true
}

// v3 completes a candidate just before it is validated or started.
func v3(sc *panel.ServerConfigResponse) *panel.ServerConfigResponse { return completeV3(sc, nil) }

// v3JSON completes a hand-written server config response body: missing v3
// routing fields get their defaults and an identity snapshot covers the
// delivered protocols with the given users (none by default), keyed by the
// body so different candidates get different snapshot IDs.
func v3JSON(body string, users ...map[string]any) string {
	var resp map[string]any
	if err := json.Unmarshal([]byte(body), &resp); err != nil {
		panic(err)
	}
	data, ok := resp["data"].(map[string]any)
	if !ok || data["routing"] == nil {
		return body
	}
	if routing, ok := data["routing"].(map[string]any); ok {
		for key, value := range map[string]any{
			"user_defaults":        []any{},
			"target_ip_preference": "none",
			"dns":                  map[string]any{"query_strategy": "UseIP", "resolvers": []any{map[string]any{"id": "dns_00000000-0000-4000-8000-000000000001", "protocol": "system", "address": "", "domains": []any{}, "outbound_id": "direct"}}},
		} {
			if _, set := routing[key]; !set {
				routing[key] = value
			}
		}
		if rules, ok := routing["rules"].([]any); ok {
			for _, rule := range rules {
				if m, ok := rule.(map[string]any); ok && m["user_ids"] == nil {
					m["user_ids"] = []any{}
				}
			}
		}
	}
	identities := []any{}
	for _, u := range users {
		identities = append(identities, u)
	}
	types := map[string]bool{}
	if list, ok := data["protocols"].([]any); ok {
		for _, p := range list {
			if t, ok := p.(map[string]any)["type"].(string); ok {
				types[t] = true
			}
		}
	}
	names := make([]string, 0, len(types))
	for t := range types {
		names = append(names, t)
	}
	sort.Strings(names)
	protocols := []map[string]any{}
	for _, t := range names {
		protocols = append(protocols, map[string]any{"protocol": t, "users": identities})
	}
	sum := sha256.Sum256([]byte(body))
	data["identity_snapshot"] = map[string]any{"snapshot_id": hex.EncodeToString(sum[:]), "protocols": protocols}
	out, _ := json.Marshal(resp)
	return string(out)
}

// v3Proto completes a protobuf candidate like completeV3: version 3, empty
// defaults, the system DNS default and a snapshot covering the protocols.
func v3Proto(data *serverv1.QueryServerProtocolConfigData) *serverv1.QueryServerProtocolConfigData {
	if p := data.Routing; p != nil {
		p.Version = panel.RoutingVersion
		if p.Dns == nil {
			p.Dns = &serverv1.DNSPolicy{QueryStrategy: "UseIP", Resolvers: []*serverv1.DNSResolverPolicy{{Id: "dns_00000000-0000-4000-8000-000000000001", Protocol: "system", Domains: []string{}, OutboundId: "direct"}}}
		}
		if p.TargetIpPreference == "" {
			p.TargetIpPreference = "none"
		}
	}
	types := map[string]bool{}
	for _, p := range data.Protocols {
		types[p.Type] = true
	}
	names := make([]string, 0, len(types))
	for t := range types {
		names = append(names, t)
	}
	sort.Strings(names)
	snap := &serverv1.IdentitySnapshot{}
	for _, t := range names {
		snap.Protocols = append(snap.Protocols, &serverv1.ProtocolIdentity{Protocol: t})
	}
	body, _ := json.Marshal(struct {
		R *serverv1.RoutingPolicy
		N []string
	}{data.Routing, names})
	sum := sha256.Sum256(body)
	snap.SnapshotId = hex.EncodeToString(sum[:])
	data.IdentitySnapshot = snap
	return data
}

// dataPlaneUser is the VLESS identity the listener tests connect with.
var dataPlaneUser = map[string]any{"id": 1, "uuid": "00000000-0000-0000-0000-000000000001", "speed_limit": 0, "device_limit": 0, "account_id": 1}

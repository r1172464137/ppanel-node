package core

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"

	"github.com/perfect-panel/ppanel-node/api/panel"
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

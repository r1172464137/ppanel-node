package outbound

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/perfect-panel/ppanel-node/api/panel"
)

func validateOrderedV2(data *panel.Data) error {
	p := data.Routing
	if p.UserDefaults == nil || data.IdentitySnapshot == nil || data.Protocols == nil {
		return fmt.Errorf("routing version 2 requires user defaults and identity snapshot")
	}
	snapshot := data.IdentitySnapshot
	if snapshot.Protocols == nil || len(snapshot.SnapshotID) != 64 || snapshot.SnapshotID != strings.ToLower(snapshot.SnapshotID) {
		return fmt.Errorf("invalid snapshot ID")
	}
	if _, err := hex.DecodeString(snapshot.SnapshotID); err != nil {
		return fmt.Errorf("invalid snapshot ID")
	}
	clone := *data
	policy := *p
	clone.Routing = &policy
	clone.IdentitySnapshot = nil
	policy.Version = 1
	policy.Mode = strings.Replace(policy.Mode, "ordered-v2-", "ordered-v1-", 1)
	policy.UserDefaults = nil
	policy.DNSPolicy = nil
	policy.Outbounds = append([]panel.Outbound{}, p.Outbounds...)
	for i := range policy.Outbounds {
		policy.Outbounds[i].ViaOutboundID = ""
	}
	policy.Rules = append([]panel.RouteRule{}, p.Rules...)
	for i := range policy.Rules {
		policy.Rules[i].UserIDs = nil
	}
	if err := ValidateOrdered(&clone); err != nil {
		return err
	}
	if p.Mode != "ordered-v2-local" && p.Mode != "ordered-v2-inherited" {
		return fmt.Errorf("invalid v2 mode")
	}
	content := struct {
		Version      int                 `json:"version"`
		Outbounds    []panel.Outbound    `json:"outbounds"`
		Rules        []panel.RouteRule   `json:"rules"`
		Default      string              `json:"default_outbound_id"`
		UserDefaults []panel.UserDefault `json:"user_defaults"`
		DNSPolicy    *panel.DNSPolicy    `json:"dns_policy,omitempty"`
	}{p.Version, p.Outbounds, p.Rules, p.DefaultOutboundID, p.UserDefaults, p.DNSPolicy}
	raw, err := json.Marshal(content)
	if err != nil || len(raw) > MaxOrderedJSONBytes {
		return fmt.Errorf("v2 routing exceeds size limit")
	}
	byID := map[string]panel.Outbound{}
	for _, o := range p.Outbounds {
		byID[o.ID] = o
	}
	if _, err := chainLinks(p.Outbounds); err != nil {
		return err
	}
	ids := map[string]bool{"direct": true, "block": true}
	for id := range byID {
		ids[id] = true
	}
	if len(p.UserDefaults) > MaxOrderedValues {
		return fmt.Errorf("too many user defaults")
	}
	users := map[int64]bool{}
	for _, u := range p.UserDefaults {
		if u.UserID <= 0 || users[u.UserID] || !ids[u.OutboundID] {
			return fmt.Errorf("invalid user default")
		}
		users[u.UserID] = true
	}
	for _, r := range p.Rules {
		if len(r.UserIDs) > MaxRouteRules {
			return fmt.Errorf("too many user IDs")
		}
		seen := map[int64]bool{}
		for _, id := range r.UserIDs {
			if id <= 0 || seen[id] {
				return fmt.Errorf("invalid user rule")
			}
			seen[id] = true
		}
	}
	expectedProtocols := make(map[string]bool, len(*data.Protocols))
	for _, protocol := range *data.Protocols {
		expectedProtocols[protocol.Type] = true
	}
	protocols := map[string]bool{}
	subscriptions := map[int]panel.UserInfo{}
	for _, p := range snapshot.Protocols {
		if !expectedProtocols[p.Protocol] || protocols[p.Protocol] || p.Users == nil {
			return fmt.Errorf("invalid snapshot protocol")
		}
		protocols[p.Protocol] = true
		uuids := map[string]bool{}
		ids := map[int]bool{}
		for _, u := range p.Users {
			if u.Id <= 0 || u.AccountID <= 0 || !validText(u.Uuid, 200, false) || uuids[u.Uuid] || ids[u.Id] || u.SpeedLimit < 0 || u.DeviceLimit < 0 {
				return fmt.Errorf("invalid snapshot user")
			}
			if previous, ok := subscriptions[u.Id]; ok && previous != u {
				return fmt.Errorf("inconsistent subscription identity across protocols")
			}
			subscriptions[u.Id] = u
			uuids[u.Uuid] = true
			ids[u.Id] = true
		}
	}
	for _, p := range *data.Protocols {
		if !protocols[p.Type] {
			return fmt.Errorf("missing snapshot protocol")
		}
	}
	return validateDNSPolicy(p)
}

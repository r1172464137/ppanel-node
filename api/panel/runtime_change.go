package panel

import (
	"reflect"
	"strings"
)

// RuntimeOnlyChange reports whether candidate differs from applied only in
// settings that do not affect the data plane: the panel pull/push intervals and
// the traffic report threshold. Such a candidate is applied by adjusting the
// periodic tasks; the Xray instance, listeners and connections stay untouched.
// Any other difference - routing content or identity, DNS, protocols, users -
// returns false and requires a full switch.
func RuntimeOnlyChange(applied, candidate *ServerConfigResponse) bool {
	if applied == nil || candidate == nil || applied.Data == nil || candidate.Data == nil {
		return false
	}
	if applied.UseProtobuf != candidate.UseProtobuf {
		return false
	}
	a, b := *applied.Data, *candidate.Data
	if a.PullInterval == b.PullInterval && a.PushInterval == b.PushInterval && a.TrafficReportThreshold == b.TrafficReportThreshold {
		return false // no runtime difference: not this kind of change
	}
	a.PullInterval, a.PushInterval, a.TrafficReportThreshold = 0, 0, 0
	b.PullInterval, b.PushInterval, b.TrafficReportThreshold = 0, 0, 0
	return reflect.DeepEqual(a, b)
}

// IdentityOnlyChange reports whether candidate differs from applied only in
// its identity snapshot (and possibly intervals/threshold): routing content
// and identity, protocols and listeners are unchanged. It returns the
// accounts whose set of identities changed (added, removed or UUID changed);
// accounts with limit-only changes are not listed.
func IdentityOnlyChange(applied, candidate *ServerConfigResponse) (map[int64]bool, bool) {
	if applied == nil || candidate == nil || applied.Data == nil || candidate.Data == nil ||
		applied.Data.IdentitySnapshot == nil || candidate.Data.IdentitySnapshot == nil {
		return nil, false
	}
	if applied.UseProtobuf != candidate.UseProtobuf {
		return nil, false
	}
	a, b := *applied.Data, *candidate.Data
	a.PullInterval, a.PushInterval, a.TrafficReportThreshold = 0, 0, 0
	b.PullInterval, b.PushInterval, b.TrafficReportThreshold = 0, 0, 0
	a.IdentitySnapshot, b.IdentitySnapshot = nil, nil
	if !reflect.DeepEqual(a, b) {
		return nil, false
	}
	type key struct {
		protocol, uuid string
	}
	owners := func(s *IdentitySnapshot) map[key]int64 {
		m := map[key]int64{}
		for _, p := range s.Protocols {
			for _, u := range p.Users {
				m[key{p.Protocol, strings.ToLower(u.UUID)}] = u.AccountID
			}
		}
		return m
	}
	before, after := owners(applied.Data.IdentitySnapshot), owners(candidate.Data.IdentitySnapshot)
	changed := map[int64]bool{}
	for k, acc := range before {
		if other, ok := after[k]; !ok || other != acc {
			changed[acc] = true
		}
	}
	for k, acc := range after {
		if other, ok := before[k]; !ok || other != acc {
			changed[acc] = true
		}
	}
	return changed, true
}

// SameCandidate reports whether two responses carry the same delivered body.
func SameCandidate(a, b *ServerConfigResponse) bool {
	if a == nil || b == nil {
		return false
	}
	if a == b {
		return true
	}
	return a.bodyHash != "" && a.bodyHash == b.bodyHash && a.UseProtobuf == b.UseProtobuf
}

// Applied returns the candidate that is currently applied, or nil.
func (c *ServerClient) Applied() *ServerConfigResponse {
	if c == nil {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.applied
}

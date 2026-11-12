package panel

import "reflect"

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

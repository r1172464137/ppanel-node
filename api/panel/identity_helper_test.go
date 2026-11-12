package panel

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
)

// injectIdentity adds an identity snapshot to a JSON delivery payload that
// lacks one: one entry per delivered protocol type, with no users. The
// snapshot ID hashes the data object, so a different candidate gets a
// different ID.
func injectIdentity(payload string) string {
	var envelope map[string]any
	if err := json.Unmarshal([]byte(payload), &envelope); err != nil {
		return payload
	}
	data, ok := envelope["data"].(map[string]any)
	if !ok {
		return payload
	}
	if _, has := data["identity_snapshot"]; has {
		return payload
	}
	body, _ := json.Marshal(data)
	sum := sha256.Sum256(body)
	types := map[string]bool{}
	if list, ok := data["protocols"].([]any); ok {
		for _, p := range list {
			if m, ok := p.(map[string]any); ok {
				if t, ok := m["type"].(string); ok {
					types[t] = true
				}
			}
		}
	}
	names := make([]string, 0, len(types))
	for t := range types {
		names = append(names, t)
	}
	sort.Strings(names)
	protocols := []any{}
	for _, t := range names {
		protocols = append(protocols, map[string]any{"protocol": t, "users": []any{}})
	}
	data["identity_snapshot"] = map[string]any{"snapshot_id": hex.EncodeToString(sum[:]), "protocols": protocols}
	out, _ := json.Marshal(envelope)
	return string(out)
}

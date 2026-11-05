package outbound

import (
	"fmt"
	"strings"

	"github.com/perfect-panel/ppanel-node/api/panel"
)

// chainLinks includes existing raw references as well as the structured field.
// Built-in terminal tags are not custom graph vertices.
func chainLinks(outbounds []panel.Outbound) (map[string]string, error) {
	known := make(map[string]bool, len(outbounds))
	for _, out := range outbounds {
		known[out.ID] = true
	}
	links := make(map[string]string, len(outbounds))
	for _, out := range outbounds {
		via := out.ViaOutboundID
		stream, err := buildOutboundStreamConfig(out)
		if err != nil {
			return nil, err
		}
		if stream != nil && stream.SocketSettings != nil {
			raw := stream.SocketSettings.DialerProxy
			if raw != "" {
				if via != "" {
					return nil, fmt.Errorf("outbound %q raw dialerProxy conflicts with via_outbound_id", out.ID)
				}
				switch raw {
				case DefaultTag, BlockTag:
				default:
					if !strings.HasPrefix(raw, "routing_") {
						return nil, fmt.Errorf("outbound %q raw dialerProxy has no stable target", out.ID)
					}
					via = strings.TrimPrefix(raw, "routing_")
				}
			}
		}
		if via != "" && !known[via] {
			return nil, fmt.Errorf("outbound %q has a missing predecessor", out.ID)
		}
		links[out.ID] = via
	}
	for _, out := range outbounds {
		seen := map[string]bool{}
		for id := out.ID; id != ""; id = links[id] {
			if seen[id] {
				return nil, fmt.Errorf("outbound chain cycle at %q", out.ID)
			}
			seen[id] = true
		}
	}
	return links, nil
}

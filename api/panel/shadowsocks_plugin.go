package panel

import (
	"fmt"
	"strings"
)

// The node's Shadowsocks listener does not implement SIP003 plugins. Reject
// plugin semantics before publishing a candidate or building a listener.
func ValidateShadowsocksInboundPlugin(protocol Protocol) error {
	switch strings.ToLower(strings.TrimSpace(protocol.Plugin)) {
	case "", "none", "false", "off", "disabled":
	default:
		return fmt.Errorf("Shadowsocks inbound plugins are unsupported")
	}
	switch options := protocol.PluginOptions.(type) {
	case nil:
		return nil
	case string:
		if strings.TrimSpace(options) == "" {
			return nil
		}
	case map[string]any:
		if len(options) == 0 {
			return nil
		}
	}
	return fmt.Errorf("Shadowsocks inbound plugin options are unsupported")
}

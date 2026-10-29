package outbound

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/perfect-panel/ppanel-node/api/panel"
	"github.com/perfect-panel/ppanel-node/core/streamguard"
)

// A protocol may build successfully yet have no forwarding implementation;
// this allowlist is intentionally independent of Xray's configuration loader.
func validateOutboundCapability(item panel.Outbound) error {
	protocol := normalizeOutboundProtocol(item.Protocol)
	switch protocol {
	case "freedom", "blackhole", "http", "socks", "shadowsocks", "trojan", "vmess", "vless", "anytls", "hysteria":
	case "tuic":
		return fmt.Errorf("TUIC outbound is not implemented by this Xray build")
	default:
		return fmt.Errorf("unsupported ordered outbound protocol %q", item.Protocol)
	}
	if err := validateNoUOT(item); err != nil {
		return err
	}
	if strings.TrimSpace(item.Plugin) != "" || hasPluginOptions(item.PluginOptions) {
		return fmt.Errorf("outbound plugins are unsupported")
	}
	if strings.TrimSpace(item.Settings) != "" {
		decoder := json.NewDecoder(strings.NewReader(item.Settings))
		decoder.UseNumber()
		var value any
		if err := decoder.Decode(&value); err != nil {
			return fmt.Errorf("invalid outbound settings: %w", err)
		}
		if err := rejectRawPluginSettings(value); err != nil {
			return err
		}
	}
	if err := streamguard.ValidateURI("spider_x", item.SpiderX, true); err != nil {
		return err
	}
	if err := streamguard.ValidateURI("path", item.Path, false); err != nil {
		return err
	}
	// Validate the projected transport too, even when raw settings override it.
	if err := validateTransportName(item.Transport); err != nil {
		return err
	}
	stream, err := buildOutboundStreamConfig(item)
	if err != nil {
		return err
	}
	if err := streamguard.ValidateStream(stream, validateTransportName); err != nil {
		return err
	}
	if strings.TrimSpace(item.XHTTPExtra) != "" {
		if err := streamguard.ValidateXHTTPExtra([]byte(item.XHTTPExtra), validateTransportName); err != nil {
			return err
		}
	}
	if stream != nil {
		network := "tcp"
		if stream.Network != nil {
			network = strings.ToLower(strings.TrimSpace(string(*stream.Network)))
		}
		if stream.Method != nil {
			network = strings.ToLower(strings.TrimSpace(string(*stream.Method)))
		}
		if protocol == "hysteria" && network != "hysteria" {
			return fmt.Errorf("Hysteria outbound requires Hysteria transport")
		}
		if protocol != "hysteria" && network == "hysteria" {
			return fmt.Errorf("Hysteria transport requires Hysteria outbound")
		}
	}
	return nil
}

func hasPluginOptions(value any) bool {
	switch v := value.(type) {
	case nil:
		return false
	case string:
		return strings.TrimSpace(v) != ""
	case map[string]any:
		return len(v) != 0
	default:
		return true
	}
}

func rejectRawPluginSettings(value any) error {
	switch v := value.(type) {
	case map[string]any:
		for key, child := range v {
			normal := strings.NewReplacer("_", "", "-", "").Replace(strings.ToLower(key))
			if normal == "plugin" || normal == "pluginopts" || normal == "pluginoptions" {
				if hasPluginOptions(child) {
					return fmt.Errorf("outbound plugins are unsupported")
				}
			} else if err := rejectRawPluginSettings(child); err != nil {
				return err
			}
		}
	case []any:
		for _, child := range v {
			if err := rejectRawPluginSettings(child); err != nil {
				return err
			}
		}
	}
	return nil
}

func validateTransportName(value string) error {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", "raw", "tcp", "ws", "websocket", "grpc", "httpupgrade", "xhttp", "splithttp", "kcp", "mkcp", "hysteria":
		return nil
	case "tuic":
		return fmt.Errorf("TUIC outbound transport dialer is not implemented")
	default:
		return fmt.Errorf("unsupported outbound transport %q", value)
	}
}

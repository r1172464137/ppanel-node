package core

import (
	"fmt"
	"strings"

	"github.com/perfect-panel/ppanel-node/api/panel"
	outboundbuilder "github.com/perfect-panel/ppanel-node/core/outbound"
	"github.com/perfect-panel/ppanel-node/core/streamguard"
)

func ValidateServerConfig(serverconfig *panel.ServerConfigResponse) error {
	if serverconfig == nil {
		return fmt.Errorf("server config is nil")
	}
	if serverconfig.Data == nil {
		return fmt.Errorf("server config data is nil")
	}
	if err := panel.ValidateDeliveryMetadata(serverconfig.Data); err != nil {
		return err
	}
	if err := outboundbuilder.ValidateOrdered(serverconfig.Data); err != nil {
		return fmt.Errorf("ordered routing v1 required: %w", err)
	}
	if err := outboundbuilder.ValidateDNS(serverconfig.Data); err != nil {
		return err
	}
	for i, protocol := range *serverconfig.Data.Protocols {
		if protocol.UoT || protocol.UoTVersion != 0 {
			return fmt.Errorf("protocol[%d] configured UDP-over-TCP is unsupported", i)
		}
		if err := streamguard.ValidateNoUOTValue(protocol.PluginOptions); err != nil {
			return fmt.Errorf("protocol[%d]: %w", i, err)
		}
		if strings.TrimSpace(protocol.XHTTPExtra) != "" {
			if err := streamguard.ValidateNoUOTJSON([]byte(protocol.XHTTPExtra)); err != nil {
				return fmt.Errorf("protocol[%d]: %w", i, err)
			}
		}
		if !panel.IsSupportedProtocol(protocol.Type) {
			if protocol.Enable {
				return fmt.Errorf("protocol[%d] %q is enabled but unsupported", i, protocol.Type)
			}
			continue
		}
		if err := validateProtocol(protocol); err != nil {
			return fmt.Errorf("protocol[%d] %s config invalid: %w", i, protocol.Type, err)
		}
	}
	return nil
}

func validateProtocol(protocol panel.Protocol) error {
	if protocol.Security == "reality" && (protocol.RealityXver < 0 || protocol.RealityXver > 2) {
		return fmt.Errorf("reality_xver must be 0, 1 or 2")
	}
	if !protocol.Enable {
		return nil
	}
	if strings.TrimSpace(protocol.Type) == "" {
		return fmt.Errorf("type is required")
	}
	if protocol.Port <= 0 || protocol.Port > 65535 {
		return fmt.Errorf("port must be between 1 and 65535")
	}
	if err := streamguard.ValidateURI("path", protocol.Path, false); err != nil {
		return err
	}
	if err := streamguard.ValidateURI("obfs_path", protocol.ObfsPath, false); err != nil {
		return err
	}
	if strings.TrimSpace(protocol.XHTTPExtra) != "" {
		if err := streamguard.ValidateXHTTPExtra([]byte(protocol.XHTTPExtra), nil); err != nil {
			return err
		}
	}
	if strings.EqualFold(strings.TrimSpace(protocol.Type), "shadowsocks") {
		if err := panel.ValidateShadowsocksInboundPlugin(protocol); err != nil {
			return err
		}
	}

	switch protocol.Type {
	case "vless", "vmess", "trojan":
		if err := validateStreamProtocol(protocol); err != nil {
			return err
		}
	case "shadowsocks":
		if strings.TrimSpace(protocol.Cipher) == "" {
			return fmt.Errorf("cipher is required")
		}
		switch strings.ToLower(strings.TrimSpace(protocol.Cipher)) {
		case "none", "plain":
			return fmt.Errorf("Shadowsocks cipher %q is no longer supported by Xray", protocol.Cipher)
		}
	case "tuic", "hysteria", "hysteria2":
		if err := validateTLSConfig(protocol); err != nil {
			return err
		}
	case "anytls":
	}
	return nil
}

func validateStreamProtocol(protocol panel.Protocol) error {
	if strings.TrimSpace(protocol.Transport) == "" {
		return fmt.Errorf("transport is required")
	}
	switch protocol.Transport {
	case "tcp", "ws", "websocket", "grpc", "httpupgrade", "splithttp", "xhttp":
	default:
		return fmt.Errorf("unsupported transport %q", protocol.Transport)
	}

	switch protocol.Security {
	case "", "none":
	case "tls":
		if err := validateTLSConfig(protocol); err != nil {
			return err
		}
	case "reality":
		if strings.TrimSpace(protocol.RealityPrivateKey) == "" {
			return fmt.Errorf("reality_private_key is required")
		}
		if strings.TrimSpace(protocol.RealityShortID) == "" {
			return fmt.Errorf("reality_short_id is required")
		}
		if strings.TrimSpace(protocol.SNI) == "" {
			return fmt.Errorf("sni is required for reality")
		}
		if protocol.RealityServerPort <= 0 || protocol.RealityServerPort > 65535 {
			return fmt.Errorf("reality_server_port must be between 1 and 65535")
		}
	default:
		return fmt.Errorf("unsupported security %q", protocol.Security)
	}

	if protocol.Type == "vless" {
		return validateVlessEncryption(protocol)
	}
	return nil
}

func validateTLSConfig(protocol panel.Protocol) error {
	switch strings.TrimSpace(protocol.CertMode) {
	case "", "none", "file":
		return nil
	case "self", "dns", "http":
		if strings.TrimSpace(protocol.SNI) == "" {
			return fmt.Errorf("sni is required for tls cert_mode %q", protocol.CertMode)
		}
		return nil
	default:
		return fmt.Errorf("unsupported cert_mode %q", protocol.CertMode)
	}
}

func validateVlessEncryption(protocol panel.Protocol) error {
	if protocol.Encryption == "" || protocol.Encryption == "none" {
		return nil
	}
	if protocol.Encryption != "mlkem768x25519plus" {
		return fmt.Errorf("unsupported vless encryption %q", protocol.Encryption)
	}
	if strings.TrimSpace(protocol.EncryptionMode) == "" {
		return fmt.Errorf("encryption_mode is required")
	}
	switch protocol.EncryptionMode {
	case "native", "xorpub", "random":
	default:
		return fmt.Errorf("unsupported encryption_mode %q", protocol.EncryptionMode)
	}
	if strings.TrimSpace(protocol.EncryptionTicket) == "" {
		return fmt.Errorf("encryption_ticket is required")
	}
	if strings.TrimSpace(protocol.EncryptionPrivateKey) == "" {
		return fmt.Errorf("encryption_private_key is required")
	}
	return nil
}

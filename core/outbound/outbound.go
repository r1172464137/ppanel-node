package outbound

import (
	"encoding/json"
	"fmt"

	"github.com/xtls/xray-core/core"
	coreConf "github.com/xtls/xray-core/infra/conf"
)

// build default freedom outbund
// buildDefaultOutbound builds the node-direct Freedom outbound. Its domain
// strategy follows the target IP preference: prefer a family when both are
// available, never disable the other one.
func buildDefaultOutbound(preference string) (*core.OutboundHandlerConfig, error) {
	strategy := "UseIP"
	switch preference {
	case "prefer_ipv4":
		strategy = "UseIPv4v6"
	case "prefer_ipv6":
		strategy = "UseIPv6v4"
	}
	outboundDetourConfig := &coreConf.OutboundDetourConfig{}
	outboundDetourConfig.Protocol = "freedom"
	outboundDetourConfig.Tag = DefaultTag
	//sendthrough := "origin"
	//outboundDetourConfig.SendThrough = &sendthrough

	proxySetting := &coreConf.FreedomConfig{
		DomainStrategy: strategy,
	}
	var setting json.RawMessage
	setting, err := json.Marshal(proxySetting)
	if err != nil {
		return nil, fmt.Errorf("marshal proxy config error: %s", err)
	}
	outboundDetourConfig.Settings = &setting
	return outboundDetourConfig.Build()
}

// build block outbund
func buildBlockOutbound() (*core.OutboundHandlerConfig, error) {
	outboundDetourConfig := &coreConf.OutboundDetourConfig{}
	outboundDetourConfig.Protocol = "blackhole"
	outboundDetourConfig.Tag = BlockTag
	return outboundDetourConfig.Build()
}

// build dns outbound
func buildDnsOutbound() (*core.OutboundHandlerConfig, error) {
	outboundDetourConfig := &coreConf.OutboundDetourConfig{}
	outboundDetourConfig.Protocol = "dns"
	outboundDetourConfig.Tag = DNSTag
	return outboundDetourConfig.Build()
}

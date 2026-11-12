package core

import (
	"net"

	outboundbuilder "github.com/perfect-panel/ppanel-node/core/outbound"

	"github.com/perfect-panel/ppanel-node/api/panel"
)

// hasPublicIPv6 checks if the machine has a public IPv6 address
func hasPublicIPv6() bool {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return false
	}
	for _, addr := range addrs {
		ipNet, ok := addr.(*net.IPNet)
		if !ok {
			continue
		}
		ip := ipNet.IP
		// Check if it's IPv6, not loopback, not link-local, not private/ULA
		if ip.To4() == nil && !ip.IsLoopback() && !ip.IsLinkLocalUnicast() && !ip.IsPrivate() {
			return true
		}
	}
	return false
}

// GetCustomConfig compiles DNS, outbounds, the router and the account default
// map. inboundTag returns the Xray inbound tag of a delivered protocol.
func GetCustomConfig(serverconfig *panel.ServerConfigResponse, inboundTag func(protocol string) string) (*outboundbuilder.BuildResult, error) {
	return outboundbuilder.Build(serverconfig, hasPublicIPv6(), inboundTag)
}

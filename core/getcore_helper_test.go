package core

import (
	"github.com/perfect-panel/ppanel-node/api/panel"
	"github.com/perfect-panel/ppanel-node/conf"
	"github.com/xtls/xray-core/core"
)

// getCore builds and creates an (unstarted) Xray instance for tests that
// exercise the compiled configuration directly.
func getCore(c *conf.Conf, serverconfig *panel.ServerConfigResponse) (*core.Instance, error) {
	cfg, _, err := buildCoreConfig(c, v3(serverconfig))
	if err != nil {
		return nil, err
	}
	return core.New(cfg)
}

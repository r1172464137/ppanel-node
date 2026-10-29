package cmd

import (
	"github.com/perfect-panel/ppanel-node/common/logx"
	"github.com/perfect-panel/ppanel-node/conf"
)

// Called once, only after the first candidate and its listeners are applied.
func initializeProcessServices(c *conf.Conf) (*logx.Handle, *pprofManager) {
	handle, err := logx.Setup(logx.Config{Level: c.LogConfig.Level, Output: c.LogConfig.Output})
	if err != nil {
		handle, _ = logx.Setup(logx.Config{Level: c.LogConfig.Level})
		logx.Component("server").WithError(err).Error("初始化日志失败，使用stdout替代")
	}
	pprof := &pprofManager{}
	if err := pprof.Init(c.PprofPort); err != nil {
		logx.Component("server").WithError(err).Error("启动pprof服务失败")
	}
	return handle, pprof
}

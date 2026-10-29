package cmd

import (
	"context"
	"fmt"
	_ "net/http/pprof"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/perfect-panel/ppanel-node/api/panel"
	"github.com/perfect-panel/ppanel-node/common/logx"
	"github.com/perfect-panel/ppanel-node/conf"
	"github.com/perfect-panel/ppanel-node/core"
	"github.com/perfect-panel/ppanel-node/node"
	"github.com/spf13/cobra"
)

var (
	config string
	watch  bool
)

var serverCommand = cobra.Command{
	Use:   "server",
	Short: "Run ppnode server",
	Run:   serverHandle,
	Args:  cobra.NoArgs,
}

func init() {
	serverCommand.PersistentFlags().
		StringVarP(&config, "config", "c",
			"/etc/PPanel-node/config.yml", "config file path")
	serverCommand.PersistentFlags().
		BoolVarP(&watch, "watch", "w",
			true, "watch file path change")
	command.AddCommand(&serverCommand)
}

func serverHandle(_ *cobra.Command, _ []string) {
	showVersion()
	c := conf.New()
	err := c.LoadFromPath(config)
	if err != nil {
		logx.Component("server").WithError(err).Error("读取配置文件失败，将在启动重试中重新读取")
		c = conf.New()
	}
	var logHandle *logx.Handle
	defer func() { _ = logHandle.Close() }()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	p := panel.NewServerClient(&c.ApiConfig)
	reporter := newServerReporter(p, time.Minute)
	reporter.start()
	defer reporter.close()
	reloadCh := make(chan struct{}, 1)
	var nodes *node.Node
	var xraycore *core.XrayCore
	var serverconfig *panel.ServerConfigResponse
	backoff := 5 * time.Second
	for {
		var attemptConf *conf.Conf
		nodes, xraycore, serverconfig, attemptConf, err = initialAttemptFromFile(ctx, config, reporter, reloadCh)
		if err == nil {
			c = attemptConf
			break
		}
		if ctx.Err() != nil {
			return
		}
		logx.Component("server").WithError(err).Error("启动候选失败，将重试")
		reporter.reportSoon()
		timer := time.NewTimer(backoff)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
		backoff = min(backoff*2, time.Minute)
	}
	// A failed initial candidate may have used stale local settings. Only the
	// first successfully applied configuration initializes process services.
	var pprof *pprofManager
	logHandle, pprof = initializeProcessServices(c)
	defer pprof.Close()
	defer func() { _ = xraycore.Close() }()
	defer func() {
		nodes.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := nodes.FlushTraffic(ctx); err != nil {
			logx.Component("server").WithError(err).Error("退出前上报剩余流量失败")
		}
	}()
	reporter.reportSoon()
	logx.Component("server").WithField("server_total", serverconfig.Data.Total).Info("节点启动成功")
	if watch {
		// On file change, just signal reload; do not run reload concurrently here
		err = c.Watch(config, func() {
			select {
			case reloadCh <- struct{}{}:
			default: // drop if a reload is already queued
			}
		})
		if err != nil {
			logx.Component("server").WithError(err).Error("启动配置监听失败")
			return
		}
	}
	// clear memory
	runtime.GC()

	var retry *time.Timer
	var retryC <-chan time.Time
	backoff = 5 * time.Second
	defer func() {
		if retry != nil {
			retry.Stop()
		}
	}()
	for {
		select {
		case <-ctx.Done():
			return
		case <-reloadCh:
		case <-retryC:
			retryC = nil
		}
		logx.Component("server").Info("收到重载信号，正在重新加载配置")
		newLogHandle, err := reload(config, &nodes, &xraycore, logHandle)
		if err != nil {
			logx.Component("server").WithError(err).Error("重载失败")
			reporter.reportSoon()
			if retry == nil {
				retry = time.NewTimer(backoff)
			} else {
				if !retry.Stop() {
					select {
					case <-retry.C:
					default:
					}
				}
				retry.Reset(backoff)
			}
			retryC = retry.C
			backoff = min(backoff*2, time.Minute)
			continue
		}
		logHandle = newLogHandle
		if err := pprof.CheckReload(xraycore.Config.PprofPort); err != nil {
			logx.Component("server").Warn("pprof 端口变更需重启进程；不会创建第二个监听")
		}
		if err := reporter.setClient(xraycore.Client); err != nil {
			logx.Component("server").WithError(err).Error("状态 client 代际切换失败")
		}
		reporter.reportSoon()
		if retry != nil {
			retry.Stop()
		}
		retryC, backoff = nil, 5*time.Second
	}

}

func reload(config string, nodes **node.Node, xcore **core.XrayCore, logHandle *logx.Handle) (*logx.Handle, error) {
	// Preserve old reload channel so new core continues to receive signals
	var oldReloadCh chan struct{}
	if xcore != nil && *xcore != nil {
		oldReloadCh = (*xcore).ReloadCh
	}

	newConf := conf.New()
	if err := newConf.LoadFromPath(config); err != nil {
		if xcore != nil && *xcore != nil && (*xcore).Client != nil {
			(*xcore).Client.RecordFailure(nil, panel.StageConfig)
		}
		return logHandle, err
	}
	if err := panel.ValidateAPITimeout(newConf.ApiConfig.Timeout); err != nil {
		if xcore != nil && *xcore != nil && (*xcore).Client != nil {
			(*xcore).Client.RecordFailure(nil, panel.StageConfig)
		}
		return logHandle, err
	}
	logx.Component("server").Info("新配置加载成功")
	p := panel.NewServerClient(&newConf.ApiConfig)
	if xcore != nil && *xcore != nil && (*xcore).Client != nil {
		old := (*xcore).Client
		if old.APIHost == newConf.ApiConfig.ApiHost && old.ServerId == newConf.ApiConfig.ServerId && old.SecretKey == newConf.ApiConfig.SecretKey {
			if old.Timeout == newConf.ApiConfig.Timeout {
				p = old
			} else {
				p.ShareCandidateState(old)
			}
		}
	}
	serverconfig, err := panel.GetServerConfig(context.Background(), p)
	if err != nil {
		p.RecordFailure(nil, panel.StageFetch)
		return logHandle, fmt.Errorf("fetch candidate: %w", err)
	}
	if serverconfig == nil {
		serverconfig = p.AppliedOrPending()
	}
	if err := validateCandidate(p, serverconfig); err != nil {
		p.RecordFailure(serverconfig, panel.StageValidate)
		return logHandle, fmt.Errorf("validate candidate: %w", err)
	}

	newCore := core.New(newConf, p)
	// Reattach reload channel
	newCore.ReloadCh = oldReloadCh
	if err := newCore.StartPrepared(serverconfig); err != nil {
		stage := panel.StageBuild
		if strings.HasPrefix(err.Error(), "start core:") {
			stage = panel.StageCoreStart
		}
		p.RecordFailure(serverconfig, stage)
		_ = newCore.Close()
		return logHandle, fmt.Errorf("%s candidate: %w", stage, err)
	}
	logx.Component("server").Info("新Xray核心启动成功")
	newNodes, err := node.New(newCore, newConf, serverconfig)
	if err != nil {
		p.RecordFailure(serverconfig, panel.StagePrepare)
		_ = newCore.Close()
		return logHandle, fmt.Errorf("prepare candidate: %w", err)
	}

	if err := newNodes.Prepare(); err != nil {
		p.RecordFailure(serverconfig, panel.StagePrepare)
		newNodes.Close()
		_ = newCore.Close()
		return logHandle, fmt.Errorf("prepare candidate: %w", err)
	}

	oldNodes := *nodes
	oldCore := *xcore
	newNodes.InheritTraffic(oldNodes)
	restore := func(stage string, cause error) (*logx.Handle, error) {
		p.RecordFailure(serverconfig, panel.StageForOperation(stage))
		cleanup := func() { newNodes.Close(); _ = newCore.Close() }
		var restart func() error
		if oldNodes != nil && oldCore != nil {
			restart = oldNodes.Start
		}
		restored, err := restorePrevious(stage, cause, cleanup, restart)
		if !restored {
			p.InvalidateApplied()
			p.RecordFailure(serverconfig, panel.StageRestore)
			if oldCore != nil && oldCore.Client != nil && oldCore.Client != p {
				oldCore.Client.InvalidateApplied()
				oldCore.Client.RecordFailure(nil, panel.StageRestore)
			}
		}
		return logHandle, err
	}
	// Keep the old core and the prepared node snapshots until the new listeners
	// are bound. Rollback never fetches users or certificates from the panel.
	if oldNodes != nil {
		if err := oldNodes.Stop(); err != nil {
			return restore("stop", err)
		}
	}
	if err := newNodes.Start(); err != nil {
		return restore("bind", err)
	}

	if err := newCore.Activate(serverconfig); err != nil {
		return restore("monitor", err)
	}
	if err := p.Commit(serverconfig); err != nil {
		return restore("prepare", fmt.Errorf("commit candidate: %w", err))
	}
	*nodes = newNodes
	*xcore = newCore
	if oldNodes != nil {
		oldNodes.Close()
	}
	if oldCore != nil {
		_ = oldCore.Close()
	}
	if p.HasPending() && oldReloadCh != nil {
		select {
		case oldReloadCh <- struct{}{}:
		default:
		}
	}
	logx.Component("server").Info("实例切换成功")
	newLogHandle := logHandle
	if h, err := logx.Setup(logx.Config{
		Level:  newConf.LogConfig.Level,
		Output: newConf.LogConfig.Output,
	}); err != nil {
		logx.Component("server").WithError(err).Error("重载日志配置失败，继续使用旧日志配置")
	} else {
		if logHandle != nil {
			_ = logHandle.Close()
		}
		newLogHandle = h
	}
	logx.Component("server").WithField("server_total", serverconfig.Data.Total).Info("节点重载成功")
	runtime.GC()
	return newLogHandle, nil
}

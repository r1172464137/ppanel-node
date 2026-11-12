package core

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/perfect-panel/ppanel-node/api/panel"
	"github.com/perfect-panel/ppanel-node/common/logx"
	"github.com/perfect-panel/ppanel-node/common/task"
	"github.com/perfect-panel/ppanel-node/conf"
	"github.com/perfect-panel/ppanel-node/core/app/dispatcher"
	_ "github.com/perfect-panel/ppanel-node/core/distro/all"
	"github.com/perfect-panel/ppanel-node/limiter"
	"github.com/xtls/xray-core/app/proxyman"
	"github.com/xtls/xray-core/app/stats"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/inbound"
	"github.com/xtls/xray-core/features/outbound"
	"github.com/xtls/xray-core/features/routing"
	coreConf "github.com/xtls/xray-core/infra/conf"
	"google.golang.org/protobuf/proto"
)

type AddUsersParams struct {
	Tag   string
	Users []panel.UserInfo
	*panel.NodeInfo
}

type XrayCore struct {
	Config                      *conf.Conf
	Client                      *panel.ServerClient
	ReloadCh                    chan struct{}
	serverConfigMonitorPeriodic *task.Task
	monitorMu                   sync.Mutex
	lastSignaledCandidate       string
	access                      sync.Mutex
	Server                      *core.Instance
	LimiterManager              *limiter.Manager
	users                       *UserMap
	ihm                         inbound.Manager
	ohm                         outbound.Manager
	dispatcher                  *dispatcher.DefaultDispatcher
	// built is the compiled Xray configuration of the current candidate. It
	// survives StopInstance so a rollback can start the same configuration
	// again without contacting the panel.
	built *core.Config
}

type UserMap struct {
	uidMap  map[string]int
	mapLock sync.RWMutex
}

func New(config *conf.Conf, client *panel.ServerClient) *XrayCore {
	core := &XrayCore{
		Config:         config,
		Client:         client,
		LimiterManager: limiter.NewManager(),
		users: &UserMap{
			uidMap: make(map[string]int),
		},
	}
	return core
}

// Start retains the existing standalone behavior. Reload prepares a core
// without its monitor and activates it only after the listener switch commits.
func (v *XrayCore) Start(serverconfig *panel.ServerConfigResponse) error {
	if err := v.Build(serverconfig); err != nil {
		return err
	}
	if err := v.StartInstance(); err != nil {
		return err
	}
	if err := v.Activate(serverconfig); err != nil {
		_ = v.StopInstance()
		return fmt.Errorf("start core monitor: %w", err)
	}
	return nil
}

// StartPrepared builds and starts the instance without its monitor. It is
// only safe when no other Xray instance is serving (initial startup).
func (v *XrayCore) StartPrepared(serverconfig *panel.ServerConfigResponse) error {
	if err := v.Build(serverconfig); err != nil {
		return err
	}
	return v.StartInstance()
}

// Build validates the candidate and compiles its Xray configuration without
// creating an instance. Creating an instance (core.New) re-points Xray's
// process-wide system dialer - the DNS client and outbound manager used by
// dialerProxy and domain-strategy dialing - so it must not happen while
// another instance still serves traffic. Build is pure and safe at any time.
func (v *XrayCore) Build(serverconfig *panel.ServerConfigResponse) error {
	v.access.Lock()
	defer v.access.Unlock()
	if serverconfig == nil {
		return fmt.Errorf("server config is nil")
	}
	if err := panel.ValidateDeliveryMetadata(serverconfig.Data); err != nil {
		return err
	}
	cfg, err := buildCoreConfig(v.Config, serverconfig)
	if err != nil {
		return fmt.Errorf("build core: %w", err)
	}
	v.built = cfg
	return nil
}

// StartInstance creates and starts the Xray instance from the built
// configuration. Callers must have stopped every other instance first.
func (v *XrayCore) StartInstance() error {
	v.access.Lock()
	defer v.access.Unlock()
	if v.built == nil {
		return fmt.Errorf("build core: configuration not built")
	}
	if v.Server != nil {
		return fmt.Errorf("start core: instance already running")
	}
	server, err := core.New(v.built)
	if err != nil {
		return fmt.Errorf("start core: create Xray instance: %w", err)
	}
	if err := server.Start(); err != nil {
		_ = server.Close()
		return fmt.Errorf("start core: %w", err)
	}
	v.Server = server
	v.ihm = server.GetFeature(inbound.ManagerType()).(inbound.Manager)
	v.ohm = server.GetFeature(outbound.ManagerType()).(outbound.Manager)
	v.dispatcher = server.GetFeature(routing.DispatcherType()).(*dispatcher.DefaultDispatcher)
	v.dispatcher.LimiterManager = v.LimiterManager
	v.users.mapLock.Lock()
	v.users.uidMap = make(map[string]int)
	v.users.mapLock.Unlock()
	return nil
}

// StopInstance closes the Xray instance - every listener and every connection
// it carries - but keeps the built configuration, limiters, traffic counters
// and monitor, so
// StartInstance can bring the same configuration back during a rollback.
func (v *XrayCore) StopInstance() error {
	if v == nil {
		return nil
	}
	v.access.Lock()
	defer v.access.Unlock()
	server := v.Server
	// The dispatcher is kept: its per-user traffic counters stay readable so
	// the controllers can collect what the closed connections carried.
	v.Server, v.ihm, v.ohm = nil, nil, nil
	if server == nil {
		return nil
	}
	// Closing the Xray instance does not end connections that are already
	// relaying; cut them explicitly so nothing keeps running on the retired
	// configuration (or uncounted).
	if v.dispatcher != nil {
		v.dispatcher.CloseAllLinks()
	}
	return server.Close()
}

// Running reports whether an Xray instance is currently started.
func (v *XrayCore) Running() bool {
	if v == nil {
		return false
	}
	v.access.Lock()
	defer v.access.Unlock()
	return v.Server != nil
}

func (v *XrayCore) Activate(serverconfig *panel.ServerConfigResponse) error {
	v.access.Lock()
	defer v.access.Unlock()
	if v.Server == nil {
		return fmt.Errorf("core is not running")
	}
	if v.serverConfigMonitorPeriodic == nil {
		return v.startTasks(serverconfig)
	}
	return nil
}

func (v *XrayCore) Close() error {
	if v == nil {
		return nil
	}
	v.access.Lock()
	defer v.access.Unlock()
	if v.serverConfigMonitorPeriodic != nil {
		v.serverConfigMonitorPeriodic.Close()
		v.serverConfigMonitorPeriodic = nil
	}
	server := v.Server
	v.Config = nil
	v.built = nil
	v.ihm = nil
	v.ohm = nil
	v.dispatcher = nil
	v.LimiterManager = nil
	v.Server = nil
	if server == nil {
		return nil
	}
	err := server.Close()
	if err != nil {
		return err
	}
	return nil
}

// buildCoreConfig compiles the candidate into an Xray configuration. It has no
// side effects; see Build for why instance creation is a separate step.
func buildCoreConfig(c *conf.Conf, serverconfig *panel.ServerConfigResponse) (*core.Config, error) {
	// Log Config
	coreLogConfig := &coreConf.LogConfig{
		LogLevel:  c.LogConfig.Level,
		AccessLog: c.LogConfig.Access,
		ErrorLog:  c.LogConfig.Output,
	}
	// Custom config
	dnsConfig, outBoundConfig, routeConfig, err := GetCustomConfig(serverconfig)
	if err != nil {
		return nil, fmt.Errorf("build custom configuration: %w", err)
	}
	// Inbound config
	var inBoundConfig []*core.InboundHandlerConfig

	// Policy config
	levelPolicyConfig := &coreConf.Policy{
		StatsUserUplink:   true,
		StatsUserDownlink: true,
		Handshake:         proto.Uint32(4),
		// ppnode lowered this to 30s, which xray's polling activity timer turns
		// into a ~60s effective timeout, dropping idle-but-healthy long-lived
		// connections (interactive SSH, database sessions, MQTT/WebSocket, etc.).
		// Restore it to 120 — the value used by upstream wyx2685/v2node, which
		// this project is modified from.
		ConnectionIdle: proto.Uint32(120),
		UplinkOnly:     proto.Uint32(2),
		DownlinkOnly:   proto.Uint32(4),
		BufferSize:     proto.Int32(64),
	}
	corePolicyConfig := &coreConf.PolicyConfig{}
	corePolicyConfig.Levels = map[uint32]*coreConf.Policy{0: levelPolicyConfig}
	policyConfig, _ := corePolicyConfig.Build()
	// Build Xray conf
	config := &core.Config{
		App: []*serial.TypedMessage{
			serial.ToTypedMessage(coreLogConfig.Build()),
			serial.ToTypedMessage(&dispatcher.Config{}),
			serial.ToTypedMessage(&stats.Config{}),
			serial.ToTypedMessage(&proxyman.InboundConfig{}),
			serial.ToTypedMessage(&proxyman.OutboundConfig{}),
			serial.ToTypedMessage(policyConfig),
			serial.ToTypedMessage(dnsConfig),
			serial.ToTypedMessage(routeConfig),
		},
		Inbound:  inBoundConfig,
		Outbound: outBoundConfig,
	}
	return config, nil
}

// SetMonitorInterval applies a new panel pull interval to the running config
// monitor without touching the Xray instance.
func (v *XrayCore) SetMonitorInterval(seconds int) error {
	interval, err := panel.IntervalDuration(seconds)
	if err != nil {
		return fmt.Errorf("pull interval: %w", err)
	}
	v.access.Lock()
	monitor := v.serverConfigMonitorPeriodic
	v.access.Unlock()
	if monitor == nil {
		return nil
	}
	return monitor.SetInterval(interval)
}

func (c *XrayCore) startTasks(serverconfig *panel.ServerConfigResponse) error {
	if serverconfig == nil || serverconfig.Data == nil {
		return fmt.Errorf("missing configuration")
	}
	interval, err := panel.IntervalDuration(serverconfig.Data.PullInterval)
	if err != nil {
		return fmt.Errorf("pull interval: %w", err)
	}
	monitor := &task.Task{Interval: interval, Execute: c.ServerConfigMonitor, ReloadCh: c.ReloadCh}
	// Recheck immediately around cutover: a retired old client's in-flight
	// observation is deliberately fenced and must be rediscovered promptly.
	if err := monitor.Start(true); err != nil {
		return err
	}
	c.serverConfigMonitorPeriodic = monitor
	return nil
}

func (c *XrayCore) ServerConfigMonitor(ctx context.Context) (err error) {
	if c.Client == nil {
		return nil
	}
	newServerConfig, err := panel.GetServerConfig(ctx, c.Client)
	if err != nil {
		if ctx.Err() != nil || errors.Is(err, panel.ErrRetiredClient) {
			return nil
		}
		c.Client.RecordFailure(nil, panel.StageFetch)
		logx.Component("xray").Error("获取服务端配置失败，已记录脱敏 fetch 状态")
		return nil
	}
	if newServerConfig == nil {
		c.monitorMu.Lock()
		c.lastSignaledCandidate = ""
		c.monitorMu.Unlock()
		return nil
	}
	c.monitorMu.Lock()
	key := newServerConfig.CandidateKey()
	if key != "" && key == c.lastSignaledCandidate {
		c.monitorMu.Unlock()
		return nil
	}
	c.lastSignaledCandidate = key
	c.monitorMu.Unlock()
	if newServerConfig != nil {
		logx.Component("xray").Info("检测到服务端配置变更，已投递重载信号")
		// Non-blocking signal to avoid goroutine stuck when channel is full or nil
		if c.ReloadCh != nil {
			select {
			case c.ReloadCh <- struct{}{}:
			default:
			}
		}
	}
	return nil
}

package core

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/perfect-panel/ppanel-node/api/panel"
	"github.com/perfect-panel/ppanel-node/common/format"
	"github.com/perfect-panel/ppanel-node/common/logx"
	"github.com/perfect-panel/ppanel-node/common/task"
	"github.com/perfect-panel/ppanel-node/conf"
	"github.com/perfect-panel/ppanel-node/core/app/dispatcher"
	_ "github.com/perfect-panel/ppanel-node/core/distro/all"
	outboundbuilder "github.com/perfect-panel/ppanel-node/core/outbound"
	"github.com/perfect-panel/ppanel-node/limiter"
	"github.com/xtls/xray-core/app/proxyman"
	"github.com/xtls/xray-core/app/stats"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/core"
	featureDNS "github.com/xtls/xray-core/features/dns"
	"github.com/xtls/xray-core/features/inbound"
	"github.com/xtls/xray-core/features/outbound"
	"github.com/xtls/xray-core/features/routing"
	coreConf "github.com/xtls/xray-core/infra/conf"
	"github.com/xtls/xray-core/transport/internet"
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
	failedClosed                atomic.Bool
	Server                      *core.Instance
	preparedConfig              *core.Config
	LimiterManager              *limiter.Manager
	users                       *UserMap
	ihm                         inbound.Manager
	ohm                         outbound.Manager
	dispatcher                  *dispatcher.DefaultDispatcher
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
	return v.start(serverconfig, true)
}

func (v *XrayCore) StartPrepared(serverconfig *panel.ServerConfigResponse) error {
	return v.start(serverconfig, false)
}

// Prepare compiles a candidate without replacing Xray's process-global dialer.
func (v *XrayCore) Prepare(serverconfig *panel.ServerConfigResponse) error {
	v.access.Lock()
	defer v.access.Unlock()
	config, err := coreConfiguration(v.Config, serverconfig)
	if err != nil {
		return err
	}
	v.preparedConfig = config
	return nil
}

func (v *XrayCore) Quiesce() {
	if v != nil && v.dispatcher != nil {
		v.dispatcher.Quiesce()
	}
}

// RestoreDialer is used only after candidate cleanup and before old listeners
// restart; two active generations must not share the global dialer manager.
func (v *XrayCore) RestoreDialer() error {
	if v == nil || v.Server == nil || v.FailedClosed() {
		return fmt.Errorf("previous core is unavailable")
	}
	internet.InitSystemDialer(v.Server.GetFeature(featureDNS.ClientType()).(featureDNS.Client), v.ohm)
	v.dispatcher.Resume()
	return nil
}

func (v *XrayCore) start(serverconfig *panel.ServerConfigResponse, monitor bool) error {
	v.access.Lock()
	defer v.access.Unlock()
	if serverconfig == nil {
		return fmt.Errorf("server config is nil")
	}
	if err := panel.ValidateDeliveryMetadata(serverconfig.Data); err != nil {
		return err
	}
	var server *core.Instance
	var err error
	if v.preparedConfig != nil {
		server, err = newCoreInstance(v.preparedConfig, serverconfig)
		v.preparedConfig = nil
	} else {
		server, err = getCore(v.Config, serverconfig)
	}
	if err != nil {
		return fmt.Errorf("build core: %w", err)
	}
	v.Server = server
	if err := v.Server.Start(); err != nil {
		_ = v.Server.Close()
		v.Server = nil
		return fmt.Errorf("start core: %w", err)
	}
	v.ihm = v.Server.GetFeature(inbound.ManagerType()).(inbound.Manager)
	v.ohm = v.Server.GetFeature(outbound.ManagerType()).(outbound.Manager)
	v.dispatcher = v.Server.GetFeature(routing.DispatcherType()).(*dispatcher.DefaultDispatcher)
	v.dispatcher.LimiterManager = v.LimiterManager
	if p := serverconfig.Data.Routing; p != nil && p.Version == 2 && serverconfig.Data.IdentitySnapshot != nil {
		byAccount := make(map[int64]string, len(p.UserDefaults))
		for _, entry := range p.UserDefaults {
			tag := entry.OutboundID
			switch tag {
			case "direct":
				tag = "Default"
			case "block":
				tag = "block"
			default:
				tag = "routing_" + tag
			}
			byAccount[entry.UserID] = tag
		}
		fallback := make(map[string]string)
		for _, protocol := range serverconfig.Data.IdentitySnapshot.Protocols {
			tag := panel.InboundTag(v.Config.ApiConfig.ApiHost, protocol.Protocol, v.Config.ApiConfig.ServerId)
			for _, user := range protocol.Users {
				if target := byAccount[user.AccountID]; target != "" {
					fallback[format.UserTag(tag, user.Uuid)] = target
				}
			}
		}
		v.dispatcher.SetUserFallback(fallback)
	}
	if monitor {
		if err := v.startTasks(serverconfig); err != nil {
			_ = v.Server.Close()
			v.Server, v.ihm, v.ohm, v.dispatcher = nil, nil, nil, nil
			return fmt.Errorf("start core monitor: %w", err)
		}
	}
	return nil
}

// FailClosed stops the running core when an inbound cannot be safely restored.
// The existing reload path may replace it, but it must never be restarted in place.
func (v *XrayCore) FailClosed() error {
	v.access.Lock()
	defer v.access.Unlock()
	if v.failedClosed.Swap(true) {
		return nil
	}
	if v.Client != nil {
		v.Client.InvalidateApplied()
		v.Client.RecordFailure(nil, panel.StageRestore)
	}
	if v.Server == nil {
		return nil
	}
	err := v.Server.Close()
	if v.dispatcher != nil {
		v.dispatcher.LinkManagers.Range(func(_, value any) bool {
			value.(*dispatcher.LinkManager).CloseAll()
			return true
		})
	}
	return err
}

func (v *XrayCore) FailedClosed() bool { return v.failedClosed.Load() }

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
	v.ihm = nil
	v.ohm = nil
	v.dispatcher = nil
	v.LimiterManager = nil
	v.Server = nil
	v.preparedConfig = nil
	if server == nil {
		return nil
	}
	err := server.Close()
	if err != nil {
		return err
	}
	return nil
}

func coreConfiguration(c *conf.Conf, serverconfig *panel.ServerConfigResponse) (*core.Config, error) {
	if c == nil || serverconfig == nil || serverconfig.Data == nil {
		return nil, fmt.Errorf("missing core configuration")
	}
	// Log Config
	coreLogConfig := &coreConf.LogConfig{
		LogLevel:  c.LogConfig.Level,
		AccessLog: c.LogConfig.Access,
		ErrorLog:  c.LogConfig.Output,
	}
	// The inbound tag includes the local panel endpoint and server ID.
	candidate := *serverconfig
	data := *serverconfig.Data
	candidate.Data = &data
	data.DeliveryAPIHost = c.ApiConfig.ApiHost
	data.DeliveryServerID = c.ApiConfig.ServerId
	// Custom config
	dnsConfig, outBoundConfig, routeConfig, err := GetCustomConfig(&candidate)
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

func getCore(c *conf.Conf, serverconfig *panel.ServerConfigResponse) (*core.Instance, error) {
	config, err := coreConfiguration(c, serverconfig)
	if err != nil {
		return nil, err
	}
	return newCoreInstance(config, serverconfig)
}

func newCoreInstance(config *core.Config, serverconfig *panel.ServerConfigResponse) (*core.Instance, error) {
	server, err := core.New(config)
	if err != nil {
		return nil, fmt.Errorf("create Xray instance: %w", err)
	}
	dispatch := server.GetFeature(routing.DispatcherType()).(*dispatcher.DefaultDispatcher)
	if p := serverconfig.Data.Routing; p != nil && p.Version == 2 {
		blocked := map[string]bool{"block": true}
		hasIPRules := false
		for _, rule := range p.Rules {
			if rule.Enabled != nil && *rule.Enabled && rule.Kind == "ip" {
				hasIPRules = true
			}
		}
		for _, outbound := range p.Outbounds {
			tag := "routing_" + outbound.ID
			switch strings.ToLower(outbound.Protocol) {
			case "block", "reject", "blackhole":
				blocked[tag] = true
			}
		}
		dispatch.SetIPRuleChecks(hasIPRules, blocked)
	}
	if p := serverconfig.Data.Routing; p != nil && p.DNSPolicy != nil {
		targets := make(map[string]dispatcher.DNSRouteTarget, len(p.DNSPolicy.Resolvers))
		for _, resolver := range p.DNSPolicy.Resolvers {
			host, port, err := outboundbuilder.PolicyDNSHost(resolver)
			if err != nil {
				_ = server.Close()
				return nil, err
			}
			target := dispatcher.DNSRouteTarget{Host: host, Port: xnet.Port(port)}
			if resolver.BootstrapIP != "" {
				target.Bootstrap = xnet.ParseAddress(resolver.BootstrapIP)
			}
			targets[outboundbuilder.PolicyDNSTag(resolver.ID)] = target
		}
		dispatch.SetDNSTargets(targets)
	}
	return server, nil
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

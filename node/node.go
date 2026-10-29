package node

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/perfect-panel/ppanel-node/common/task"

	"github.com/perfect-panel/ppanel-node/api/panel"
	"github.com/perfect-panel/ppanel-node/common/logx"
	"github.com/perfect-panel/ppanel-node/common/serverstatus"
	"github.com/perfect-panel/ppanel-node/conf"
	vCore "github.com/perfect-panel/ppanel-node/core"
)

type Node struct {
	controllers    []*Controller
	traffic        *trafficQueue
	reportPeriodic *task.Task
	pushInterval   time.Duration
	statusClient   *panel.ServerClient
}

func New(core *vCore.XrayCore, config *conf.Conf, serverconfig *panel.ServerConfigResponse) (*Node, error) {
	if err := vCore.ValidateServerConfig(serverconfig); err != nil {
		return nil, err
	}
	node := &Node{
		controllers: make([]*Controller, 0, len(*serverconfig.Data.Protocols)),
		traffic:     newTrafficQueue(),
	}
	if core != nil {
		node.statusClient = core.Client
	}
	pushDuration, err := panel.IntervalDuration(serverconfig.Data.PushInterval)
	if err != nil {
		return nil, err
	}
	pullDuration, err := panel.IntervalDuration(serverconfig.Data.PullInterval)
	if err != nil {
		return nil, err
	}
	pushinterval := int(pushDuration / time.Second)
	pullinterval := int(pullDuration / time.Second)
	node.pushInterval = pushDuration
	for _, nodeconfig := range *serverconfig.Data.Protocols {
		if !panel.IsSupportedProtocol(nodeconfig.Type) {
			if nodeconfig.Enable {
				return nil, fmt.Errorf("enabled protocol %q is unsupported", nodeconfig.Type)
			}
			logx.Component("node").WithField("protocol", nodeconfig.Type).Warn("节点不支持该协议，已跳过对应配置")
			continue
		}
		n := &panel.NodeInfo{
			Id:                     config.ApiConfig.ServerId,
			Type:                   nodeconfig.Type,
			TrafficReportThreshold: serverconfig.Data.TrafficReportThreshold,
			PushInterval:           pushinterval,
			PullInterval:           pullinterval,
			ACMEEmail:              config.ApiConfig.ACMEEmail,
			ACMECADirURL:           config.ApiConfig.ACMECADirURL,
			Protocol:               &nodeconfig,
		}
		p, err := panel.NewNodeClient(&conf.NodeApiConfig{
			APIHost:     config.ApiConfig.ApiHost,
			NodeType:    nodeconfig.Type,
			NodeID:      config.ApiConfig.ServerId,
			SecretKey:   config.ApiConfig.SecretKey,
			Timeout:     config.ApiConfig.Timeout,
			UseProtobuf: serverconfig.UseProtobuf,
		})
		if err != nil {
			return nil, err
		}
		if node.statusClient != nil {
			if err := node.statusClient.BindNodeClient(p); err != nil {
				return nil, err
			}
		}
		controller := NewController(core, p, n)
		controller.traffic = node.traffic
		node.controllers = append(node.controllers, controller)
	}

	return node, nil
}

func (n *Node) Prepare() error {
	for _, c := range n.controllers {
		if c != nil && c.info.Protocol.Enable {
			if err := c.Prepare(); err != nil {
				return err
			}
		}
	}
	return nil
}

// InheritTraffic keeps unacknowledged reports even if a protocol is removed.
func (n *Node) InheritTraffic(old *Node) {
	if old == nil {
		return
	}
	n.traffic = old.traffic
	for _, c := range n.controllers {
		c.traffic = n.traffic
	}
}

func (n *Node) Start() error {
	if err := n.Prepare(); err != nil {
		return err
	}
	for i := range n.controllers {
		if n.controllers[i] == nil {
			continue
		}
		if !n.controllers[i].info.Protocol.Enable {
			continue
		}
		err := n.controllers[i].Start()
		if err != nil {
			_ = n.Stop()
			return fmt.Errorf("启动节点 [%s-%s-%d] 失败: %s",
				n.controllers[i].apiClient.APIHost,
				n.controllers[i].info.Type,
				n.controllers[i].info.Id,
				err)
		}
	}
	if n.reportPeriodic == nil {
		n.reportPeriodic = &task.Task{Name: "reportNode", Interval: n.pushInterval, Execute: n.report}
	}
	if err := n.reportPeriodic.Start(false); err != nil {
		_ = n.Stop()
		return fmt.Errorf("start traffic report task: %w", err)
	}
	return nil
}

func (n *Node) report(ctx context.Context) error {
	snapshots := make(map[*Controller][]panel.UserTraffic)
	for _, c := range n.controllers {
		if c.started {
			snapshots[c] = c.collectTraffic(max(c.info.TrafficReportThreshold, 0))
		}
	}
	// Traffic ACKs take priority over online/status calls, which may time out.
	result := n.traffic.report(ctx)
	for _, c := range n.controllers {
		if ctx.Err() != nil {
			return errors.Join(result, ctx.Err())
		}
		if c.started {
			_ = c.reportOnlineAndStatus(ctx, snapshots[c])
		}
	}
	// Certificate-pin reports are the only protocol-specific statuses. The
	// independent server reporter remains alive through stop/restore failures.
	if n.statusClient != nil && ctx.Err() == nil {
		var status *panel.NodeStatus
		for _, c := range n.controllers {
			if c != nil && c.started && c.info.Protocol != nil && strings.TrimSpace(c.info.Protocol.CertMode) == "self" {
				if status == nil {
					cpu, mem, disk, uptime, err := serverstatus.GetSystemInfo()
					if err != nil {
						logx.Component("node").WithError(err).Error("获取系统信息失败")
					}
					status = &panel.NodeStatus{CPU: cpu, Mem: mem, Disk: disk, Uptime: uptime}
				}
				if err := n.statusClient.ReportCertificateStatus(ctx, c.apiClient, status); err != nil {
					logx.Node(c.tag).WithError(err).Error("上报证书状态失败")
				}
			}
		}
	}
	return result
}

func (n *Node) Stop() error {
	if n == nil {
		return nil
	}
	if n.reportPeriodic != nil {
		n.reportPeriodic.Close()
		n.reportPeriodic = nil
	}
	var result error
	for _, c := range n.controllers {
		result = errors.Join(result, c.Stop())
	}
	return result
}

func (n *Node) Close() {
	if n == nil {
		return
	}
	_ = n.Stop()
	for _, c := range n.controllers {
		if c == nil {
			continue
		}
		if err := c.Close(); err != nil {
			logx.Node(c.tag).WithError(err).Error("关闭节点控制器失败")
		}
	}
	n.controllers = nil
}

// FlushTraffic attempts final delivery after Stop has collected the last batch.
func (n *Node) FlushTraffic(ctx context.Context) error { return n.traffic.report(ctx) }

package node

import (
	"fmt"
	"strings"

	"github.com/perfect-panel/ppanel-node/api/panel"
	"github.com/perfect-panel/ppanel-node/common/logx"
	"github.com/perfect-panel/ppanel-node/common/task"
	vCore "github.com/perfect-panel/ppanel-node/core"
	inboundbuilder "github.com/perfect-panel/ppanel-node/core/inbound"
	"github.com/perfect-panel/ppanel-node/limiter"
	xray "github.com/xtls/xray-core/core"
)

type Controller struct {
	server                  *vCore.XrayCore
	apiClient               *panel.NodeClient
	tag                     string
	limiter                 *limiter.Limiter
	userList                []panel.UserInfo
	aliveMap                map[int]int
	info                    *panel.NodeInfo
	userListMonitorPeriodic *task.Task
	renewCertPeriodic       *task.Task
	traffic                 *trafficQueue
	prepared                bool
	started                 bool
	inboundConfig           *xray.InboundHandlerConfig
}

// NewController return a Node controller with default parameters.
// NewController returns a protocol controller whose users come from the
// candidate's identity snapshot.
func NewController(core *vCore.XrayCore, api *panel.NodeClient, info *panel.NodeInfo, users []panel.UserInfo) *Controller {
	controller := &Controller{
		server:    core,
		apiClient: api,
		info:      info,
		traffic:   newTrafficQueue(),
		userList:  users,
	}
	return controller
}

// Prepare completes network requests and builds the inbound before stopping a
// running node. The cached certificate and user snapshot also support rollback.
func (c *Controller) Prepare() error {
	if c.prepared {
		return nil
	}
	var err error
	c.tag = c.buildNodeTag(c.info)
	selfCertificate := usesTLSCertificate(c.info) && strings.TrimSpace(c.info.Protocol.CertMode) == "self"
	if selfCertificate {
		if err = c.requestCert(); err != nil {
			return fmt.Errorf("request self-signed certificate: %w", err)
		}
		if err = c.reportSelfCertificateSHA256(); err != nil {
			return fmt.Errorf("report self-signed certificate fingerprint: %w", err)
		}
	}

	// Users come from the candidate's identity snapshot; only the online
	// device list is read separately (device limits).
	c.aliveMap, err = c.apiClient.GetUserAlive()
	if err != nil {
		return fmt.Errorf("failed to get user alive list: %s", err)
	}
	if usesTLSCertificate(c.info) && !selfCertificate {
		err = c.requestCert()
		if err != nil {
			return fmt.Errorf("request cert error: %s", err)
		}
	}
	c.inboundConfig, err = inboundbuilder.Build(c.info, c.tag)
	if err != nil {
		return fmt.Errorf("build inbound: %w", err)
	}
	c.prepared = true
	return nil
}

func (c *Controller) Start() error {
	if c.started {
		return nil
	}
	if err := c.Prepare(); err != nil {
		return err
	}
	if c.limiter == nil {
		c.limiter = c.server.LimiterManager.Add(c.tag, c.userList, c.aliveMap, c.info.Type)
	}
	if err := c.server.AddNodeConfig(c.inboundConfig); err != nil {
		return err
	}
	c.started = true
	added, err := c.server.AddUsers(&vCore.AddUsersParams{
		Tag:      c.tag,
		Users:    c.userList,
		NodeInfo: c.info,
	})
	if err != nil {
		return fmt.Errorf("add users error: %s", err)
	}
	logx.Node(c.tag).WithField("user_added", added).Info("已添加新用户")
	if err := c.startTasks(c.info); err != nil {
		_ = c.Stop()
		return err
	}
	return nil
}

// Stop releases listeners while retaining prepared configuration, users,
// limiters and pending traffic so Start can restore service without the panel.
func (c *Controller) Stop() error {
	if c == nil {
		return nil
	}
	if c.userListMonitorPeriodic != nil {
		c.userListMonitorPeriodic.Close()
		c.userListMonitorPeriodic = nil
	}
	if c.renewCertPeriodic != nil {
		c.renewCertPeriodic.Close()
		c.renewCertPeriodic = nil
	}
	if !c.started {
		return nil
	}
	if err := c.server.DelNode(c.tag); err != nil {
		return err
	}
	c.started = false
	c.collectTraffic(0)
	return nil
}

// markInstanceStopped stops the controller's tasks and forgets the listener
// that died with its Xray instance.
func (c *Controller) markInstanceStopped() {
	if c.userListMonitorPeriodic != nil {
		c.userListMonitorPeriodic.Close()
		c.userListMonitorPeriodic = nil
	}
	if c.renewCertPeriodic != nil {
		c.renewCertPeriodic.Close()
		c.renewCertPeriodic = nil
	}
	c.started = false
	// The instance is closed, so the counters are final: collect everything,
	// including bytes carried by connections after the listener was removed.
	c.collectTraffic(0)
}

func (c *Controller) Close() error {
	if c == nil {
		return nil
	}
	err := c.Stop()
	if c.server != nil && c.server.LimiterManager != nil && c.tag != "" {
		c.server.LimiterManager.Delete(c.tag)
	}
	return err
}

func (c *Controller) buildNodeTag(node *panel.NodeInfo) string {
	return panel.InboundTag(c.apiClient.APIHost, node.Type, node.Id)
}

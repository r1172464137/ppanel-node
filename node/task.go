package node

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/perfect-panel/ppanel-node/api/panel"
	"github.com/perfect-panel/ppanel-node/common/logx"
	"github.com/perfect-panel/ppanel-node/common/task"
	vCore "github.com/perfect-panel/ppanel-node/core"
)

func (c *Controller) startTasks(node *panel.NodeInfo) error {
	if _, err := panel.IntervalDuration(node.PullInterval); err != nil {
		return fmt.Errorf("pull interval: %w", err)
	}
	// Users, limits and UUIDs arrive with each candidate (identity snapshot);
	// no periodic user polling remains.
	if usesTLSCertificate(node) {
		switch node.Protocol.CertMode {
		case "none", "", "file", "self":
		default:
			c.renewCertPeriodic = &task.Task{
				Name:     "renewCert",
				Interval: time.Hour * 24,
				Execute:  c.renewCertTask,
				ReloadCh: c.server.ReloadCh,
			}
			logx.Node(c.tag).Info("证书定期更新任务已启动")
			// delay to start renewCert
			if err := c.renewCertPeriodic.Start(true); err != nil {
				c.renewCertPeriodic = nil
				return fmt.Errorf("start certificate renewal: %w", err)
			}
		}
	}
	return nil
}

func usesTLSCertificate(node *panel.NodeInfo) bool {
	if node == nil || node.Protocol == nil {
		return false
	}
	if node.Protocol.Security == "tls" {
		return true
	}
	switch node.Type {
	case "tuic", "hysteria", "hysteria2":
		mode := strings.TrimSpace(node.Protocol.CertMode)
		return mode != "" && mode != "none"
	default:
		return false
	}
}

// applyIdentity reconciles the running users of this protocol with users.
func (c *Controller) applyIdentity(users []panel.UserInfo) error {
	removed, added, changed := diffIdentity(c.userList, users)
	if len(removed) > 0 {
		c.collectTraffic(0)
		if err := c.server.DelUsers(removed, c.tag, c.info); err != nil {
			return fmt.Errorf("remove users: %w", err)
		}
	}
	if len(added) > 0 {
		if _, err := c.server.AddUsers(&vCore.AddUsersParams{Tag: c.tag, NodeInfo: c.info, Users: added}); err != nil {
			return fmt.Errorf("add users: %w", err)
		}
	}
	if c.limiter != nil {
		c.limiter.UpdateUser(c.tag, added, removed)
		c.limiter.UpdateLimits(c.tag, changed)
	}
	c.userList = append([]panel.UserInfo(nil), users...)
	if len(added)+len(removed)+len(changed) > 0 {
		logx.Node(c.tag).WithFields(map[string]interface{}{"user_added": len(added), "user_deleted": len(removed), "user_limits": len(changed)}).Info("用户身份已就地更新")
	}
	return nil
}

// diffIdentity compares users by UUID: removed and added identities, and
// identities whose subscription ID or limits changed.
func diffIdentity(old, next []panel.UserInfo) (removed, added, changed []panel.UserInfo) {
	byUUID := make(map[string]panel.UserInfo, len(old))
	for _, u := range old {
		byUUID[u.Uuid] = u
	}
	for _, u := range next {
		prev, ok := byUUID[u.Uuid]
		if !ok {
			added = append(added, u)
			continue
		}
		delete(byUUID, u.Uuid)
		if prev != u {
			changed = append(changed, u)
		}
	}
	for _, u := range old {
		if _, ok := byUUID[u.Uuid]; ok {
			removed = append(removed, u)
		}
	}
	return removed, added, changed
}

func (c *Controller) reportOnlineAndStatus(ctx context.Context, userTraffic []panel.UserTraffic) (err error) {
	if onlineDevice, err := c.limiter.GetOnlineDevice(); err != nil {
		logx.Node(c.tag).WithError(err).Error("获取在线设备失败")
	} else if len(*onlineDevice) > 0 {
		// Only report user has traffic > 100kb to allow ping test
		var result []panel.OnlineUser
		var nocountUID = make(map[int]struct{})
		for _, traffic := range userTraffic {
			total := traffic.Upload + traffic.Download
			if total <= 0 {
				nocountUID[traffic.UID] = struct{}{}
			}
		}
		for _, online := range *onlineDevice {
			if _, ok := nocountUID[online.UID]; !ok {
				result = append(result, online)
			}
		}
		if err = c.apiClient.ReportNodeOnlineUsers(ctx, &result); err != nil {
			logx.Node(c.tag).WithError(err).Error("上报在线用户失败")
		} else {
			logx.Node(c.tag).WithFields(map[string]interface{}{
				"online_total":    len(*onlineDevice),
				"online_reported": len(result),
			}).Info("已上报在线用户")
		}
	}

	userTraffic = nil
	return nil
}

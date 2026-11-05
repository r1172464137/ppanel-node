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
	interval, err := panel.IntervalDuration(node.PullInterval)
	if err != nil {
		return fmt.Errorf("user monitor interval: %w", err)
	}
	if c.identitySnapshot == nil {
		c.userListMonitorPeriodic = &task.Task{
			Name:     "userListMonitor",
			Interval: interval,
			Execute:  c.userListMonitor,
			ReloadCh: c.server.ReloadCh,
		}
		if err := c.userListMonitorPeriodic.Start(false); err != nil {
			c.userListMonitorPeriodic = nil
			return fmt.Errorf("start user monitor: %w", err)
		}
		logx.Node(c.tag).Info("用户列表监控任务已启动")
	}
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
				if c.userListMonitorPeriodic != nil {
					c.userListMonitorPeriodic.Close()
					c.userListMonitorPeriodic = nil
				}
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

func (c *Controller) userListMonitor(ctx context.Context) (err error) {
	// get user info
	newU, err := c.apiClient.GetUserList(ctx)
	if err != nil {
		logx.Node(c.tag).WithError(err).Error("获取用户列表失败")
		return nil
	}
	// get user alive
	newA, err := c.apiClient.GetUserAlive()
	if err != nil {
		logx.Node(c.tag).WithError(err).Error("获取在线列表失败")
		return nil
	}
	// update alive list
	if newA != nil {
		c.limiter.SetAliveList(newA)
	}
	// update user list
	// newU == nil indicates 304 Not Modified; empty slice means the list is empty
	if newU == nil {
		return nil
	}
	deleted, added := compareUserList(c.userList, newU)
	if len(deleted) > 0 {
		c.collectTraffic(0)
		// have deleted users
		err = c.server.DelUsers(deleted, c.tag, c.info)
		if err != nil {
			logx.Node(c.tag).WithError(err).Error("删除用户失败")
			c.restoreUsersAfterFailure()
			return nil
		}
	}
	if len(added) > 0 {
		// have added users
		_, err = c.server.AddUsers(&vCore.AddUsersParams{
			Tag:      c.tag,
			NodeInfo: c.info,
			Users:    added,
		})
		if err != nil {
			logx.Node(c.tag).WithError(err).Error("添加用户失败")
			c.restoreUsersAfterFailure()
			return nil
		}
	}
	if len(added) > 0 || len(deleted) > 0 {
		// update Limiter
		c.limiter.UpdateUser(c.tag, added, deleted)
	}
	c.userList = newU
	c.apiClient.CommitUserList()
	if len(added)+len(deleted) != 0 {
		logx.Node(c.tag).WithFields(map[string]interface{}{
			"user_deleted": len(deleted),
			"user_added":   len(added),
		}).Info("用户列表已更新")
	}
	return nil
}

// Rebuild the inbound after a partial user-manager mutation; a failed restore
// leaves the listener stopped and asks the existing core reload path to retry.
func (c *Controller) restoreUsersAfterFailure() {
	c.collectTraffic(0)
	remove := c.server.DelNode
	if c.removeInbound != nil {
		remove = c.removeInbound
	}
	if err := remove(c.tag); err != nil {
		logx.Node(c.tag).WithError(err).Error("停止用户恢复监听器失败")
		c.failClosedForUserRestore()
		return
	}
	c.started.Store(false)
	c.server.ResetNodeUsers(c.tag)
	if err := c.server.AddNodeConfig(c.inboundConfig); err != nil {
		logx.Node(c.tag).WithError(err).Error("恢复监听器失败")
		c.requestUserReload()
		return
	}
	c.started.Store(true)
	if _, err := c.server.AddUsers(&vCore.AddUsersParams{Tag: c.tag, NodeInfo: c.info, Users: c.userList}); err != nil {
		logx.Node(c.tag).WithError(err).Error("恢复用户失败")
		if stopErr := remove(c.tag); stopErr != nil {
			logx.Node(c.tag).WithError(stopErr).Error("停止不完整监听器失败")
			c.failClosedForUserRestore()
			return
		}
		c.started.Store(false)
		c.requestUserReload()
	}
}

func (c *Controller) failClosedForUserRestore() {
	if err := c.server.FailClosed(); err != nil {
		logx.Node(c.tag).WithError(err).Error("关闭不完整核心失败")
	}
	c.requestUserReload()
}

func (c *Controller) requestUserReload() {
	if c.server.ReloadCh != nil {
		select {
		case c.server.ReloadCh <- struct{}{}:
		default:
		}
	}
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

func compareUserList(old, new []panel.UserInfo) (deleted, added []panel.UserInfo) {
	oldMap := make(map[panel.UserInfo]int, len(old))
	for i, user := range old {
		oldMap[user] = i
	}

	for _, user := range new {
		if _, exists := oldMap[user]; !exists {
			added = append(added, user)
		} else {
			delete(oldMap, user)
		}
	}

	for _, index := range oldMap {
		deleted = append(deleted, old[index])
	}

	return deleted, added
}

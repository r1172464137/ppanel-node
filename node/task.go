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
	// Lease renewals are independent of traffic retries in both v1 and v2.
	c.onlinePeriodic = &task.Task{Name: "reportOnline", Interval: time.Duration(min(max(node.PushInterval, 1), 60)) * time.Second, Execute: c.heartbeat}
	if err := c.onlinePeriodic.Start(false); err != nil {
		if c.userListMonitorPeriodic != nil {
			c.userListMonitorPeriodic.Close()
			c.userListMonitorPeriodic = nil
		}
		c.onlinePeriodic = nil
		return fmt.Errorf("start online monitor: %w", err)
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
				c.onlinePeriodic.Close()
				c.onlinePeriodic = nil
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
	// update user list
	// newU == nil indicates 304 Not Modified; empty slice means the list is empty
	if newU == nil {
		return nil
	}
	// A reload switch owns the live core exclusively. Acquisition is cancelled
	// with the task context, so stopping a generation can never wait on a lock
	// that the reload itself is holding.
	if err := c.server.LockLive(ctx); err != nil {
		return nil
	}
	defer c.server.UnlockLive()
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

// Counts are advisory; refresh them separately so an unavailable endpoint
// cannot delay v1 identity changes or the transactional ETag commit.
func (c *Controller) refreshAlive(ctx context.Context) {
	alive, err := c.apiClient.GetUserAlive(ctx)
	if err != nil {
		logx.Node(c.tag).WithError(err).Error("获取在线列表失败")
	} else if alive != nil {
		c.limiter.UpdateAliveList(alive)
	}
}

func (c *Controller) heartbeat(ctx context.Context) error {
	err := c.reportOnline(ctx)
	if ctx.Err() == nil {
		c.refreshAlive(ctx)
	}
	return err
}

func (c *Controller) reportOnline(ctx context.Context) error {
	online, err := c.limiter.GetOnlineDevice()
	if err != nil {
		return err
	}
	for start := 0; start < len(*online); start += 10000 {
		batch := (*online)[start:min(start+10000, len(*online))]
		sentAt := time.Now()
		if err := c.apiClient.ReportNodeOnlineUsers(ctx, &batch); err != nil {
			return err
		}
		c.limiter.OnlineReportAcknowledged(batch, sentAt)
	}
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

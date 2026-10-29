package cmd

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/perfect-panel/ppanel-node/api/panel"
	"github.com/perfect-panel/ppanel-node/common/logx"
	"github.com/perfect-panel/ppanel-node/common/serverstatus"
)

// The reporter belongs to the server process, not a protocol or a core. It
// therefore survives a failed listener restore and works with zero protocols.
type serverReporter struct {
	mu       sync.RWMutex
	client   *panel.ServerClient
	interval time.Duration
	wake     chan struct{}
	cancel   context.CancelFunc
	done     chan struct{}
}

func newServerReporter(client *panel.ServerClient, interval time.Duration) *serverReporter {
	r := &serverReporter{interval: interval, wake: make(chan struct{}, 1)}
	if err := r.setClient(client); err != nil {
		logx.Component("server").WithError(err).Error("无法初始化状态上报")
	}
	return r
}
func (r *serverReporter) start() {
	ctx, cancel := context.WithCancel(context.Background())
	r.cancel = cancel
	r.done = make(chan struct{})
	go func() {
		defer close(r.done)
		timer := time.NewTimer(0)
		defer timer.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-timer.C:
			case <-r.wake:
			}
			requestCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
			err := r.report(requestCtx)
			cancel()
			if err != nil && ctx.Err() == nil {
				logx.Component("server").WithError(err).Warn("上报服务器状态失败")
			}
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			timer.Reset(r.interval)
		}
	}()
}
func (r *serverReporter) close() {
	if r.cancel != nil {
		r.cancel()
		<-r.done
	}
}
func (r *serverReporter) setClient(c *panel.ServerClient) error {
	if c != nil {
		if err := c.ActivateStatusPublisher(); err != nil {
			return err
		}
	}
	r.mu.Lock()
	old := r.client
	r.client = c
	r.mu.Unlock()
	if old != nil && old != c {
		old.State.SetNotifier(nil)
	}
	if c != nil {
		c.State.SetNotifier(r.reportSoon)
	}
	return nil
}
func (r *serverReporter) report(ctx context.Context) error {
	// Keep the selected client stable through delivery: a retired client's
	// snapshot must never receive a later sequence after a client switch.
	r.mu.RLock()
	defer r.mu.RUnlock()
	client := r.client
	if client == nil {
		return nil
	}
	cpu, mem, disk, uptime, err := serverstatus.GetSystemInfo()
	if err != nil {
		logx.Component("server").WithError(err).Warn("获取服务器状态失败")
	}
	err = client.ReportServerStatus(ctx, &panel.NodeStatus{CPU: cpu, Mem: mem, Disk: disk, Uptime: uptime})
	if errors.Is(err, panel.ErrRetiredClient) {
		return nil
	}
	return err
}
func (r *serverReporter) recordFailure(stage panel.FailureStage) {
	r.mu.RLock()
	client := r.client
	r.mu.RUnlock()
	if client != nil {
		client.RecordFailure(nil, stage)
	}
}

func (r *serverReporter) reportSoon() {
	// Coalesce updates; the one owned goroutine serializes status snapshots.
	select {
	case r.wake <- struct{}{}:
	default:
	}
}

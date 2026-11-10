package core

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"syscall"
	"time"

	"github.com/perfect-panel/ppanel-node/common/logx"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/inbound"
)

const (
	bindRetryInitialDelay = 25 * time.Millisecond
	bindRetryMaxDelay     = 400 * time.Millisecond
	bindRetryMaxElapsed   = 2 * time.Second
)

func (v *XrayCore) removeInbound(tag string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return v.ihm.RemoveHandler(ctx, tag)
}

func isAddressInUse(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, syscall.EADDRINUSE) {
		return true
	}
	return strings.Contains(strings.ToLower(err.Error()), "address already in use")
}

// addInbound waits briefly for a listener that was just released. The wait is
// bounded and logged so an externally occupied port still fails the candidate.
func (v *XrayCore) addInbound(config *core.InboundHandlerConfig) error {
	started := time.Now()
	wait := bindRetryInitialDelay
	for attempt := 1; ; attempt++ {
		err := v.addInboundOnce(config)
		if err == nil || !isAddressInUse(err) {
			return err
		}
		remaining := bindRetryMaxElapsed - time.Since(started)
		if remaining <= 0 {
			return err
		}
		delay := min(wait, remaining)
		logx.Component("xray").WithFields(map[string]interface{}{
			"tag":     config.Tag,
			"attempt": attempt,
			"wait":    delay.String(),
		}).WithError(err).Warn("监听端口暂时被占用，等待后重试")
		time.Sleep(delay)
		wait = min(wait*2, bindRetryMaxDelay)
	}
}

func (v *XrayCore) addInboundOnce(config *core.InboundHandlerConfig) error {
	rawHandler, err := core.CreateObject(v.Server, config)
	if err != nil {
		return err
	}
	handler, ok := rawHandler.(inbound.Handler)
	if !ok {
		return fmt.Errorf("not an InboundHandler: %s", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := v.ihm.AddHandler(ctx, handler); err != nil {
		// The manager registers the handler before Start. Remove this failed
		// registration without removing a different handler on duplicate tags.
		if current, lookupErr := v.ihm.GetHandler(ctx, handler.Tag()); lookupErr == nil && current == handler {
			_ = v.ihm.RemoveHandler(ctx, handler.Tag())
		} else {
			_ = handler.Close()
		}
		return err
	}
	return nil
}

package dispatcher

import (
	"context"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/transport"
)

type activeDispatch struct {
	link   *transport.Link
	cancel context.CancelFunc
	conn   net.Conn
	user   string
}

func (flow activeDispatch) close() {
	flow.cancel()
	// DispatchLink can read directly from the inbound socket rather than a
	// pipe; closing only its buffer wrappers does not interrupt that read.
	if flow.conn != nil {
		_ = flow.conn.Close()
	}
	_ = common.Close(flow.link.Writer)
	_ = common.Interrupt(flow.link.Reader)
}

func (d *DefaultDispatcher) beginDispatch(ctx context.Context, link *transport.Link) (context.Context, func(), bool) {
	d.dispatchMu.Lock()
	defer d.dispatchMu.Unlock()
	if d.paused {
		return ctx, nil, false
	}
	ctx, cancel := context.WithCancel(ctx)
	if d.activeDispatches == nil {
		d.activeDispatches = make(map[uint64]activeDispatch)
	}
	d.nextDispatch++
	id := d.nextDispatch
	flow := activeDispatch{link: link, cancel: cancel}
	if inbound := session.InboundFromContext(ctx); inbound != nil {
		flow.conn = inbound.Conn
		if inbound.User != nil {
			flow.user = inbound.User.Email
		}
	}
	d.activeDispatches[id] = flow
	d.dispatches.Add(1)
	return ctx, func() {
		cancel()
		d.dispatchMu.Lock()
		delete(d.activeDispatches, id)
		d.dispatchMu.Unlock()
		d.dispatches.Done()
	}, true
}

// Quiesce prevents old requests from using Xray's process-global dialer while
// a replacement core is constructed. Call after removing the old listeners.
func (d *DefaultDispatcher) Quiesce() {
	d.dispatchMu.Lock()
	d.paused = true
	active := make([]activeDispatch, 0, len(d.activeDispatches))
	for _, flow := range d.activeDispatches {
		active = append(active, flow)
	}
	d.dispatchMu.Unlock()
	for _, flow := range active {
		flow.close()
	}
	d.dispatches.Wait()
}

func (d *DefaultDispatcher) CloseUserFlows(user string) {
	d.dispatchMu.Lock()
	var active []activeDispatch
	for _, flow := range d.activeDispatches {
		if flow.user == user {
			active = append(active, flow)
		}
	}
	d.dispatchMu.Unlock()
	for _, flow := range active {
		flow.close()
	}
}

func (d *DefaultDispatcher) Resume() {
	d.dispatchMu.Lock()
	d.paused = false
	d.dispatchMu.Unlock()
}

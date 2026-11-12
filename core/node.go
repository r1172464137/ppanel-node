package core

import (
	"errors"
	"fmt"
	"strings"
	"syscall"
	"time"

	xray "github.com/xtls/xray-core/core"

	"github.com/perfect-panel/ppanel-node/api/panel"
	inboundbuilder "github.com/perfect-panel/ppanel-node/core/inbound"
)

func (v *XrayCore) AddNode(tag string, info *panel.NodeInfo) error {
	inBoundConfig, err := inboundbuilder.Build(info, tag)
	if err != nil {
		return fmt.Errorf("build inbound error: %s", err)
	}
	err = v.addInbound(inBoundConfig)
	if err != nil {
		return fmt.Errorf("add inbound error: %s", err)
	}
	return nil
}

// DelNode removes a listener. With no running instance there is nothing to
// remove: closing the instance already closed every listener.
func (v *XrayCore) DelNode(tag string) error {
	if !v.Running() {
		return nil
	}
	err := v.removeInbound(tag)
	if err != nil {
		return fmt.Errorf("remove in error: %s", err)
	}
	return nil
}

// bindRetryWindow bounds how long AddNodeConfig waits for a port that is still
// being released (for example by the instance closed a moment ago). A port
// held by another process is reported after this window; nothing is killed.
var bindRetryWindow = 3 * time.Second

func (v *XrayCore) AddNodeConfig(config *xray.InboundHandlerConfig) error {
	if !v.Running() {
		return fmt.Errorf("bind listener: core is not running")
	}
	deadline := time.Now().Add(bindRetryWindow)
	for {
		err := v.addInbound(config)
		if err == nil || !isAddrInUse(err) || time.Now().After(deadline) {
			return err
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func isAddrInUse(err error) bool {
	return errors.Is(err, syscall.EADDRINUSE) || strings.Contains(err.Error(), "address already in use")
}

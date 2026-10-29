package outbound

import (
	"fmt"
	"strings"

	"github.com/perfect-panel/ppanel-node/api/panel"
	"github.com/perfect-panel/ppanel-node/core/streamguard"
)

// Non-default panel/raw UoT settings are unsupported for every ordered
// outbound. Do not silently apply configurations whose UDP semantics differ.
func validateNoUOT(item panel.Outbound) error {
	if item.UoT || item.UoTVersion != 0 {
		return fmt.Errorf("configured UDP-over-TCP is unsupported")
	}
	for _, raw := range []string{item.Settings, item.StreamSettings, item.XHTTPExtra} {
		if strings.TrimSpace(raw) == "" {
			continue
		}
		if err := streamguard.ValidateNoUOTJSON([]byte(raw)); err != nil {
			return err
		}
	}
	return nil
}

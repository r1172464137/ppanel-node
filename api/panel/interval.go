package panel

import (
	"fmt"
	"time"
)

const MaxIntervalSeconds = 86400
const DefaultIntervalSeconds = 60

// Both server pull and push intervals use 0 for the existing default. Bounds
// are checked before converting to time.Duration or multiplying by a unit.
func IntervalDuration(seconds int) (time.Duration, error) {
	if seconds < 0 || seconds > MaxIntervalSeconds {
		return 0, fmt.Errorf("interval must be 0 or 1..%d seconds", MaxIntervalSeconds)
	}
	if seconds == 0 {
		seconds = DefaultIntervalSeconds
	}
	return time.Duration(seconds) * time.Second, nil
}

func ValidateDeliveryMetadata(data *Data) error {
	if data == nil || data.Protocols == nil {
		return fmt.Errorf("protocol config is missing")
	}
	if data.Total != len(*data.Protocols) {
		return fmt.Errorf("total does not match protocol count")
	}
	if _, err := IntervalDuration(data.PullInterval); err != nil {
		return fmt.Errorf("pull_interval: %w", err)
	}
	if _, err := IntervalDuration(data.PushInterval); err != nil {
		return fmt.Errorf("push_interval: %w", err)
	}
	return nil
}

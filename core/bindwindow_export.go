package core

import "time"

// SetBindRetryWindow changes the bounded wait for a port that is still being
// released and returns a function restoring the previous value. Tests use it
// to keep permanent-conflict cases short.
func SetBindRetryWindow(d time.Duration) (restore func()) {
	old := bindRetryWindow
	bindRetryWindow = d
	return func() { bindRetryWindow = old }
}

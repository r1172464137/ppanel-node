package limiter

import (
	"testing"
	"time"

	"github.com/perfect-panel/ppanel-node/api/panel"
	"github.com/perfect-panel/ppanel-node/common/format"
)

func TestOnlineSnapshotAndConcurrentInsertCannotLoseIP(t *testing.T) {
	user := panel.UserInfo{Id: 7, Uuid: "user"}
	lim := NewManager().Add("tag", []panel.UserInfo{user}, nil, "vless")
	tag := format.UserTag("tag", user.Uuid)
	if _, reject := lim.CheckLimit(tag, "192.0.2.1", true); reject {
		t.Fatal("first IP rejected")
	}
	lim.mu.Lock()
	started, done := make(chan struct{}), make(chan struct{})
	go func() { close(started); lim.CheckLimit(tag, "192.0.2.2", true); close(done) }()
	<-started
	// Exercise the exact snapshot+delete implementation while the add is
	// blocked on the same lock; it cannot insert into the map being drained.
	first := lim.collectOnlineLocked()
	select {
	case <-done:
		lim.mu.Unlock()
		t.Fatal("writer entered during snapshot")
	default:
	}
	lim.mu.Unlock()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("writer did not resume")
	}
	second, err := lim.GetOnlineDevice()
	if err != nil {
		t.Fatal(err)
	}
	if len(first) != 1 || first[0].IP != "192.0.2.1" || len(*second) != 1 || (*second)[0].IP != "192.0.2.2" {
		t.Fatalf("snapshot lost IP: first=%v second=%v", first, *second)
	}
}

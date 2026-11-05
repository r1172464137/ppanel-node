package limiter

import (
	"github.com/perfect-panel/ppanel-node/api/panel"
	"github.com/perfect-panel/ppanel-node/common/format"
	"testing"
	"time"
)

func TestOnlineSnapshotAndConcurrentInsertCannotLoseIP(t *testing.T) {
	user := panel.UserInfo{Id: 7, Uuid: "user"}
	lim := NewManager().Add("tag", []panel.UserInfo{user}, nil, "vless")
	tag := format.UserTag("tag", user.Uuid)
	if _, reject := lim.CheckLimit(tag, "192.0.2.1", true); reject {
		t.Fatal("first IP rejected")
	}
	first, err := lim.GetOnlineDevice()
	if err != nil || len(*first) != 1 || (*first)[0].IP != "192.0.2.1" {
		t.Fatalf("first snapshot: %v, %v", first, err)
	}
	lim.aliveMu.Lock()
	started, done := make(chan struct{}), make(chan struct{})
	go func() { close(started); lim.CheckLimit(tag, "192.0.2.2", true); close(done) }()
	<-started
	select {
	case <-done:
		lim.aliveMu.Unlock()
		t.Fatal("writer entered during snapshot")
	default:
	}
	lim.aliveMu.Unlock()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("writer did not resume")
	}
	snapshot, err := lim.GetOnlineDevice()
	if err != nil {
		t.Fatal(err)
	}
	found := map[string]bool{}
	for _, entry := range *snapshot {
		found[entry.IP] = true
	}
	if !found["192.0.2.1"] || !found["192.0.2.2"] {
		t.Fatalf("snapshot lost IP: %v", *snapshot)
	}
}

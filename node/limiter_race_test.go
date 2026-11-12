package node

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/perfect-panel/ppanel-node/api/panel"
	"github.com/perfect-panel/ppanel-node/common/format"
	"github.com/perfect-panel/ppanel-node/conf"
	"github.com/perfect-panel/ppanel-node/limiter"
)

// Exercise the actual controller's userListMonitor concurrently with live
// dispatch checks, user updates and heartbeat snapshots.
func TestUserMonitorAndLimiterConcurrent(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNotModified) }))
	defer srv.Close()
	client, err := panel.NewNodeClient(&conf.NodeApiConfig{APIHost: srv.URL, NodeType: "vless", NodeID: 7})
	if err != nil {
		t.Fatal(err)
	}
	user := panel.UserInfo{Id: 1, Uuid: "00000000-0000-0000-0000-000000000001", DeviceLimit: 10}
	lim := limiter.NewManager().Add("race", []panel.UserInfo{user}, map[int]int{1: 1}, "vless")
	c := &Controller{apiClient: client, limiter: lim, tag: "race"}
	var wg sync.WaitGroup
	wg.Add(3)
	go func() {
		defer wg.Done()
		for i := 0; i < 400; i++ {
			// Identity updates change limits while connections are checked.
			c.limiter.SetAliveList(map[int]int{1: i % 3})
			c.limiter.UpdateLimits(c.tag, []panel.UserInfo{{Id: 1, Uuid: user.Uuid, DeviceLimit: 1 + i%5, SpeedLimit: i % 2}})
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < 5000; i++ {
			lim.CheckLimit(format.UserTag("race", user.Uuid), fmt.Sprintf("192.0.2.%d", i%200), true)
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < 400; i++ {
			lim.UpdateUser("race", nil, []panel.UserInfo{user})
			lim.UpdateUser("race", []panel.UserInfo{user}, nil)
			_, _ = lim.GetOnlineDevice()
		}
	}()
	wg.Wait()
}

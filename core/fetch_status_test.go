package core

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/perfect-panel/ppanel-node/api/panel"
	serverv1 "github.com/perfect-panel/ppanel-node/api/server/v1"
	"github.com/perfect-panel/ppanel-node/conf"
	"google.golang.org/protobuf/proto"
)

func TestMonitorFetchFailuresAreReportedAndClearOn304(t *testing.T) {
	var mode atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch mode.Load() {
		case 1:
			w.Header().Set("Content-Type", "application/protobuf")
			w.WriteHeader(426)
			b, _ := proto.Marshal(&serverv1.Result{Code: 426, Message: "secret-message"})
			w.Write(b)
		case 2:
			w.Header().Set("Content-Type", "application/protobuf")
			w.Write([]byte{0xff})
		case 3:
			fmt.Fprint(w, strings.Repeat("x", panel.MaxServerConfigResponseBytes+1))
		case 4:
			fmt.Fprint(w, `{"secret":"secret-message"`)
		default:
			w.Header().Set("ETag", `"ok"`)
			if r.Header.Get("If-None-Match") == `"ok"` {
				w.WriteHeader(304)
				return
			}
			fmt.Fprint(w, `{"code":200,"data":{"protocols":[],"routing":{"version":1,"outbounds":[],"rules":[],"default_outbound_id":"direct","mode":"ordered-v1-inherited","source":"global","source_revision":1}}}`)
		}
	}))
	defer srv.Close()
	c := panel.NewServerClient(&conf.ServerApiConfig{ApiHost: srv.URL, ServerId: 7})
	first, err := panel.GetServerConfig(context.Background(), c)
	if err != nil {
		t.Fatal(err)
	}
	c.Commit(first)
	notify := make(chan struct{}, 10)
	c.State.SetNotifier(func() {
		select {
		case notify <- struct{}{}:
		default:
		}
	})
	x := New(conf.New(), c)
	for _, m := range []int32{1, 2, 3, 4} {
		mode.Store(m)
		_ = x.ServerConfigMonitor(context.Background())
		s := c.State.Snapshot()
		if s.Error == nil || s.Error.Stage != "fetch" || strings.Contains(s.Error.Message, "secret") {
			t.Fatalf("mode %d: %+v", m, s)
		}
		select {
		case <-notify:
		default:
			t.Fatalf("mode %d did not wake status reporter", m)
		}
		mode.Store(0)
		_ = x.ServerConfigMonitor(context.Background())
		if s = c.State.Snapshot(); s.Error != nil {
			t.Fatalf("mode %d recovery left fetch error: %+v", m, s)
		}
		select {
		case <-notify:
		default:
			t.Fatalf("mode %d recovery did not wake reporter", m)
		}
	}
}

package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/perfect-panel/ppanel-node/api/panel"
	"github.com/perfect-panel/ppanel-node/common/logx"
	"github.com/perfect-panel/ppanel-node/conf"
)

func TestReloadTimeoutRebuildsClientWithoutLosingCandidateState(t *testing.T) {
	var conditional atomic.Bool
	reports := make(chan panel.ServerPushStatusRequest, 2)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/server/status" {
			var report panel.ServerPushStatusRequest
			if err := json.NewDecoder(r.Body).Decode(&report); err != nil {
				t.Error(err)
			}
			reports <- report
			fmt.Fprint(w, `{"code":200}`)
			return
		}
		w.Header().Set("ETag", `"v1"`)
		if r.Header.Get("If-None-Match") == `"v1"` {
			conditional.Store(true)
			w.WriteHeader(304)
			return
		}
		fmt.Fprint(w, `{"code":200,"data":{"protocols":[],"total":0,"routing":{"version":1,"outbounds":[],"rules":[],"default_outbound_id":"direct","mode":"ordered-v1-inherited","source":"global","source_revision":1}}}`)
	}))
	defer server.Close()
	cfg := conf.New()
	cfg.LogConfig.Level = "error"
	cfg.ApiConfig = conf.ServerApiConfig{ApiHost: server.URL, ServerId: 7, Timeout: 1}
	old := panel.NewServerClient(&cfg.ApiConfig)
	n, x, _, err := startInitial(context.Background(), cfg, old, make(chan struct{}, 1))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { n.Close(); x.Close() }()
	if err := old.ReportServerStatus(context.Background(), &panel.NodeStatus{}); err != nil {
		t.Fatal(err)
	}
	firstReport := <-reports
	path := filepath.Join(t.TempDir(), "config.yml")
	if err := os.WriteFile(path, []byte(fmt.Sprintf("Log:\n  Level: error\nApi:\n  ApiHost: %q\n  ServerID: 7\n  Timeout: 2\n", server.URL)), 0600); err != nil {
		t.Fatal(err)
	}
	h, err := reload(path, &n, &x, nil)
	if err != nil {
		t.Fatal(err)
	}
	if h != nil {
		defer h.Close()
	}
	fresh := x.Client
	if fresh == old || fresh.State != old.State || fresh.Timeout != 2 || fresh.Client.GetClient().Timeout != 2*time.Second {
		t.Fatalf("timeout client not safely replaced: old=%p new=%p timeout=%v", old, fresh, fresh.Client.GetClient().Timeout)
	}
	if !conditional.Load() || fresh.ServerConfigEtag != `"v1"` || fresh.State.Snapshot().Applied.SourceRevision != 1 {
		t.Fatalf("candidate state lost: %+v", fresh.State.Snapshot())
	}
	if err := fresh.ReportServerStatus(context.Background(), &panel.NodeStatus{}); err != nil {
		t.Fatal(err)
	}
	secondReport := <-reports
	if firstReport.RoutingStatus == nil || secondReport.RoutingStatus == nil || firstReport.InstanceID != secondReport.InstanceID || firstReport.Sequence == 0 || secondReport.Sequence <= firstReport.Sequence {
		t.Fatalf("sequence lost across client rebuild: %+v %+v", firstReport, secondReport)
	}
}

func TestProcessServicesUseFirstSuccessfulConfigAndDoNotDuplicatePprof(t *testing.T) {
	reserve := func() int {
		t.Helper()
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer l.Close()
		return l.Addr().(*net.TCPAddr).Port
	}
	oldPort, newPort := reserve(), reserve()
	for newPort == oldPort {
		newPort = reserve()
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("secret_key") != "fixed" {
			http.Error(w, "denied", 403)
			return
		}
		fmt.Fprint(w, `{"code":200,"data":{"protocols":null,"total":0,"routing":{"version":1,"outbounds":[],"rules":[],"default_outbound_id":"direct","mode":"ordered-v1-inherited","source":"global","source_revision":1}}}`)
	}))
	defer server.Close()
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yml")
	oldLog := filepath.Join(dir, "old.log")
	newLog := filepath.Join(dir, "new.log")
	write := func(secret, logPath string, port int) {
		t.Helper()
		body := fmt.Sprintf("Log:\n  Level: error\n  Output: %q\nApi:\n  ApiHost: %q\n  ServerID: 7\n  SecretKey: %q\n  Timeout: 2\nPprofPort: %d\n", logPath, server.URL, secret, port)
		if err := os.WriteFile(path, []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
	}
	reporter := newServerReporter(panel.NewServerClient(&conf.ServerApiConfig{}), time.Hour)
	write("wrong", oldLog, oldPort)
	if _, _, _, _, err := initialAttemptFromFile(context.Background(), path, reporter, nil); err == nil {
		t.Fatal("invalid credentials succeeded")
	}
	if _, err := os.Stat(oldLog); !os.IsNotExist(err) {
		t.Fatalf("failed config initialized old log: %v", err)
	}
	oldListener, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", oldPort))
	if err != nil {
		t.Fatalf("failed config opened pprof: %v", err)
	}
	oldListener.Close()
	write("fixed", newLog, newPort)
	n, x, _, successful, err := initialAttemptFromFile(context.Background(), path, reporter, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { n.Close(); x.Close() }()
	h, pprof := initializeProcessServices(successful)
	defer func() { pprof.Close(); h.Close(); restored, _ := logx.Setup(logx.Config{}); _ = restored.Close() }()
	logx.Component("test").Error("first-success-log-receipt")
	body, err := os.ReadFile(newLog)
	if err != nil || !strings.Contains(string(body), "first-success-log-receipt") {
		t.Fatalf("successful log not initialized: %v", err)
	}
	client := &http.Client{Timeout: 2 * time.Second, Transport: &http.Transport{Proxy: nil}}
	response, err := client.Get(fmt.Sprintf("http://127.0.0.1:%d/debug/pprof/", newPort))
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != 200 {
		t.Fatalf("pprof status=%d", response.StatusCode)
	}
	if err := pprof.Init(newPort); err != nil {
		t.Fatal(err)
	}
	if err := pprof.Init(oldPort); err == nil {
		t.Fatal("pprof change did not require restart")
	}
	oldListener, err = net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", oldPort))
	if err != nil {
		t.Fatalf("reload started another pprof listener: %v", err)
	}
	oldListener.Close()
}

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
	"github.com/perfect-panel/ppanel-node/conf"
	"github.com/perfect-panel/ppanel-node/core"
)

func TestBackendProtocolsNullStopsPriorListener(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	listener.Close()
	var rev atomic.Int32
	rev.Store(1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v2/server/7":
			n := rev.Load()
			etag := fmt.Sprintf(`"%d"`, n)
			w.Header().Set("ETag", etag)
			if r.Header.Get("If-None-Match") == etag {
				w.WriteHeader(304)
				return
			}
			protocols, total := "null", 0
			if n == 1 {
				protocols = fmt.Sprintf(`[{"type":"vless","enable":true,"port":%d,"transport":"tcp"}]`, port)
				total = 1
			}
			fmt.Fprintf(w, `{"code":200,"msg":"success","data":{"traffic_report_threshold":0,"push_interval":3600,"pull_interval":3600,"ip_strategy":"","dns":null,"protocols":%s,"total":%d,"routing":{"version":1,"outbounds":[],"rules":[],"default_outbound_id":"direct","mode":"ordered-v1-inherited","source":"global","source_server_id":0,"source_revision":%d,"local_transition_revision":0}}}`, protocols, total, n)
		case "/v1/server/user":
			fmt.Fprint(w, `{"code":200,"data":{"users":[]}}`)
		default:
			fmt.Fprint(w, `{"code":200}`)
		}
	}))
	defer srv.Close()
	cfg := conf.New()
	cfg.LogConfig.Level = "error"
	cfg.ApiConfig = conf.ServerApiConfig{ApiHost: srv.URL, ServerId: 7, Timeout: 1}
	path := filepath.Join(t.TempDir(), "config.yml")
	if err := os.WriteFile(path, []byte(fmt.Sprintf("Log:\n  Level: error\nApi:\n  ApiHost: %q\n  ServerID: 7\n  Timeout: 1\n", srv.URL)), 0600); err != nil {
		t.Fatal(err)
	}
	client := panel.NewServerClient(&cfg.ApiConfig)
	n, x, _, err := startInitial(context.Background(), cfg, client, make(chan struct{}, 1))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { n.Close(); x.Close() }()
	addr := net.JoinHostPort("127.0.0.1", fmt.Sprint(port))
	conn, err := net.DialTimeout("tcp", addr, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()
	rev.Store(2)
	h, err := reload(path, &n, &x, nil)
	if err != nil {
		t.Fatal(err)
	}
	if h != nil {
		defer h.Close()
	}
	if s := client.State.Snapshot(); s.Applied == nil || s.Applied.SourceRevision != 2 {
		t.Fatalf("zero protocol not applied: %+v", s)
	}
	if conn, err := net.DialTimeout("tcp", addr, 200*time.Millisecond); err == nil {
		conn.Close()
		t.Fatal("old listener survived protocols:null")
	}
}

func TestReloadABAObservedDuringPreparation(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	listener.Close()
	var current atomic.Int32
	current.Store(1)
	entered, release := make(chan struct{}), make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v2/server/7":
			n := current.Load()
			etag := fmt.Sprintf(`"%d"`, n)
			w.Header().Set("ETag", etag)
			if r.Header.Get("If-None-Match") == etag {
				w.WriteHeader(304)
				return
			}
			protocols, total := "null", 0
			if n == 2 {
				protocols = fmt.Sprintf(`[{"type":"vless","enable":true,"port":%d,"transport":"tcp"}]`, port)
				total = 1
			}
			fmt.Fprintf(w, `{"code":200,"data":{"protocols":%s,"total":%d,"pull_interval":3600,"push_interval":3600,"routing":{"version":1,"outbounds":[],"rules":[],"default_outbound_id":"direct","mode":"ordered-v1-inherited","source":"global","source_revision":%d}}}`, protocols, total, n)
		case "/v1/server/user":
			close(entered)
			<-release
			fmt.Fprint(w, `{"code":200,"data":{"users":[]}}`)
		default:
			fmt.Fprint(w, `{"code":200}`)
		}
	}))
	defer srv.Close()
	cfg := conf.New()
	cfg.LogConfig.Level = "error"
	cfg.ApiConfig = conf.ServerApiConfig{ApiHost: srv.URL, ServerId: 7, Timeout: 3}
	path := filepath.Join(t.TempDir(), "config.yml")
	if err := os.WriteFile(path, []byte(fmt.Sprintf("Log:\n  Level: error\nApi:\n  ApiHost: %q\n  ServerID: 7\n  Timeout: 4\n", srv.URL)), 0600); err != nil {
		t.Fatal(err)
	}
	client := panel.NewServerClient(&cfg.ApiConfig)
	ch := make(chan struct{}, 1)
	n, x, _, err := startInitial(context.Background(), cfg, client, ch)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { n.Close(); x.Close() }()
	oldCore := x
	current.Store(2)
	done := make(chan error, 1)
	go func() {
		h, e := reload(path, &n, &x, nil)
		if h != nil {
			h.Close()
		}
		done <- e
	}()
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("B did not enter preparation")
	}
	current.Store(1)
	if err := oldCore.ServerConfigMonitor(context.Background()); err != nil {
		t.Fatal(err)
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if x.Client == client || x.Client.Timeout != 4 || x.Client.State != client.State {
		t.Fatal("timeout replacement did not share candidate state")
	}
	if !client.HasPending() || client.State.Snapshot().Pending.SourceRevision != 1 {
		t.Fatalf("ABA pending lost: %+v", client.State.Snapshot())
	}
	select {
	case <-ch:
	case <-time.After(time.Second):
		t.Fatal("ABA replacement did not signal reload")
	}
	h, err := reload(path, &n, &x, nil)
	if err != nil {
		t.Fatal(err)
	}
	if h != nil {
		h.Close()
	}
	if s := client.State.Snapshot(); s.Pending != nil || s.Applied.SourceRevision != 1 {
		t.Fatalf("ABA was not restored after 304: %+v", s)
	}
	if c, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", fmt.Sprint(port)), 200*time.Millisecond); err == nil {
		c.Close()
		t.Fatal("B listener remained open")
	}
}

func TestMonitorFetchFailureWakesServerReporter(t *testing.T) {
	var broken atomic.Bool
	reports := make(chan panel.ServerPushStatusRequest, 20)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v2/server/7":
			if broken.Load() {
				http.Error(w, "secret-token", 426)
				return
			}
			w.Header().Set("ETag", `"ok"`)
			if r.Header.Get("If-None-Match") == `"ok"` {
				w.WriteHeader(304)
				return
			}
			fmt.Fprint(w, `{"code":200,"data":{"protocols":[],"routing":{"version":1,"outbounds":[],"rules":[],"default_outbound_id":"direct","mode":"ordered-v1-inherited","source":"global","source_revision":1}}}`)
		case "/v1/server/status":
			var status panel.ServerPushStatusRequest
			if err := json.NewDecoder(r.Body).Decode(&status); err != nil {
				t.Error(err)
			}
			reports <- status
			fmt.Fprint(w, `{"code":200}`)
		}
	}))
	defer srv.Close()
	cfg := conf.New()
	cfg.ApiConfig = conf.ServerApiConfig{ApiHost: srv.URL, ServerId: 7, Timeout: 1}
	client := panel.NewServerClient(&cfg.ApiConfig)
	candidate, err := panel.GetServerConfig(context.Background(), client)
	if err != nil {
		t.Fatal(err)
	}
	client.Commit(candidate)
	r := newServerReporter(client, time.Hour)
	r.start()
	defer r.close()
	select {
	case <-reports:
	case <-time.After(time.Second):
		t.Fatal("no initial heartbeat")
	}
	x := core.New(cfg, client)
	broken.Store(true)
	_ = x.ServerConfigMonitor(context.Background())
	select {
	case status := <-reports:
		if status.Error == nil || status.Error.Stage != "fetch" || strings.Contains(status.Error.Message, "secret") {
			t.Fatalf("bad fetch receipt %+v", status)
		}
	case <-time.After(time.Second):
		t.Fatal("monitor did not wake reporter")
	}
	broken.Store(false)
	_ = x.ServerConfigMonitor(context.Background())
	select {
	case status := <-reports:
		if status.Error != nil {
			t.Fatalf("fetch recovery not reported %+v", status)
		}
	case <-time.After(time.Second):
		t.Fatal("recovery did not wake reporter")
	}
}

func TestInitialRetryReloadsFileAndClient(t *testing.T) {
	var requests atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.URL.Query().Get("secret_key") != "fixed" {
			http.Error(w, "bad secret", 403)
			return
		}
		fmt.Fprint(w, `{"code":200,"data":{"protocols":null,"pull_interval":3600,"routing":{"version":1,"outbounds":[],"rules":[],"default_outbound_id":"direct","mode":"ordered-v1-inherited","source":"global","source_revision":1}}}`)
	}))
	defer srv.Close()
	path := filepath.Join(t.TempDir(), "config.yml")
	writeConfig := func(secret string) {
		t.Helper()
		if err := os.WriteFile(path, []byte(fmt.Sprintf("Log:\n  Level: error\nApi:\n  ApiHost: %q\n  ServerID: 7\n  SecretKey: %q\n  Timeout: 1\n", srv.URL, secret)), 0600); err != nil {
			t.Fatal(err)
		}
	}
	r := newServerReporter(panel.NewServerClient(&conf.ServerApiConfig{}), time.Hour)
	if _, _, _, _, err := initialAttemptFromFile(context.Background(), path, r, nil); err == nil {
		t.Fatal("missing config accepted")
	}
	writeConfig("wrong")
	if _, _, _, _, err := initialAttemptFromFile(context.Background(), path, r, nil); err == nil {
		t.Fatal("invalid secret accepted")
	}
	old := r.client
	id := old.State.Snapshot().InstanceID
	writeConfig("fixed")
	n, x, _, cfg, err := initialAttemptFromFile(context.Background(), path, r, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer x.Close()
	defer n.Close()
	if cfg.ApiConfig.SecretKey != "fixed" || r.client == old || r.client.State.Snapshot().InstanceID != id || requests.Load() < 2 {
		t.Fatal("retry failed to rebuild client from fixed config")
	}
}

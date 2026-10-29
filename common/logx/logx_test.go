package logx

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	log "github.com/sirupsen/logrus"
)

func TestParseLevel(t *testing.T) {
	tests := map[string]log.Level{
		"debug":   log.DebugLevel,
		"info":    log.InfoLevel,
		"warn":    log.WarnLevel,
		"warning": log.WarnLevel,
		"error":   log.ErrorLevel,
		"unknown": log.InfoLevel,
		"":        log.InfoLevel,
	}
	for input, want := range tests {
		if got := parseLevel(input); got != want {
			t.Fatalf("parseLevel(%q) = %s, want %s", input, got, want)
		}
	}
}

func TestSetupStdout(t *testing.T) {
	h, err := Setup(Config{Level: "debug"})
	if err != nil {
		t.Fatalf("Setup() error = %v", err)
	}
	defer h.Close()
	if got := log.GetLevel(); got != log.DebugLevel {
		t.Fatalf("log level = %s, want debug", got)
	}
}

func TestFailedReloadKeepsPreviousLogger(t *testing.T) {
	path := filepath.Join(t.TempDir(), "previous.log")
	h, err := Setup(Config{Level: "error", Output: path})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { h.Close(); restored, _ := Setup(Config{}); _ = restored.Close() }()
	if _, err := Setup(Config{Level: "debug", Output: filepath.Join(path, "missing.log")}); err == nil {
		t.Fatal("invalid log path accepted")
	}
	if log.GetLevel() != log.ErrorLevel {
		t.Fatal("failed log preparation changed log level")
	}
	Component("test").Error("previous-log-retained")
	body, err := os.ReadFile(path)
	if err != nil || !strings.Contains(string(body), "previous-log-retained") {
		t.Fatalf("previous logger lost: %v", err)
	}
}

func TestScopedFields(t *testing.T) {
	if got := Component("server").Data[FieldComponent]; got != "server" {
		t.Fatalf("component field = %v, want server", got)
	}
	entry := Node("node-1")
	if got := entry.Data[FieldComponent]; got != "node" {
		t.Fatalf("component field = %v, want node", got)
	}
	if got := entry.Data[FieldNodeTag]; got != "node-1" {
		t.Fatalf("node_tag field = %v, want node-1", got)
	}
	entry = Task("sync")
	if got := entry.Data[FieldComponent]; got != "task" {
		t.Fatalf("component field = %v, want task", got)
	}
	if got := entry.Data[FieldTask]; got != "sync" {
		t.Fatalf("task field = %v, want sync", got)
	}
}

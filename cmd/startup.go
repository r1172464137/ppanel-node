package cmd

import (
	"context"
	"fmt"
	"strings"

	"github.com/perfect-panel/ppanel-node/api/panel"
	"github.com/perfect-panel/ppanel-node/conf"
	"github.com/perfect-panel/ppanel-node/core"
	"github.com/perfect-panel/ppanel-node/node"
)

// restorePrevious distinguishes a successful rollback from a dual failure.
func restorePrevious(stage string, cause error, cleanup func(), restart func() error) (bool, error) {
	cleanup()
	if restart == nil {
		return false, fmt.Errorf("%s failed: %w; previous core unavailable", stage, cause)
	}
	if err := restart(); err != nil {
		return false, fmt.Errorf("%s failed: %w; restoring previous nodes failed: %v", stage, cause, err)
	}
	if stage == "stop" {
		// A failed removal leaves a controller's started flag ambiguous; Start
		// cannot prove its listener is usable in that case.
		return false, fmt.Errorf("stop failed: %w; previous listener availability is unverified", cause)
	}
	return true, fmt.Errorf("%s failed, previous nodes restored: %w", stage, cause)
}

func validateCandidate(client *panel.ServerClient, candidate *panel.ServerConfigResponse) error {
	if err := core.ValidateServerConfig(candidate); err != nil {
		return err
	}
	if p := candidate.Data.Routing; p != nil && p.Mode == "ordered-v1-local" && p.SourceServerID != int64(client.ServerId) {
		return fmt.Errorf("local routing identity refers to another server")
	}
	return nil
}

// Each startup attempt re-reads local configuration and creates a fresh API
// client, so an operator can repair the URL, server ID or secret in place.
func initialAttemptFromFile(ctx context.Context, path string, reporter *serverReporter, reloadCh chan struct{}) (*node.Node, *core.XrayCore, *panel.ServerConfigResponse, *conf.Conf, error) {
	cfg := conf.New()
	if err := cfg.LoadFromPath(path); err != nil {
		reporter.recordFailure(panel.StageConfig)
		return nil, nil, nil, nil, fmt.Errorf("load local config: %w", err)
	}
	if err := panel.ValidateAPITimeout(cfg.ApiConfig.Timeout); err != nil {
		reporter.recordFailure(panel.StageConfig)
		return nil, nil, nil, nil, err
	}
	client := panel.NewServerClient(&cfg.ApiConfig)
	if err := reporter.setClient(client); err != nil {
		return nil, nil, nil, nil, err
	}
	n, x, candidate, err := startInitial(ctx, cfg, client, reloadCh)
	return n, x, candidate, cfg, err
}

// startInitial makes one attempt, leaving the candidate pending on failure.
// The process-level reporter continues independently while the caller retries.
func startInitial(ctx context.Context, cfg *conf.Conf, client *panel.ServerClient, reloadCh chan struct{}) (*node.Node, *core.XrayCore, *panel.ServerConfigResponse, error) {
	if err := panel.ValidateAPITimeout(cfg.ApiConfig.Timeout); err != nil {
		client.RecordFailure(nil, panel.StageConfig)
		return nil, nil, nil, err
	}
	candidate, err := panel.GetServerConfig(ctx, client)
	if err != nil {
		client.RecordFailure(nil, panel.StageFetch)
		return nil, nil, nil, fmt.Errorf("fetch candidate: %w", err)
	}
	if candidate == nil {
		candidate = client.AppliedOrPending()
	}
	if err := validateCandidate(client, candidate); err != nil {
		client.RecordFailure(candidate, panel.StageValidate)
		return nil, nil, candidate, fmt.Errorf("validate candidate: %w", err)
	}
	x := core.New(cfg, client)
	x.ReloadCh = reloadCh
	if err := x.StartPrepared(candidate); err != nil {
		stage := panel.StageBuild
		if strings.HasPrefix(err.Error(), "start core:") {
			stage = panel.StageCoreStart
		}
		client.RecordFailure(candidate, stage)
		_ = x.Close()
		return nil, nil, candidate, fmt.Errorf("%s candidate: %w", stage, err)
	}
	n, err := node.New(x, cfg, candidate)
	if err != nil {
		client.RecordFailure(candidate, panel.StagePrepare)
		_ = x.Close()
		return nil, nil, candidate, fmt.Errorf("prepare candidate: %w", err)
	}
	if err := n.Prepare(); err != nil {
		client.RecordFailure(candidate, panel.StagePrepare)
		n.Close()
		_ = x.Close()
		return nil, nil, candidate, fmt.Errorf("prepare candidate: %w", err)
	}
	if err := n.Start(); err != nil {
		client.RecordFailure(candidate, panel.StageBind)
		n.Close()
		_ = x.Close()
		return nil, nil, candidate, fmt.Errorf("bind candidate: %w", err)
	}
	if err := x.Activate(candidate); err != nil {
		client.RecordFailure(candidate, panel.StageMonitor)
		n.Close()
		_ = x.Close()
		return nil, nil, candidate, fmt.Errorf("start monitor: %w", err)
	}
	if err := client.Commit(candidate); err != nil {
		n.Close()
		_ = x.Close()
		return nil, nil, candidate, fmt.Errorf("commit candidate: %w", err)
	}
	if client.HasPending() && reloadCh != nil {
		select {
		case reloadCh <- struct{}{}:
		default:
		}
	}
	return n, x, candidate, nil
}

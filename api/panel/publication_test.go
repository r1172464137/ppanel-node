package panel

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/perfect-panel/ppanel-node/conf"
)

func publicationCandidate(revision int64) *ServerConfigResponse {
	return &ServerConfigResponse{Data: &Data{Routing: &RoutingPolicy{RoutingIdentity: RoutingIdentity{Mode: "ordered-v1-inherited", Source: "global", SourceRevision: revision}}}}
}

func TestPublicationFenceRejectsRetiredServerAndCertificateClients(t *testing.T) {
	// Distinct host/secret and independent candidate state, same server ID.
	old := NewServerClient(&conf.ServerApiConfig{ApiHost: "http://old.invalid", SecretKey: "old", ServerId: 8201})
	fresh := NewServerClient(&conf.ServerApiConfig{ApiHost: "http://new.invalid", SecretKey: "new", ServerId: 8201})
	if err := old.Commit(publicationCandidate(1)); err != nil {
		t.Fatal(err)
	}
	old.statusMu.Lock()
	startedServer, startedCert := make(chan struct{}), make(chan struct{})
	serverResult, certResult := make(chan error, 1), make(chan error, 1)
	go func() {
		close(startedServer)
		serverResult <- old.ReportServerStatus(context.Background(), &NodeStatus{})
	}()
	node, err := NewNodeClient(&conf.NodeApiConfig{APIHost: "http://old.invalid", SecretKey: "old", NodeID: 8201, NodeType: "vless"})
	if err != nil {
		t.Fatal(err)
	}
	if err := old.BindNodeClient(node); err != nil {
		t.Fatal(err)
	}
	go func() {
		close(startedCert)
		certResult <- old.ReportCertificateStatus(context.Background(), node, &NodeStatus{})
	}()
	<-startedServer
	<-startedCert
	if err := fresh.Commit(publicationCandidate(2)); err != nil {
		t.Fatal(err)
	}
	current, err := fresh.statusPayloadAt(&NodeStatus{}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	old.statusMu.Unlock()
	for _, ch := range []<-chan error{serverResult, certResult} {
		select {
		case err := <-ch:
			if !errors.Is(err, ErrRetiredClient) {
				t.Fatalf("old client issued status: %v", err)
			}
		case <-time.After(time.Second):
			t.Fatal("retired client remained blocked")
		}
	}
	if _, err := old.statusPayloadAt(&NodeStatus{}, time.Now()); !errors.Is(err, ErrRetiredClient) {
		t.Fatalf("old client acquired sequence: %v", err)
	}
	after, err := fresh.statusPayloadAt(&NodeStatus{}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if current.Applied.SourceRevision != 2 || after.Applied.SourceRevision != 2 || after.Sequence <= current.Sequence {
		t.Fatalf("wrong current status: %+v %+v", current, after)
	}
	if err := old.ActivateStatusPublisher(); !errors.Is(err, ErrRetiredClient) {
		t.Fatalf("old client was resurrected: %v", err)
	}
	if err := fresh.ReportCertificateStatus(context.Background(), node, &NodeStatus{}); !errors.Is(err, ErrRetiredClient) {
		t.Fatalf("old controller accepted by new generation: %v", err)
	}
}

func TestFetchWaitCanBeCanceled(t *testing.T) {
	client := NewServerClient(&conf.ServerApiConfig{ServerId: 8205})
	client.fetchGate <- struct{}{}
	defer func() { <-client.fetchGate }()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, err := GetServerConfig(ctx, client); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("waiting fetch did not honor cancellation: %v", err)
	}
}

func TestRetiredFetchCannotMutateSharedStateAfterPromotion(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	var releaseOnce sync.Once
	unblock := func() { releaseOnce.Do(func() { close(release) }) }
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(entered)
		<-release
		fmt.Fprint(w, `{"code":200,"data":{"protocols":[],"total":0,"routing":{"version":1,"outbounds":[],"rules":[],"default_outbound_id":"direct","mode":"ordered-v1-inherited","source":"global","source_revision":1}}}`)
	}))
	defer func() { unblock(); server.Close() }()
	old := NewServerClient(&conf.ServerApiConfig{ApiHost: server.URL, SecretKey: "same", ServerId: 8204, Timeout: 2})
	fresh := NewServerClient(&conf.ServerApiConfig{ApiHost: server.URL, SecretKey: "same", ServerId: 8204, Timeout: 3})
	if !fresh.ShareCandidateState(old) {
		t.Fatal("candidate state was not shared")
	}
	first := publicationCandidate(1)
	first.bodyHash = "old"
	if err := old.Commit(first); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { _, err := GetServerConfig(context.Background(), old); done <- err }()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("old fetch did not start")
	}
	second := publicationCandidate(2)
	second.bodyHash = "new"
	if err := fresh.Commit(second); err != nil {
		unblock()
		t.Fatal(err)
	}
	unblock()
	select {
	case err := <-done:
		if !errors.Is(err, ErrRetiredClient) {
			t.Fatalf("old fetch was not fenced: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("old fetch stuck")
	}
	old.RecordFailure(first, StageValidate)
	state := fresh.State.Snapshot()
	if state.Applied == nil || state.Applied.SourceRevision != 2 || state.Pending != nil || state.Error != nil {
		t.Fatalf("retired fetch mutated shared state: %+v", state)
	}
}

func TestOlderProvisionalGenerationCannotResurrect(t *testing.T) {
	active := NewServerClient(&conf.ServerApiConfig{ServerId: 8203})
	older := NewServerClient(&conf.ServerApiConfig{ServerId: 8203})
	newer := NewServerClient(&conf.ServerApiConfig{ServerId: 8203})
	if err := active.Commit(publicationCandidate(1)); err != nil {
		t.Fatal(err)
	}
	if err := newer.Commit(publicationCandidate(3)); err != nil {
		t.Fatal(err)
	}
	if err := older.ActivateStatusPublisher(); !errors.Is(err, ErrRetiredClient) {
		t.Fatalf("old provisional client activated: %v", err)
	}
	if err := older.Commit(publicationCandidate(2)); !errors.Is(err, ErrRetiredClient) {
		t.Fatalf("old provisional candidate committed: %v", err)
	}
	payload, err := newer.statusPayloadAt(&NodeStatus{}, time.Now())
	if err != nil || payload.Applied.SourceRevision != 3 {
		t.Fatalf("new generation damaged: %+v %v", payload, err)
	}
}

func TestPublicationFenceOrdersInflightReportsAcrossHosts(t *testing.T) {
	arrived, release := make(chan ServerPushStatusRequest, 1), make(chan struct{})
	var releaseOnce sync.Once
	unblock := func() { releaseOnce.Do(func() { close(release) }) }
	oldServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var v ServerPushStatusRequest
		if err := json.NewDecoder(r.Body).Decode(&v); err != nil {
			t.Error(err)
		}
		arrived <- v
		<-release
		fmt.Fprint(w, `{"code":200}`)
	}))
	defer func() { unblock(); oldServer.Close() }()
	newReports := make(chan ServerPushStatusRequest, 1)
	newServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var v ServerPushStatusRequest
		if err := json.NewDecoder(r.Body).Decode(&v); err != nil {
			t.Error(err)
		}
		newReports <- v
		fmt.Fprint(w, `{"code":200}`)
	}))
	defer newServer.Close()
	old := NewServerClient(&conf.ServerApiConfig{ApiHost: oldServer.URL, SecretKey: "old", ServerId: 8202, Timeout: 2})
	fresh := NewServerClient(&conf.ServerApiConfig{ApiHost: newServer.URL, SecretKey: "new", ServerId: 8202, Timeout: 2})
	if err := old.Commit(publicationCandidate(1)); err != nil {
		t.Fatal(err)
	}
	oldResult := make(chan error, 1)
	go func() { oldResult <- old.ReportServerStatus(context.Background(), &NodeStatus{}) }()
	var oldReport ServerPushStatusRequest
	select {
	case oldReport = <-arrived:
	case <-time.After(time.Second):
		t.Fatal("old request not in flight")
	}
	if err := fresh.Commit(publicationCandidate(2)); err != nil {
		t.Fatal(err)
	}
	if err := fresh.ReportServerStatus(context.Background(), &NodeStatus{}); err != nil {
		t.Fatal(err)
	}
	newReport := <-newReports
	unblock()
	if err := <-oldResult; err != nil {
		t.Fatal(err)
	}
	if oldReport.InstanceID != newReport.InstanceID || oldReport.Sequence == 0 || newReport.Sequence <= oldReport.Sequence || newReport.Applied.SourceRevision != 2 {
		t.Fatalf("generation order lost: old=%+v new=%+v", oldReport, newReport)
	}
	if err := old.ReportServerStatus(context.Background(), &NodeStatus{}); !errors.Is(err, ErrRetiredClient) {
		t.Fatalf("retired client reported: %v", err)
	}
}

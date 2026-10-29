package panel

import (
	"crypto/rand"
	"fmt"
	"sync"
	"sync/atomic"
)

// RoutingState is shared by the server, its monitor and all protocol
// controllers. Only the serialized switch path may advance Applied.
type RoutingState struct {
	mu         sync.Mutex
	applied    *RoutingIdentity
	pending    *RoutingIdentity
	lastError  *RoutingError
	fetchError *RoutingError
	serverID   int
	instanceID string
	notify     func()
}

type RoutingError struct {
	Identity *RoutingIdentity `json:"identity,omitempty"`
	Stage    string           `json:"stage"`
	Message  string           `json:"message"`
}

type RoutingStatus struct {
	Version    int              `json:"routing_version"`
	Applied    *RoutingIdentity `json:"routing_applied,omitempty"`
	Pending    *RoutingIdentity `json:"routing_pending,omitempty"`
	Error      *RoutingError    `json:"routing_error,omitempty"`
	InstanceID string           `json:"instance_id"`
	Sequence   uint64           `json:"routing_sequence"`
}

var processIDOnce sync.Once
var processID string
var processRoutingSequence atomic.Uint64

// Sequence is independent of wall-clock time and shared by all clients in
// this process. Zero is reserved for absence by the receiver.
func nextRoutingSequence() uint64 {
	v := processRoutingSequence.Add(1)
	if v == 0 {
		panic("routing status sequence exhausted")
	}
	return v
}

// Generated once per process, not once per API client or reload.
func ProcessInstanceID() string {
	processIDOnce.Do(func() {
		var b [16]byte
		if _, err := rand.Read(b[:]); err != nil {
			panic(fmt.Sprintf("generate process instance ID: %v", err))
		}
		b[6] = (b[6] & 0x0f) | 0x40
		b[8] = (b[8] & 0x3f) | 0x80
		processID = fmt.Sprintf("%x-%x-%x-%x-%x", b[:4], b[4:6], b[6:8], b[8:10], b[10:])
	})
	return processID
}
func NewRoutingState(serverID int) *RoutingState {
	return &RoutingState{serverID: serverID, instanceID: ProcessInstanceID()}
}
func (s *RoutingState) SetNotifier(fn func()) {
	if s == nil {
		return
	}
	s.mu.Lock()
	s.notify = fn
	s.mu.Unlock()
}
func (s *RoutingState) signal() {
	if s == nil {
		return
	}
	s.mu.Lock()
	fn := s.notify
	s.mu.Unlock()
	if fn != nil {
		fn()
	}
}

func copyIdentity(v *RoutingIdentity) *RoutingIdentity {
	if v == nil {
		return nil
	}
	x := *v
	return &x
}
func identityOf(v *ServerConfigResponse, serverID int) *RoutingIdentity {
	if v == nil || v.Data == nil {
		return nil
	}
	if v.Data.Routing == nil {
		// Legacy responses carry no authoritative revision/source identity.
		return nil
	}
	id := &v.Data.Routing.RoutingIdentity
	// A corrupt candidate must not inject arbitrary/secret or unbounded text
	// into status reports. Publish identities only when their shape is valid.
	if id.SourceRevision <= 0 || id.LocalTransitionRevision < 0 {
		return nil
	}
	switch id.Mode {
	case "ordered-v1-local":
		if id.Source != "server" || id.SourceServerID <= 0 || id.SourceServerID != int64(serverID) || id.SourceRevision != id.LocalTransitionRevision {
			return nil
		}
	case "ordered-v1-inherited":
		if id.Source != "global" || id.SourceServerID != 0 {
			return nil
		}
	default:
		return nil
	}
	return copyIdentity(id)
}
func (s *RoutingState) setPending(id *RoutingIdentity) {
	if s == nil {
		return
	}
	s.mu.Lock()
	s.pending = copyIdentity(id)
	s.mu.Unlock()
	s.signal()
}

// A failed rollback makes the last applied configuration unavailable; do not
// advertise it as currently applied merely because it once started.
func (s *RoutingState) InvalidateApplied() {
	if s == nil {
		return
	}
	s.mu.Lock()
	s.applied = nil
	s.mu.Unlock()
	s.signal()
}

func (s *RoutingState) commit(id, pending *RoutingIdentity) {
	if s == nil {
		return
	}
	s.mu.Lock()
	s.applied, s.pending = copyIdentity(id), copyIdentity(pending)
	s.mu.Unlock()
	s.signal()
}

// RecordFailure deliberately sends a fixed, non-secret message; detailed
// diagnostics remain in the local log, never in a status heartbeat.
func (s *RoutingState) RecordFailure(candidate *ServerConfigResponse, stage FailureStage) {
	if s == nil {
		return
	}
	if !stage.valid() {
		stage = StageForOperation(string(stage))
	}
	s.mu.Lock()
	id := identityOf(candidate, s.serverID)
	if id == nil && candidate == nil && stage != StageFetch {
		id = copyIdentity(s.pending)
	}
	value := &RoutingError{Identity: id, Stage: string(stage), Message: "candidate failed during " + string(stage)}
	if stage == StageFetch {
		s.fetchError = value
	} else {
		s.lastError = value
	}
	s.mu.Unlock()
	s.signal()
}

// A healthy fetch clears only fetch errors, not a failed apply/restore.
func (s *RoutingState) ClearFetchFailure() {
	if s == nil {
		return
	}
	s.mu.Lock()
	changed := s.fetchError != nil
	if changed {
		s.fetchError = nil
	}
	s.mu.Unlock()
	if changed {
		s.signal()
	}
}
func (s *RoutingState) Snapshot() RoutingStatus {
	if s == nil {
		return RoutingStatus{Version: 1}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	v := RoutingStatus{Version: 1, InstanceID: s.instanceID, Applied: copyIdentity(s.applied), Pending: copyIdentity(s.pending)}
	lastError := s.lastError
	if s.fetchError != nil {
		lastError = s.fetchError
	}
	if lastError != nil {
		e := *lastError
		e.Identity = copyIdentity(e.Identity)
		v.Error = &e
	}
	return v
}

// Commit is called only after the new core and every required listener are
// running. A newer observation remains pending if it arrived during the switch.
func (c *ServerClient) Commit(v *ServerConfigResponse) error {
	if c == nil || v == nil || c.publication == nil {
		return fmt.Errorf("invalid candidate")
	}
	gate := c.publication.gate
	gate.mu.Lock()
	defer gate.mu.Unlock()
	if err := c.activatePublisherLocked(); err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.applied = v
	c.ServerConfigEtag, c.responseBodyHash, c.UseProtobuf = v.etag, v.bodyHash, v.UseProtobuf
	// Reconcile against the latest observation, not the previous pending slot:
	// A(applied) -> B(in flight) -> A(observed) must enqueue A after B commits.
	c.pending = nil
	if c.observed != nil && c.observed.bodyHash != v.bodyHash {
		c.pending = c.observed
	}
	var pending *RoutingIdentity
	if c.pending != nil {
		pending = identityOf(c.pending, c.ServerId)
	}
	c.State.commit(identityOf(v, c.ServerId), pending)
	return nil
}

func (c *ServerClient) AppliedOrPending() *ServerConfigResponse {
	if c == nil {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.pending != nil {
		return c.pending
	}
	return c.applied
}

// CandidateKey identifies the observed body, not an applied ETag. It is used
// solely to coalesce monitor notifications while a bad candidate is retried.
func (v *ServerConfigResponse) CandidateKey() string {
	if v == nil {
		return ""
	}
	return v.bodyHash
}

func (c *ServerClient) HasPending() bool {
	if c == nil {
		return false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.pending != nil
}

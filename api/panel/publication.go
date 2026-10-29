package panel

import (
	"errors"
	"fmt"
	"sync"
	"time"
)

var ErrRetiredClient = errors.New("server client generation is retired")

// The registry is process-wide, keyed by server ID, even when API host/secret
// changes. Each client is a provisional generation until activated/applied.
type publicationGate struct {
	mu     sync.Mutex
	next   uint64
	active *publicationLease
}
type publicationLease struct {
	gate       *publicationGate
	generation uint64
	retired    bool // protected by gate.mu
}

var publicationRegistry = struct {
	sync.Mutex
	servers map[int]*publicationGate
}{servers: make(map[int]*publicationGate)}

func newPublicationLease(serverID int) *publicationLease {
	publicationRegistry.Lock()
	gate := publicationRegistry.servers[serverID]
	if gate == nil {
		gate = &publicationGate{}
		publicationRegistry.servers[serverID] = gate
	}
	publicationRegistry.Unlock()
	gate.mu.Lock()
	defer gate.mu.Unlock()
	gate.next++
	if gate.next == 0 {
		panic("status client generation exhausted")
	}
	return &publicationLease{gate: gate, generation: gate.next}
}

func (c *ServerClient) retiredLocked() bool {
	lease := c.publication
	if lease.retired {
		return true
	}
	if current := lease.gate.active; current != nil && current.generation > lease.generation {
		lease.retired = true
		return true
	}
	return false
}

func (c *ServerClient) activatePublisherLocked() error {
	lease := c.publication
	if c.retiredLocked() {
		return ErrRetiredClient
	}
	if previous := lease.gate.active; previous != nil && previous != lease {
		previous.retired = true
	}
	lease.gate.active = lease
	return nil
}

// ActivateStatusPublisher is used for initial capability reporting before a
// core exists. Reload promotes the new client atomically in Commit instead.
func (c *ServerClient) ActivateStatusPublisher() error {
	if c == nil || c.publication == nil {
		return ErrRetiredClient
	}
	c.publication.gate.mu.Lock()
	defer c.publication.gate.mu.Unlock()
	return c.activatePublisherLocked()
}

// BindNodeClient assigns a protocol controller to exactly this server-client
// generation. It is called once before the controller starts any tasks.
func (c *ServerClient) BindNodeClient(node *NodeClient) error {
	if c == nil || node == nil || c.publication == nil || node.NodeId != c.ServerId || node.APIHost != c.APIHost || node.SecretKey != c.SecretKey {
		return fmt.Errorf("node client identity does not match server client")
	}
	node.publication = c.publication
	return nil
}

// statusPayloadAt obtains snapshot, process sequence and client generation
// while holding the same gate used for promotion. An old in-flight request may
// arrive late, but cannot acquire a newer sequence after the promotion.
func (c *ServerClient) statusPayloadAt(status *NodeStatus, now time.Time) (ServerPushStatusRequest, error) {
	if c == nil || c.publication == nil {
		return ServerPushStatusRequest{}, ErrRetiredClient
	}
	gate := c.publication.gate
	gate.mu.Lock()
	defer gate.mu.Unlock()
	if c.retiredLocked() || gate.active != c.publication {
		return ServerPushStatusRequest{}, ErrRetiredClient
	}
	routing := c.State.Snapshot()
	routing.Sequence = nextRoutingSequence()
	return ServerPushStatusRequest{Cpu: status.CPU, Mem: status.Mem, Disk: status.Disk, UpdatedAt: now.UnixMilli(), RoutingStatus: &routing}, nil
}

// Mutation through a retired client is suppressed as well: timeout-rebuilt
// clients may share the same candidate/state storage with the old core.
func (c *ServerClient) RecordFailure(candidate *ServerConfigResponse, stage FailureStage) {
	if c == nil || c.publication == nil {
		return
	}
	gate := c.publication.gate
	gate.mu.Lock()
	defer gate.mu.Unlock()
	if !c.retiredLocked() {
		c.State.RecordFailure(candidate, stage)
	}
}
func (c *ServerClient) InvalidateApplied() {
	if c == nil || c.publication == nil {
		return
	}
	gate := c.publication.gate
	gate.mu.Lock()
	defer gate.mu.Unlock()
	if !c.retiredLocked() {
		c.State.InvalidateApplied()
	}
}

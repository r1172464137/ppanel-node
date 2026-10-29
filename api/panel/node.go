package panel

import (
	"context"
	"fmt"
	"time"

	serverv1 "github.com/perfect-panel/ppanel-node/api/server/v1"
)

type NodeInfo struct {
	Id                     int
	Type                   string
	PushInterval           int
	PullInterval           int
	TrafficReportThreshold int
	ACMEEmail              string
	ACMECADirURL           string
	Protocol               *Protocol
}

type ServerPushStatusRequest struct {
	Cpu       float64 `json:"cpu"`
	Mem       float64 `json:"mem"`
	Disk      float64 `json:"disk"`
	UpdatedAt int64   `json:"updated_at"`
	*RoutingStatus
}

type NodeStatus struct {
	CPU    float64
	Mem    float64
	Disk   float64
	Uptime uint64
}

// ReportServerStatus is independent of protocol controllers and therefore
// works even when the effective configuration has no runnable protocols.
func (c *ServerClient) ReportServerStatus(ctx context.Context, status *NodeStatus) error {
	c.statusMu.Lock()
	defer c.statusMu.Unlock()
	c.mu.Lock()
	useProto := c.UseProtobuf
	c.mu.Unlock()
	payload, err := c.statusPayloadAt(status, time.Now())
	if err != nil {
		return err
	}
	request := c.Client.R().SetContext(ctx).SetQueryParam("server_id", fmt.Sprint(c.ServerId))
	if useProto {
		if err := setProtobufRequestBody(request, statusToProtobuf(payload)); err != nil {
			return err
		}
	} else {
		request.SetBody(payload).ForceContentType("application/json")
	}
	r, err := request.Post("/v1/server/status")
	if err != nil {
		if ctx.Err() != nil {
			return fmt.Errorf("report server status: %w", ctx.Err())
		}
		return fmt.Errorf("report server status: transport failed")
	}
	return checkPanelResponse(r, c.APIHost+"/v1/server/status")
}

// A certificate report is serialized with server heartbeats, and snapshots
// routing state only after acquiring the same lock.
func (c *ServerClient) ReportCertificateStatus(ctx context.Context, node *NodeClient, status *NodeStatus) error {
	if node == nil || node.publication == nil || node.publication != c.publication {
		return ErrRetiredClient
	}
	c.statusMu.Lock()
	defer c.statusMu.Unlock()
	payload, err := c.statusPayloadAt(status, time.Now())
	if err != nil {
		return err
	}
	return node.reportStatusPayload(ctx, payload)
}

// Certificate reports use the same fenced payload as server heartbeats.
func (c *NodeClient) reportStatusPayload(ctx context.Context, payload ServerPushStatusRequest) error {
	request := c.Client.R().SetContext(ctx)
	if c.UseProtobuf {
		if err := setProtobufRequestBody(request, statusToProtobuf(payload)); err != nil {
			return err
		}
	} else {
		request.SetBody(payload).ForceContentType("application/json")
	}
	r, err := request.Post("/v1/server/status")
	if err != nil {
		if ctx.Err() != nil {
			return fmt.Errorf("report protocol certificate status: %w", ctx.Err())
		}
		return fmt.Errorf("report protocol certificate status: transport failed")
	}
	return checkPanelResponse(r, c.APIHost+"/v1/server/status")
}

func routingIdentityToProtobuf(v *RoutingIdentity) *serverv1.RoutingIdentity {
	if v == nil {
		return nil
	}
	return &serverv1.RoutingIdentity{Mode: v.Mode, Source: v.Source, SourceServerId: v.SourceServerID,
		SourceRevision: v.SourceRevision, LocalTransitionRevision: v.LocalTransitionRevision}
}
func statusToProtobuf(v ServerPushStatusRequest) *serverv1.PushServerStatusRequest {
	p := &serverv1.PushServerStatusRequest{Cpu: v.Cpu, Mem: v.Mem, Disk: v.Disk, UpdatedAt: v.UpdatedAt}
	if s := v.RoutingStatus; s != nil {
		p.RoutingVersion = uint32(s.Version)
		p.InstanceId = s.InstanceID
		p.RoutingSequence = s.Sequence
		p.RoutingApplied, p.RoutingPending = routingIdentityToProtobuf(s.Applied), routingIdentityToProtobuf(s.Pending)
		if s.Error != nil {
			p.RoutingError = &serverv1.RoutingError{Identity: routingIdentityToProtobuf(s.Error.Identity), Stage: s.Error.Stage, Message: s.Error.Message}
		}
	}
	return p
}

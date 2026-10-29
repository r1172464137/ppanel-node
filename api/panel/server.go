package panel

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"unicode/utf8"

	serverv1 "github.com/perfect-panel/ppanel-node/api/server/v1"
	"google.golang.org/protobuf/proto"
)

type ServerConfigResponse struct {
	Code        int    `json:"code"`
	Msg         string `json:"msg"`
	Data        *Data  `json:"data"`
	UseProtobuf bool   `json:"-"`
	etag        string
	bodyHash    string
}

type Data struct {
	TrafficReportThreshold int            `json:"traffic_report_threshold"`
	PushInterval           int            `json:"push_interval"`
	PullInterval           int            `json:"pull_interval"`
	IPStrategy             string         `json:"ip_strategy"`
	DNS                    *[]DNSItem     `json:"dns"`
	Block                  *[]string      `json:"block"`
	BlockIPs               *[]string      `json:"block_ips"`
	BlockProtocols         *[]string      `json:"block_protocols"`
	Outbound               *[]Outbound    `json:"outbound"`
	Protocols              *[]Protocol    `json:"protocols"`
	Total                  int            `json:"total"`
	Routing                *RoutingPolicy `json:"routing,omitempty"`
	// Retain JSON presence, including explicit null, for fail-closed validation.
	RoutingPresent       bool `json:"-"`
	LegacyRoutingPresent bool `json:"-"`
}

// Marshal ordered delivery without the reserved legacy routing keys.
func (d Data) MarshalJSON() ([]byte, error) {
	if d.Routing == nil {
		return nil, fmt.Errorf("ordered routing v1 required")
	}
	if d.LegacyRoutingPresent || (d.Block != nil && len(*d.Block) > 0) || (d.BlockIPs != nil && len(*d.BlockIPs) > 0) || (d.BlockProtocols != nil && len(*d.BlockProtocols) > 0) || (d.Outbound != nil && len(*d.Outbound) > 0) {
		return nil, fmt.Errorf("mixed routing configuration")
	}
	return json.Marshal(struct {
		TrafficReportThreshold int            `json:"traffic_report_threshold"`
		PushInterval           int            `json:"push_interval"`
		PullInterval           int            `json:"pull_interval"`
		IPStrategy             string         `json:"ip_strategy"`
		DNS                    *[]DNSItem     `json:"dns"`
		Protocols              *[]Protocol    `json:"protocols"`
		Total                  int            `json:"total"`
		Routing                *RoutingPolicy `json:"routing"`
	}{d.TrafficReportThreshold, d.PushInterval, d.PullInterval, d.IPStrategy, d.DNS, d.Protocols, d.Total, d.Routing})
}

func (d *Data) UnmarshalJSON(b []byte) error {
	if err := checkDuplicateJSON(b); err != nil {
		return err
	}
	fields, err := exactObject(b, dataJSONNames)
	if err != nil {
		return err
	}
	for _, entry := range []struct {
		name    string
		allowed map[string]bool
	}{{"protocols", protocolJSONNames}, {"dns", dnsJSONNames}} {
		if raw, ok := fields[entry.name]; ok {
			if err := validateArrayObjects(raw, entry.allowed, entry.name); err != nil {
				return err
			}
		}
	}
	if raw, ok := fields["routing"]; ok {
		if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
			return fmt.Errorf("routing must not be null")
		}
		if err := validatePolicyJSON(raw); err != nil {
			return fmt.Errorf("invalid routing policy: %w", err)
		}
	}
	type alias Data
	var value alias
	decoder := json.NewDecoder(bytes.NewReader(b))
	decoder.UseNumber()
	if err := decoder.Decode(&value); err != nil {
		return err
	}
	*d = Data(value)
	_, d.RoutingPresent = fields["routing"]
	// The backend emits protocols:null when there are zero protocols. Missing
	// is different: it remains nil and is rejected by GetServerConfig.
	if raw, ok := fields["protocols"]; ok && bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		empty := []Protocol{}
		d.Protocols = &empty
	}
	for _, key := range []string{"block", "block_ips", "block_protocols", "outbound"} {
		if _, ok := fields[key]; ok {
			d.LegacyRoutingPresent = true
		}
	}
	return nil
}

type RoutingIdentity struct {
	Mode                    string `json:"mode"`
	Source                  string `json:"source"`
	SourceServerID          int64  `json:"source_server_id"`
	SourceRevision          int64  `json:"source_revision"`
	LocalTransitionRevision int64  `json:"local_transition_revision"`
}

type RoutingPolicy struct {
	Version           int         `json:"version"`
	Outbounds         []Outbound  `json:"outbounds"`
	Rules             []RouteRule `json:"rules"`
	DefaultOutboundID string      `json:"default_outbound_id"`
	RoutingIdentity
}

type RouteRule struct {
	ID         string   `json:"id"`
	Enabled    *bool    `json:"enabled"`
	Remark     string   `json:"remark"`
	Kind       string   `json:"kind"`
	Values     []string `json:"values"`
	OutboundID string   `json:"outbound_id"`
}

type DNSItem struct {
	Proto      string   `json:"proto"`
	Address    string   `json:"address"`
	ServerName string   `json:"server_name"`
	Domains    []string `json:"domains"`
}

func (d *DNSItem) UnmarshalJSON(raw []byte) error {
	if err := checkDuplicateJSON(raw); err != nil {
		return err
	}
	fields, err := exactObject(raw, dnsJSONNames)
	if err != nil {
		return err
	}
	for _, name := range []string{"proto", "address", "server_name"} {
		if value, ok := fields[name]; ok && bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return fmt.Errorf("DNS %s must be a string", name)
		}
	}
	type alias DNSItem
	var value alias
	if err := json.Unmarshal(raw, &value); err != nil {
		return err
	}
	*d = DNSItem(value)
	return nil
}

type Outbound struct {
	ID                      string   `json:"id,omitempty"`
	Name                    string   `json:"name"`
	Protocol                string   `json:"protocol"`
	Address                 string   `json:"address"`
	Port                    int      `json:"port"`
	User                    string   `json:"user,omitempty"`
	Password                string   `json:"password"`
	UUID                    string   `json:"uuid,omitempty"`
	Cipher                  string   `json:"cipher,omitempty"`
	Plugin                  string   `json:"plugin,omitempty"`
	PluginOptions           any      `json:"plugin_opts,omitempty"`
	Security                string   `json:"security,omitempty"`
	SNI                     string   `json:"sni,omitempty"`
	ALPN                    []string `json:"alpn,omitempty"`
	AllowInsecure           bool     `json:"allow_insecure,omitempty"`
	Fingerprint             string   `json:"fingerprint,omitempty"`
	Transport               string   `json:"transport,omitempty"`
	Host                    string   `json:"host,omitempty"`
	Path                    string   `json:"path,omitempty"`
	ServiceName             string   `json:"service_name,omitempty"`
	XHTTPMode               string   `json:"xhttp_mode,omitempty"`
	XHTTPExtra              string   `json:"xhttp_extra,omitempty"`
	Flow                    string   `json:"flow,omitempty"`
	Encryption              string   `json:"encryption,omitempty"`
	EncryptionMode          string   `json:"encryption_mode,omitempty"`
	EncryptionRTT           string   `json:"encryption_rtt,omitempty"`
	EncryptionTicket        string   `json:"encryption_ticket,omitempty"`
	EncryptionClientPadding string   `json:"encryption_client_padding,omitempty"`
	EncryptionPassword      string   `json:"encryption_password,omitempty"`
	Multiplex               string   `json:"multiplex,omitempty"`
	UoT                     bool     `json:"uot,omitempty"`
	UoTVersion              int      `json:"uot_version,omitempty"`
	CongestionController    string   `json:"congestion_controller,omitempty"`
	UDPStream               bool     `json:"udp_stream,omitempty"`
	ReduceRTT               bool     `json:"reduce_rtt,omitempty"`
	Heartbeat               int      `json:"heartbeat,omitempty"`
	RealityPublicKey        string   `json:"reality_public_key,omitempty"`
	RealityShortID          string   `json:"reality_short_id,omitempty"`
	SpiderX                 string   `json:"spider_x,omitempty"`
	Settings                string   `json:"settings,omitempty"`
	StreamSettings          string   `json:"stream_settings,omitempty"`
	Rules                   []string `json:"rules"`
	IPRules                 []string `json:"ip_rules"`
	ProtocolRules           []string `json:"protocol_rules"`
}

type Protocol struct {
	Type                    string  `json:"type"`
	Port                    int     `json:"port"`
	Enable                  bool    `json:"enable"`
	Security                string  `json:"security"`
	SNI                     string  `json:"sni"`
	AllowInsecure           bool    `json:"allow_insecure"`
	Fingerprint             string  `json:"fingerprint"`
	RealityServerAddr       string  `json:"reality_server_addr"`
	RealityServerPort       int     `json:"reality_server_port"`
	RealityXver             int     `json:"reality_xver"` // Target-side PROXY version (0/1/2), independent of reception.
	RealityPrivateKey       string  `json:"reality_private_key"`
	RealityPublicKey        string  `json:"reality_public_key"`
	RealityShortID          string  `json:"reality_short_id"`
	Transport               string  `json:"transport"`
	Host                    string  `json:"host"`
	Path                    string  `json:"path"`
	ServiceName             string  `json:"service_name"`
	Cipher                  string  `json:"cipher"`
	ServerKey               string  `json:"server_key"`
	Plugin                  string  `json:"plugin,omitempty"`
	PluginOptions           any     `json:"plugin_opts,omitempty"`
	Flow                    string  `json:"flow"`
	UoT                     bool    `json:"uot"`
	UoTVersion              int     `json:"uot_version"`
	AcceptProxyProtocol     bool    `json:"accept_proxy_protocol"`
	HopPorts                string  `json:"hop_ports"`
	HopInterval             int     `json:"hop_interval"`
	ObfsPassword            string  `json:"obfs_password"`
	DisableSNI              bool    `json:"disable_sni"`
	ReduceRTT               bool    `json:"reduce_rtt"`
	UDPRelayMode            string  `json:"udp_relay_mode"`
	CongestionController    string  `json:"congestion_controller"`
	Multiplex               string  `json:"multiplex"`
	PaddingScheme           string  `json:"padding_scheme"`
	UpMbps                  int     `json:"up_mbps"`
	DownMbps                int     `json:"down_mbps"`
	Obfs                    string  `json:"obfs"`
	ObfsHost                string  `json:"obfs_host"`
	ObfsPath                string  `json:"obfs_path"`
	XHTTPMode               string  `json:"xhttp_mode"`
	XHTTPExtra              string  `json:"xhttp_extra"`
	Encryption              string  `json:"encryption"`
	EncryptionMode          string  `json:"encryption_mode"`
	EncryptionRTT           string  `json:"encryption_rtt"`
	EncryptionTicket        string  `json:"encryption_ticket"`
	EncryptionServerPadding string  `json:"encryption_server_padding"`
	EncryptionPrivateKey    string  `json:"encryption_private_key"`
	EncryptionClientPadding string  `json:"encryption_client_padding"`
	EncryptionPassword      string  `json:"encryption_password"`
	EchEnable               bool    `json:"ech_enable"`
	EchServerName           string  `json:"ech_server_name"`
	Ratio                   float64 `json:"ratio"`
	CertMode                string  `json:"cert_mode"`
	CertDNSProvider         string  `json:"cert_dns_provider"`
	CertDNSEnv              string  `json:"cert_dns_env"`
}

const MaxServerConfigResponseBytes = 2 * 1024 * 1024
const RoutingVersionHeader = "X-PPanel-Routing-Version"

// GetServerConfig observes a candidate; it does not claim it has been applied.
// A 304 or identical body returns a pending candidate until Commit succeeds.
func GetServerConfig(ctx context.Context, c *ServerClient) (*ServerConfigResponse, error) {
	// Waiting for a parallel fetch must remain cancelable when an old core is
	// stopped, even if the current panel request is slow.
	select {
	case c.fetchGate <- struct{}{}:
		defer func() { <-c.fetchGate }()
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	c.mu.Lock()
	etag := c.observedEtag
	c.mu.Unlock()
	client := c.Client
	path := fmt.Sprintf("/v2/server/%d", c.ServerId)
	request := client.R().SetContext(ctx).SetDoNotParseResponse(true).
		SetHeader("If-None-Match", etag).SetHeader(RoutingVersionHeader, "1")
	setProtobufResponseAccept(request)
	r, err := request.Get(path)
	if err != nil {
		if ctx.Err() != nil {
			return nil, fmt.Errorf("配置请求已取消: %w", ctx.Err())
		}
		// The transport error can contain the secret_key query parameter.
		return nil, fmt.Errorf("配置请求失败 (%s)", path)
	}
	if r.RawBody() != nil {
		defer r.RawBody().Close()
	}
	if r.StatusCode() == http.StatusNotModified {
		gate := c.publication.gate
		gate.mu.Lock()
		defer gate.mu.Unlock()
		if c.retiredLocked() {
			return nil, ErrRetiredClient
		}
		c.State.ClearFetchFailure()
		c.mu.Lock()
		defer c.mu.Unlock()
		return c.pending, nil
	}
	if r.RawBody() == nil {
		return nil, fmt.Errorf("服务端响应体为空")
	}
	body, err := io.ReadAll(io.LimitReader(r.RawBody(), MaxServerConfigResponseBytes+1))
	if err != nil {
		return nil, fmt.Errorf("读取服务端响应失败: %w", err)
	}
	if len(body) > MaxServerConfigResponseBytes {
		return nil, fmt.Errorf("服务端响应超过 %d 字节", MaxServerConfigResponseBytes)
	}
	if r.StatusCode() < 200 || r.StatusCode() >= 300 {
		if isProtobufResponse(r) {
			result, err := unmarshalProtobufResult(body)
			if err != nil {
				return nil, fmt.Errorf("HTTP %d: %w", r.StatusCode(), err)
			}
			return nil, fmt.Errorf("HTTP %d: code=%d msg=%s", r.StatusCode(), result.Code, result.Message)
		}
		return nil, fmt.Errorf("HTTP %d: %s", r.StatusCode(), string(body))
	}
	resp := &ServerConfigResponse{}
	if isProtobufResponse(r) {
		message := &serverv1.QueryServerProtocolConfigResponse{}
		if err := (proto.UnmarshalOptions{RecursionLimit: 100}).Unmarshal(body, message); err != nil {
			return nil, fmt.Errorf("解码 Protobuf 响应体失败: %w", err)
		}
		if message.Data != nil {
			// Check int64 values before narrowing to int on 32-bit builds.
			if message.Data.Total != int64(len(message.Data.Protocols)) {
				return nil, fmt.Errorf("total does not match protocol count")
			}
			if message.Data.PullInterval < 0 || message.Data.PullInterval > MaxIntervalSeconds || message.Data.PushInterval < 0 || message.Data.PushInterval > MaxIntervalSeconds {
				return nil, fmt.Errorf("invalid pull/push interval")
			}
			// Reject before int64-to-int narrowing, including on 32-bit nodes.
			for _, p := range message.Data.Protocols {
				if p != nil && (p.Uot || p.UotVersion != 0) {
					return nil, fmt.Errorf("configured UDP-over-TCP is unsupported")
				}
			}
			if message.Data.Routing != nil {
				for _, o := range message.Data.Routing.Outbounds {
					if o != nil && (o.Uot || o.UotVersion != 0) {
						return nil, fmt.Errorf("configured UDP-over-TCP is unsupported")
					}
				}
			}
		}
		if message.Data != nil && message.Data.Routing != nil {
			if err := rejectUnknownRoutingFields(message.Data.Routing.ProtoReflect()); err != nil {
				return nil, err
			}
		}
		resp = serverConfigResponseFromProtobuf(message)
	} else {
		if !utf8.Valid(body) {
			return nil, fmt.Errorf("响应体不是有效 UTF-8")
		}
		if err := json.Unmarshal(body, resp); err != nil {
			return nil, fmt.Errorf("解码响应体失败: %w", err)
		}
	}
	resp.UseProtobuf = isProtobufResponse(r)
	if err := checkPanelEnvelope(resp.Code, resp.Msg, client.BaseURL+path); err != nil {
		return nil, err
	}
	if resp.Data == nil {
		return nil, fmt.Errorf("服务端配置为空")
	}
	if err := ValidateDeliveryMetadata(resp.Data); err != nil {
		return nil, err
	}
	if resp.Data.Routing == nil {
		return nil, fmt.Errorf("ordered routing v1 required; legacy configuration rejected")
	}
	hash := sha256.Sum256(body)
	resp.bodyHash = hex.EncodeToString(hash[:])
	resp.etag = r.Header().Get("ETag")
	gate := c.publication.gate
	gate.mu.Lock()
	defer gate.mu.Unlock()
	if c.retiredLocked() {
		return nil, ErrRetiredClient
	}
	c.State.ClearFetchFailure()
	c.mu.Lock()
	defer c.mu.Unlock()
	c.observedEtag = resp.etag
	c.observed = resp // independent of the currently applied and in-flight candidates
	if c.responseBodyHash == resp.bodyHash && c.applied != nil {
		c.pending = nil
		c.State.setPending(nil)
		return nil, nil
	}
	c.pending = resp
	c.State.setPending(identityOf(resp, c.ServerId))
	return resp, nil
}

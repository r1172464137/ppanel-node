package panel

import (
	"bytes"
	"encoding/json"
	"fmt"
	"mime"
	"strings"

	"github.com/go-resty/resty/v2"
	serverv1 "github.com/perfect-panel/ppanel-node/api/server/v1"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/known/structpb"
)

const protobufContentType = "application/protobuf"

func setProtobufRequestBody(request *resty.Request, message proto.Message) error {
	body, err := proto.Marshal(message)
	if err != nil {
		return fmt.Errorf("编码 Protobuf 请求失败: %w", err)
	}
	request.SetBody(body).
		SetHeader("Content-Type", protobufContentType).
		SetHeader("Accept", protobufContentType)
	return nil
}

func setProtobufResponseAccept(request *resty.Request) {
	request.SetHeader("Accept", protobufContentType)
}

func isProtobufResponse(response *resty.Response) bool {
	if response == nil {
		return false
	}
	contentType, _, err := mime.ParseMediaType(response.Header().Get("Content-Type"))
	return err == nil && strings.EqualFold(contentType, protobufContentType)
}

// Unknown fields inside an ordered policy may change its routing semantics;
// never drop them and continue with a partially understood candidate.
func rejectUnknownRoutingFields(message protoreflect.Message) error {
	if len(message.GetUnknown()) != 0 {
		return fmt.Errorf("unknown Protobuf field in %s", message.Descriptor().FullName())
	}
	var result error
	message.Range(func(field protoreflect.FieldDescriptor, value protoreflect.Value) bool {
		if field.Kind() != protoreflect.MessageKind && field.Kind() != protoreflect.GroupKind {
			return true
		}
		if field.IsMap() {
			if field.MapValue().Kind() == protoreflect.MessageKind {
				value.Map().Range(func(_ protoreflect.MapKey, v protoreflect.Value) bool {
					result = rejectUnknownRoutingFields(v.Message())
					return result == nil
				})
			}
		} else if field.IsList() {
			list := value.List()
			for i := 0; i < list.Len() && result == nil; i++ {
				result = rejectUnknownRoutingFields(list.Get(i).Message())
			}
		} else {
			result = rejectUnknownRoutingFields(value.Message())
		}
		return result == nil
	})
	return result
}

func unmarshalProtobufResult(body []byte) (*serverv1.Result, error) {
	result := &serverv1.Result{}
	if err := proto.Unmarshal(body, result); err != nil {
		return nil, fmt.Errorf("解码 Protobuf 响应体失败: %w", err)
	}
	return result, nil
}

func serverConfigResponseFromProtobuf(message *serverv1.QueryServerProtocolConfigResponse) *ServerConfigResponse {
	response := &ServerConfigResponse{
		Code: int(message.Code),
		Msg:  message.Message,
	}
	if message.Data == nil {
		return response
	}

	dns := make([]DNSItem, 0, len(message.Data.Dns))
	for _, item := range message.Data.Dns {
		if item == nil {
			continue
		}
		dns = append(dns, DNSItem{
			Proto:      item.Proto,
			Address:    item.Address,
			ServerName: item.ServerName,
			Domains:    append([]string(nil), item.Domains...),
		})
	}

	outbound := make([]Outbound, 0, len(message.Data.Outbound))
	for _, item := range message.Data.Outbound {
		if item != nil {
			outbound = append(outbound, outboundFromProtobuf(item))
		}
	}

	protocols := make([]Protocol, 0, len(message.Data.Protocols))
	for _, item := range message.Data.Protocols {
		if item == nil {
			continue
		}
		protocols = append(protocols, Protocol{
			Type: item.Type, Port: int(item.Port), Enable: item.Enable, Security: item.Security,
			SNI: item.Sni, AllowInsecure: item.AllowInsecure, Fingerprint: item.Fingerprint,
			RealityServerAddr: item.RealityServerAddr, RealityServerPort: int(item.RealityServerPort),
			RealityXver:       int(item.RealityXver),
			RealityPrivateKey: item.RealityPrivateKey, RealityPublicKey: item.RealityPublicKey,
			RealityShortID: item.RealityShortId, Transport: item.Transport, Host: item.Host,
			Path: item.Path, ServiceName: item.ServiceName, Cipher: item.Cipher, ServerKey: item.ServerKey,
			Plugin: item.Plugin, PluginOptions: jsonValueFromProtobuf(item.PluginOptions),
			Flow: item.Flow, UoT: item.Uot, UoTVersion: int(item.UotVersion),
			AcceptProxyProtocol: item.AcceptProxyProtocol, HopPorts: item.HopPorts,
			HopInterval: int(item.HopInterval), ObfsPassword: item.ObfsPassword, DisableSNI: item.DisableSni,
			ReduceRTT: item.ReduceRtt, UDPRelayMode: item.UdpRelayMode,
			CongestionController: item.CongestionController, Multiplex: item.Multiplex,
			PaddingScheme: item.PaddingScheme, UpMbps: int(item.UpMbps), DownMbps: int(item.DownMbps),
			Obfs: item.Obfs, ObfsHost: item.ObfsHost, ObfsPath: item.ObfsPath, XHTTPMode: item.XhttpMode,
			XHTTPExtra: item.XhttpExtra, Encryption: item.Encryption, EncryptionMode: item.EncryptionMode,
			EncryptionRTT: item.EncryptionRtt, EncryptionTicket: item.EncryptionTicket,
			EncryptionServerPadding: item.EncryptionServerPadding, EncryptionPrivateKey: item.EncryptionPrivateKey,
			EncryptionClientPadding: item.EncryptionClientPadding, EncryptionPassword: item.EncryptionPassword,
			EchEnable: item.EchEnable, EchServerName: item.EchServerName, Ratio: item.Ratio,
			CertMode: item.CertMode, CertDNSProvider: item.CertDnsProvider, CertDNSEnv: item.CertDnsEnv,
		})
	}

	response.Data = &Data{
		TrafficReportThreshold: int(message.Data.TrafficReportThreshold),
		PushInterval:           int(message.Data.PushInterval),
		PullInterval:           int(message.Data.PullInterval),
		IPStrategy:             message.Data.IpStrategy,
		DNS:                    &dns,
		Block:                  ptrToSlice(append([]string(nil), message.Data.Block...)),
		BlockIPs:               ptrToSlice(append([]string(nil), message.Data.BlockIps...)),
		BlockProtocols:         ptrToSlice(append([]string(nil), message.Data.BlockProtocols...)),
		Outbound:               &outbound,
		Protocols:              &protocols,
		Total:                  int(message.Data.Total),
	}
	if p := message.Data.Routing; p != nil {
		policy := &RoutingPolicy{
			Version: int(p.Version), DefaultOutboundID: p.DefaultOutboundId,
			Outbounds: make([]Outbound, 0, len(p.Outbounds)), Rules: make([]RouteRule, 0, len(p.Rules)),
			RoutingIdentity: RoutingIdentity{Mode: p.Mode, Source: p.Source, SourceServerID: p.SourceServerId,
				SourceRevision: p.SourceRevision, LocalTransitionRevision: p.LocalTransitionRevision},
		}
		for _, item := range p.Outbounds {
			if item == nil {
				policy.Outbounds = append(policy.Outbounds, Outbound{})
				continue
			}
			policy.Outbounds = append(policy.Outbounds, outboundFromProtobuf(item))
		}
		for _, item := range p.Rules {
			if item == nil {
				policy.Rules = append(policy.Rules, RouteRule{})
				continue
			}
			kind := ""
			switch item.Kind {
			case serverv1.RouteKind_ROUTE_KIND_DOMAIN:
				kind = "domain"
			case serverv1.RouteKind_ROUTE_KIND_IP:
				kind = "ip"
			case serverv1.RouteKind_ROUTE_KIND_PROTOCOL:
				kind = "protocol"
			}
			policy.Rules = append(policy.Rules, RouteRule{ID: item.Id, Enabled: item.Enabled, Remark: item.Remark,
				Kind: kind, Values: append([]string(nil), item.Values...), OutboundID: item.OutboundId})
		}
		response.Data.Routing = policy
		response.Data.RoutingPresent = true
		// Repeated protobuf fields do not carry presence. Nonempty legacy fields
		// still constitute a mixed policy and are rejected by the builder.
	}
	return response
}

func jsonValueFromProtobuf(value *structpb.Value) any {
	if value == nil {
		return nil
	}
	options := value.AsInterface()
	if encoded, err := json.Marshal(options); err == nil {
		decoder := json.NewDecoder(bytes.NewReader(encoded))
		decoder.UseNumber()
		_ = decoder.Decode(&options)
	}
	return options
}

func outboundFromProtobuf(item *serverv1.Outbound) Outbound {
	return Outbound{
		ID: item.Id, Name: item.Name, Protocol: item.Protocol, Address: item.Address, Port: int(item.Port),
		User: item.User, Password: item.Password, UUID: item.Uuid, Cipher: item.Cipher,
		Plugin: item.Plugin, PluginOptions: jsonValueFromProtobuf(item.PluginOptions), ALPN: append([]string(nil), item.Alpn...),
		Security: item.Security, SNI: item.Sni, AllowInsecure: item.AllowInsecure,
		Fingerprint: item.Fingerprint, Transport: item.Transport, Host: item.Host, Path: item.Path,
		ServiceName: item.ServiceName, XHTTPMode: item.XhttpMode, XHTTPExtra: item.XhttpExtra,
		Flow: item.Flow, Encryption: item.Encryption, EncryptionMode: item.EncryptionMode,
		EncryptionRTT: item.EncryptionRtt, EncryptionTicket: item.EncryptionTicket,
		EncryptionClientPadding: item.EncryptionClientPadding, EncryptionPassword: item.EncryptionPassword,
		Multiplex: item.Multiplex, UoT: item.Uot, UoTVersion: int(item.UotVersion),
		CongestionController: item.CongestionController, UDPStream: item.UdpStream,
		ReduceRTT: item.ReduceRtt, Heartbeat: int(item.Heartbeat), RealityPublicKey: item.RealityPublicKey,
		RealityShortID: item.RealityShortId, SpiderX: item.SpiderX, Settings: item.Settings,
		StreamSettings: item.StreamSettings, Rules: append([]string{}, item.Rules...),
		IPRules: append([]string{}, item.IpRules...), ProtocolRules: append([]string{}, item.ProtocolRules...),
	}
}

func ptrToSlice(values []string) *[]string {
	return &values
}

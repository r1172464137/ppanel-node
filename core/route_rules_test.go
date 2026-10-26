package core

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/perfect-panel/ppanel-node/api/panel"
	"github.com/perfect-panel/ppanel-node/conf"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/platform/filesystem"
	"github.com/xtls/xray-core/common/session"
	xray "github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/routing"
	routingSession "github.com/xtls/xray-core/features/routing/session"
	coreConf "github.com/xtls/xray-core/infra/conf"
)

type socksRouteEvidence struct {
	transport string
	command   byte
	host      string
	port      int
}

type controlledSOCKSServer struct {
	tcp       net.Listener
	udp       net.PacketConn
	evidence  chan socksRouteEvidence
	done      chan struct{}
	closeOnce sync.Once
	mu        sync.Mutex
	conns     map[net.Conn]struct{}
}

func startControlledSOCKSServer(t *testing.T) *controlledSOCKSServer {
	t.Helper()
	tcpListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	udpConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		tcpListener.Close()
		t.Fatal(err)
	}
	server := &controlledSOCKSServer{
		tcp: tcpListener, udp: udpConn,
		evidence: make(chan socksRouteEvidence, 32), done: make(chan struct{}),
		conns: make(map[net.Conn]struct{}),
	}
	go server.accept()
	go server.serveUDP()
	t.Cleanup(server.close)
	return server
}

func (s *controlledSOCKSServer) close() {
	s.closeOnce.Do(func() {
		close(s.done)
		_ = s.tcp.Close()
		_ = s.udp.Close()
		s.mu.Lock()
		for conn := range s.conns {
			_ = conn.Close()
		}
		s.mu.Unlock()
	})
}

func (s *controlledSOCKSServer) port() int {
	return s.tcp.Addr().(*net.TCPAddr).Port
}

func (s *controlledSOCKSServer) record(evidence socksRouteEvidence) {
	timer := time.NewTimer(time.Second)
	defer timer.Stop()
	select {
	case s.evidence <- evidence:
	case <-s.done:
	case <-timer.C:
	}
}

func (s *controlledSOCKSServer) accept() {
	for {
		conn, err := s.tcp.Accept()
		if err != nil {
			return
		}
		s.mu.Lock()
		select {
		case <-s.done:
			s.mu.Unlock()
			_ = conn.Close()
			return
		default:
			s.conns[conn] = struct{}{}
			s.mu.Unlock()
			go s.serveTCP(conn)
		}
	}
}

func (s *controlledSOCKSServer) serveTCP(conn net.Conn) {
	defer func() {
		s.mu.Lock()
		delete(s.conns, conn)
		s.mu.Unlock()
		_ = conn.Close()
	}()
	_ = conn.SetDeadline(time.Now().Add(15 * time.Second))

	header := make([]byte, 2)
	if _, err := io.ReadFull(conn, header); err != nil || header[0] != 5 {
		return
	}
	methods := make([]byte, int(header[1]))
	if _, err := io.ReadFull(conn, methods); err != nil {
		return
	}
	if _, err := conn.Write([]byte{5, 0}); err != nil {
		return
	}

	request := make([]byte, 4)
	if _, err := io.ReadFull(conn, request); err != nil || request[0] != 5 {
		return
	}
	host, port, err := readSOCKSAddress(conn, request[3])
	if err != nil {
		return
	}
	s.record(socksRouteEvidence{transport: "tcp-control", command: request[1], host: host, port: port})

	boundPort := 0
	if request[1] == 3 {
		boundPort = s.udp.LocalAddr().(*net.UDPAddr).Port
	}
	reply := []byte{5, 0, 0, 1, 127, 0, 0, 1, byte(boundPort >> 8), byte(boundPort)}
	if _, err := conn.Write(reply); err != nil {
		return
	}

	switch request[1] {
	case 1:
		// The mock intentionally echoes without dialing the requested target. A
		// successful echo therefore proves that Xray selected this SOCKS route.
		_, _ = io.Copy(conn, conn)
	case 3:
		_, _ = io.Copy(io.Discard, conn)
	}
}

func (s *controlledSOCKSServer) serveUDP() {
	packet := make([]byte, 64*1024)
	for {
		n, client, err := s.udp.ReadFrom(packet)
		if err != nil {
			return
		}
		if n < 4 || packet[0] != 0 || packet[1] != 0 || packet[2] != 0 {
			continue
		}
		host, port, _, err := parseSOCKSAddress(packet[3:n])
		if err != nil {
			continue
		}
		s.record(socksRouteEvidence{transport: "udp-datagram", command: 3, host: host, port: port})
		_, _ = s.udp.WriteTo(packet[:n], client)
	}
}

func readSOCKSAddress(reader io.Reader, addressType byte) (string, int, error) {
	var length int
	switch addressType {
	case 1:
		length = net.IPv4len
	case 4:
		length = net.IPv6len
	case 3:
		value := []byte{0}
		if _, err := io.ReadFull(reader, value); err != nil {
			return "", 0, err
		}
		length = int(value[0])
	default:
		return "", 0, fmt.Errorf("unsupported SOCKS address type %d", addressType)
	}
	value := make([]byte, length+2)
	if _, err := io.ReadFull(reader, value); err != nil {
		return "", 0, err
	}
	host := string(value[:length])
	if addressType != 3 {
		host = net.IP(value[:length]).String()
	}
	return host, int(binary.BigEndian.Uint16(value[length:])), nil
}

func parseSOCKSAddress(packet []byte) (host string, port int, consumed int, err error) {
	if len(packet) == 0 {
		return "", 0, 0, io.ErrUnexpectedEOF
	}
	addressType := packet[0]
	var length int
	switch addressType {
	case 1:
		length = net.IPv4len
	case 4:
		length = net.IPv6len
	case 3:
		if len(packet) < 2 {
			return "", 0, 0, io.ErrUnexpectedEOF
		}
		length = int(packet[1])
		packet = packet[1:]
		consumed++
	default:
		return "", 0, 0, fmt.Errorf("unsupported SOCKS address type %d", addressType)
	}
	if len(packet) < 1+length+2 {
		return "", 0, 0, io.ErrUnexpectedEOF
	}
	host = string(packet[1 : 1+length])
	if addressType != 3 {
		host = net.IP(packet[1 : 1+length]).String()
	}
	port = int(binary.BigEndian.Uint16(packet[1+length : 1+length+2]))
	return host, port, consumed + 1 + length + 2, nil
}

type packetReadResult struct {
	n       int
	address net.Addr
	err     error
}

func readPacketWithContext(ctx context.Context, conn net.PacketConn, buffer []byte) (int, net.Addr, error) {
	result := make(chan packetReadResult, 1)
	go func() {
		n, address, err := conn.ReadFrom(buffer)
		result <- packetReadResult{n: n, address: address, err: err}
	}()
	select {
	case value := <-result:
		return value.n, value.address, value.err
	case <-ctx.Done():
		_ = conn.Close()
		select {
		case value := <-result:
			if value.err == nil {
				return value.n, value.address, nil
			}
		case <-time.After(time.Second):
		}
		return 0, nil, ctx.Err()
	}
}

func TestStructuredRoutesUseControlledSOCKSForTCPAndUDP(t *testing.T) {
	socks := startControlledSOCKSServer(t)
	outbounds := []panel.Outbound{{
		Name: "controlled-socks", Protocol: "socks", Address: "127.0.0.1", Port: socks.port(),
		Rules: []string{"route.example"}, IPRules: []string{"127.0.0.1/32"},
	}}
	server, err := getCore(conf.New(), &panel.ServerConfigResponse{Data: &panel.Data{
		Outbound: &outbounds, Protocols: &[]panel.Protocol{}, PullInterval: 3600,
	}})
	if err != nil {
		t.Fatalf("build real Xray core: %v", err)
	}
	if err := server.Start(); err != nil {
		server.Close()
		t.Fatalf("start real Xray core: %v", err)
	}
	t.Cleanup(func() { _ = server.Close() })

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	tcpConn, err := xray.Dial(ctx, server, xnet.TCPDestination(xnet.DomainAddress("route.example"), 443))
	if err != nil {
		t.Fatalf("dial TCP through Xray: %v", err)
	}
	_ = tcpConn.SetDeadline(time.Now().Add(10 * time.Second))
	payload := []byte("structured TCP route evidence")
	if _, err := tcpConn.Write(payload); err != nil {
		t.Fatal(err)
	}
	reply := make([]byte, len(payload))
	if _, err := io.ReadFull(tcpConn, reply); err != nil {
		t.Fatalf("read controlled SOCKS TCP echo: %v", err)
	}
	_ = tcpConn.Close()
	if string(reply) != string(payload) {
		t.Fatalf("TCP echo = %q, want %q", reply, payload)
	}

	udpConn, err := xray.DialUDP(ctx, server)
	if err != nil {
		t.Fatalf("dial UDP through Xray: %v", err)
	}
	defer udpConn.Close()
	udpTarget := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 5353}
	udpPayload := []byte("structured UDP route evidence")
	if _, err := udpConn.WriteTo(udpPayload, udpTarget); err != nil {
		t.Fatalf("write UDP through Xray: %v", err)
	}
	udpReply := make([]byte, len(udpPayload))
	n, _, err := readPacketWithContext(ctx, udpConn, udpReply)
	if err != nil {
		t.Fatalf("read controlled SOCKS UDP echo: %v", err)
	}
	if string(udpReply[:n]) != string(udpPayload) {
		t.Fatalf("UDP echo = %q, want %q", udpReply[:n], udpPayload)
	}

	seenTCP, seenUDP := false, false
	deadline := time.NewTimer(3 * time.Second)
	defer deadline.Stop()
	for !seenTCP || !seenUDP {
		select {
		case evidence := <-socks.evidence:
			switch {
			case evidence.transport == "tcp-control" && evidence.command == 1 && evidence.host == "route.example" && evidence.port == 443:
				seenTCP = true
			case evidence.transport == "udp-datagram" && evidence.command == 3 && evidence.host == "127.0.0.1" && evidence.port == 5353:
				seenUDP = true
			}
		case <-deadline.C:
			t.Fatalf("controlled SOCKS route evidence incomplete: TCP=%v UDP=%v", seenTCP, seenUDP)
		}
	}
}

func reserveTCPUDPPort(t *testing.T) int {
	t.Helper()
	for attempt := 0; attempt < 100; attempt++ {
		tcpListener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		port := tcpListener.Addr().(*net.TCPAddr).Port
		udpConn, err := net.ListenPacket("udp", fmt.Sprintf("127.0.0.1:%d", port))
		if err != nil {
			_ = tcpListener.Close()
			continue
		}
		_ = udpConn.Close()
		_ = tcpListener.Close()
		return port
	}
	t.Fatal("could not reserve a TCP/UDP port pair")
	return 0
}

func addSniffingDokodemoInbound(t *testing.T, core *XrayCore, port int) {
	t.Helper()
	settingsData, err := json.Marshal(map[string]interface{}{
		"address": "198.51.100.1",
		"port":    6881,
		"network": "tcp,udp",
	})
	if err != nil {
		t.Fatal(err)
	}
	settings := json.RawMessage(settingsData)
	inbound, err := (&coreConf.InboundDetourConfig{
		Tag:      "sniffing-test",
		Protocol: "dokodemo-door",
		ListenOn: &coreConf.Address{Address: xnet.ParseAddress("127.0.0.1")},
		PortList: &coreConf.PortList{Range: []coreConf.PortRange{{From: uint32(port), To: uint32(port)}}},
		Settings: &settings,
		SniffingConfig: &coreConf.SniffingConfig{
			Enabled: true,
		},
	}).Build()
	if err != nil {
		t.Fatalf("build sniffing inbound: %v", err)
	}
	if err := core.AddNodeConfig(inbound); err != nil {
		t.Fatalf("add sniffing inbound: %v", err)
	}
}

func dialTCPWithContext(ctx context.Context, address string) (net.Conn, error) {
	dialer := net.Dialer{Timeout: 250 * time.Millisecond}
	for {
		conn, err := dialer.DialContext(ctx, "tcp", address)
		if err == nil {
			return conn, nil
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(10 * time.Millisecond):
		}
	}
}

func TestBitTorrentAndUTPProtocolRulesUseControlledSOCKS(t *testing.T) {
	socks := startControlledSOCKSServer(t)
	outbounds := []panel.Outbound{{
		Name: "bittorrent-socks", Protocol: "socks", Address: "127.0.0.1", Port: socks.port(),
		ProtocolRules: []string{"bittorrent"},
	}}
	config := conf.New()
	config.LogConfig.Level = "error"
	xcore := New(config, nil)
	if err := xcore.Start(&panel.ServerConfigResponse{Data: &panel.Data{
		Outbound: &outbounds, Protocols: &[]panel.Protocol{}, PullInterval: 3600,
	}}); err != nil {
		t.Fatalf("start Xray with BitTorrent protocol route: %v", err)
	}
	t.Cleanup(func() { _ = xcore.Close() })

	inboundPort := reserveTCPUDPPort(t)
	addSniffingDokodemoInbound(t, xcore, inboundPort)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	handshake := make([]byte, 68)
	handshake[0] = 19
	copy(handshake[1:20], "BitTorrent protocol")
	copy(handshake[28:48], "01234567890123456789")
	copy(handshake[48:68], "-PPNODE-ROUTE-TEST01")
	tcpConn, err := dialTCPWithContext(ctx, fmt.Sprintf("127.0.0.1:%d", inboundPort))
	if err != nil {
		t.Fatalf("dial sniffing TCP inbound: %v", err)
	}
	_ = tcpConn.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := tcpConn.Write(handshake); err != nil {
		_ = tcpConn.Close()
		t.Fatal(err)
	}
	tcpReply := make([]byte, len(handshake))
	if _, err := io.ReadFull(tcpConn, tcpReply); err != nil {
		_ = tcpConn.Close()
		t.Fatalf("read BitTorrent handshake echo: %v", err)
	}
	_ = tcpConn.Close()
	if string(tcpReply) != string(handshake) {
		t.Fatal("BitTorrent handshake changed in controlled SOCKS route")
	}

	udpConn, err := net.DialUDP("udp", nil, &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: inboundPort})
	if err != nil {
		t.Fatalf("dial sniffing UDP inbound: %v", err)
	}
	defer udpConn.Close()
	_ = udpConn.SetDeadline(time.Now().Add(10 * time.Second))
	utpSYN := make([]byte, 20)
	utpSYN[0] = 0x41 // ST_SYN, µTP version 1
	binary.BigEndian.PutUint16(utpSYN[2:4], 0x1234)
	binary.BigEndian.PutUint32(utpSYN[4:8], 1)
	binary.BigEndian.PutUint32(utpSYN[12:16], 64*1024)
	binary.BigEndian.PutUint16(utpSYN[16:18], 1)
	if _, err := udpConn.Write(utpSYN); err != nil {
		t.Fatalf("write valid µTP ST_SYN: %v", err)
	}
	udpReply := make([]byte, len(utpSYN))
	n, err := udpConn.Read(udpReply)
	if err != nil {
		t.Fatalf("read µTP ST_SYN echo: %v", err)
	}
	if n != len(utpSYN) || string(udpReply[:n]) != string(utpSYN) {
		t.Fatalf("µTP echo = %x, want %x", udpReply[:n], utpSYN)
	}

	seenTCP, seenUTP := false, false
	timer := time.NewTimer(3 * time.Second)
	defer timer.Stop()
	for !seenTCP || !seenUTP {
		select {
		case evidence := <-socks.evidence:
			if evidence.host != "198.51.100.1" || evidence.port != 6881 {
				continue
			}
			if evidence.transport == "tcp-control" && evidence.command == 1 {
				seenTCP = true
			}
			if evidence.transport == "udp-datagram" && evidence.command == 3 {
				seenUTP = true
			}
		case <-timer.C:
			t.Fatalf("protocol route evidence incomplete: BitTorrent TCP=%v µTP ST_SYN=%v", seenTCP, seenUTP)
		}
	}
}

const geodataExecutableSearchHelper = "PPNODE_GEODATA_EXECUTABLE_SEARCH_HELPER"

func TestProductionGeositeAndGeoIPRouteDecisionsOnRealCore(t *testing.T) {
	if os.Getenv(geodataExecutableSearchHelper) == "1" {
		runProductionGeodataRouteDecisions(t)
		return
	}

	assetDir := os.Getenv("PPNODE_TEST_GEODATA")
	if assetDir == "" {
		assetDir = filepath.Join("..", "output", "release-geodata")
	}
	for _, name := range []string{"geosite.dat", "geoip.dat"} {
		info, err := os.Stat(filepath.Join(assetDir, name))
		if err != nil || info.Size() == 0 {
			t.Skipf("production geodata unavailable at %s (set PPNODE_TEST_GEODATA): %v", assetDir, err)
		}
	}

	// Run a copied test process with the data beside its executable and with all
	// Xray asset environment overrides removed. This exercises the production
	// search path used by /usr/local/PPanel-node and the container image.
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	processDir := t.TempDir()
	copiedExecutable := filepath.Join(processDir, "ppnode-core-assets-test")
	binary, err := os.ReadFile(executable)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(copiedExecutable, binary, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"geosite.dat", "geoip.dat"} {
		data, err := os.ReadFile(filepath.Join(assetDir, name))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(processDir, name), data, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	command := exec.Command(copiedExecutable, "-test.run=^TestProductionGeositeAndGeoIPRouteDecisionsOnRealCore$", "-test.v")
	for _, entry := range os.Environ() {
		key, _, _ := strings.Cut(entry, "=")
		if key == geodataExecutableSearchHelper || key == "PPNODE_TEST_GEODATA" || key == "xray.location.asset" || key == "XRAY_LOCATION_ASSET" {
			continue
		}
		command.Env = append(command.Env, entry)
	}
	command.Env = append(command.Env, geodataExecutableSearchHelper+"=1")
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("real-core subprocess without asset env failed: %v\n%s", err, output)
	}
}

func runProductionGeodataRouteDecisions(t *testing.T) {
	if os.Getenv("xray.location.asset") != "" || os.Getenv("XRAY_LOCATION_ASSET") != "" {
		t.Fatal("test helper unexpectedly has an Xray asset environment override")
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"geosite.dat", "geoip.dat"} {
		resolved, err := filesystem.ResolveAsset(name)
		if err != nil {
			t.Fatalf("resolve executable-relative %s: %v", name, err)
		}
		if filepath.Dir(resolved) != filepath.Dir(executable) {
			t.Fatalf("%s resolved to %s instead of executable directory %s", name, resolved, filepath.Dir(executable))
		}
	}
	blockDomains := []string{"geosite:category-pt"}
	blockIPs := []string{"geoip:private", "10.0.0.0/8", "fc00::/7"}
	blockProtocols := []string{"bittorrent"}
	outbounds := []panel.Outbound{{
		Name: "cn-direct", Protocol: "direct", Rules: []string{"geosite:cn"}, IPRules: []string{"geoip:cn"},
	}}
	server, err := getCore(conf.New(), &panel.ServerConfigResponse{Data: &panel.Data{
		Block: &blockDomains, BlockIPs: &blockIPs, BlockProtocols: &blockProtocols,
		Outbound: &outbounds, Protocols: &[]panel.Protocol{}, PullInterval: 3600,
	}})
	if err != nil {
		t.Fatalf("build Xray with production geosite/geoip data: %v", err)
	}
	if err := server.Start(); err != nil {
		server.Close()
		t.Fatalf("start Xray with production geosite/geoip data: %v", err)
	}

	router := server.GetFeature(routing.RouterType()).(routing.Router)
	assertRoute := func(name string, destination xnet.Destination, wantTag string) {
		t.Helper()
		ctx := session.ContextWithOutbounds(context.Background(), []*session.Outbound{{Target: destination}})
		route, err := router.PickRoute(routingSession.AsRoutingContext(ctx))
		if err != nil {
			t.Fatalf("%s route decision: %v", name, err)
		}
		if got := route.GetOutboundTag(); got != wantTag {
			t.Fatalf("%s route tag = %q, want %q", name, got, wantTag)
		}
	}
	assertRoute("category-pt geosite", xnet.TCPDestination(xnet.DomainAddress("hdchina.org"), 443), "block")
	assertRoute("private geoip", xnet.TCPDestination(xnet.ParseAddress("10.23.45.67"), 443), "block")
	assertRoute("CN geosite", xnet.TCPDestination(xnet.DomainAddress("www.baidu.com"), 443), "cn-direct")
	assertRoute("CN geoip", xnet.TCPDestination(xnet.ParseAddress("223.5.5.5"), 53), "cn-direct")

	if err := server.Close(); err != nil {
		t.Fatalf("close Xray: %v", err)
	}
}

package cmd

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/perfect-panel/ppanel-node/common/logx"
)

// Pprof is process-scoped and starts once, after the first successful apply.
// Later port changes require restart; reload never opens a second listener.
type pprofService struct {
	server   *http.Server
	listener net.Listener
}

type pprofManager struct {
	initialized bool
	port        int
	service     *pprofService
}

func (m *pprofManager) Init(port int) error {
	if m.initialized {
		return m.CheckReload(port)
	}
	m.initialized, m.port = true, port
	service, err := startPprof(port)
	m.service = service
	return err
}
func (m *pprofManager) CheckReload(port int) error {
	if !m.initialized || port != m.port {
		return fmt.Errorf("pprof port changes require process restart")
	}
	return nil
}
func (m *pprofManager) Close() {
	if m.service != nil {
		m.service.Close()
	}
}

func startPprof(port int) (*pprofService, error) {
	if port == 0 {
		return nil, nil
	}
	if port < 1 || port > 65535 {
		return nil, fmt.Errorf("invalid pprof port")
	}
	listener, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		return nil, err
	}
	server := &http.Server{Handler: http.DefaultServeMux, ReadHeaderTimeout: 10 * time.Second}
	service := &pprofService{server: server, listener: listener}
	go func() {
		if err := server.Serve(listener); err != nil && err != http.ErrServerClosed {
			logx.Component("server").WithError(err).Error("pprof服务失败")
		}
	}()
	return service, nil
}
func (p *pprofService) Close() {
	if p == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_ = p.server.Shutdown(ctx)
	_ = p.listener.Close()
}

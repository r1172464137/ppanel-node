package dispatcher

import (
	"net"
	sync "sync"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
)

type ManagedWriter struct {
	writer  buf.Writer
	manager *LinkManager
}

func (w *ManagedWriter) WriteMultiBuffer(mb buf.MultiBuffer) error {
	return w.writer.WriteMultiBuffer(mb)
}

func (w *ManagedWriter) Close() error {
	w.manager.RemoveWriter(w)
	return common.Close(w.writer)
}

// LinkManager tracks one user's active links so they can be cut when the user
// is removed or the whole instance is retired. Closing only the buffer
// wrappers is not enough: a link served by DispatchLink or by splice copy keeps
// running on the inbound connection, so the real connection is closed too.
type LinkManager struct {
	links map[*ManagedWriter]linkEntry
	mu    sync.Mutex
}

type linkEntry struct {
	reader buf.Reader
	conn   net.Conn
}

func newLinkManager() *LinkManager {
	return &LinkManager{links: make(map[*ManagedWriter]linkEntry)}
}

func (m *LinkManager) AddLink(writer *ManagedWriter, reader buf.Reader, conn net.Conn) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.links[writer] = linkEntry{reader: reader, conn: conn}
}

func (m *LinkManager) RemoveWriter(writer *ManagedWriter) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.links, writer)
}

func (m *LinkManager) CloseAll() {
	m.mu.Lock()
	links := m.links
	m.links = make(map[*ManagedWriter]linkEntry)
	m.mu.Unlock()
	for w, e := range links {
		if e.conn != nil {
			_ = e.conn.Close()
		}
		common.Close(w.writer)
		if e.reader != nil {
			common.Interrupt(e.reader)
		}
	}
}

// Len reports the number of tracked links (for tests and diagnostics).
func (m *LinkManager) Len() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.links)
}

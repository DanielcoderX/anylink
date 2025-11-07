package bridge

import (
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

type TCPPool struct {
	mu       sync.Mutex
	conns    map[string][]net.Conn      // pooled connections per backend
	backends map[string][]string        // logical target -> multiple backend addresses
	counters map[string]*uint32         // round-robin counters per logical target
	maxSize  int
}

func NewTCPPool(max int) *TCPPool {
	return &TCPPool{
		conns:    make(map[string][]net.Conn),
		backends: make(map[string][]string),
		counters: make(map[string]*uint32),
		maxSize:  max,
	}
}

// AddTargets registers multiple backend addresses for a logical target
func (p *TCPPool) AddTargets(logical string, targets []string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.backends[logical] = targets
	var zero uint32
	p.counters[logical] = &zero
}

// Get returns a TCP connection to a backend for the logical target (round-robin)
func (p *TCPPool) Get(logical string) (net.Conn, error) {
	p.mu.Lock()
	backends, ok := p.backends[logical]
	if !ok || len(backends) == 0 {
		p.mu.Unlock()
		return nil, fmt.Errorf("no backends for target %s", logical)
	}

	// pick backend using round-robin
	idx := atomic.AddUint32(p.counters[logical], 1)
	backend := backends[int(idx)%len(backends)]

	// check pool for existing connection
	conns := p.conns[backend]
	if len(conns) > 0 {
		conn := conns[len(conns)-1]
		p.conns[backend] = conns[:len(conns)-1]
		p.mu.Unlock()
		return conn, nil
	}
	p.mu.Unlock()

	// create new connection
	return net.DialTimeout("tcp", backend, 5*time.Second)
}

// Put returns a TCP connection to the pool
func (p *TCPPool) Put(target string, conn net.Conn) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.conns[target]) >= p.maxSize {
		conn.Close()
		return
	}
	p.conns[target] = append(p.conns[target], conn)
}
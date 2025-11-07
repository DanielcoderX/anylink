package server

import (
	"sync"
	"time"

	"github.com/DanielcoderX/anylink/internal/logger"
)

// StreamMetrics stores per-stream metrics
type StreamMetrics struct {
	BytesSent     int64
	BytesReceived int64
	Errors        int64
	LastActive    time.Time
	mu            sync.Mutex
}

// MetricsManager manages metrics for multiple streams/clients
type MetricsManager struct {
	streams map[string]*StreamMetrics
	mu      sync.Mutex
}

// NewMetricsManager creates a manager
func NewMetricsManager() *MetricsManager {
	return &MetricsManager{
		streams: make(map[string]*StreamMetrics),
	}
}

// RegisterStream registers a new stream by ID
func (m *MetricsManager) RegisterStream(id string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, exists := m.streams[id]; !exists {
		m.streams[id] = &StreamMetrics{
			LastActive: time.Now(),
		}
	}
}

// AddBytes adds sent/received bytes
func (m *MetricsManager) AddBytes(id string, sent, recv int64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if s, ok := m.streams[id]; ok {
		s.mu.Lock()
		s.BytesSent += sent
		s.BytesReceived += recv
		s.LastActive = time.Now()
		s.mu.Unlock()
	}
}

// AddError increments error count
func (m *MetricsManager) AddError(id string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if s, ok := m.streams[id]; ok {
		s.mu.Lock()
		s.Errors++
		s.mu.Unlock()
	}
}

// PrintMetrics prints metrics snapshot
func (m *MetricsManager) PrintMetrics() {
	m.mu.Lock()
	defer m.mu.Unlock()
	log := logger.New("metrics")
	for id, s := range m.streams {
		s.mu.Lock()
		log.Debug("Stream %s: sent=%d recv=%d errors=%d lastActive=%s",
			id, s.BytesSent, s.BytesReceived, s.Errors, s.LastActive.Format(time.RFC3339))
		s.mu.Unlock()
	}
}

// Cleanup removes idle streams
func (m *MetricsManager) Cleanup(idleTimeout time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := time.Now()
	for id, s := range m.streams {
		s.mu.Lock()
		if now.Sub(s.LastActive) > idleTimeout {
			delete(m.streams, id)
		}
		s.mu.Unlock()
	}
}

package server

import (
	"context"
	"net"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/DanielcoderX/anylink/internal/bridge"
	"github.com/DanielcoderX/anylink/internal/config"
	"github.com/DanielcoderX/anylink/internal/logger"
	"github.com/gorilla/websocket"
	"github.com/quic-go/quic-go"
)

// ----- Target Validation -----

type TargetRule struct {
	Raw      string
	Regex    *regexp.Regexp
	CIDRNet  *net.IPNet
	IsDomain bool
}

// compileRules prepares target rules (CIDR, regex, domain)
func compileRules(list []string) ([]*TargetRule, error) {
	var rules []*TargetRule
	for _, t := range list {
		r := &TargetRule{Raw: t}
		if strings.Contains(t, "/") { // CIDR
			_, cidrNet, err := net.ParseCIDR(t)
			if err != nil {
				return nil, err
			}
			r.CIDRNet = cidrNet
		} else if strings.ContainsAny(t, "*?") { // wildcard domain -> regex
			pattern := "^" + regexp.QuoteMeta(t) + "$"
			pattern = strings.ReplaceAll(pattern, `\*`, ".*")
			reg, err := regexp.Compile(pattern)
			if err != nil {
				return nil, err
			}
			r.Regex = reg
			r.IsDomain = true
		} else if strings.Contains(t, ":") { // IP:Port exact match
			// nothing needed, compare directly
		} else { // domain exact
			r.IsDomain = true
		}
		rules = append(rules, r)
	}
	return rules, nil
}

// isAllowedEnhanced checks a target against compiled rules
func isAllowedEnhanced(rules []*TargetRule, target string) bool {
	if len(rules) == 0 {
		return true
	}
	host, _, _ := net.SplitHostPort(target)
	for _, r := range rules {
		if r.CIDRNet != nil {
			ip := net.ParseIP(host)
			if ip != nil && r.CIDRNet.Contains(ip) {
				return true
			}
		} else if r.Regex != nil {
			if r.Regex.MatchString(target) {
				return true
			}
		} else if r.IsDomain {
			if host == r.Raw {
				return true
			}
		} else {
			if target == r.Raw {
				return true
			}
		}
	}
	return false
}

type Server struct {
	cfg  *config.Config
	http *http.Server
	quic *quic.Listener

	tlsManager *TLSManager
	tcpPool    *bridge.TCPPool
	sessions   map[string]*sessionState
	sessionsMu sync.Mutex
	log        *logger.Logger
}

type sessionState struct {
	sess       quic.Connection
	streams    map[quic.StreamID]*bridge.Bridge
	lastActive time.Time
	mu         sync.Mutex
}

func New(cfg *config.Config) *Server {
	tcpPool := bridge.NewTCPPool(cfg.TCPPoolSize)
	tlsMgr := NewTLSManager(
		24*time.Hour,             // cert rotation every 24h
		[]string{"anylink-quic"}, // ALPN
		false,                    // optional client cert auth
		nil,                      // client CAs
	)
	return &Server{
		cfg:        cfg,
		tlsManager: tlsMgr,
		tcpPool:    tcpPool,
		sessions:   make(map[string]*sessionState),
		log:        logger.New("server"),
	}
}

// Start runs WS HTTP server and QUIC listener
func (s *Server) Start() error {
	// ----- WebSocket handler -----
	upgrader := websocket.Upgrader{
		ReadBufferSize:  8192,
		WriteBufferSize: 8192,
		CheckOrigin:     func(r *http.Request) bool { return true },
	}

	mux := http.NewServeMux()
	rules, _ := compileRules(s.cfg.AllowedTargets)

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		target, ok := extractTarget(r)
		if !ok {
			http.Error(w, "missing target", http.StatusBadRequest)
			return
		}
		if !isAllowedEnhanced(rules, target) {
			http.Error(w, "target not allowed", http.StatusForbidden)
			return
		}

		ws, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			s.log.Error("WS upgrade error: %v", err)
			return
		}
		defer ws.Close()

		tcpConn, err := s.tcpPool.Get(target)
		if err != nil {
			s.log.Error("dial %s: %v", target, err)
			_ = ws.WriteMessage(websocket.CloseMessage,
				websocket.FormatCloseMessage(websocket.CloseInternalServerErr, "connect failed"))
			return
		}
		defer s.tcpPool.Put(target, tcpConn)

		b := bridge.NewWSBridge(ws, tcpConn, &bridge.Config{ReadTimeout: s.cfg.ReadTimeout})
		defer b.Close()
		b.Wg().Wait()
	})

	s.http = &http.Server{
		Addr:    s.cfg.Addr,
		Handler: mux,
	}

	// ----- QUIC listener -----

	tlsConf := s.tlsManager.GetTLSConfig()

	listener, err := quic.ListenAddr(
		s.cfg.QUICAddr,
		tlsConf,
		&quic.Config{
			MaxIdleTimeout:                 30 * time.Second,
			MaxIncomingStreams:             1024,
			MaxIncomingUniStreams:          512,
			InitialStreamReceiveWindow:     64 * 1024,
			InitialConnectionReceiveWindow: 512 * 1024,
			KeepAlivePeriod:                30 * time.Second,
			Allow0RTT:                      true,
		},
	)
	if err != nil {
		return err
	}
	s.quic = listener

	// QUIC accept loop
	go s.quicAcceptLoop()

	// QUIC session idle cleanup
	go s.cleanupIdleSessions()

	// HTTP server listen with TLS (WSS)
	if s.cfg.EnableWSS {
		s.http.TLSConfig = s.tlsManager.GetTLSConfig()
		return s.http.ListenAndServeTLS("", "") // certs handled by TLSConfig
	}
	// run HTTP server
	return s.http.ListenAndServe()
}

// QUIC accept loop
func (s *Server) quicAcceptLoop() {
	for {
		sess, err := s.quic.Accept(context.Background())
		if err != nil {
			s.log.Error("QUIC accept error: %v", err)
			return
		}
		go s.handleQUICSession(sess)
	}
}

// Handle multi-stream QUIC session
func (s *Server) handleQUICSession(sess quic.Connection) {
	st := &sessionState{
		sess:       sess,
		streams:    make(map[quic.StreamID]*bridge.Bridge),
		lastActive: time.Now(),
	}
	s.sessionsMu.Lock()
	s.sessions[sess.RemoteAddr().String()] = st
	s.sessionsMu.Unlock()

	for {
		stream, err := sess.AcceptStream(context.Background())
		if err != nil {
			s.log.Error("QUIC stream accept error: %v", err)
			break
		}

		st.mu.Lock()
		b := bridge.NewQUICBridge(stream, nil, &bridge.Config{ReadTimeout: s.cfg.ReadTimeout})
		st.streams[stream.StreamID()] = b
		st.mu.Unlock()

		st.lastActive = time.Now()

		go func(stream quic.Stream, b *bridge.Bridge) {
			b.Wg().Wait()
			b.Close()
			st.mu.Lock()
			delete(st.streams, stream.StreamID())
			st.mu.Unlock()
		}(stream, b)
	}

	// remove session
	s.sessionsMu.Lock()
	delete(s.sessions, sess.RemoteAddr().String())
	s.sessionsMu.Unlock()
	sess.CloseWithError(0, "session closed")
}

// Idle session cleanup
func (s *Server) cleanupIdleSessions() {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		now := time.Now()
		s.sessionsMu.Lock()
		for addr, st := range s.sessions {
			if now.Sub(st.lastActive) > 30*time.Second {
				s.log.Debug("closing idle session %s", addr)
				st.sess.CloseWithError(0, "idle timeout")
				delete(s.sessions, addr)
			}
		}
		s.sessionsMu.Unlock()
	}
}

func (s *Server) Shutdown(ctx context.Context) error {
	if s.http != nil {
		_ = s.http.Shutdown(ctx)
	}
	if s.quic != nilValueListener {
		_ = s.quic.Close()
	}
	if s.tlsManager != nil {
		s.tlsManager.Stop()
	}
	return nil
}

// ----- helpers -----
func extractTarget(r *http.Request) (string, bool) {
	path := strings.TrimPrefix(r.URL.Path, "/")
	if path != "" && strings.Contains(path, ":") {
		return path, true
	}
	if t := r.URL.Query().Get("target"); t != "" {
		return t, true
	}
	return "", false
}

func isAllowed(list []string, target string) bool {
	if len(list) == 0 {
		return true
	}
	for _, t := range list {
		if t == target {
			return true
		}
	}
	return false
}

// nilValueListener is a zero value for quic.Listener
var nilValueListener interface{} = (interface{})(nil)

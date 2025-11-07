package bridge

import (
	"encoding/binary"
	"io"
	"net"
	"sync"
	"time"

	"github.com/DanielcoderX/anylink/internal/logger"
	"github.com/gorilla/websocket"
	"github.com/quic-go/quic-go"
)

// BridgeType defines the type of transport
type BridgeType int

const (
	WSBridge BridgeType = iota
	QUICBridge
)

// Bridge represents a single connection bridge (TCP ↔ WS or TCP ↔ QUIC)
type Bridge struct {
	bridgeType BridgeType

	ws      *websocket.Conn
	quicStr quic.Stream
	tcpConn net.Conn
	cfg     *Config
	log     *logger.Logger
	wg      sync.WaitGroup

	// Metrics
	BytesSent     int64
	BytesReceived int64

	// target for QUIC auto-dial
	target string
}

// Config holds bridge options
type Config struct {
	ReadTimeout time.Duration
}

// WS frame: [streamID(4B)][len(4B)][payload]
func writeWSFrame(ws *websocket.Conn, streamID uint32, data []byte) error {
	buf := make([]byte, 8+len(data))
	binary.BigEndian.PutUint32(buf[0:4], streamID)
	binary.BigEndian.PutUint32(buf[4:8], uint32(len(data)))
	copy(buf[8:], data)
	return ws.WriteMessage(websocket.BinaryMessage, buf)
}

func readWSFrame(r io.Reader) (streamID uint32, payload []byte, err error) {
	header := make([]byte, 8)
	if _, err = io.ReadFull(r, header); err != nil {
		return
	}
	streamID = binary.BigEndian.Uint32(header[0:4])
	length := binary.BigEndian.Uint32(header[4:8])
	payload = make([]byte, length)
	_, err = io.ReadFull(r, payload)
	return
}

// NewWSBridge starts a TCP ↔ WS bridge
func NewWSBridge(ws *websocket.Conn, tcpConn net.Conn, cfg *Config) *Bridge {
	b := &Bridge{
		bridgeType: WSBridge,
		ws:         ws,
		tcpConn:    tcpConn,
		cfg:        cfg,
		log:        logger.New("bridge"),
	}
	b.startWS()
	return b
}

// NewQUICBridge starts a QUIC stream bridge; TCP dial deferred until first message if tcpConn is nil
func NewQUICBridge(qs quic.Stream, tcpConn net.Conn, cfg *Config) *Bridge {
	b := &Bridge{
		bridgeType: QUICBridge,
		quicStr:    qs,
		tcpConn:    tcpConn, // can be nil
		cfg:        cfg,
		log:        logger.New("bridge"),
	}
	b.startQUIC()
	return b
}

// startWS launches TCP ↔ WS copying
func (b *Bridge) startWS() {

	b.ws.SetReadLimit(1 << 20)
	_ = b.ws.SetReadDeadline(time.Now().Add(b.cfg.ReadTimeout))
	b.ws.SetPongHandler(func(string) error {
		_ = b.ws.SetReadDeadline(time.Now().Add(b.cfg.ReadTimeout))
		return nil
	})

	b.wg.Add(2)

	// TCP -> WS
	go func() {
		defer b.wg.Done()
		buf := make([]byte, 32*1024)
		for {
			n, err := b.tcpConn.Read(buf)
			if n > 0 {
				b.BytesSent += int64(n)
				if ew := writeWSFrame(b.ws, 1, buf[:n]); ew != nil {
					return
				}
			}
			if err != nil {
				return
			}
		}
	}()

	// WS -> TCP
	go func() {
		defer b.wg.Done()
		for {
			mt, rdr, err := b.ws.NextReader()
			if err != nil {
				return
			}
			if mt != websocket.BinaryMessage {
				continue
			}
			streamID, payload, err := readWSFrame(rdr)
			if err != nil {
				return
			}
			if streamID != 1 {
				continue
			}
			n, _ := b.tcpConn.Write(payload)
			b.BytesReceived += int64(n)
			b.log.Trace("WS->TCP %d bytes", n)
			b.log.Debug("WS->TCP activity")
		}
	}()
}

// startQUIC launches TCP ↔ QUIC copying; auto-dials TCP target if needed
func (b *Bridge) startQUIC() {
	b.wg.Add(2)

	// QUIC -> TCP
	go func() {
		defer b.wg.Done()
		buf := make([]byte, 32*1024)
		for {
			n, err := b.quicStr.Read(buf)
			if n > 0 {
				// On first message, auto-dial TCP if tcpConn is nil
				if b.tcpConn == nil {
					b.target = string(buf[:n])
					tcp, err := net.Dial("tcp", b.target)
					if err != nil {
						b.log.Error("QUIC auto-dial failed: %v", err)
						return
					}
					b.tcpConn = tcp
					b.log.Debug("QUIC auto-dialed TCP target: %s", b.target)
					continue // target message ignored
				}

				b.BytesReceived += int64(n)
				if _, ew := b.tcpConn.Write(buf[:n]); ew != nil {
					return
				}
				b.log.Trace("QUIC->TCP %d bytes", n)
				b.log.Debug("QUIC->TCP activity")
			}
			if err != nil {
				return
			}
		}
	}()

	// TCP -> QUIC
	go func() {
		defer b.wg.Done()
		buf := make([]byte, 32*1024)
		for {
			// wait until tcpConn exists
			if b.tcpConn == nil {
				time.Sleep(10 * time.Millisecond)
				continue
			}
			n, err := b.tcpConn.Read(buf)
			if n > 0 {
				b.BytesSent += int64(n)
				if _, ew := b.quicStr.Write(buf[:n]); ew != nil {
					return
				}
			}
			if err != nil {
				return
			}
		}
	}()
}

// Close shuts down connections and waits for goroutines
func (b *Bridge) Close() {
	if b.ws != nil {
		b.ws.Close()
	}
	if b.quicStr != nilValueStream {
		b.quicStr.CancelRead(0)
		b.quicStr.CancelWrite(0)
	}
	if b.tcpConn != nil {
		b.tcpConn.Close()
	}
	b.wg.Wait()
}

func (b *Bridge) Wg() *sync.WaitGroup {
	return &b.wg
}

// nilValueStream is a zero value to compare quic.Stream interface
var nilValueStream interface{} = (interface{})(nil)

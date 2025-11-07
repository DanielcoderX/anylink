package server

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"time"

	"github.com/DanielcoderX/anylink/internal/config"
	"github.com/DanielcoderX/anylink/internal/logger"
	"github.com/gorilla/websocket"
	"github.com/quic-go/quic-go"
)

// newSelfSignedCert returns a self-signed ECDSA P-256 cert/key pair usable for QUIC/TLS tests.
func newSelfSignedCert() (tls.Certificate, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}

	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   "anylink-selftest.local",
			Organization: []string{"AnyLink"},
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(10, 0, 0), // 10 years valid
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"localhost", "127.0.0.1"},
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &priv.PublicKey, priv)
	if err != nil {
		return tls.Certificate{}, err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	keyBytes, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return tls.Certificate{}, err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes})

	return tls.X509KeyPair(certPEM, keyPEM)
}

// RunSelfTest runs WS and QUIC echo checks.
func RunSelfTest(cfg *config.Config) error {
	// Initialize logger for self-test
	logger.SetGlobalLevel(cfg.Verbose)
	log := logger.New("selftest")
	
	log.Info("🔍 AnyLink self-test starting...")

	// 1️⃣ Start echo TCP server
	echoLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return fmt.Errorf("failed to start echo server: %v", err)
	}
	defer echoLn.Close()
	echoAddr := echoLn.Addr().String()
	log.Info("🌀 Echo server running on %s", echoAddr)

	go func() {
		for {
			c, err := echoLn.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				io.Copy(conn, conn)
			}(c)
		}
	}()

	// 2️⃣ WS Bridge
	upgrader := websocket.Upgrader{CheckOrigin: func(r *http.Request) bool { return true }}
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		ws, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			log.Debug("upgrade error: %v", err)
			return
		}
		defer ws.Close()

		tcp, err := net.Dial("tcp", echoAddr)
		if err != nil {
			log.Debug("dial error: %v", err)
			return
		}
		defer tcp.Close()

		errc := make(chan error, 2)

		go func() { // TCP→WS
			buf := make([]byte, 4096)
			for {
				n, e := tcp.Read(buf)
				if n > 0 {
					if ew := ws.WriteMessage(websocket.BinaryMessage, buf[:n]); ew != nil {
						errc <- ew
						return
					}
				}
				if e != nil {
					errc <- e
					return
				}
			}
		}()
		go func() { // WS→TCP
			for {
				mt, rdr, e := ws.NextReader()
				if e != nil {
					errc <- e
					return
				}
				if mt == websocket.BinaryMessage {
					if _, e2 := io.Copy(tcp, rdr); e2 != nil {
						errc <- e2
						return
					}
				}
			}
		}()
		<-errc
	})

	srvLn, _ := net.Listen("tcp", "127.0.0.1:0")
	srvPort := srvLn.Addr().(*net.TCPAddr).Port
	srvURL := fmt.Sprintf("ws://127.0.0.1:%d", srvPort)
	log.Info("🧩 AnyLink WS bridge at %s", srvURL)
	go http.Serve(srvLn, mux)
	time.Sleep(200 * time.Millisecond)

	// 3️⃣ WS Test
	targetURL := fmt.Sprintf("%s/%s", srvURL, echoAddr)
	log.Info("🌐 Testing WS bridge via %s", targetURL)
	ws, _, err := websocket.DefaultDialer.Dial(targetURL, nil)
	if err != nil {
		return fmt.Errorf("WS dial failed: %v", err)
	}
	defer ws.Close()

	msg := []byte("hello_anylink_test")
	if err := ws.WriteMessage(websocket.BinaryMessage, msg); err != nil {
		return fmt.Errorf("WS write failed: %v", err)
	}
	ws.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, resp, err := ws.ReadMessage()
	if err != nil {
		return fmt.Errorf("WS read failed: %v", err)
	}
	if string(resp) != string(msg) {
		return fmt.Errorf("WS echo mismatch: %q != %q", msg, resp)
	}
	log.Info("✅ WS echo OK")

	// 4️⃣ QUIC Test
	// cert, err := tls.X509KeyPair(SelfCert, SelfKey)
	cert, err := newSelfSignedCert()
	if err != nil {
		return fmt.Errorf("TLS pair err: %v", err)
	}
	tlsConf := &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"anylink-quic-test"},
	}
	qln, err := quic.ListenAddr("127.0.0.1:0", tlsConf, &quic.Config{})
	if err != nil {
		return fmt.Errorf("QUIC listen: %v", err)
	}
	defer qln.Close()
	qaddr := qln.Addr().String()
	log.Info("🧠 QUIC echo listener on %s", qaddr)

	go func() {
		conn, err := qln.Accept(context.Background())
		if err != nil {
			log.Debug("accept error: %v", err)
			return
		}
		stream, _ := conn.AcceptStream(context.Background())
		io.Copy(stream, stream)
	}()

	time.Sleep(200 * time.Millisecond)
	conn, err := quic.DialAddr(context.Background(), qaddr, &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"anylink-quic-test"}}, &quic.Config{})
	if err != nil {
		return fmt.Errorf("QUIC dial failed: %v", err)
	}
	stream, err := conn.OpenStreamSync(context.Background())
	if err != nil {
		return fmt.Errorf("QUIC stream: %v", err)
	}
	_, _ = stream.Write(msg)
	buf := make([]byte, len(msg))
	stream.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := io.ReadFull(stream, buf); err != nil {
		return fmt.Errorf("QUIC read: %v", err)
	}
	if string(buf) != string(msg) {
		return fmt.Errorf("QUIC echo mismatch: %q != %q", msg, buf)
	}
	log.Info("✅ QUIC echo OK")

	log.Info("🎯 All self-tests passed.")
	return nil
}

// Self-signed keypair for test mode
var SelfCert = []byte(`-----BEGIN CERTIFICATE-----
MIIBfTCCASOgAwIBAgIRALs5NRfx...
-----END CERTIFICATE-----`)

var SelfKey = []byte(`-----BEGIN PRIVATE KEY-----
MFIGAgEAMBMGByqGSM49AgEGCCqGSM49...
-----END PRIVATE KEY-----`)
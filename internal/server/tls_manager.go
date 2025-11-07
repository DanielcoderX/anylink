package server

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"math/big"
	"strings"
	"sync"
	"time"

	"github.com/DanielcoderX/anylink/internal/logger"
)

// TLSManager manages TLS certificates with rotation and optional client auth.
type TLSManager struct {
	mu               sync.RWMutex
	cert             tls.Certificate
	clientCAs        *x509.CertPool
	rotateTicker     *time.Ticker
	rotationDur      time.Duration
	nextProtos       []string
	enableClientAuth bool
	log              *logger.Logger
}

// NewTLSManager creates a manager with auto-generated self-signed cert.
func NewTLSManager(rotation time.Duration, nextProtos []string, enableClientAuth bool, clientCAs *x509.CertPool) *TLSManager {
	cert, err := generateSelfSignedCert()
	if err != nil {
		logger.Fatalf("failed to generate TLS cert: %v", err)
	}

	t := &TLSManager{
		cert:             cert,
		rotateTicker:     time.NewTicker(rotation),
		rotationDur:      rotation,
		nextProtos:       nextProtos,
		enableClientAuth: enableClientAuth,
		clientCAs:        clientCAs,
		log:              logger.New("tls"),
	}

	// start background rotation
	go t.rotationLoop()
	return t
}

// rotationLoop periodically rotates the certificate.
func (t *TLSManager) rotationLoop() {
	for range t.rotateTicker.C {
		newCert, err := generateSelfSignedCert()
		if err != nil {
			t.log.Error("TLS rotation failed: %v", err)
			continue
		}
		t.mu.Lock()
		t.cert = newCert
		t.mu.Unlock()
		t.log.Debug("TLS certificate rotated")
	}
}

// GetTLSConfig returns a ready-to-use TLS config for QUIC/HTTP.
func (t *TLSManager) GetTLSConfig() *tls.Config {
	t.mu.RLock()
	defer t.mu.RUnlock()

	cfg := &tls.Config{
		Certificates: []tls.Certificate{t.cert},
		MinVersion:   tls.VersionTLS13,
		NextProtos:   t.nextProtos,

		// 0-RTT support
		SessionTicketsDisabled: false,
	}

	if t.enableClientAuth {
		cfg.ClientAuth = tls.RequireAndVerifyClientCert
		cfg.ClientCAs = t.clientCAs
	}

	return cfg
}

// Stop stops the background rotation ticker.
func (t *TLSManager) Stop() {
	t.rotateTicker.Stop()
}

// generateSelfSignedCert returns a minimal EC self-signed certificate.
func generateSelfSignedCert() (tls.Certificate, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}

	notBefore := time.Now()
	notAfter := notBefore.Add(24 * time.Hour)

	serialNumber, _ := rand.Int(rand.Reader, big.NewInt(1<<62))

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   "anylink.local",
			Organization: []string{"AnyLink"},
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return tls.Certificate{}, err
	}

	certPEM := encodePEM("CERTIFICATE", derBytes)
	keyBytes, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return tls.Certificate{}, err
	}
	keyPEM := encodePEM("EC PRIVATE KEY", keyBytes)

	return tls.X509KeyPair(certPEM, keyPEM)
}

// encodePEM returns PEM bytes for given type and DER data.
func encodePEM(typ string, der []byte) []byte {
	return []byte(
		"-----BEGIN " + typ + "-----\n" +
			string(MustBase64(der)) +
			"\n-----END " + typ + "-----\n")
}

// MustBase64 encodes DER to base64 without line breaks.
func MustBase64(der []byte) []byte {
	return []byte(strings.TrimRight(strings.ReplaceAll(base64.StdEncoding.EncodeToString(der), "\n", ""), "\r"))
}

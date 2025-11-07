# 🚀 AnyLink

AnyLink bridges TCP services over **WebSocket (WS/WSS)** and **QUIC**, providing a modern, secure, and multiplexed transport layer.

It’s designed for **high-performance tunneling**, with:
- QUIC RFC 9000 support (multi-stream, 0-RTT, TLS 1.3)
- Dynamic TLS key rotation
- TCP pooling
- Configurable logging levels
- Optional self-test mode
- Bridge-level metrics and flow tracking

---

## ⚙️ Quick Start

### 1️⃣ Run with CLI flags

```bash
anylink --addr :8080 --quic :4242 \
  --allow "127.0.0.1:22,10.0.0.1:3306" \
  --verbose debug

This exposes:
	•	ws://localhost:8080
	•	quic://localhost:4242

Both forward TCP streams to the allowed target addresses.

⸻

2️⃣ Run with Config File

anylink --config ./anylink.yaml

Example anylink.yaml:

listen:
  ws: ":8080"
  quic: ":4242"

allowed_targets:
  - "127.0.0.1:22"
  - "10.0.0.1:3306"

bridge:
  read_timeout: 45s
  tcp_pool_size: 16

logging:
  level: info


⸻

🧠 Self-Test Mode

To verify QUIC and WebSocket tunnels:

anylink --selftest --verbose=trace

Expected output:

🔍 AnyLink self-test starting...
✅ WS echo OK
✅ QUIC echo OK
🎯 All self-tests passed.


⸻

🔒 TLS & QUIC Features
	•	TLS 1.3 only with ALPN negotiation
	•	Automatic key rotation every 12 hours
	•	Optional client authentication
	•	0-RTT QUIC session resumption

⸻

🧰 Logging Levels

Level	Description
quiet	Silent except fatal errors
error	Only errors
info	Normal operational logs
debug	Detailed events
trace	Per-stream data (heavy)


⸻

📊 Metrics (optional)

Expose /metrics for Prometheus (if enabled):

active_connections  12
bytes_sent_total    1250944
bytes_received_total 1184387


⸻

🧩 Directory Structure

.
├── cmd/anylink/main.go
├── internal/
│   ├── bridge/        # TCP↔WS / TCP↔QUIC bridges + pooling
│   ├── server/        # TLS manager, metrics, selftest, main server
│   ├── config/        # YAML/flag config loader
│   └── logger/        # Logging subsystem
└── anylink.yaml       # Configuration example


⸻

🧠 Example Use Cases
	•	Expose an SSH server over WebSocket (e.g. via CDN)
	•	Access databases securely over QUIC tunnels
	•	Build Web-based remote clients over WS with TCP backends

⸻
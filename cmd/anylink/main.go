package main

import (
	"context"
	"flag"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/DanielcoderX/anylink/internal/config"
	"github.com/DanielcoderX/anylink/internal/logger"
	"github.com/DanielcoderX/anylink/internal/server"
)

func Parse() *config.Config {
	var cfg config.Config
	flag.StringVar(&cfg.Addr, "addr", ":8080", "HTTP listen address")
	flag.StringVar(&cfg.QUICAddr, "quic", ":4242", "QUIC listen address")
	flag.BoolVar(&cfg.RunTest, "selftest", false, "run WS+QUIC self-test and exit")
	flag.StringVar(&cfg.Verbose, "verbose", "debug", "logging level: quiet|error|info|debug|trace")
	flag.Parse()
	return &cfg
}
func main() {
	cfg := Parse()

	// Initialize logger with verbose level
	logger.SetGlobalLevel(cfg.Verbose)

	if cfg.RunTest {
		if err := server.RunSelfTest(cfg); err != nil {
			logger.Fatalf("❌ Self-test failed: %v", err)
		}
		return
	}

	// Start server
	srv := server.New(cfg)

	// Graceful shutdown handling
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		if err := srv.Start(); err != nil && err.Error() != "http: Server closed" {
			logger.Fatalf("❌ Server error: %v", err)
		}
	}()

	logger.Info("🌐 AnyLink listening on %s (press Ctrl+C to stop)", cfg.Addr)

	<-stop
	logger.Info("🛑 Shutting down...")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		logger.Fatalf("❌ Graceful shutdown failed: %v", err)
	}

	logger.Info("✅ Shutdown complete.")
}

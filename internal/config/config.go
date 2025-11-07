package config

import (
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/pelletier/go-toml/v2"
	"gopkg.in/yaml.v3"
)

const Version = "0.1.0"

type Config struct {
	Addr           string        `json:"addr" yaml:"addr" toml:"addr"`
	AllowedTargets []string      `json:"allowed_targets" yaml:"allowed_targets" toml:"allowed_targets"`
	ReadTimeout    time.Duration `json:"timeout" yaml:"timeout" toml:"timeout"`
	ShowVersion    bool          `json:"-" yaml:"-" toml:"-"`
	RunTest        bool          `json:"-" yaml:"-" toml:"-"`
	ConfigPath     string        `json:"-" yaml:"-" toml:"-"`
	Verbose        string        `json:"verbose" yaml:"verbose" toml:"verbose"`
	// QUIC fields
	TLSCert  tls.Certificate
	QUICAddr string

	EnableWSS   bool `json:"enable_wss" yaml:"enable_wss" toml:"enable_wss"`
	TCPPoolSize int  `json:"tcp_pool_size" yaml:"tcp_pool_size" toml:"tcp_pool_size"`
}

// Parse parses CLI arguments and (optionally) loads a config file.
func Parse() *Config {
	cfg := &Config{}
	allow := flag.String("allow", "", "Comma-separated list of allowed backend targets (e.g., 127.0.0.1:22,10.0.0.1:3306). Leave empty to allow all targets.")

	flag.StringVar(&cfg.Addr, "addr", ":8080", "Address and port to listen on (e.g., :8080 or 0.0.0.0:9000)")
	flag.StringVar(&cfg.Addr, "a", ":8080", "alias for --addr")
	flag.StringVar(&cfg.ConfigPath, "config", "", "Path to YAML/JSON/TOML configuration file")
	flag.DurationVar(&cfg.ReadTimeout, "timeout", 60*time.Second, "Read timeout for WebSocket connections.")
	flag.BoolVar(&cfg.ShowVersion, "version", false, "Show version and exit")
	flag.BoolVar(&cfg.RunTest, "test", false, "Run internal echo test and exit")

	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(),
			`AnyLink — Turn any TCP server into a WebSocket endpoint.

Usage:
  anylink [options]

Examples:
  anylink --addr :8080 --allow "127.0.0.1:22,10.0.0.1:3306"
  anylink --config ./anylink.yaml
  anylink -a :9000

Options:
`)
		flag.PrintDefaults()
		fmt.Println(`
Description:
  AnyLink exposes arbitrary TCP services (e.g. SSH, Redis, PostgreSQL)
  over WebSocket connections so browsers or web clients can connect
  directly to them via ws:// or wss://.`)
	}

	flag.Parse()

	if cfg.ShowVersion {
		fmt.Printf("AnyLink version %s\n", Version)
		os.Exit(0)
	}

	// Load from file if provided
	if cfg.ConfigPath != "" {
		fileCfg, err := loadFromFile(cfg.ConfigPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "❌ Failed to load config file: %v\n", err)
			os.Exit(2)
		}
		merge(cfg, fileCfg)
	}

	cfg.AllowedTargets = split(*allow)
	validate(cfg)
	return cfg
}

// split converts comma-separated string to []string
func split(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	for i := range parts {
		parts[i] = strings.TrimSpace(parts[i])
	}
	return parts
}

func validate(cfg *Config) {
	if !strings.Contains(cfg.Addr, ":") {
		fmt.Fprintf(os.Stderr, "invalid address: %s (must include a port)\n", cfg.Addr)
		os.Exit(2)
	}
}

// loadFromFile parses a YAML/JSON/TOML config file
func loadFromFile(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	c := &Config{}
	switch strings.ToLower(filepath.Ext(path)) {
	case ".yaml", ".yml":
		err = yaml.Unmarshal(data, c)
	case ".json":
		err = json.Unmarshal(data, c)
	case ".toml":
		err = toml.Unmarshal(data, c)
	default:
		return nil, fmt.Errorf("unsupported config format: %s", path)
	}
	return c, err
}

// merge: CLI overrides file-based config
func merge(dst, src *Config) {
	if dst.Addr == ":8080" && src.Addr != "" {
		dst.Addr = src.Addr
	}
	if len(dst.AllowedTargets) == 0 && len(src.AllowedTargets) > 0 {
		dst.AllowedTargets = src.AllowedTargets
	}
	if dst.ReadTimeout == 60*time.Second && src.ReadTimeout != 0 {
		dst.ReadTimeout = src.ReadTimeout
	}
}

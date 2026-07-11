// Package config loads VulnaScout agent configuration from a JSON file with
// environment-variable overrides.
//
// A YAML format is planned, but the agent stays dependency-free (standard
// library only) so it cross-compiles to a single static binary for amd64 and
// arm64 without CGO; JSON is used for configuration in the meantime.
package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
)

// Default locations.
const (
	DefaultStateDir                 = "/var/lib/vulna"
	DefaultConfigPath               = "/etc/vulna/agent.json"
	DefaultHeartbeatIntervalSeconds = 60
	// DefaultResultQueueMaxBytes caps the durable result backlog held for an
	// intermittent link (256 MiB). At the cap the Scout applies backpressure
	// rather than filling the disk.
	DefaultResultQueueMaxBytes = 256 << 20
)

// Config holds VulnaScout agent configuration.
type Config struct {
	// ServerURL is the base URL of the VulnaDash orchestrator.
	ServerURL string `json:"server_url"`
	// StateDir is where enrollment material and local state are stored.
	StateDir string `json:"state_dir"`
	// ServerCAPath optionally pins the orchestrator's TLS CA (PEM). Empty means
	// the system trust store is used (e.g. for publicly-trusted certificates).
	ServerCAPath string `json:"server_ca_path,omitempty"`
	// HeartbeatIntervalSeconds is the default heartbeat cadence; the server may
	// suggest a different interval in its heartbeat response.
	HeartbeatIntervalSeconds int `json:"heartbeat_interval_seconds"`
	// InsecureSkipVerify disables orchestrator TLS verification. DEV/LAB ONLY.
	InsecureSkipVerify bool `json:"insecure_skip_verify,omitempty"`
	// ResultQueueMaxBytes caps the durable result backlog (payload bytes) kept
	// while the orchestrator is unreachable. Zero disables the cap.
	ResultQueueMaxBytes int64 `json:"result_queue_max_bytes,omitempty"`
}

// Default returns a Config populated with default values.
func Default() Config {
	return Config{
		StateDir:                 DefaultStateDir,
		HeartbeatIntervalSeconds: DefaultHeartbeatIntervalSeconds,
		ResultQueueMaxBytes:      DefaultResultQueueMaxBytes,
	}
}

// Load reads configuration from a JSON file (if present) and then applies
// environment overrides. A missing file is not an error: defaults plus
// environment variables are used.
func Load(path string) (Config, error) {
	cfg := Default()
	if path != "" {
		data, err := os.ReadFile(path) //nolint:gosec // operator-provided config path
		switch {
		case err == nil:
			if err := json.Unmarshal(data, &cfg); err != nil {
				return cfg, fmt.Errorf("parse config %s: %w", path, err)
			}
		case errors.Is(err, os.ErrNotExist):
			// Fall through to defaults + environment.
		default:
			return cfg, fmt.Errorf("read config %s: %w", path, err)
		}
	}
	applyEnv(&cfg)
	if cfg.StateDir == "" {
		cfg.StateDir = DefaultStateDir
	}
	if cfg.HeartbeatIntervalSeconds <= 0 {
		cfg.HeartbeatIntervalSeconds = DefaultHeartbeatIntervalSeconds
	}
	return cfg, nil
}

func applyEnv(cfg *Config) {
	if v := os.Getenv("VULNASCOUT_SERVER_URL"); v != "" {
		cfg.ServerURL = v
	}
	if v := os.Getenv("VULNASCOUT_STATE_DIR"); v != "" {
		cfg.StateDir = v
	}
	if v := os.Getenv("VULNASCOUT_SERVER_CA"); v != "" {
		cfg.ServerCAPath = v
	}
	if v := os.Getenv("VULNASCOUT_HEARTBEAT_INTERVAL"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			cfg.HeartbeatIntervalSeconds = n
		}
	}
	if v := os.Getenv("VULNASCOUT_INSECURE_SKIP_VERIFY"); v != "" {
		cfg.InsecureSkipVerify = strings.EqualFold(v, "true") || v == "1"
	}
}

// Validate checks the fields required for network operations.
func (c Config) Validate() error {
	if strings.TrimSpace(c.ServerURL) == "" {
		return errors.New("server_url is required")
	}
	if !strings.HasPrefix(c.ServerURL, "https://") && !strings.HasPrefix(c.ServerURL, "http://") {
		return errors.New("server_url must be an http(s) URL")
	}
	return nil
}

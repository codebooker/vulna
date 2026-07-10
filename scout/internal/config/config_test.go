package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDefault(t *testing.T) {
	c := Default()
	if c.StateDir != DefaultStateDir {
		t.Errorf("StateDir = %q, want %q", c.StateDir, DefaultStateDir)
	}
	if c.HeartbeatIntervalSeconds != DefaultHeartbeatIntervalSeconds {
		t.Errorf("HeartbeatIntervalSeconds = %d", c.HeartbeatIntervalSeconds)
	}
}

func TestLoadMissingFileUsesDefaults(t *testing.T) {
	c, err := Load(filepath.Join(t.TempDir(), "nope.json"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if c.StateDir != DefaultStateDir {
		t.Errorf("StateDir = %q", c.StateDir)
	}
}

func TestLoadFromFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "agent.json")
	body := `{"server_url":"https://x.example","state_dir":"/tmp/s","heartbeat_interval_seconds":30}`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if c.ServerURL != "https://x.example" {
		t.Errorf("ServerURL = %q", c.ServerURL)
	}
	if c.StateDir != "/tmp/s" {
		t.Errorf("StateDir = %q", c.StateDir)
	}
	if c.HeartbeatIntervalSeconds != 30 {
		t.Errorf("HeartbeatIntervalSeconds = %d", c.HeartbeatIntervalSeconds)
	}
}

func TestEnvOverride(t *testing.T) {
	t.Setenv("VULNASCOUT_SERVER_URL", "https://env.example")
	t.Setenv("VULNASCOUT_HEARTBEAT_INTERVAL", "45")
	c, err := Load("")
	if err != nil {
		t.Fatal(err)
	}
	if c.ServerURL != "https://env.example" {
		t.Errorf("ServerURL = %q", c.ServerURL)
	}
	if c.HeartbeatIntervalSeconds != 45 {
		t.Errorf("HeartbeatIntervalSeconds = %d", c.HeartbeatIntervalSeconds)
	}
}

func TestValidate(t *testing.T) {
	if err := (Config{}).Validate(); err == nil {
		t.Error("expected error for empty server_url")
	}
	if err := (Config{ServerURL: "ftp://x"}).Validate(); err == nil {
		t.Error("expected error for non-http(s) url")
	}
	if err := (Config{ServerURL: "https://x"}).Validate(); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

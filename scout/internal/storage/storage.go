// Package storage manages VulnaScout's durable local state on disk.
//
// Enrollment material (client key, client certificate, orchestrator CA) and a
// small JSON state file live under a single state directory with restrictive
// permissions. A SQLite-backed durable job queue arrives with job handling in a
// later phase; enrollment and heartbeat need only these files.
package storage

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

const (
	keyFile    = "client_key.pem"
	certFile   = "client_cert.pem"
	caFile     = "ca_cert.pem"
	stateFile  = "state.json"
	policyFile = "policy.json"
)

// State is the persisted enrollment state.
type State struct {
	ProbeID          string `json:"probe_id"`
	SiteID           string `json:"site_id"`
	Fingerprint      string `json:"certificate_fingerprint"`
	EnrolledAt       string `json:"enrolled_at"`
	ServerURL        string `json:"server_url"`
	SigningPublicKey string `json:"signing_public_key,omitempty"`
}

// Store manages on-disk VulnaScout state under a base directory.
type Store struct {
	dir string
}

// New returns a Store rooted at dir, creating the directory (0700) if needed.
func New(dir string) (*Store, error) {
	if dir == "" {
		return nil, fmt.Errorf("state directory must not be empty")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("create state dir %s: %w", dir, err)
	}
	return &Store{dir: dir}, nil
}

func (s *Store) path(name string) string { return filepath.Join(s.dir, name) }

// KeyPath, CertPath and CAPath expose file locations for TLS loading.
func (s *Store) KeyPath() string  { return s.path(keyFile) }
func (s *Store) CertPath() string { return s.path(certFile) }
func (s *Store) CAPath() string   { return s.path(caFile) }

// IsEnrolled reports whether the client key, certificate, and state exist.
func (s *Store) IsEnrolled() bool {
	for _, f := range []string{keyFile, certFile, stateFile} {
		if _, err := os.Stat(s.path(f)); err != nil {
			return false
		}
	}
	return true
}

// SaveKey writes the client private key with owner-only permissions.
func (s *Store) SaveKey(pemBytes []byte) error {
	return writeFile(s.path(keyFile), pemBytes, 0o600)
}

// SaveCert writes the issued client certificate.
func (s *Store) SaveCert(pemBytes []byte) error {
	return writeFile(s.path(certFile), pemBytes, 0o644)
}

// SaveCA writes the orchestrator CA certificate.
func (s *Store) SaveCA(pemBytes []byte) error {
	return writeFile(s.path(caFile), pemBytes, 0o644)
}

// SaveState persists the enrollment state as JSON (owner-only).
func (s *Store) SaveState(st State) error {
	data, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal state: %w", err)
	}
	return writeFile(s.path(stateFile), data, 0o600)
}

// LoadState reads the enrollment state.
func (s *Store) LoadState() (State, error) {
	var st State
	data, err := os.ReadFile(s.path(stateFile))
	if err != nil {
		return st, err
	}
	if err := json.Unmarshal(data, &st); err != nil {
		return st, fmt.Errorf("parse state: %w", err)
	}
	return st, nil
}

// SavePolicy persists the raw signed local-policy document.
func (s *Store) SavePolicy(raw []byte) error {
	return writeFile(s.path(policyFile), raw, 0o600)
}

// LoadPolicy reads the raw signed local-policy document, if present.
func (s *Store) LoadPolicy() ([]byte, error) {
	return os.ReadFile(s.path(policyFile))
}

func writeFile(path string, data []byte, perm os.FileMode) error {
	if err := os.WriteFile(path, data, perm); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	// WriteFile only applies perm on create; enforce it for existing files too.
	if err := os.Chmod(path, perm); err != nil {
		return fmt.Errorf("chmod %s: %w", path, err)
	}
	return nil
}

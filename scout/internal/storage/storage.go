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
	keyFile           = "client_key.pem"
	certFile          = "client_cert.pem"
	caFile            = "ca_cert.pem"
	stateFile         = "state.json"
	policyFile        = "policy.json"
	credentialKeyFile = "credential_encryption.key"
	stopFile          = "stop.flag"
	diagnosticsFile   = "last-reset-diagnostics.json"
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

// SaveCredentialKey stores the raw X25519 private key used only to decrypt
// per-job credential envelopes. Vault values themselves are never stored.
func (s *Store) SaveCredentialKey(raw []byte) error {
	return writeFile(s.path(credentialKeyFile), raw, 0o600)
}

// LoadCredentialKey reads the raw X25519 private key into process memory.
func (s *Store) LoadCredentialKey() ([]byte, error) {
	return os.ReadFile(s.path(credentialKeyFile))
}

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

// StopFlag is the persisted local emergency-stop marker.
type StopFlag struct {
	Reason    string `json:"reason"`
	CreatedAt string `json:"created_at"`
}

// SetStop writes the local emergency-stop marker. This is a purely local kill
// switch: it works with no network and is authoritative even when the
// orchestrator is unreachable or compromised. The run loop refuses to start (and
// stops any running job) while it is present.
func (s *Store) SetStop(reason string, now string) error {
	data, err := json.MarshalIndent(StopFlag{Reason: reason, CreatedAt: now}, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal stop flag: %w", err)
	}
	return writeFile(s.path(stopFile), data, 0o600)
}

// ClearStop removes the emergency-stop marker (used by `resume`).
func (s *Store) ClearStop() error {
	err := os.Remove(s.path(stopFile))
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("clear stop flag: %w", err)
	}
	return nil
}

// IsStopped reports whether the emergency stop is set and, if so, its reason.
func (s *Store) IsStopped() (bool, string) {
	data, err := os.ReadFile(s.path(stopFile))
	if err != nil {
		return false, ""
	}
	var flag StopFlag
	if json.Unmarshal(data, &flag) == nil {
		return true, flag.Reason
	}
	return true, ""
}

// Reset revokes the local identity by deleting the client key, certificate, and
// enrollment state so the Scout can re-enroll cleanly. Before deleting, it
// preserves a small diagnostics snapshot (never secrets) so an operator can still
// see what the prior identity was. The private key is shredded-by-removal; it
// never left the Scout.
func (s *Store) Reset(diagnostics []byte) error {
	if len(diagnostics) > 0 {
		if err := writeFile(s.path(diagnosticsFile), diagnostics, 0o600); err != nil {
			return err
		}
	}
	for _, f := range []string{
		keyFile, certFile, caFile, stateFile, policyFile, credentialKeyFile, stopFile,
	} {
		if err := os.Remove(s.path(f)); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("remove %s: %w", f, err)
		}
	}
	return nil
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

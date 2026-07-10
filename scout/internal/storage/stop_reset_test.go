package storage

import (
	"os"
	"path/filepath"
	"testing"
)

func TestStopFlagLifecycle(t *testing.T) {
	s, err := New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if stopped, _ := s.IsStopped(); stopped {
		t.Fatal("should not be stopped initially")
	}
	if err := s.SetStop("operator emergency stop", "2026-07-10T00:00:00Z"); err != nil {
		t.Fatal(err)
	}
	stopped, reason := s.IsStopped()
	if !stopped || reason != "operator emergency stop" {
		t.Fatalf("expected stopped with reason, got %v %q", stopped, reason)
	}
	if err := s.ClearStop(); err != nil {
		t.Fatal(err)
	}
	if stopped, _ := s.IsStopped(); stopped {
		t.Fatal("should be cleared")
	}
}

func TestResetWipesIdentityKeepsDiagnostics(t *testing.T) {
	dir := t.TempDir()
	s, err := New(dir)
	if err != nil {
		t.Fatal(err)
	}
	// Seed a full enrolled identity.
	if err := s.SaveKey([]byte("KEY")); err != nil {
		t.Fatal(err)
	}
	if err := s.SaveCert([]byte("CERT")); err != nil {
		t.Fatal(err)
	}
	if err := s.SaveState(State{ProbeID: "p1", ServerURL: "https://x"}); err != nil {
		t.Fatal(err)
	}
	if !s.IsEnrolled() {
		t.Fatal("should be enrolled after seeding")
	}

	if err := s.Reset([]byte(`{"probe_id":"p1"}`)); err != nil {
		t.Fatal(err)
	}
	if s.IsEnrolled() {
		t.Fatal("reset must wipe the identity")
	}
	// Key must be gone (private key removed).
	if _, err := os.Stat(filepath.Join(dir, keyFile)); !os.IsNotExist(err) {
		t.Fatal("client key must be removed by reset")
	}
	// Diagnostics preserved.
	data, err := os.ReadFile(filepath.Join(dir, diagnosticsFile))
	if err != nil {
		t.Fatalf("diagnostics should be preserved: %v", err)
	}
	if string(data) != `{"probe_id":"p1"}` {
		t.Fatalf("unexpected diagnostics: %s", data)
	}
}

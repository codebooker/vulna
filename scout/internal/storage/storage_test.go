package storage

import (
	"os"
	"path/filepath"
	"testing"
)

func TestNewCreatesDirAndNotEnrolled(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	s, err := New(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(dir); err != nil {
		t.Fatalf("state dir not created: %v", err)
	}
	if s.IsEnrolled() {
		t.Error("fresh store should not be enrolled")
	}
}

func TestNewEmptyDirErrors(t *testing.T) {
	if _, err := New(""); err == nil {
		t.Error("expected error for empty dir")
	}
}

func TestSaveLoadRoundTrip(t *testing.T) {
	s, err := New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SaveKey([]byte("KEYPEM")); err != nil {
		t.Fatal(err)
	}
	if err := s.SaveCert([]byte("CERTPEM")); err != nil {
		t.Fatal(err)
	}
	if err := s.SaveCA([]byte("CAPEM")); err != nil {
		t.Fatal(err)
	}
	if err := s.SaveCredentialKey([]byte("X25519PRIVATEKEY")); err != nil {
		t.Fatal(err)
	}
	want := State{ProbeID: "p1", SiteID: "s1", Fingerprint: "fp", ServerURL: "https://x"}
	if err := s.SaveState(want); err != nil {
		t.Fatal(err)
	}
	if !s.IsEnrolled() {
		t.Error("store should report enrolled after saving material")
	}
	got, err := s.LoadState()
	if err != nil {
		t.Fatal(err)
	}
	if got.ProbeID != want.ProbeID || got.SiteID != want.SiteID || got.Fingerprint != want.Fingerprint {
		t.Errorf("round-trip mismatch: %+v", got)
	}
	fi, err := os.Stat(s.KeyPath())
	if err != nil {
		t.Fatal(err)
	}
	if perm := fi.Mode().Perm(); perm != 0o600 {
		t.Errorf("key file perms = %o, want 600", perm)
	}
	credentialKey, err := s.LoadCredentialKey()
	if err != nil || string(credentialKey) != "X25519PRIVATEKEY" {
		t.Fatalf("credential key round-trip failed: %q, %v", credentialKey, err)
	}
	if err := s.Reset([]byte(`{"probe_id":"p1"}`)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.LoadCredentialKey(); err == nil {
		t.Fatal("reset did not remove credential encryption key")
	}
}

package release

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"testing"
	"time"
)

func signed(t *testing.T, m Manifest) (ed25519.PublicKey, []byte, []byte, []byte) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	manifest, _ := json.Marshal(m)
	sum := sha256.Sum256(manifest)
	sums := []byte(hex.EncodeToString(sum[:]) + "  " + ManifestFileName + "\n")
	sig := ed25519.Sign(priv, sums)
	return pub, manifest, sums, sig
}

func validManifest() Manifest {
	return Manifest{
		Version:    "1.2.0",
		Channel:    ChannelStable,
		ReleasedAt: time.Now().UTC().Format(time.RFC3339),
		Security:   "recommended",
		Migration:  Migration{HasMigrations: true, Notes: "adds a column"},
	}
}

func TestVerifyValid(t *testing.T) {
	pub, manifest, sums, sig := signed(t, validManifest())
	m, err := Verify(pub, manifest, sums, sig)
	if err != nil {
		t.Fatalf("valid release should verify: %v", err)
	}
	if m.Version != "1.2.0" {
		t.Fatalf("version = %q", m.Version)
	}
}

func TestVerifyRejectsTamperedManifest(t *testing.T) {
	pub, manifest, sums, sig := signed(t, validManifest())
	manifest = append(manifest, ' ') // change bytes -> checksum no longer matches
	if _, err := Verify(pub, manifest, sums, sig); err == nil {
		t.Fatal("tampered manifest must be rejected")
	}
}

func TestVerifyRejectsBadSignature(t *testing.T) {
	pub, manifest, sums, sig := signed(t, validManifest())
	sig[0] ^= 0xff
	if _, err := Verify(pub, manifest, sums, sig); err == nil {
		t.Fatal("bad signature must be rejected")
	}
}

func TestVerifyRejectsWrongKey(t *testing.T) {
	_, manifest, sums, sig := signed(t, validManifest())
	other, _, _ := ed25519.GenerateKey(nil)
	if _, err := Verify(other, manifest, sums, sig); err == nil {
		t.Fatal("wrong key must be rejected")
	}
}

func TestValidateExpiredAndChannel(t *testing.T) {
	now := time.Now()
	m := validManifest()
	m.ExpiresAt = now.Add(-time.Hour).Format(time.RFC3339)
	if err := m.Validate(ChannelStable, "1.0.0", now); err == nil {
		t.Fatal("expired metadata must be rejected")
	}
	m2 := validManifest()
	if err := m2.Validate(ChannelCandidate, "1.0.0", now); err == nil {
		t.Fatal("channel mismatch must be rejected")
	}
	if err := m2.Validate(ChannelStable, "1.0.0", now); err != nil {
		t.Fatalf("valid manifest should pass: %v", err)
	}
}

func TestCompareVersions(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"1.2.3", "1.2.4", -1},
		{"v1.3.0", "1.2.9", 1},
		{"1.0.0", "1.0.0", 0},
		{"1.0.0", "1.0.0-rc1", 1}, // release > pre-release
		{"1.0.0-rc1", "1.0.0-rc2", -1},
	}
	for _, c := range cases {
		if got := CompareVersions(c.a, c.b); got != c.want {
			t.Errorf("Compare(%q,%q)=%d want %d", c.a, c.b, got, c.want)
		}
	}
}

func TestIsNewerThan(t *testing.T) {
	m := validManifest() // 1.2.0
	if !m.IsNewerThan("1.1.0") {
		t.Fatal("1.2.0 should be newer than 1.1.0")
	}
	if m.IsNewerThan("1.2.0") {
		t.Fatal("1.2.0 is not newer than itself")
	}
}

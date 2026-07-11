package backup

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// --------------------------------------------------------------------------- #
// Encryption
// --------------------------------------------------------------------------- #

func TestEncryptDecryptRoundTrip(t *testing.T) {
	plaintext := []byte("the quick brown fox — db.dump bytes")
	pass := []byte("correct horse battery staple")
	ct, err := Encrypt(plaintext, pass)
	if err != nil {
		t.Fatal(err)
	}
	if string(ct) == string(plaintext) {
		t.Fatal("ciphertext must differ from plaintext")
	}
	pt, err := Decrypt(ct, pass)
	if err != nil {
		t.Fatal(err)
	}
	if string(pt) != string(plaintext) {
		t.Fatalf("round trip mismatch: %q", pt)
	}
}

func TestDecryptWrongPassphraseFails(t *testing.T) {
	ct, _ := Encrypt([]byte("secret data"), []byte("right"))
	if _, err := Decrypt(ct, []byte("wrong")); err == nil {
		t.Fatal("wrong passphrase must fail")
	}
}

func TestDecryptTamperedFails(t *testing.T) {
	ct, _ := Encrypt([]byte("secret data"), []byte("pass"))
	ct[len(ct)-1] ^= 0xff // flip a ciphertext/tag byte
	if _, err := Decrypt(ct, []byte("pass")); err == nil {
		t.Fatal("tampered ciphertext must fail authentication")
	}
}

func TestEncryptRequiresPassphrase(t *testing.T) {
	if _, err := Encrypt([]byte("x"), nil); err == nil {
		t.Fatal("encryption without a passphrase must be refused")
	}
}

// --------------------------------------------------------------------------- #
// Manifest + verify
// --------------------------------------------------------------------------- #

func writeBundle(t *testing.T, encrypted bool, pass []byte) (string, Manifest) {
	t.Helper()
	dir := t.TempDir()
	archiveBytes := []byte("PK\x03\x04 pretend tar.gz payload")
	sum := sha256Hex(archiveBytes)

	archiveName := "vulna-backup.tar.gz"
	stored := archiveBytes
	m := Manifest{
		BackupVersion: CurrentBackupVersion,
		CreatedAt:     "2026-07-10T00:00:00Z",
		AppVersion:    "0.1.0",
		SchemaVersion: "abc123",
		OrgID:         "org-1",
		OrgSlug:       "default",
		Archive:       archiveName,
		ArchiveSHA256: sum,
		Contents:      []string{ClassDatabase, ClassConfig, ClassCA, ClassReports},
		SizeBytes:     int64(len(archiveBytes)),
	}
	if encrypted {
		var err error
		stored, err = Encrypt(archiveBytes, pass)
		if err != nil {
			t.Fatal(err)
		}
		archiveName = "vulna-backup.tar.gz.enc"
		m.Archive = archiveName
		m.Encrypted = true
		m.Encryption = &Encryption{Algo: EncAlgo, KDF: KDF, Iterations: Iterations}
	}
	if err := os.WriteFile(filepath.Join(dir, archiveName), stored, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := WriteManifest(dir, m); err != nil {
		t.Fatal(err)
	}
	return dir, m
}

func TestVerifyUsableUnencrypted(t *testing.T) {
	dir, _ := writeBundle(t, false, nil)
	r := VerifyBundle(dir, nil)
	if !r.Usable {
		t.Fatalf("valid bundle should be usable: %+v", r.Checks)
	}
}

func TestVerifyEncryptedNeedsPassphrase(t *testing.T) {
	dir, _ := writeBundle(t, true, []byte("pw"))
	if VerifyBundle(dir, nil).Usable {
		t.Fatal("encrypted bundle without passphrase must be unusable")
	}
	if !VerifyBundle(dir, []byte("pw")).Usable {
		t.Fatal("encrypted bundle with the right passphrase should be usable")
	}
}

func TestVerifyChecksumMismatchIsUnusable(t *testing.T) {
	dir, m := writeBundle(t, false, nil)
	// Corrupt the archive so its checksum no longer matches the manifest.
	if err := os.WriteFile(filepath.Join(dir, m.Archive), []byte("corrupted"), 0o600); err != nil {
		t.Fatal(err)
	}
	if VerifyBundle(dir, nil).Usable {
		t.Fatal("checksum mismatch must be marked unusable before any restore")
	}
}

func TestVerifyMissingRequiredClassUnusable(t *testing.T) {
	dir, m := writeBundle(t, false, nil)
	m.Contents = []string{ClassDatabase, ClassReports} // missing config + ca
	if err := WriteManifest(dir, m); err != nil {
		t.Fatal(err)
	}
	if VerifyBundle(dir, nil).Usable {
		t.Fatal("bundle missing required content must be unusable")
	}
}

func TestManifestHasNoSecrets(t *testing.T) {
	_, m := writeBundle(t, true, []byte("pw"))
	data, _ := os.ReadFile(filepath.Join(t.TempDir(), ManifestName))
	_ = data
	// The manifest struct/JSON must not carry secret material.
	blob := strings.ToLower(mustJSON(t, m))
	for _, bad := range []string{"password", "passphrase", "token", "private key", "secret_key"} {
		if strings.Contains(blob, bad) {
			t.Fatalf("manifest must not contain %q", bad)
		}
	}
}

// --------------------------------------------------------------------------- #
// Restore validation + recovery sheet
// --------------------------------------------------------------------------- #

func TestValidateRestoreSchemaAndOwnership(t *testing.T) {
	m := &Manifest{SchemaVersion: "v1", OrgID: "org-1"}
	if RestoreBlocked(ValidateRestore(m, "v1", "org-1")) {
		t.Fatal("matching schema+org should not block")
	}
	if !RestoreBlocked(ValidateRestore(m, "v2", "org-1")) {
		t.Fatal("schema mismatch must block")
	}
	if !RestoreBlocked(ValidateRestore(m, "v1", "org-2")) {
		t.Fatal("org mismatch must block")
	}
}

func TestRecoverySheetNoSecrets(t *testing.T) {
	m := &Manifest{
		OrgSlug: "default", OrgID: "org-1", AppVersion: "0.1.0",
		Encrypted: true, Encryption: &Encryption{Algo: EncAlgo, KDF: KDF},
		Contents: []string{ClassDatabase, ClassCA},
	}
	sheet := RecoverySheet(m, "/backups/vulna-backup.tar.gz.enc")
	if !strings.Contains(sheet, "CANNOT be") {
		t.Fatal("recovery sheet must state what cannot be recovered")
	}
	for _, bad := range []string{"BEGIN", "password=", "passphrase=", "token"} {
		if strings.Contains(sheet, bad) {
			t.Fatalf("recovery sheet must not contain %q", bad)
		}
	}
}

func mustJSON(t *testing.T, m Manifest) string {
	t.Helper()
	dir := t.TempDir()
	if err := WriteManifest(dir, m); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(dir, ManifestName))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

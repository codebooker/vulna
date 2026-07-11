package backup

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// CurrentBackupVersion is the manifest schema version this CLI writes/reads.
const CurrentBackupVersion = 1

// ManifestName is the manifest file inside a backup bundle directory.
const ManifestName = "manifest.json"

// Content classes a backup may include.
const (
	ClassDatabase   = "database"    // PostgreSQL dump
	ClassConfig     = "config"      // generated configuration
	ClassCA         = "ca"          // certificate authority + required key material
	ClassScoutState = "scout_state" // Scout identity metadata
	ClassReports    = "reports"
	ClassEvidence   = "evidence"
	ClassBranding   = "branding"
	ClassPresets    = "presets"
)

// RequiredClasses must be present for a bundle to be usable for a restore. The
// CA is required so that losing the host does not force re-enrolling every Scout.
var RequiredClasses = []string{ClassDatabase, ClassConfig, ClassCA}

// Encryption records the (non-secret) scheme used. It never contains a key.
type Encryption struct {
	Algo       string `json:"algo"`
	KDF        string `json:"kdf"`
	Iterations int    `json:"iterations"`
}

// Manifest is the versioned, non-secret description of a backup bundle. It must
// never contain passwords, tokens, private-key content, or evidence plaintext.
type Manifest struct {
	BackupVersion int         `json:"backup_version"`
	CreatedAt     string      `json:"created_at"`
	AppVersion    string      `json:"app_version"`
	SchemaVersion string      `json:"schema_version"`
	OrgID         string      `json:"org_id,omitempty"`
	OrgSlug       string      `json:"org_slug,omitempty"`
	Archive       string      `json:"archive"`
	ArchiveSHA256 string      `json:"archive_sha256"` // of the *plaintext* archive
	Encrypted     bool        `json:"encrypted"`
	Encryption    *Encryption `json:"encryption,omitempty"`
	Contents      []string    `json:"contents"`
	SizeBytes     int64       `json:"size_bytes"`
}

// WriteManifest writes the manifest into a bundle directory (0644; no secrets).
func WriteManifest(dir string, m Manifest) error {
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, ManifestName), append(data, '\n'), 0o644)
}

// ReadManifest reads and parses a bundle's manifest.
func ReadManifest(dir string) (*Manifest, error) {
	data, err := os.ReadFile(filepath.Join(dir, ManifestName))
	if err != nil {
		return nil, fmt.Errorf("read manifest: %w", err)
	}
	var m Manifest
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("parse manifest: %w", err)
	}
	if m.BackupVersion == 0 {
		return nil, fmt.Errorf("manifest is missing backup_version")
	}
	return &m, nil
}

// Check is one verification result.
type Check struct {
	Name   string
	OK     bool
	Detail string
}

// Report is the outcome of verifying a bundle. Usable is true only when every
// check passes — a bundle missing required files or failing a checksum is marked
// unusable *before* any destructive restore step touches it.
type Report struct {
	Usable   bool
	Checks   []Check
	Manifest *Manifest
}

func has(list []string, want string) bool {
	for _, v := range list {
		if v == want {
			return true
		}
	}
	return false
}

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// VerifyBundle validates a bundle directory. For an encrypted bundle a passphrase
// is required to decrypt and verify the archive checksum.
func VerifyBundle(dir string, passphrase []byte) Report {
	r := Report{Usable: true}
	fail := func(name, detail string) {
		r.Checks = append(r.Checks, Check{name, false, detail})
		r.Usable = false
	}
	pass := func(name, detail string) { r.Checks = append(r.Checks, Check{name, true, detail}) }

	m, err := ReadManifest(dir)
	if err != nil {
		fail("manifest", err.Error())
		return r
	}
	r.Manifest = m
	pass("manifest", fmt.Sprintf("backup v%d, app %s, schema %s", m.BackupVersion, m.AppVersion, m.SchemaVersion))

	for _, c := range RequiredClasses {
		if has(m.Contents, c) {
			pass("contents:"+c, "present")
		} else {
			fail("contents:"+c, "required content class is missing")
		}
	}

	archivePath := filepath.Join(dir, m.Archive)
	data, err := os.ReadFile(archivePath)
	if err != nil {
		fail("archive", "archive file is missing: "+m.Archive)
		return r
	}

	plaintext := data
	if m.Encrypted {
		if len(passphrase) == 0 {
			fail("decrypt", "bundle is encrypted; a recovery passphrase is required to verify it")
			return r
		}
		plaintext, err = Decrypt(data, passphrase)
		if err != nil {
			fail("decrypt", err.Error())
			return r
		}
		pass("decrypt", "decrypted with the provided passphrase")
	}

	if got := sha256Hex(plaintext); got == m.ArchiveSHA256 {
		pass("checksum", "archive checksum matches the manifest")
	} else {
		fail("checksum", "archive checksum does NOT match the manifest")
		return r
	}

	// The manifest's declared Contents come from a CLI flag; confirm the archive
	// actually carries those payloads so an empty or truncated archive can never
	// be certified usable.
	verifyArchiveContents(m, plaintext, pass, fail)
	return r
}

// ValidateRestore checks a verified manifest is safe to restore onto a host with
// the given current schema version and organization. Blocking problems (schema
// mismatch, org mismatch) are returned as failing checks.
func ValidateRestore(m *Manifest, currentSchema, currentOrgID string) []Check {
	var checks []Check
	if currentSchema != "" && m.SchemaVersion != "" && m.SchemaVersion != currentSchema {
		checks = append(checks, Check{"schema", false,
			fmt.Sprintf("backup schema %s != current %s; restore the matching app version first",
				m.SchemaVersion, currentSchema)})
	} else {
		checks = append(checks, Check{"schema", true, "schema version compatible"})
	}
	if currentOrgID != "" && m.OrgID != "" && m.OrgID != currentOrgID {
		checks = append(checks, Check{"ownership", false,
			"backup belongs to a different organization than this host"})
	} else {
		checks = append(checks, Check{"ownership", true, "organization ownership consistent"})
	}
	return checks
}

// RestoreBlocked reports whether any restore-validation check failed.
func RestoreBlocked(checks []Check) bool {
	for _, c := range checks {
		if !c.OK {
			return true
		}
	}
	return false
}

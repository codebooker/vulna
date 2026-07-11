package backup

import (
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// SHA256Hex returns the hex SHA-256 of bytes.
func SHA256Hex(b []byte) string { return sha256Hex(b) }

// HasExistingDeployment reports whether a deployment already exists in dir, so a
// restore can refuse to overwrite it without explicit confirmation.
func HasExistingDeployment(dir string) bool {
	for _, f := range []string{".env", "docker-compose.single-host.yml", ".vulna-install.json"} {
		if _, err := os.Stat(filepath.Join(dir, f)); err == nil {
			return true
		}
	}
	return false
}

// FileSHA256 returns the hex SHA-256 and size of a file.
func FileSHA256(path string) (string, int64, error) {
	f, err := os.Open(path) //nolint:gosec // operator-provided path
	if err != nil {
		return "", 0, err
	}
	defer func() { _ = f.Close() }()
	h := sha256.New()
	n, err := io.Copy(h, f)
	if err != nil {
		return "", 0, err
	}
	return fmt.Sprintf("%x", h.Sum(nil)), n, nil
}

// RecoverySheet renders a printable recovery sheet. It contains ONLY non-secret
// identifiers, the backup location, key-custody instructions, restore commands,
// and a clear statement of what cannot be recovered if the key is lost. It never
// includes passphrases, tokens, or key material.
func RecoverySheet(m *Manifest, backupLocation string) string {
	var b strings.Builder
	b.WriteString("VULNA RECOVERY SHEET\n")
	b.WriteString("====================\n\n")
	b.WriteString("Keep this with your backups. It contains NO secrets.\n\n")

	fmt.Fprintf(&b, "Organization:    %s (%s)\n", orEmpty(m.OrgSlug), orEmpty(m.OrgID))
	fmt.Fprintf(&b, "App version:     %s\n", orEmpty(m.AppVersion))
	fmt.Fprintf(&b, "Schema version:  %s\n", orEmpty(m.SchemaVersion))
	fmt.Fprintf(&b, "Backup created:  %s\n", orEmpty(m.CreatedAt))
	fmt.Fprintf(&b, "Backup location: %s\n", backupLocation)
	fmt.Fprintf(&b, "Contents:        %s\n", strings.Join(m.Contents, ", "))
	if m.Encrypted {
		fmt.Fprintf(&b, "Encryption:      %s (%s)\n", m.Encryption.Algo, m.Encryption.KDF)
		b.WriteString("\nKEY CUSTODY (required to restore):\n")
		b.WriteString("  This backup is encrypted with your recovery passphrase.\n")
		b.WriteString("  Store that passphrase somewhere separate from the backup (a password\n")
		b.WriteString("  manager or a sealed envelope). Vulna does not keep a copy.\n")
	} else {
		b.WriteString("Encryption:      none\n")
	}

	b.WriteString("\nRESTORE:\n")
	fmt.Fprintf(&b, "  vulna backup verify  %s\n", backupLocation)
	fmt.Fprintf(&b, "  vulna backup restore %s   # verifies first; confirms before overwrite\n", backupLocation)

	b.WriteString("\nWHAT CANNOT BE RECOVERED:\n")
	b.WriteString("  - If you lose the recovery passphrase, an encrypted backup CANNOT be\n")
	b.WriteString("    decrypted or restored. There is no recovery path or backdoor.\n")
	b.WriteString("  - If the internal CA key was lost AND not in a backup, existing Scouts\n")
	b.WriteString("    must be re-enrolled (their certificates can no longer be validated).\n")
	return b.String()
}

func orEmpty(s string) string {
	if s == "" {
		return "(unknown)"
	}
	return s
}

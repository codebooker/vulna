package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/codebooker/vulna/cli/internal/backup"
	"github.com/codebooker/vulna/cli/internal/buildinfo"
)

func cmdBackup(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "usage: vulna backup <create|list|verify|restore|prune|recovery-sheet>")
		return 2
	}
	switch args[0] {
	case "create":
		return cmdBackupCreate(args[1:], stdout, stderr)
	case "list":
		return cmdBackupList(args[1:], stdout, stderr)
	case "verify":
		return cmdBackupVerify(args[1:], stdout, stderr)
	case "restore":
		return cmdBackupRestore(args[1:], stdout, stderr)
	case "prune":
		return cmdBackupPrune(args[1:], stdout, stderr)
	case "recovery-sheet":
		return cmdBackupRecoverySheet(args[1:], stdout, stderr)
	default:
		fmt.Fprintf(stderr, "unknown backup subcommand: %q\n", args[0])
		return 2
	}
}

// requirePositionalBundle returns the single bundle path, rejecting the case where
// flags were placed AFTER it (Go's flag package stops parsing at the first
// positional, which would silently skip a validation flag).
func requirePositionalBundle(fs *flag.FlagSet, stderr io.Writer) (string, bool) {
	if fs.NArg() < 1 {
		fmt.Fprintln(stderr, "error: a backup bundle path is required")
		return "", false
	}
	for _, extra := range fs.Args()[1:] {
		if strings.HasPrefix(extra, "-") {
			fmt.Fprintln(stderr, "error: put flags BEFORE the bundle path "+
				"(e.g. `vulna backup verify --passphrase-env VAR <bundle>`)")
			return "", false
		}
	}
	return fs.Arg(0), true
}

// passphraseFrom reads the recovery passphrase from an environment variable so it
// never appears in argv or process listings.
func passphraseFrom(envName string) []byte {
	if envName == "" {
		return nil
	}
	return []byte(os.Getenv(envName))
}

func cmdBackupCreate(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("backup create", flag.ContinueOnError)
	fs.SetOutput(stderr)
	archive := fs.String("archive", "", "path to a tar.gz produced by deploy/backup/backup.sh")
	out := fs.String("out", "backups", "directory to write the backup bundle into")
	encrypt := fs.Bool("encrypt", false, "encrypt the bundle (requires --passphrase-env)")
	passEnv := fs.String("passphrase-env", "VULNA_BACKUP_PASSPHRASE", "env var holding the recovery passphrase")
	schema := fs.String("schema-version", "", "current database schema (alembic head)")
	orgID := fs.String("org-id", "", "organization id (ownership metadata)")
	orgSlug := fs.String("org-slug", "", "organization slug")
	contents := fs.String("contents", "database,config,ca,scout_state,reports,evidence", "content classes included")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *archive == "" {
		fmt.Fprintln(stderr, "backup create: --archive is required (run deploy/backup/backup.sh first)")
		return 2
	}
	data, err := os.ReadFile(*archive) //nolint:gosec // operator-provided path
	if err != nil {
		fmt.Fprintln(stderr, "backup create:", err)
		return 1
	}
	sum := backup.SHA256Hex(data)

	stamp := time.Now().UTC().Format("20060102T150405Z")
	bundle := filepath.Join(*out, "vulna-backup-"+stamp)
	if err := os.MkdirAll(bundle, 0o700); err != nil {
		fmt.Fprintln(stderr, "backup create:", err)
		return 1
	}

	// Describe what the archive REALLY holds (derived), not what a flag claims —
	// so the manifest can never over-claim a content class. --contents is kept as
	// an intent hint but the archive is authoritative.
	classes, err := backup.ClassesInArchive(data)
	if err != nil {
		fmt.Fprintln(stderr, "backup create: archive is not a valid tar.gz:", err)
		return 1
	}
	_ = contents // superseded by derived classes; flag retained for compatibility
	m := backup.Manifest{
		BackupVersion: backup.CurrentBackupVersion,
		CreatedAt:     time.Now().UTC().Format(time.RFC3339),
		AppVersion:    buildinfo.Version,
		SchemaVersion: *schema,
		OrgID:         *orgID,
		OrgSlug:       *orgSlug,
		ArchiveSHA256: sum,
		Contents:      classes,
		SizeBytes:     int64(len(data)),
	}

	name := "vulna-backup.tar.gz"
	stored := data
	if *encrypt {
		pass := passphraseFrom(*passEnv)
		if len(pass) == 0 {
			fmt.Fprintf(stderr, "backup create: --encrypt requires a passphrase in $%s\n", *passEnv)
			return 2
		}
		stored, err = backup.Encrypt(data, pass)
		if err != nil {
			fmt.Fprintln(stderr, "backup create:", err)
			return 1
		}
		name = "vulna-backup.tar.gz.enc"
		m.Encrypted = true
		m.Encryption = &backup.Encryption{Algo: backup.EncAlgo, KDF: backup.KDF, Iterations: backup.Iterations}
	}
	m.Archive = name

	if err := os.WriteFile(filepath.Join(bundle, name), stored, 0o600); err != nil {
		fmt.Fprintln(stderr, "backup create:", err)
		return 1
	}
	if err := backup.WriteManifest(bundle, m); err != nil {
		fmt.Fprintln(stderr, "backup create:", err)
		return 1
	}
	sheet := backup.RecoverySheet(&m, bundle)
	_ = os.WriteFile(filepath.Join(bundle, "RECOVERY-SHEET.txt"), []byte(sheet), 0o644)

	// Verify what we just wrote so a broken bundle never looks successful.
	if rep := backup.VerifyBundle(bundle, passphraseFrom(*passEnv)); !rep.Usable {
		fmt.Fprintln(stderr, "backup create: the new bundle failed self-verification")
		return 1
	}
	fmt.Fprintf(stdout, "backup written and verified: %s\n", bundle)
	fmt.Fprintf(stdout, "recovery sheet:             %s\n", filepath.Join(bundle, "RECOVERY-SHEET.txt"))
	if m.Encrypted {
		fmt.Fprintln(stdout, "This bundle is ENCRYPTED. Keep the recovery passphrase safe — it is required to restore.")
	}
	return 0
}

func cmdBackupList(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("backup list", flag.ContinueOnError)
	fs.SetOutput(stderr)
	out := fs.String("out", "backups", "directory holding backup bundles")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	entries, err := os.ReadDir(*out)
	if err != nil {
		fmt.Fprintln(stderr, "backup list:", err)
		return 1
	}
	found := 0
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		m, err := backup.ReadManifest(filepath.Join(*out, e.Name()))
		if err != nil {
			continue
		}
		found++
		enc := "plain"
		if m.Encrypted {
			enc = "encrypted"
		}
		fmt.Fprintf(stdout, "%-32s %s  app %s  schema %s  %s  %d bytes\n",
			e.Name(), m.CreatedAt, m.AppVersion, orDashB(m.SchemaVersion), enc, m.SizeBytes)
	}
	if found == 0 {
		fmt.Fprintln(stdout, "No backups found in "+*out+".")
	}
	return 0
}

func cmdBackupVerify(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("backup verify", flag.ContinueOnError)
	fs.SetOutput(stderr)
	passEnv := fs.String("passphrase-env", "VULNA_BACKUP_PASSPHRASE", "env var holding the recovery passphrase")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	bundleDir, ok := requirePositionalBundle(fs, stderr)
	if !ok {
		return 2
	}
	rep := backup.VerifyBundle(bundleDir, passphraseFrom(*passEnv))
	for _, c := range rep.Checks {
		mark := "ok  "
		if !c.OK {
			mark = "FAIL"
		}
		fmt.Fprintf(stdout, "  [%s] %-16s %s\n", mark, c.Name, c.Detail)
	}
	if rep.Usable {
		fmt.Fprintln(stdout, "backup: USABLE")
		return 0
	}
	fmt.Fprintln(stdout, "backup: UNUSABLE — do not restore this bundle")
	return 1
}

func cmdBackupRestore(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("backup restore", flag.ContinueOnError)
	fs.SetOutput(stderr)
	passEnv := fs.String("passphrase-env", "VULNA_BACKUP_PASSPHRASE", "env var holding the recovery passphrase")
	dir := fs.String("dir", ".", "deployment directory")
	schema := fs.String("schema-version", "", "current schema for compatibility check")
	orgID := fs.String("org-id", "", "current org id for ownership check")
	confirm := fs.Bool("confirm", false, "confirm overwriting an existing deployment")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	bundle, ok := requirePositionalBundle(fs, stderr)
	if !ok {
		return 2
	}

	// 1. Verify integrity BEFORE any destructive step.
	rep := backup.VerifyBundle(bundle, passphraseFrom(*passEnv))
	if !rep.Usable {
		fmt.Fprintln(stderr, "restore: backup is UNUSABLE (failed verification); refusing to restore.")
		for _, c := range rep.Checks {
			if !c.OK {
				fmt.Fprintf(stderr, "  - %s: %s\n", c.Name, c.Detail)
			}
		}
		return 1
	}

	// 2. Validate compatibility + ownership.
	vchecks := backup.ValidateRestore(rep.Manifest, *schema, *orgID)
	if backup.RestoreBlocked(vchecks) {
		fmt.Fprintln(stderr, "restore: blocked by validation:")
		for _, c := range vchecks {
			if !c.OK {
				fmt.Fprintf(stderr, "  - %s: %s\n", c.Name, c.Detail)
			}
		}
		return 1
	}

	// 3. Never overwrite an existing deployment without explicit confirmation and
	//    a safety backup.
	existing := backup.HasExistingDeployment(*dir)
	if existing && !*confirm {
		fmt.Fprintln(stderr, "restore: an existing deployment is present. Re-run with --confirm to overwrite it.")
		fmt.Fprintln(stderr, "         A safety backup of the current state will be taken first.")
		return 1
	}

	// The restore script does the destructive DB + data work; locate it before
	// touching anything so a missing script fails early, not half-way through.
	restoreScript, ok := resolveBackupScript(*dir, "restore.sh")
	if !ok {
		fmt.Fprintln(stderr, "restore: deploy/backup/restore.sh not found in this deployment; cannot apply the backup.")
		return 1
	}

	// 4. Take a safety backup of the current deployment first. If it fails we
	//    abort before any destructive step rather than leave the host unprotected.
	if existing {
		fmt.Fprintln(stdout, "Taking a safety backup of the current deployment before restoring ...")
		if _, err := runBackup(*dir, stdout, stderr); err != nil {
			fmt.Fprintln(stderr, "restore: safety backup failed; aborting before any destructive step:", err)
			return 1
		}
	}

	// 5. Decrypt (if needed) and stage the plaintext archive with a checksum
	//    sidecar so restore.sh re-verifies integrity before it applies anything.
	archivePath := filepath.Join(bundle, rep.Manifest.Archive)
	data, err := os.ReadFile(archivePath) //nolint:gosec // path from a verified bundle
	if err != nil {
		fmt.Fprintln(stderr, "restore:", err)
		return 1
	}
	plaintext := data
	if rep.Manifest.Encrypted {
		plaintext, err = backup.Decrypt(data, passphraseFrom(*passEnv))
		if err != nil {
			fmt.Fprintln(stderr, "restore: could not decrypt the bundle:", err)
			return 1
		}
	}
	stage, err := os.MkdirTemp("", "vulna-restore-")
	if err != nil {
		fmt.Fprintln(stderr, "restore:", err)
		return 1
	}
	defer os.RemoveAll(stage)
	tarPath := filepath.Join(stage, "vulna-backup.tar.gz")
	if err := os.WriteFile(tarPath, plaintext, 0o600); err != nil {
		fmt.Fprintln(stderr, "restore:", err)
		return 1
	}
	sidecar := fmt.Sprintf("%s  vulna-backup.tar.gz\n", backup.SHA256Hex(plaintext))
	if err := os.WriteFile(tarPath+".sha256", []byte(sidecar), 0o600); err != nil {
		fmt.Fprintln(stderr, "restore:", err)
		return 1
	}

	// 6. Apply. restore.sh verifies the checksum, extracts, restores data + DB.
	fmt.Fprintf(stdout, "Restoring %s (app %s, schema %s) ...\n",
		bundle, rep.Manifest.AppVersion, orDashB(rep.Manifest.SchemaVersion))
	cmd := exec.Command("bash", restoreScript, tarPath) //nolint:gosec // fixed in-repo script
	cmd.Stdout, cmd.Stderr = stdout, stderr
	if err := cmd.Run(); err != nil {
		fmt.Fprintln(stderr, "restore: restore.sh failed:", err)
		return 1
	}
	fmt.Fprintln(stdout, "Restore complete. Re-check URL/TLS and Scout settings in the Networking assistant.")
	return 0
}

// resolveBackupScript finds a deploy/backup script either under the deployment
// directory or relative to the current working directory.
func resolveBackupScript(dir, name string) (string, bool) {
	for _, cand := range []string{
		filepath.Join(dir, "deploy", "backup", name),
		filepath.Join("deploy", "backup", name),
	} {
		if _, err := os.Stat(cand); err == nil {
			return cand, true
		}
	}
	return "", false
}

func cmdBackupPrune(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("backup prune", flag.ContinueOnError)
	fs.SetOutput(stderr)
	out := fs.String("out", "backups", "directory holding backup bundles")
	keep := fs.Int("keep", 7, "number of most-recent backups to keep")
	dryRun := fs.Bool("dry-run", false, "list what would be pruned without deleting")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	entries, err := os.ReadDir(*out)
	if err != nil {
		fmt.Fprintln(stderr, "backup prune:", err)
		return 1
	}
	var bundles []string
	for _, e := range entries {
		if e.IsDir() {
			if _, err := backup.ReadManifest(filepath.Join(*out, e.Name())); err == nil {
				bundles = append(bundles, e.Name())
			}
		}
	}
	sort.Sort(sort.Reverse(sort.StringSlice(bundles))) // names are timestamped -> newest first
	if len(bundles) <= *keep {
		fmt.Fprintf(stdout, "Nothing to prune (%d backups, keeping %d).\n", len(bundles), *keep)
		return 0
	}
	for _, name := range bundles[*keep:] {
		path := filepath.Join(*out, name)
		if *dryRun {
			fmt.Fprintf(stdout, "would prune %s\n", path)
			continue
		}
		if err := os.RemoveAll(path); err != nil {
			fmt.Fprintln(stderr, "backup prune:", err)
			return 1
		}
		fmt.Fprintf(stdout, "pruned %s\n", path)
	}
	return 0
}

func cmdBackupRecoverySheet(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("backup recovery-sheet", flag.ContinueOnError)
	fs.SetOutput(stderr)
	if err := fs.Parse(args); err != nil {
		return 2
	}
	bundle, ok := requirePositionalBundle(fs, stderr)
	if !ok {
		return 2
	}
	m, err := backup.ReadManifest(bundle)
	if err != nil {
		fmt.Fprintln(stderr, "recovery-sheet:", err)
		return 1
	}
	fmt.Fprint(stdout, backup.RecoverySheet(m, bundle))
	return 0
}

// --- helpers ---

func splitCSV(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func orDashB(s string) string {
	if s == "" {
		return "—"
	}
	return s
}

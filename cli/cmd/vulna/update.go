package main

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"time"

	"github.com/codebooker/vulna/cli/internal/buildinfo"
	"github.com/codebooker/vulna/cli/internal/release"
	"github.com/codebooker/vulna/cli/internal/update"
)

// cmdUpdate dispatches `update [check|status]` (bare = apply).
func cmdUpdate(args []string, stdout, stderr io.Writer) int {
	if len(args) > 0 {
		switch args[0] {
		case "check":
			return cmdUpdateCheck(args[1:], stdout, stderr)
		case "status":
			return cmdUpdateStatus(args[1:], stdout, stderr)
		}
	}
	return cmdUpdateApply(args, stdout, stderr)
}

func loadReleasePubKey(path string) (ed25519.PublicKey, error) {
	if path == "" {
		return nil, fmt.Errorf("no pinned release public key. Set --pubkey to the Ed25519 " +
			"public key PEM (official releases embed it)")
	}
	data, err := os.ReadFile(path) //nolint:gosec // operator-provided key path
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("release public key is not valid PEM")
	}
	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	pub, ok := key.(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("release public key is not an Ed25519 key")
	}
	return pub, nil
}

func fetch(url string) ([]byte, error) {
	client := &http.Client{Timeout: 20 * time.Second}
	resp, err := client.Get(url) //nolint:gosec // operator-configured release URL
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s: status %d", url, resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 4<<20))
}

// fetchAndVerify downloads and verifies a channel's signed manifest.
func fetchAndVerify(baseURL, channel, pubkeyPath string) (*release.Manifest, error) {
	pub, err := loadReleasePubKey(pubkeyPath)
	if err != nil {
		return nil, err
	}
	base := fmt.Sprintf("%s/%s", baseURL, channel)
	manifest, err := fetch(base + "/" + release.ManifestFileName)
	if err != nil {
		return nil, fmt.Errorf("download manifest: %w", err)
	}
	sums, err := fetch(base + "/SHA256SUMS")
	if err != nil {
		return nil, fmt.Errorf("download SHA256SUMS: %w", err)
	}
	sig, err := fetch(base + "/SHA256SUMS.sig")
	if err != nil {
		return nil, fmt.Errorf("download signature: %w", err)
	}
	m, err := release.Verify(pub, manifest, sums, sig)
	if err != nil {
		return nil, err
	}
	if err := m.Validate(channel, buildinfo.Version, time.Now()); err != nil {
		return nil, err
	}
	return m, nil
}

func printManifest(w io.Writer, m *release.Manifest) {
	fmt.Fprintf(w, "  version:       %s (channel %s)\n", m.Version, m.Channel)
	fmt.Fprintf(w, "  security:      %s\n", m.Security)
	if m.MinScoutVersion != "" {
		fmt.Fprintf(w, "  min Scout:     %s\n", m.MinScoutVersion)
	}
	if m.Migration.HasMigrations {
		fmt.Fprintf(w, "  database:      schema migration (%s)\n", m.Migration.Notes)
	} else {
		fmt.Fprintln(w, "  database:      no schema migration")
	}
	if m.ScannerChanges != "" {
		fmt.Fprintf(w, "  scanners:      %s\n", m.ScannerChanges)
	}
	if m.TemplateChanges != "" {
		fmt.Fprintf(w, "  templates:     %s\n", m.TemplateChanges)
	}
	if m.Compatibility != "" {
		fmt.Fprintf(w, "  compatibility: %s\n", m.Compatibility)
	}
	if m.Notes != "" {
		fmt.Fprintf(w, "  notes:         %s\n", m.Notes)
	}
}

func cmdUpdateCheck(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("update check", flag.ContinueOnError)
	fs.SetOutput(stderr)
	channel := fs.String("channel", release.ChannelStable, "release channel: stable|candidate|development")
	dir := fs.String("dir", ".", "deployment directory (for the update state)")
	baseURL := fs.String("base-url", "https://github.com/codebooker/vulna/releases/latest/download", "release base URL")
	pubkey := fs.String("pubkey", "", "Ed25519 release public key PEM")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	m, err := fetchAndVerify(*baseURL, *channel, *pubkey)
	if err != nil {
		fmt.Fprintln(stderr, "update check:", err)
		return 1
	}
	fmt.Fprintf(stdout, "Current version: %s\n", buildinfo.Version)
	if m.IsNewerThan(buildinfo.Version) {
		fmt.Fprintln(stdout, "A newer release is available:")
	} else {
		fmt.Fprintln(stdout, "You are up to date. Latest on this channel:")
	}
	printManifest(stdout, m)

	// Record what we last saw so the web update center can display it.
	st, _ := update.LoadState(*dir)
	st.Channel = *channel
	st.LastAvailable = m.Version
	st.LastAvailableSec = m.Security
	st.LastCheckedAt = time.Now().Format(time.RFC3339)
	_ = update.SaveState(*dir, st)
	return 0
}

func cmdUpdateStatus(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("update status", flag.ContinueOnError)
	fs.SetOutput(stderr)
	dir := fs.String("dir", ".", "deployment directory")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	st, err := update.LoadState(*dir)
	if err != nil {
		fmt.Fprintln(stderr, "update status:", err)
		return 1
	}
	fmt.Fprintf(stdout, "current version:   %s\n", buildinfo.Version)
	fmt.Fprintf(stdout, "channel:           %s\n", orDash(st.Channel))
	fmt.Fprintf(stdout, "last available:    %s\n", orDash(st.LastAvailable))
	fmt.Fprintf(stdout, "last checked:      %s\n", orDash(st.LastCheckedAt))
	fmt.Fprintf(stdout, "rollback to:       %s\n", orDash(st.PriorVersion))
	if st.RollbackBackup != "" {
		fmt.Fprintf(stdout, "rollback backup:   %s\n", st.RollbackBackup)
	}
	return 0
}

func cmdUpdateApply(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("update", flag.ContinueOnError)
	fs.SetOutput(stderr)
	channel := fs.String("channel", release.ChannelStable, "release channel")
	dir := fs.String("dir", ".", "deployment directory")
	baseURL := fs.String("base-url", "https://github.com/codebooker/vulna/releases/latest/download", "release base URL")
	pubkey := fs.String("pubkey", "", "Ed25519 release public key PEM")
	noBackup := fs.Bool("no-backup", false, "skip the automatic pre-update backup (use only with your own backup)")
	yes := fs.Bool("yes", false, "proceed past warnings without prompting")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	m, err := fetchAndVerify(*baseURL, *channel, *pubkey)
	if err != nil {
		fmt.Fprintln(stderr, "update:", err)
		return 1
	}
	if !m.IsNewerThan(buildinfo.Version) {
		fmt.Fprintf(stdout, "Already at %s (latest on %s). Nothing to do.\n", buildinfo.Version, *channel)
		return 0
	}
	fmt.Fprintf(stdout, "Update %s -> %s (%s):\n", buildinfo.Version, m.Version, *channel)
	printManifest(stdout, m)

	deps := update.Deps{
		MinFreeBytes:  2 << 30,
		DataDir:       *dir,
		FreeDisk:      freeDisk,
		BackupPresent: func() (bool, string) { return backupPresent(*dir) },
	}
	checks := update.Preflight(deps, m)
	fmt.Fprintln(stdout, "\nPre-update checks:")
	warned := false
	for _, c := range checks {
		fmt.Fprintf(stdout, "  [%-4s] %-12s %s\n", c.Status, c.Name, c.Detail)
		if c.Status == update.Fail && c.Remediation != "" {
			fmt.Fprintf(stdout, "         -> %s\n", c.Remediation)
		}
		if c.Status == update.Warn {
			warned = true
		}
	}
	if update.Blocking(checks) {
		fmt.Fprintln(stderr, "\nupdate: blocked by pre-update checks; resolve them and retry.")
		return 1
	}
	if warned && !*yes {
		fmt.Fprintln(stderr, "\nupdate: warnings present; re-run with --yes to proceed.")
		return 1
	}

	backupPath := ""
	if *noBackup {
		fmt.Fprintln(stdout, "\nSkipping automatic backup (--no-backup).")
	} else {
		backupPath, err = runBackup(*dir, stdout, stderr)
		if err != nil {
			fmt.Fprintln(stderr, "update: automatic backup failed; aborting:", err)
			return 1
		}
	}

	st, _ := update.LoadState(*dir)
	st.Channel = *channel
	st = update.RecordApplied(st, m.Version, backupPath, m.Migration.HasMigrations, time.Now())
	if err := update.SaveState(*dir, st); err != nil {
		fmt.Fprintln(stderr, "update: could not record state:", err)
		return 1
	}

	fmt.Fprintln(stdout, "\nApply the new version:")
	fmt.Fprintf(stdout, "  cd %s && docker compose -f docker-compose.yml -f docker-compose.single-host.yml pull\n", *dir)
	fmt.Fprintf(stdout, "  docker compose -f docker-compose.yml -f docker-compose.single-host.yml up -d --build\n")
	fmt.Fprintln(stdout, "Migrations run automatically on API start; watch health afterward.")
	fmt.Fprintln(stdout, "If the stack does not become healthy, run `vulna rollback` to restore the prior version.")
	return 0
}

func cmdRollback(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("rollback", flag.ContinueOnError)
	fs.SetOutput(stderr)
	dir := fs.String("dir", ".", "deployment directory")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	st, err := update.LoadState(*dir)
	if err != nil {
		fmt.Fprintln(stderr, "rollback:", err)
		return 1
	}
	version, backup, hadMigr, err := update.PrepareRollback(st)
	if err != nil {
		fmt.Fprintln(stderr, "rollback:", err)
		return 1
	}
	fmt.Fprintf(stdout, "Rolling back to %s.\n", version)
	if hadMigr {
		if backup == "" {
			fmt.Fprintln(stderr, "rollback: the update changed the database but no backup was recorded; "+
				"restore from your own backup before downgrading to avoid an incompatible schema.")
			return 1
		}
		fmt.Fprintf(stdout, "This release changed the database. Restore the pre-update backup first:\n")
		fmt.Fprintf(stdout, "  deploy/backup/restore.sh %s\n", backup)
	}
	fmt.Fprintf(stdout, "Then redeploy the prior version and bring the stack up:\n")
	fmt.Fprintf(stdout, "  cd %s && docker compose -f docker-compose.yml -f docker-compose.single-host.yml up -d\n", *dir)

	// Record the rollback: current becomes the prior version; clear the pointer.
	st.CurrentVersion = version
	st.PriorVersion = ""
	st.RollbackBackup = ""
	st.RollbackHadMigr = false
	_ = update.SaveState(*dir, st)
	return 0
}

// --- helpers ---

func orDash(s string) string {
	if s == "" {
		return "—"
	}
	return s
}

func freeDisk(path string) (uint64, error) {
	dir := path
	if _, err := os.Stat(dir); err != nil {
		dir = filepath.Dir(dir)
	}
	var st syscall.Statfs_t
	if err := syscall.Statfs(dir, &st); err != nil {
		return 0, err
	}
	return uint64(st.Bavail) * uint64(st.Bsize), nil
}

func backupPresent(dir string) (bool, string) {
	for _, d := range []string{filepath.Join(dir, "backups"), filepath.Join(dir, "data", "backups")} {
		entries, err := os.ReadDir(d)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if !e.IsDir() && filepath.Ext(e.Name()) == ".gz" {
				return true, "found backup " + e.Name()
			}
		}
	}
	return false, ""
}

func runBackup(dir string, stdout, stderr io.Writer) (string, error) {
	script := "deploy/backup/backup.sh"
	if _, err := os.Stat(script); err != nil {
		// Backup script not present in this deployment layout; warn but continue.
		fmt.Fprintln(stdout, "note: deploy/backup/backup.sh not found; skipping automatic backup.")
		return "", nil
	}
	out := filepath.Join(dir, "backups")
	_ = os.MkdirAll(out, 0o700)
	cmd := exec.Command("bash", script) //nolint:gosec // fixed in-repo script
	cmd.Env = append(os.Environ(), "VULNA_BACKUP_DIR="+out)
	cmd.Stdout, cmd.Stderr = stdout, stderr
	if err := cmd.Run(); err != nil {
		return "", err
	}
	fmt.Fprintf(stdout, "Pre-update backup written under %s\n", out)
	return out, nil
}

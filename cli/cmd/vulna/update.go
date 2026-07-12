package main

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/codebooker/vulna/cli/internal/buildinfo"
	"github.com/codebooker/vulna/cli/internal/deploy"
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

	// Apply the update by pulling the new images and restarting the stack. State
	// is only recorded AFTER this succeeds, so a failed or not-yet-run update is
	// never recorded as applied (which would leave a false rollback point).
	if err := deploy.SourceHasCompose(*dir); err != nil {
		fmt.Fprintln(stderr, "\nupdate: Compose files not found in", *dir, "-", err)
		fmt.Fprintln(stderr, "update: cannot apply automatically; not recording this version as applied.")
		return 1
	}
	// Remember the version currently pinned so a failed pull/up can revert it —
	// otherwise .env is left pointing at a release that never came up, and a later
	// restart would try (and fail, or half-activate) that partial version.
	priorEnv, _ := deploy.ReadEnv(filepath.Join(*dir, deploy.EnvFile))
	priorVersion := priorEnv["VULNA_VERSION"]

	// Pin the deployment to the new version BEFORE pulling, so `docker compose
	// pull` actually fetches that release's images (the api/frontend image tags
	// are ${VULNA_VERSION}).
	if err := deploy.SetEnvVersion(*dir, m.Version); err != nil {
		fmt.Fprintln(stderr, "update: could not set the target version:", err)
		return 1
	}
	revertVersion := func() {
		if priorVersion != "" {
			if err := deploy.SetEnvVersion(*dir, priorVersion); err != nil {
				fmt.Fprintln(stderr, "update: WARNING could not revert VULNA_VERSION to",
					priorVersion, "-", err)
			} else {
				fmt.Fprintln(stderr, "update: reverted the pinned version to", priorVersion)
			}
		}
	}
	// recoverPrior restores the previously running release after a failed apply. If
	// the failed update ran schema migrations, the database is now on the NEW schema,
	// so simply restarting the OLD app would pair it with an incompatible database —
	// we must restore the pre-update database too. The pre-update backup's own .env
	// re-pins the old version, so safeRestore brings the whole prior state back up.
	// recoverPrior returns an error if it could NOT restore the prior state, so the
	// caller reports the true outcome instead of always claiming "restored the prior
	// release."
	recoverPrior := func() error {
		if m.Migration.HasMigrations {
			if backupPath == "" {
				return fmt.Errorf("the update changed the schema but no pre-update backup " +
					"exists (--no-backup); cannot auto-restore the database — restore from your own backup")
			}
			fmt.Fprintln(stderr, "update: restoring the pre-update state (database + volumes + config) ...")
			if err := safeRestore(*dir, backupPath, stdout, stderr); err != nil {
				return fmt.Errorf("automatic recovery failed (restore manually from %s): %w", backupPath, err)
			}
			return nil
		}
		// No schema change: re-pin the old version and restart its containers.
		if priorVersion == "" {
			return fmt.Errorf("no prior version recorded to restore")
		}
		revertVersion()
		fmt.Fprintf(stderr, "update: restoring the previous release (%s) ...\n", priorVersion)
		if err := deploy.Pull(*dir, stdout, stderr); err != nil {
			return fmt.Errorf("could not pull the previous images: %w", err)
		}
		if err := deploy.Up(*dir, stdout, stderr); err != nil {
			return fmt.Errorf("could not restart the previous release: %w", err)
		}
		return nil
	}
	// reportRecovery prints the honest outcome of a recovery attempt.
	reportRecovery := func(cause string, recErr error) int {
		if recErr != nil {
			fmt.Fprintf(stderr, "update: %s, AND recovery FAILED: %v\n", cause, recErr)
			fmt.Fprintln(stderr, "update: the deployment may be in a broken state — intervene manually.")
		} else {
			fmt.Fprintf(stderr, "update: %s; restored the prior release.\n", cause)
		}
		return 1
	}
	fmt.Fprintf(stdout, "\nPulling images for %s ...\n", m.Version)
	if err := deploy.Pull(*dir, stdout, stderr); err != nil {
		// Nothing started yet — only the pinned version changed; just revert it.
		revertVersion()
		fmt.Fprintln(stderr, "update: image pull failed; nothing was changed:", err)
		return 1
	}
	fmt.Fprintln(stdout, "Restarting the stack ...")
	if err := deploy.Up(*dir, stdout, stderr); err != nil {
		return reportRecovery(fmt.Sprintf("bringing the stack up failed: %v", err), recoverPrior())
	}
	// `up -d` only means Compose accepted the request — containers may still be
	// starting and their health checks can fail later. Confirm the stack is actually
	// healthy BEFORE recording the update as applied.
	fmt.Fprintln(stdout, "Waiting for containers to become healthy ...")
	if err := deploy.WaitHealthy(*dir, 3*time.Minute, stdout); err != nil {
		return reportRecovery(fmt.Sprintf("the new release did not become healthy: %v", err), recoverPrior())
	}

	st, _ := update.LoadState(*dir)
	st.Channel = *channel
	// On first update the state file has no current version yet; seed it with the
	// running version so the rollback point is real, not empty.
	if st.CurrentVersion == "" {
		st.CurrentVersion = buildinfo.Version
	}
	st = update.RecordApplied(st, m.Version, backupPath, m.Migration.HasMigrations, time.Now())
	if err := update.SaveState(*dir, st); err != nil {
		fmt.Fprintln(stderr, "update: applied, but could not record state:", err)
		return 1
	}

	fmt.Fprintf(stdout, "\nUpdated to %s. Migrations run automatically on API start; watch health afterward.\n", m.Version)
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
	version, backupPath, hadMigr, err := update.PrepareRollback(st)
	if err != nil {
		fmt.Fprintln(stderr, "rollback:", err)
		return 1
	}
	if err := deploy.SourceHasCompose(*dir); err != nil {
		fmt.Fprintln(stderr, "rollback: Compose files not found in", *dir, "-", err)
		return 1
	}
	fmt.Fprintf(stdout, "Rolling back to %s.\n", version)

	// Resolve the pre-update backup up front (before touching anything) when the
	// update changed the schema, so a missing backup aborts early.
	archive := ""
	if hadMigr {
		if backupPath == "" {
			fmt.Fprintln(stderr, "rollback: the update changed the database but no backup was recorded; "+
				"restore from your own backup before downgrading to avoid an incompatible schema.")
			return 1
		}
		a, ok := newestArchive(backupPath)
		if !ok {
			fmt.Fprintln(stderr, "rollback: could not find the pre-update backup archive under", backupPath)
			return 1
		}
		archive = a
	}

	// Confirm the OLD images are actually available BEFORE any destructive step, so a
	// failed pull can't strand a half-rolled-back stack. Capture the currently-pinned
	// version so a pull failure leaves the running stack untouched.
	nowEnv, _ := deploy.ReadEnv(filepath.Join(*dir, deploy.EnvFile))
	runningVersion := nowEnv["VULNA_VERSION"]
	if err := deploy.SetEnvVersion(*dir, version); err != nil {
		fmt.Fprintln(stderr, "rollback: could not set the prior version:", err)
		return 1
	}
	fmt.Fprintf(stdout, "Pulling images for %s ...\n", version)
	if err := deploy.Pull(*dir, stdout, stderr); err != nil {
		if runningVersion != "" {
			_ = deploy.SetEnvVersion(*dir, runningVersion) // leave the running stack as-is
		}
		fmt.Fprintln(stderr, "rollback: old images are not available; nothing was changed:", err)
		return 1
	}

	if hadMigr {
		// Old images confirmed. Restore the complete pre-update state — safeRestore
		// verifies the archive checksum, stops all writers, restores the DB + volumes
		// into an isolated postgres, restores the pre-update .env, and restarts. Since
		// that .env re-pins the OLD version, this brings back the prior release wholesale.
		if deploy.HasPostgresService(*dir) {
			if err := safeRestore(*dir, archive, stdout, stderr); err != nil {
				fmt.Fprintln(stderr, "rollback: restore failed; leaving the rollback point intact:", err)
				return 1
			}
			// Re-pin the prior version in case the backup's .env differed.
			_ = deploy.SetEnvVersion(*dir, version)
			if err := deploy.Up(*dir, stdout, stderr); err != nil {
				fmt.Fprintln(stderr, "rollback: bringing the stack up failed:", err)
				return 1
			}
		} else {
			// Host/dev deployment.
			script, ok := resolveBackupScript(*dir, "restore.sh")
			if !ok {
				fmt.Fprintln(stderr, "rollback: deploy/backup/restore.sh not found; cannot restore the database automatically.")
				return 1
			}
			cmd := exec.Command("bash", script, archive) //nolint:gosec // fixed in-repo script
			cmd.Stdout, cmd.Stderr = stdout, stderr
			if err := cmd.Run(); err != nil {
				fmt.Fprintln(stderr, "rollback: database restore failed; leaving the rollback point intact:", err)
				return 1
			}
			if err := deploy.Up(*dir, stdout, stderr); err != nil {
				fmt.Fprintln(stderr, "rollback: bringing the stack up failed:", err)
				return 1
			}
		}
	} else {
		// No schema change: just restart on the prior release's images.
		fmt.Fprintln(stdout, "Bringing the stack up on the prior release ...")
		if err := deploy.Up(*dir, stdout, stderr); err != nil {
			fmt.Fprintln(stderr, "rollback: bringing the stack up failed; leaving the rollback point intact:", err)
			return 1
		}
	}

	// Only now that the rollback actually happened: current becomes the prior
	// version and the (now consumed) rollback pointer is cleared.
	st.CurrentVersion = version
	st.PriorVersion = ""
	st.RollbackBackup = ""
	st.RollbackHadMigr = false
	if err := update.SaveState(*dir, st); err != nil {
		fmt.Fprintln(stderr, "rollback: rolled back, but could not record state:", err)
		return 1
	}
	fmt.Fprintf(stdout, "Rolled back to %s.\n", version)
	return 0
}

// newestArchive resolves a recorded backup location to a single archive file: if
// it is already a file it is returned as-is; if it is a directory the most recent
// *.tar.gz within it is chosen (backup filenames are timestamped).
func newestArchive(path string) (string, bool) {
	info, err := os.Stat(path)
	if err != nil {
		return "", false
	}
	if !info.IsDir() {
		return path, true
	}
	entries, err := os.ReadDir(path)
	if err != nil {
		return "", false
	}
	newest := ""
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".tar.gz") {
			continue
		}
		if e.Name() > newest {
			newest = e.Name()
		}
	}
	if newest == "" {
		return "", false
	}
	return filepath.Join(path, newest), true
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

func runBackup(dir string, stdout, stderr io.Writer) (archivePath string, err error) {
	// Locate the script under the deployment dir OR the cwd (same resolution as
	// restore). Fail closed if it is missing: a caller that promised a safety backup
	// (pre-update, pre-restore) must not silently proceed unprotected.
	script, ok := resolveBackupScript(dir, "backup.sh")
	if !ok {
		return "", fmt.Errorf("deploy/backup/backup.sh not found under %s or the current "+
			"directory; cannot take a safety backup (pass --no-backup to skip intentionally)", dir)
	}
	out := filepath.Join(dir, "backups")
	if err := os.MkdirAll(out, 0o700); err != nil {
		return "", err
	}
	// Pin an EXACT archive path so the caller can record and later restore precisely
	// this backup (not "whatever .tar.gz is newest at rollback time").
	archive := filepath.Join(out, "vulna-backup-"+time.Now().UTC().Format("20060102T150405Z")+".tar.gz")
	// Point the assembler at the deployment .env so the DB password + evidence master
	// key (which live in the install dir, NOT under VULNA_DATA) are captured.
	env := append(os.Environ(),
		"VULNA_ENV_FILE="+filepath.Join(dir, deploy.EnvFile),
		"VULNA_BACKUP_FILE="+archive,
	)

	// Compose deployment: PostgreSQL and the data volumes live inside containers, not
	// on the host. Dump the DB inside the postgres container and copy EACH persistent
	// volume out via a helper container (independent of the app containers), then hand
	// both to the assembler. Without this a real backup fails with "no database dump
	// source" and omits the Scout identity.
	//
	// If the stack is STOPPED but has data (e.g. a pre-restore safety backup on a
	// stopped host), bring ONLY postgres up so we can still dump it — otherwise the
	// documented stopped-host restore could never take its safety backup and abort.
	if deploy.HasPostgresService(dir) && deploy.PostgresDataExists(dir) {
		// Record postgres's ORIGINAL container state. `!PostgresReady()` is NOT the same
		// as "stopped" (a running-but-unhealthy container is also not ready), so decide
		// on the actual running state and, if we start it, put it back EXACTLY as we
		// found it on every exit path — never leave a postgres container we started
		// lingering when a later step (readiness, temp dir, snapshot, backup.sh) fails.
		if !deploy.PostgresRunning(dir) {
			fmt.Fprintln(stdout, "Starting postgres to take a backup ...")
			if upErr := deploy.UpServices(dir, stdout, stderr, "postgres"); upErr != nil {
				return "", fmt.Errorf("starting postgres for the backup: %w", upErr)
			}
			defer func() {
				if sErr := deploy.StopServices(dir, stdout, stderr, "postgres"); sErr != nil {
					err = errors.Join(err, fmt.Errorf(
						"stopping postgres (started only for the backup) failed — it may be left running: %w", sErr))
				}
			}()
		}
		if wErr := deploy.WaitPostgresReady(dir, 60*time.Second); wErr != nil {
			return "", wErr
		}
	}
	if deploy.HasPostgresService(dir) && deploy.PostgresReady(dir) {
		stage, mkErr := os.MkdirTemp("", "vulna-backup-stage-")
		if mkErr != nil {
			return "", mkErr
		}
		defer os.RemoveAll(stage)

		dumpEnv, snapErr := composeSnapshot(dir, stage, stdout, stderr)
		if snapErr != nil {
			return "", snapErr
		}
		env = append(env, dumpEnv...)
	}

	// backup.sh writes exactly VULNA_BACKUP_FILE (+ .sha256).
	cmd := exec.Command("bash", script) //nolint:gosec // fixed in-repo script
	cmd.Env = env
	cmd.Stdout, cmd.Stderr = stdout, stderr
	if err := cmd.Run(); err != nil {
		return "", err
	}
	fmt.Fprintf(stdout, "Pre-update backup written: %s\n", archive)
	return archive, nil
}

// composeSnapshot takes a point-in-time-consistent snapshot into stage: it quiesces
// the writers (stops non-postgres services, keeps postgres for the dump), dumps the
// database, and copies each data volume, then returns the VULNA_DB_DUMP / VULNA_DATA
// env the assembler needs.
//
// The restart of the quiesced services is installed BEFORE stopping them, so even a
// PARTIALLY-successful stop is recovered; and a restart failure is ALWAYS combined
// (errors.Join) with any snapshot error via the named return, so a failed restart is
// never suppressed by an earlier error and the caller learns the deployment may be
// left stopped.
func composeSnapshot(dir, stage string, stdout, stderr io.Writer) (envAdd []string, err error) {
	quiesced, qErr := deploy.RunningNonPostgresServices(dir)
	if qErr != nil {
		return nil, fmt.Errorf("cannot take a consistent backup: %w", qErr)
	}
	if len(quiesced) > 0 {
		fmt.Fprintln(stdout, "Pausing services for a consistent backup ...")
		defer func() {
			if rErr := deploy.StartServices(dir, stdout, stderr, quiesced...); rErr != nil {
				err = errors.Join(err, fmt.Errorf(
					"restarting services after backup failed (deployment may be stopped): %w", rErr))
			}
		}()
		if sErr := deploy.StopServices(dir, stdout, stderr, quiesced...); sErr != nil {
			return nil, fmt.Errorf("quiescing services for a consistent backup: %w", sErr)
		}
	}

	dumpPath := filepath.Join(stage, "db.dump")
	df, cErr := os.Create(dumpPath) //nolint:gosec // temp path we just created
	if cErr != nil {
		return nil, cErr
	}
	if dErr := deploy.DumpDatabase(dir, df); dErr != nil {
		_ = df.Close()
		return nil, dErr
	}
	if clErr := df.Close(); clErr != nil {
		return nil, clErr
	}

	dataDir := filepath.Join(stage, "data")
	if mErr := os.MkdirAll(dataDir, 0o700); mErr != nil {
		return nil, mErr
	}
	// Capture every persistent volume: keys (CA/signing, required), reports, evidence,
	// and the local Scout's identity (scout_state, bootstrap) so a restore does not
	// require Scout re-enrollment.
	for _, key := range deploy.DataVolumeKeys() {
		copied, vErr := deploy.BackupVolume(dir, key, dataDir)
		if vErr != nil {
			return nil, vErr
		}
		if !copied && key == "keys" {
			return nil, fmt.Errorf("the CA/signing keys volume is missing; cannot take a usable backup")
		}
	}
	return []string{"VULNA_DB_DUMP=" + dumpPath, "VULNA_DATA=" + dataDir}, nil
}

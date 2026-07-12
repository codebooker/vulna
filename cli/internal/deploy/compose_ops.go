// Compose-aware backup/restore and health primitives. The real deployment keeps
// PostgreSQL and application data in Docker named volumes, so backups must dump
// the database inside the postgres container and copy the data volumes out of the
// api container — not read a host DATABASE_URL or a host /var/lib/vulna path.
package deploy

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// helperImage is a tiny image used to read/write named volumes independently of
// any application container (which may be stopped or removed during a restore).
const helperImage = "alpine:3.21"

// DataVolumeKeys are the persistent volumes a backup must carry, by their compose
// key: CA + signing keys, reports, evidence files, and — so restoring a host does
// not require Scout re-enrollment — the local Scout's state and bootstrap material.
func DataVolumeKeys() []string {
	return []string{"keys", "reports", "evidence", "scout_state", "bootstrap"}
}

// DatabaseEnvKeys are every .env variable the backend uses to connect to the
// database (config.py AliasChoices). On a restore they must ALL come from THIS host
// — the postgres_data volume is not re-initialized, so its roles/credentials are the
// current host's. Preserving only POSTGRES_* would let a stale DATABASE_URL or a
// prefixed variant in the backup override them and point the app at the wrong DB.
func DatabaseEnvKeys() []string {
	return []string{
		"VULNA_DATABASE_URL", "DATABASE_URL",
		"VULNA_POSTGRES_HOST", "POSTGRES_HOST",
		"VULNA_POSTGRES_PORT", "POSTGRES_PORT",
		"VULNA_POSTGRES_DB", "POSTGRES_DB",
		"VULNA_POSTGRES_USER", "POSTGRES_USER",
		"VULNA_POSTGRES_PASSWORD", "POSTGRES_PASSWORD",
	}
}

// ProjectName resolves the compose project name (volumes are `<project>_<key>`).
func ProjectName(installDir string) string {
	args := append(ComposeArgs(installDir), "config", "--format", "json")
	cmd := exec.Command("docker", args...)
	cmd.Dir = installDir
	out, err := cmd.Output()
	if err == nil {
		var cfg struct {
			Name string `json:"name"`
		}
		if json.Unmarshal(out, &cfg) == nil && cfg.Name != "" {
			return cfg.Name
		}
	}
	return "vulna"
}

func volumeName(installDir, key string) string { return ProjectName(installDir) + "_" + key }

// VolumeExists reports whether the named volume for a compose key exists.
func VolumeExists(installDir, key string) bool {
	return exec.Command("docker", "volume", "inspect", volumeName(installDir, key)).Run() == nil
}

// PostgresDataExists reports whether the database volume exists — i.e. there is
// actual data to protect (vs a clean host with only the compose files present).
func PostgresDataExists(installDir string) bool {
	return VolumeExists(installDir, "postgres_data")
}

// BackupVolume copies the contents of a named volume into destParent/<key> using a
// throwaway helper container, so it works whether or not the mounting service is
// running. A missing volume is skipped (returns copied=false). A copy FAILURE (bad
// permissions, disk full, mount error) is a real error — it is NOT swallowed, so the
// caller's safety check on required volumes (e.g. keys) cannot be defeated.
func BackupVolume(installDir, key, destParent string) (bool, error) {
	if !VolumeExists(installDir, key) {
		return false, nil
	}
	cmd := exec.Command("docker", "run", "--rm",
		"-v", volumeName(installDir, key)+":/src:ro",
		"-v", destParent+":/out",
		helperImage, "sh", "-c",
		// `set -e`, no `|| true`: any copy error fails the whole command. `/src/.`
		// copies contents (an empty volume copies nothing and still succeeds).
		"set -e; mkdir -p /out/"+key+"; cp -a /src/. /out/"+key+"/")
	if out, err := cmd.CombinedOutput(); err != nil {
		return false, fmt.Errorf("backing up volume %s: %w: %s", key, err, strings.TrimSpace(string(out)))
	}
	return true, nil
}

// RestoreVolume makes a named volume's contents EXACTLY match srcParent/<key> (a
// point-in-time restore), via a helper container that auto-creates the volume. The
// destination is always cleared first — including dotfiles (`find -mindepth 1` gets
// what `rm /dest/*` misses) — so newer files are never left behind. If the class is
// absent from the backup, the volume is EMPTIED to match that point in time.
func RestoreVolume(installDir, key, srcParent string) error {
	src := filepath.Join(srcParent, key)
	script := "set -e; find /dest -mindepth 1 -delete"
	if _, err := os.Stat(src); err == nil {
		script += "; cp -a /in/" + key + "/. /dest/"
	}
	cmd := exec.Command("docker", "run", "--rm",
		"-v", volumeName(installDir, key)+":/dest",
		"-v", srcParent+":/in:ro",
		helperImage, "sh", "-c", script)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("restoring volume %s: %w: %s", key, err, strings.TrimSpace(string(out)))
	}
	return nil
}

// pgCreds returns the Postgres user/db/password from the deployment .env, matching
// the compose defaults (user=db=vulna). Password may be empty if unset.
func pgCreds(installDir string) (user, db, password string) {
	env, _ := ReadEnv(filepath.Join(installDir, EnvFile))
	user = pick(env, "POSTGRES_USER", "vulna")
	db = pick(env, "POSTGRES_DB", "vulna")
	password = env["POSTGRES_PASSWORD"]
	return user, db, password
}

// composeExec builds a `docker compose ... exec -T [ -e ... ] <service> <cmd...>`
// command against the deployment.
func composeExec(installDir string, env []string, service string, cmdArgs ...string) *exec.Cmd {
	args := append(ComposeArgs(installDir), "--env-file", filepath.Join(installDir, EnvFile), "exec", "-T")
	for _, e := range env {
		args = append(args, "-e", e)
	}
	args = append(args, service)
	args = append(args, cmdArgs...)
	cmd := exec.Command("docker", args...)
	cmd.Dir = installDir
	return cmd
}

// HasPostgresService reports whether this deployment's Compose config defines a
// "postgres" service — i.e. the database is Compose-managed and should be
// dumped/restored via the container, not a host DATABASE_URL. Returns false if
// docker/compose is unavailable.
func HasPostgresService(installDir string) bool {
	args := append(ComposeArgs(installDir), "config", "--services")
	cmd := exec.Command("docker", args...)
	cmd.Dir = installDir
	out, err := cmd.Output()
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(out), "\n") {
		if strings.TrimSpace(line) == "postgres" {
			return true
		}
	}
	return false
}

// UpServices starts only the named services (e.g. just "postgres" so the database
// can be restored while the application stays down).
func UpServices(installDir string, stdout, stderr io.Writer, services ...string) error {
	args := append(ComposeArgs(installDir), "--env-file", filepath.Join(installDir, EnvFile), "up", "-d")
	args = append(args, services...)
	cmd := exec.Command("docker", args...)
	cmd.Dir = installDir
	cmd.Stdout, cmd.Stderr = stdout, stderr
	return cmd.Run()
}

// StopServices stops the named running services (containers kept, so they can be
// started again). Used to quiesce writers for a consistent backup.
func StopServices(installDir string, stdout, stderr io.Writer, services ...string) error {
	if len(services) == 0 {
		return nil
	}
	args := append(ComposeArgs(installDir), "stop")
	args = append(args, services...)
	cmd := exec.Command("docker", args...)
	cmd.Dir = installDir
	cmd.Stdout, cmd.Stderr = stdout, stderr
	return cmd.Run()
}

// StartServices starts the named (already-created) services.
func StartServices(installDir string, stdout, stderr io.Writer, services ...string) error {
	if len(services) == 0 {
		return nil
	}
	args := append(ComposeArgs(installDir), "start")
	args = append(args, services...)
	cmd := exec.Command("docker", args...)
	cmd.Dir = installDir
	cmd.Stdout, cmd.Stderr = stdout, stderr
	return cmd.Run()
}

// RunningNonPostgresServices returns the currently-running services other than
// postgres — the writers that must be quiesced for a consistent backup and then
// restarted afterward. It returns an ERROR (rather than an empty list) when it can't
// inspect the stack, so the caller fails closed instead of assuming "no writers" and
// backing up an inconsistent, live deployment.
func RunningNonPostgresServices(installDir string) ([]string, error) {
	states, err := serviceStates(installDir)
	if err != nil {
		return nil, fmt.Errorf("could not inspect running services: %w", err)
	}
	var out []string
	for _, s := range states {
		if s.Service != "postgres" && s.State == "running" {
			out = append(out, s.Service)
		}
	}
	return out, nil
}

// WaitPostgresReady polls until postgres accepts connections or the timeout passes.
func WaitPostgresReady(installDir string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for {
		if PostgresReady(installDir) {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("postgres not ready within %s", timeout)
		}
		time.Sleep(2 * time.Second)
	}
}

// Postgres container states we distinguish. Compose reports the Docker container
// state verbatim (created, restarting, running, removing, paused, exited, dead), plus
// "absent" here when no container exists at all.
const (
	// PgAbsent — no postgres container exists (definitively inactive).
	PgAbsent = "absent"
	// PgExited / PgCreated — definitively inactive: safe to start for a backup and
	// stop again afterward.
	PgExited  = "exited"
	PgCreated = "created"
	// PgRunning — up (may or may not be ready).
	PgRunning = "running"
	// PgRestarting — auto-recovering under its restart policy; TRANSITIONAL, must be
	// preserved (never started/stopped) — misreading it as stopped would let a backup
	// stop the recovering database.
	PgRestarting = "restarting"
)

// PostgresContainerState returns the postgres container's actual state ("absent" when
// there is none) rather than a boolean, so a caller can act ONLY on definitively
// inactive states and preserve/reject transitional ones (restarting, paused,
// removing, dead). It returns an ERROR (never a made-up state) when it cannot inspect
// the stack, so a caller fails closed instead of misclassifying a live database.
func PostgresContainerState(installDir string) (string, error) {
	states, err := serviceStates(installDir)
	if err != nil {
		return "", err
	}
	for _, s := range states {
		if s.Service == "postgres" {
			return s.State, nil
		}
	}
	return PgAbsent, nil
}

// PostgresReady reports whether the postgres service is up and accepting
// connections — the precondition for a Compose-mode dump or restore.
func PostgresReady(installDir string) bool {
	user, db, _ := pgCreds(installDir)
	cmd := composeExec(installDir, nil, "postgres", "pg_isready", "-U", user, "-d", db)
	return cmd.Run() == nil
}

// DumpDatabase streams a custom-format pg_dump of the deployment database to out,
// run inside the postgres container.
func DumpDatabase(installDir string, out io.Writer) error {
	user, db, pw := pgCreds(installDir)
	cmd := composeExec(installDir, []string{"PGPASSWORD=" + pw}, "postgres",
		"pg_dump", "--format=custom", "--no-owner", "-U", user, "-d", db)
	var stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = out, &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("pg_dump in postgres container failed: %w: %s", err, strings.TrimSpace(stderr.String()))
	}
	return nil
}

// RestoreDatabase restores a custom-format dump (read from in) into the deployment
// database, run inside the postgres container. It drops and recreates objects
// ATOMICALLY: --single-transaction (+ --exit-on-error, which it implies) wraps the
// whole restore in one transaction, so a mid-way failure rolls back and leaves the
// database unchanged rather than a mix of old and restored state.
func RestoreDatabase(installDir string, in io.Reader) error {
	user, db, pw := pgCreds(installDir)
	cmd := composeExec(installDir, []string{"PGPASSWORD=" + pw}, "postgres",
		"pg_restore", "--clean", "--if-exists", "--no-owner",
		"--single-transaction", "--exit-on-error", "-U", user, "-d", db)
	cmd.Stdin = in
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("pg_restore in postgres container failed: %w: %s", err, strings.TrimSpace(stderr.String()))
	}
	return nil
}

// composePS is the subset of `docker compose ps --format json` we read.
type composePS struct {
	Service  string `json:"Service"`
	State    string `json:"State"`
	Health   string `json:"Health"`
	ExitCode int    `json:"ExitCode"`
}

// serviceStates returns the current per-service state/health.
func serviceStates(installDir string) ([]composePS, error) {
	args := append(ComposeArgs(installDir), "ps", "--format", "json", "--all")
	cmd := exec.Command("docker", args...)
	cmd.Dir = installDir
	out, err := cmd.Output()
	if err != nil {
		return nil, err
	}
	var states []composePS
	// Newer compose prints one JSON object per line; older prints a JSON array.
	trimmed := bytes.TrimSpace(out)
	if len(trimmed) > 0 && trimmed[0] == '[' {
		if err := json.Unmarshal(trimmed, &states); err != nil {
			return nil, err
		}
		return states, nil
	}
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var p composePS
		if err := json.Unmarshal([]byte(line), &p); err != nil {
			return nil, err
		}
		states = append(states, p)
	}
	return states, nil
}

// oneShotServices returns, per compose service name, whether it is a one-shot/init
// service (restart policy "no"/none) that is EXPECTED to exit — e.g.
// scout-ca-export, which copies the CA once and stops. Everything else must stay
// running. Reading the real restart policy (rather than name-matching) means a dead
// long-running service that happens to exit 0 is still flagged.
func oneShotServices(installDir string) (map[string]bool, error) {
	args := append(ComposeArgs(installDir), "config", "--format", "json")
	cmd := exec.Command("docker", args...)
	cmd.Dir = installDir
	out, err := cmd.Output()
	if err != nil {
		return nil, err
	}
	var cfg struct {
		Services map[string]struct {
			Restart string `json:"restart"`
		} `json:"services"`
	}
	if err := json.Unmarshal(out, &cfg); err != nil {
		return nil, err
	}
	oneShot := make(map[string]bool, len(cfg.Services))
	for name, s := range cfg.Services {
		r := strings.TrimSpace(s.Restart)
		oneShot[name] = r == "" || r == "no" || r == "none"
	}
	return oneShot, nil
}

// notReady returns the services that are not yet ready. `expected` maps every
// service name to whether it is one-shot. A service is ready when it is healthy
// (if it has a health check), running (long-running, no health check), or — only if
// it is one-shot — exited with code 0. A MISSING expected service, an empty project,
// a non-zero exit, or a long-running service that has exited are all NOT ready.
func notReady(expected map[string]bool, states []composePS) []string {
	byName := make(map[string]composePS, len(states))
	for _, s := range states {
		byName[s.Service] = s
	}
	var bad []string
	for name, isOneShot := range expected {
		s, present := byName[name]
		if !present {
			bad = append(bad, name+" (missing)")
			continue
		}
		switch {
		case s.Health == "healthy":
		case s.Health == "" && s.State == "running":
		case isOneShot && s.Health == "" && s.State == "exited" && s.ExitCode == 0:
		default:
			detail := s.State
			if s.Health != "" {
				detail = s.Health
			} else if s.State == "exited" {
				detail = fmt.Sprintf("exited code %d", s.ExitCode)
			}
			bad = append(bad, fmt.Sprintf("%s (%s)", name, detail))
		}
	}
	sort.Strings(bad)
	return bad
}

// WaitHealthy polls compose until every EXPECTED service is ready or the timeout
// elapses, so an update is only recorded applied once the stack is actually up (not
// merely once `up -d` returned, and not when the project is empty). Returns the
// not-ready services on timeout.
func WaitHealthy(installDir string, timeout time.Duration, stdout io.Writer) error {
	expected, err := oneShotServices(installDir)
	if err != nil {
		return fmt.Errorf("could not read expected services: %w", err)
	}
	if len(expected) == 0 {
		return fmt.Errorf("compose config lists no services")
	}
	deadline := time.Now().Add(timeout)
	var last []string
	for {
		states, sErr := serviceStates(installDir)
		if sErr == nil {
			if last = notReady(expected, states); len(last) == 0 {
				return nil
			}
		}
		if time.Now().After(deadline) {
			if sErr != nil {
				return fmt.Errorf("could not read container health: %w", sErr)
			}
			return fmt.Errorf("containers not ready within %s: %s", timeout, strings.Join(last, ", "))
		}
		if stdout != nil {
			fmt.Fprintf(stdout, "  waiting for containers to become ready: %s\n", strings.Join(last, ", "))
		}
		time.Sleep(3 * time.Second)
	}
}

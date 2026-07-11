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
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

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
// database, run inside the postgres container. It drops and recreates objects.
func RestoreDatabase(installDir string, in io.Reader) error {
	user, db, pw := pgCreds(installDir)
	cmd := composeExec(installDir, []string{"PGPASSWORD=" + pw}, "postgres",
		"pg_restore", "--clean", "--if-exists", "--no-owner", "-U", user, "-d", db)
	cmd.Stdin = in
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("pg_restore in postgres container failed: %w: %s", err, strings.TrimSpace(stderr.String()))
	}
	return nil
}

// CopyFromContainer copies a path out of a service container to a host path
// (`docker compose cp service:src dest`).
func CopyFromContainer(installDir, service, src, dest string) error {
	args := append(ComposeArgs(installDir), "cp", service+":"+src, dest)
	cmd := exec.Command("docker", args...)
	cmd.Dir = installDir
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("compose cp %s:%s failed: %w: %s", service, src, err, strings.TrimSpace(string(out)))
	}
	return nil
}

// CopyToContainer copies a host path into a service container
// (`docker compose cp src service:dest`).
func CopyToContainer(installDir, service, src, dest string) error {
	args := append(ComposeArgs(installDir), "cp", src, service+":"+dest)
	cmd := exec.Command("docker", args...)
	cmd.Dir = installDir
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("compose cp to %s:%s failed: %w: %s", service, dest, err, strings.TrimSpace(string(out)))
	}
	return nil
}

// composePS is the subset of `docker compose ps --format json` we read.
type composePS struct {
	Service string `json:"Service"`
	State   string `json:"State"`
	Health  string `json:"Health"`
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

// unhealthy returns the services that are not yet healthy: a service WITH a health
// check must be "healthy"; one without must at least be "running".
func unhealthy(states []composePS) []string {
	var bad []string
	for _, s := range states {
		switch {
		case s.Health == "healthy":
			continue
		case s.Health == "" && s.State == "running":
			continue
		default:
			detail := s.State
			if s.Health != "" {
				detail = s.Health
			}
			bad = append(bad, fmt.Sprintf("%s (%s)", s.Service, detail))
		}
	}
	return bad
}

// WaitHealthy polls compose until every service is healthy/running or the timeout
// elapses, so an update is only recorded applied once the stack is actually up —
// not merely once `up -d` returned. Returns the still-unhealthy services on timeout.
func WaitHealthy(installDir string, timeout time.Duration, stdout io.Writer) error {
	deadline := time.Now().Add(timeout)
	var last []string
	for {
		states, err := serviceStates(installDir)
		if err == nil {
			if last = unhealthy(states); len(last) == 0 {
				return nil
			}
		}
		if time.Now().After(deadline) {
			if err != nil {
				return fmt.Errorf("could not read container health: %w", err)
			}
			return fmt.Errorf("containers not healthy within %s: %s", timeout, strings.Join(last, ", "))
		}
		if stdout != nil {
			fmt.Fprintf(stdout, "  waiting for containers to become healthy: %s\n", strings.Join(last, ", "))
		}
		time.Sleep(3 * time.Second)
	}
}

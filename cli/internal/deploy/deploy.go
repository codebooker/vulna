// Package deploy materializes the generated single-host deployment: a
// restrictive config directory, a 0600 environment file with generated secrets
// (never rotated on re-run), and an install record. It also drives Docker
// Compose. Nothing here is destructive unless explicitly requested.
package deploy

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"

	"github.com/codebooker/vulna/cli/internal/buildinfo"
	"github.com/codebooker/vulna/cli/internal/config"
	"github.com/codebooker/vulna/cli/internal/secrets"
)

// composeFiles are the two Compose files that define the single-host stack.
var composeFiles = []string{"docker-compose.yml", "docker-compose.single-host.yml"}

// singleHostServices/ports/capabilities describe the stack for the dry-run plan.
var (
	singleHostServices = []string{
		"caddy", "api", "frontend", "postgres", "redis", "scout-ca-export", "relay-netns", "relay-egress", "local-scout",
	}
	singleHostCapabilities = []string{
		"api & workers: no added Linux capabilities, no Docker socket",
		"relay-egress: NET_ADMIN only (WireGuard routes/firewall; no Docker socket)",
		"local-scout: all capabilities dropped (Nmap connect-scan only)",
	}
)

// ActionKind categorizes a planned change.
type ActionKind string

const (
	// ActionMkdir creates a directory.
	ActionMkdir ActionKind = "mkdir"
	// ActionWrite writes a file.
	ActionWrite ActionKind = "write"
	// ActionKeep preserves an existing file unchanged (e.g. secrets on re-run).
	ActionKeep ActionKind = "keep"
)

// Action is a single planned filesystem change.
type Action struct {
	Kind   ActionKind
	Path   string
	Mode   os.FileMode
	Secret bool
	Note   string
}

// Plan is the set of changes an install would make. It is printed verbatim in
// --dry-run and executed otherwise.
type Plan struct {
	Actions      []Action
	Services     []string
	Ports        []int
	Capabilities []string
}

// EnvFile is the generated environment file name inside the install dir.
const EnvFile = ".env"

// RecordFile is the install record (non-secret) inside the install dir.
const RecordFile = ".vulna-install.json"

// BuildEnv returns the desired environment map for the given options, reusing
// any secrets already present in existing (so re-runs never rotate them).
func BuildEnv(o config.Options, existing map[string]string) (map[string]string, error) {
	env := map[string]string{}

	pgpw := existing["POSTGRES_PASSWORD"]
	if pgpw == "" {
		var err error
		if pgpw, err = secrets.Password(); err != nil {
			return nil, err
		}
	}
	secret := existing["VULNA_SECRET_KEY"]
	if secret == "" {
		var err error
		if secret, err = secrets.SessionKey(); err != nil {
			return nil, err
		}
	}
	adminpw := existing["VULNA_ADMIN_PASSWORD"]
	if adminpw == "" {
		var err error
		if adminpw, err = secrets.Password(); err != nil {
			return nil, err
		}
	}
	// Master key for at-rest evidence encryption. Generated once and NEVER rotated
	// on re-runs (rotating it would orphan already-encrypted evidence). Without it
	// the backend stores raw scanner output in plaintext.
	masterKey := existing["VULNA_MASTER_KEY"]
	if masterKey == "" {
		var err error
		if masterKey, err = secrets.SessionKey(); err != nil {
			return nil, err
		}
	}
	relayToken := existing["VULNA_RELAY_EGRESS_TOKEN"]
	if relayToken == "" {
		var err error
		if relayToken, err = secrets.SessionKey(); err != nil {
			return nil, err
		}
	}

	env["POSTGRES_PASSWORD"] = pgpw
	env["VULNA_SECRET_KEY"] = secret
	env["VULNA_ADMIN_PASSWORD"] = adminpw
	env["VULNA_MASTER_KEY"] = masterKey
	env["VULNA_RELAY_EGRESS_TOKEN"] = relayToken
	// The released version the stack runs. Compose pins the api/frontend image
	// tags to this, so `vulna update` (which rewrites it) actually changes what
	// runs. Preserve an existing value; default to the installer's own version.
	env["VULNA_VERSION"] = pick(existing, "VULNA_VERSION", defaultVersion())
	// Non-secret settings: preserve an operator's manual edits if present.
	env["VULNA_ADMIN_EMAIL"] = pick(existing, "VULNA_ADMIN_EMAIL", o.AdminEmail)
	env["VULNA_DOMAIN"] = pick(existing, "VULNA_DOMAIN", o.Domain())
	publicHost := o.Domain()
	if publicHost == "" {
		publicHost = "localhost"
	}
	env["VULNA_PUBLIC_BASE_URL"] = pick(
		existing, "VULNA_PUBLIC_BASE_URL", "https://"+publicHost,
	)
	env["VULNA_RELAY_ENDPOINT"] = pick(
		existing, "VULNA_RELAY_ENDPOINT", publicHost+":51820",
	)
	env["CADDY_TLS"] = pick(existing, "CADDY_TLS", o.CaddyTLS())
	return env, nil
}

func pick(existing map[string]string, key, fallback string) string {
	if v, ok := existing[key]; ok && v != "" {
		return v
	}
	return fallback
}

// PlanInstall computes the actions required for the given options without
// touching the filesystem.
func PlanInstall(o config.Options) (Plan, error) {
	existing, _ := ReadEnv(filepath.Join(o.InstallDir, EnvFile))
	env, err := BuildEnv(o, existing)
	if err != nil {
		return Plan{}, err
	}

	var actions []Action
	for _, dir := range []string{o.ConfigDir, o.DataDir} {
		if dir == "" {
			continue
		}
		if _, statErr := os.Stat(dir); statErr != nil {
			actions = append(actions, Action{Kind: ActionMkdir, Path: dir, Mode: 0o700})
		}
	}

	envPath := filepath.Join(o.InstallDir, EnvFile)
	if len(existing) == 0 {
		actions = append(actions, Action{Kind: ActionWrite, Path: envPath, Mode: 0o600, Secret: true,
			Note: "generated secrets (database, session, admin password)"})
	} else {
		added := missingKeys(existing, env)
		if len(added) == 0 {
			actions = append(actions, Action{Kind: ActionKeep, Path: envPath, Mode: 0o600, Secret: true,
				Note: "existing secrets preserved (not rotated)"})
		} else {
			actions = append(actions, Action{Kind: ActionWrite, Path: envPath, Mode: 0o600, Secret: true,
				Note: "add missing keys " + strings.Join(added, ", ") + "; existing secrets preserved"})
		}
	}

	actions = append(actions, Action{Kind: ActionWrite, Path: filepath.Join(o.InstallDir, RecordFile),
		Mode: 0o644, Note: "install record (non-secret)"})

	ports := []int{80, 443, 8443, 51820}
	return Plan{Actions: actions, Services: singleHostServices, Ports: ports, Capabilities: singleHostCapabilities}, nil
}

// Apply performs an install: creates dirs, writes the env file (preserving
// existing secrets), and writes the install record. It is idempotent.
func Apply(o config.Options) error {
	for _, dir := range []string{o.InstallDir, o.ConfigDir, o.DataDir} {
		if dir == "" {
			continue
		}
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return fmt.Errorf("create %s: %w", dir, err)
		}
	}

	envPath := filepath.Join(o.InstallDir, EnvFile)
	existing, _ := ReadEnv(envPath)
	env, err := BuildEnv(o, existing)
	if err != nil {
		return err
	}
	if err := WriteEnv(envPath, env); err != nil {
		return err
	}
	if err := config.Save(filepath.Join(o.InstallDir, RecordFile), o); err != nil {
		return fmt.Errorf("write install record: %w", err)
	}
	return nil
}

// ReadEnv parses a KEY=VALUE env file into a map. A missing file yields an empty
// map and no error.
func ReadEnv(path string) (map[string]string, error) {
	m := map[string]string{}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return m, nil
		}
		return m, err
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		m[strings.TrimSpace(k)] = strings.TrimSpace(v)
	}
	return m, nil
}

// WriteEnv writes the env map to path with 0600 permissions, keys sorted for a
// stable file.
func WriteEnv(path string, env map[string]string) error {
	keys := make([]string, 0, len(env))
	for k := range env {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	b.WriteString("# Generated by `vulna install`. Contains secrets — keep 0600.\n")
	b.WriteString("# Re-running the installer never rotates existing secrets.\n")
	for _, k := range keys {
		fmt.Fprintf(&b, "%s=%s\n", k, env[k])
	}
	// Write 0600 atomically-ish: create with restrictive mode from the start.
	if err := os.WriteFile(path, []byte(b.String()), 0o600); err != nil {
		return err
	}
	return os.Chmod(path, 0o600)
}

func missingKeys(existing, desired map[string]string) []string {
	var out []string
	for k := range desired {
		if _, ok := existing[k]; !ok {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}

// ComposeArgs returns the base `docker compose -f ... -f ...` arguments for the
// install directory.
func ComposeArgs(installDir string) []string {
	args := []string{"compose"}
	for _, f := range composeFiles {
		args = append(args, "-f", filepath.Join(installDir, f))
	}
	return args
}

// SourceHasCompose reports whether the install dir contains the Compose files.
func SourceHasCompose(installDir string) error {
	for _, f := range composeFiles {
		if _, err := os.Stat(filepath.Join(installDir, f)); err != nil {
			return fmt.Errorf("missing %s in %s", f, installDir)
		}
	}
	return nil
}

// defaultVersion is the version a fresh install pins to (the CLI's own build).
func defaultVersion() string {
	if v := buildinfo.Version; v != "" && v != "unknown" {
		return v
	}
	return "dev"
}

// SetEnvVersion rewrites VULNA_VERSION in the deployment .env, so a subsequent
// `docker compose pull` fetches that version's images. Used by update/rollback to
// actually change the running version (not just record it).
func SetEnvVersion(installDir, version string) error {
	envPath := filepath.Join(installDir, EnvFile)
	env, err := ReadEnv(envPath)
	if err != nil {
		return err
	}
	env["VULNA_VERSION"] = version
	return WriteEnv(envPath, env)
}

// Pull fetches the images referenced by the Compose files (e.g. after an update
// changed the pinned tags). It does not touch the running stack.
func Pull(installDir string, stdout, stderr io.Writer) error {
	args := append(ComposeArgs(installDir), "--env-file", filepath.Join(installDir, EnvFile), "pull")
	cmd := exec.Command("docker", args...)
	cmd.Dir = installDir
	cmd.Stdout, cmd.Stderr = stdout, stderr
	return cmd.Run()
}

// Up starts the stack. envFile is passed so Compose reads the generated secrets.
func Up(installDir string, stdout, stderr io.Writer) error {
	args := append(ComposeArgs(installDir), "--env-file", filepath.Join(installDir, EnvFile), "up", "-d")
	cmd := exec.Command("docker", args...)
	cmd.Dir = installDir
	cmd.Stdout, cmd.Stderr = stdout, stderr
	return cmd.Run()
}

// Down stops the stack. removeVolumes must be explicitly requested.
func Down(installDir string, removeVolumes bool, stdout, stderr io.Writer) error {
	args := append(ComposeArgs(installDir), "--env-file", filepath.Join(installDir, EnvFile), "down")
	if removeVolumes {
		args = append(args, "-v")
	}
	cmd := exec.Command("docker", args...)
	cmd.Dir = installDir
	cmd.Stdout, cmd.Stderr = stdout, stderr
	return cmd.Run()
}

// RemoveGeneratedFiles deletes only the installer-generated files (env + record),
// never data. Returns the list of removed paths.
func RemoveGeneratedFiles(installDir string) ([]string, error) {
	var removed []string
	for _, f := range []string{EnvFile, RecordFile} {
		p := filepath.Join(installDir, f)
		if _, err := os.Stat(p); err == nil {
			if err := os.Remove(p); err != nil {
				return removed, err
			}
			removed = append(removed, p)
		}
	}
	return removed, nil
}

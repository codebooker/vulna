// Package scannersandbox confines external scanner processes to a disposable
// workspace while leaving their network access intact for authorized scans.
package scannersandbox

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
)

const workspaceEnv = "VULNA_SCANNER_WORKSPACE"

const (
	nucleiTemplatesEnv = "VULNA_NUCLEI_TEMPLATES"
	nucleiIgnoreFile   = ".nuclei-ignore"
)

// ProtectCurrentProcess prevents same-UID scanner descendants from inspecting
// the Scout's memory or /proc environment through ptrace access checks.
func ProtectCurrentProcess() error {
	return protectCurrentProcess()
}

// Execute validates the hidden helper invocation, applies platform isolation,
// and preserves the scanner's exit status.
func Execute(args []string, stdout, stderr io.Writer) int {
	if len(args) < 2 || args[0] != "--" {
		fmt.Fprintln(stderr, "scanner-sandbox: expected -- followed by a command")
		return 2
	}
	workspace, err := validateWorkspace(os.Getenv(workspaceEnv))
	if err != nil {
		fmt.Fprintln(stderr, "scanner-sandbox:", err)
		return 1
	}
	if err := prepareWorkspace(workspace); err != nil {
		fmt.Fprintln(stderr, "scanner-sandbox: prepare workspace:", err)
		return 1
	}
	// Landlock domains are inherited from the calling thread. Pin this goroutine
	// from restriction through fork/exec so Go cannot migrate it to an
	// unrestricted runtime thread before the scanner child is created.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if err := applyPlatformSandbox(workspace); err != nil {
		fmt.Fprintln(stderr, "scanner-sandbox: isolation unavailable:", err)
		return 1
	}

	cmd := exec.Command(args[1], args[2:]...)
	cmd.Dir = workspace
	cmd.Env = sandboxEnvironment(os.Environ(), workspace)
	cmd.Stdin = os.Stdin
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	if err := cmd.Run(); err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			code, signal := normalizedExitCode(exitErr)
			if signal != "" {
				fmt.Fprintf(stderr, "scanner-sandbox: command terminated by signal %s\n", signal)
			}
			return code
		}
		fmt.Fprintln(stderr, "scanner-sandbox: execute:", err)
		return 1
	}
	return 0
}

func validateWorkspace(path string) (string, error) {
	if path == "" {
		return "", fmt.Errorf("%s is required", workspaceEnv)
	}
	realWorkspace, err := filepath.EvalSymlinks(path)
	if err != nil {
		return "", fmt.Errorf("resolve workspace: %w", err)
	}
	realWorkspace, err = filepath.Abs(realWorkspace)
	if err != nil {
		return "", fmt.Errorf("absolute workspace: %w", err)
	}
	realTemp, err := filepath.EvalSymlinks(os.TempDir())
	if err != nil {
		return "", fmt.Errorf("resolve temporary root: %w", err)
	}
	rel, err := filepath.Rel(realTemp, realWorkspace)
	if err != nil || rel == "." || rel == ".." || filepath.IsAbs(rel) ||
		len(rel) >= 3 && rel[:3] == ".."+string(filepath.Separator) {
		return "", fmt.Errorf("workspace must be a child of %s", realTemp)
	}
	info, err := os.Stat(realWorkspace)
	if err != nil {
		return "", fmt.Errorf("stat workspace: %w", err)
	}
	if !info.IsDir() {
		return "", fmt.Errorf("workspace is not a directory")
	}
	return realWorkspace, nil
}

func prepareWorkspace(workspace string) error {
	for _, name := range []string{"home", "tmp", ".config", ".cache"} {
		if err := os.MkdirAll(filepath.Join(workspace, name), 0o700); err != nil {
			return err
		}
	}
	// Nuclei's packaged config points relative template helpers at the immutable
	// /opt template set, but Nuclei also writes provider state beside that config.
	// Give it a private copy rather than making /opt or Scout state writable.
	if source := os.Getenv("XDG_CONFIG_HOME"); source != "" {
		if info, err := os.Stat(source); err == nil && info.IsDir() {
			if err := copyTree(source, filepath.Join(workspace, ".config")); err != nil {
				return err
			}
		}
	}
	return seedNucleiIgnore(workspace)
}

// seedNucleiIgnore preserves ProjectDiscovery's default template exclusions
// when the immutable template pack and writable Nuclei config live in separate
// trees. Without it Nuclei logs an error and silently runs templates that the
// upstream pack excludes for weak matchers or unsafe/default-inapplicable tags.
func seedNucleiIgnore(workspace string) error {
	templatesDir := os.Getenv(nucleiTemplatesEnv)
	if templatesDir == "" {
		return nil
	}
	destination := filepath.Join(workspace, ".config", "nuclei", nucleiIgnoreFile)
	if info, err := os.Stat(destination); err == nil && info.Mode().IsRegular() {
		return nil
	} else if err != nil && !os.IsNotExist(err) {
		return err
	}
	source := filepath.Join(templatesDir, nucleiIgnoreFile)
	data, err := os.ReadFile(source)
	if err != nil {
		return fmt.Errorf("read packaged Nuclei ignore policy: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(destination), 0o700); err != nil {
		return err
	}
	if err := os.WriteFile(destination, data, 0o600); err != nil {
		return fmt.Errorf("seed Nuclei ignore policy: %w", err)
	}
	return nil
}

func copyTree(source, destination string) error {
	return filepath.WalkDir(source, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		rel, err := filepath.Rel(source, path)
		if err != nil {
			return err
		}
		target := filepath.Join(destination, rel)
		info, err := entry.Info()
		if err != nil {
			return err
		}
		switch {
		case entry.IsDir():
			return os.MkdirAll(target, 0o700)
		case info.Mode().IsRegular():
			data, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			return os.WriteFile(target, data, 0o600)
		default:
			return nil
		}
	})
}

func sandboxEnvironment(environment []string, workspace string) []string {
	overrides := map[string]string{
		"HOME":               filepath.Join(workspace, "home"),
		"TMPDIR":             filepath.Join(workspace, "tmp"),
		"XDG_CONFIG_HOME":    filepath.Join(workspace, ".config"),
		"XDG_CACHE_HOME":     filepath.Join(workspace, ".cache"),
		"VULNA_SCANNER_HOME": workspace,
	}
	result := make([]string, 0, len(environment)+len(overrides))
	for _, entry := range environment {
		key, _, _ := splitEnvironment(entry)
		if _, replaced := overrides[key]; !replaced {
			result = append(result, entry)
		}
	}
	for key, value := range overrides {
		result = append(result, key+"="+value)
	}
	return result
}

func splitEnvironment(entry string) (string, string, bool) {
	for i := range entry {
		if entry[i] == '=' {
			return entry[:i], entry[i+1:], true
		}
	}
	return entry, "", false
}

func unsupportedPlatformError() error {
	return fmt.Errorf("per-scanner Landlock isolation requires Linux (running %s)", runtime.GOOS)
}

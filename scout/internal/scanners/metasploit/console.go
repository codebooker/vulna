package metasploit

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strings"
	"time"
)

// ConsoleRunner drives Metasploit by executing msfconsole with a generated
// resource script — matching the scout's exec-based scanner adapters (nmap,
// nuclei, ...) and staying dependency-free. The resource script runs one module
// against one target and then kills all sessions (teardown atomic with the run);
// as a safety net RunModule also issues a fresh-context session kill so teardown
// still happens if the run was time-boxed before the inline kill executed.
type ConsoleRunner struct {
	Binary string // default "msfconsole"
}

func (c *ConsoleRunner) binary() string {
	if c.Binary != "" {
		return c.Binary
	}
	return "msfconsole"
}

// RunModule runs the module and returns the console output as evidence. Sessions
// are torn down in-band (and by the safety-net kill), so none are returned for
// the worker to chase.
func (c *ConsoleRunner) RunModule(ctx context.Context, spec ModuleSpec) (RunResult, error) {
	script, err := buildResourceScript(spec)
	if err != nil {
		return RunResult{}, err
	}
	f, err := os.CreateTemp("", "vulna-msf-*.rc")
	if err != nil {
		return RunResult{}, err
	}
	defer func() { _ = os.Remove(f.Name()) }()
	if _, err := f.WriteString(script); err != nil {
		_ = f.Close()
		return RunResult{}, err
	}
	_ = f.Close()

	// Safety net: whatever happens (including a time-boxed cancel that stops the
	// inline "sessions -K"), best-effort kill all sessions on a fresh context.
	defer c.killAllSessions()

	cmd := exec.CommandContext(ctx, c.binary(), "-q", "-n", "-r", f.Name())
	out, runErr := cmd.CombinedOutput()
	res := RunResult{
		Evidence: map[string]any{"console": string(out)},
		Success:  runErr == nil,
	}
	if ctx.Err() != nil {
		return res, ctx.Err()
	}
	return res, runErr
}

// StopSession kills one session by id.
func (c *ConsoleRunner) StopSession(ctx context.Context, id string) error {
	args, err := stopSessionArgs(id)
	if err != nil {
		return err
	}
	return exec.CommandContext(ctx, c.binary(), args...).Run()
}

func (c *ConsoleRunner) killAllSessions() {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	_ = exec.CommandContext(ctx, c.binary(), teardownArgs()...).Run()
}

// buildResourceScript renders a safe msfconsole resource script: use the module,
// set the (already scope-validated) target, payload, and options, run without
// interacting, then kill all sessions. Every token is checked for newline/control
// characters so an option value cannot inject an extra console command.
func buildResourceScript(spec ModuleSpec) (string, error) {
	if err := safeToken("module", spec.Module); err != nil {
		return "", err
	}
	if err := safeToken("target", spec.Target); err != nil {
		return "", err
	}
	if spec.Payload != "" {
		if err := safeToken("payload", spec.Payload); err != nil {
			return "", err
		}
	}
	var b strings.Builder
	fmt.Fprintf(&b, "use %s\n", spec.Module)
	fmt.Fprintf(&b, "set RHOSTS %s\n", spec.Target)
	if spec.Payload != "" {
		fmt.Fprintf(&b, "set PAYLOAD %s\n", spec.Payload)
	}
	keys := make([]string, 0, len(spec.Options))
	for k := range spec.Options {
		keys = append(keys, k)
	}
	sort.Strings(keys) // deterministic
	for _, k := range keys {
		v := fmt.Sprintf("%v", spec.Options[k])
		if err := safeToken("option key", k); err != nil {
			return "", err
		}
		if err := safeToken("option value", v); err != nil {
			return "", err
		}
		fmt.Fprintf(&b, "set %s %s\n", k, v)
	}
	b.WriteString("run -z\n")      // run, do not drop to an interactive session
	b.WriteString("sessions -K\n") // teardown: kill all sessions
	b.WriteString("exit -y\n")
	return b.String(), nil
}

func teardownArgs() []string {
	return []string{"-q", "-n", "-x", "sessions -K; exit -y"}
}

func stopSessionArgs(id string) ([]string, error) {
	if err := safeToken("session id", id); err != nil {
		return nil, err
	}
	if strings.ContainsAny(id, " ;") {
		return nil, fmt.Errorf("session id %q is not a bare token", id)
	}
	return []string{"-q", "-n", "-x", "sessions -k " + id + "; exit -y"}, nil
}

// safeToken rejects a value that could break out of its resource-script line.
func safeToken(what, s string) error {
	if strings.ContainsAny(s, "\r\n") {
		return fmt.Errorf("%s contains a newline", what)
	}
	for _, r := range s {
		if r < 0x20 && r != '\t' {
			return fmt.Errorf("%s contains a control character", what)
		}
	}
	return nil
}

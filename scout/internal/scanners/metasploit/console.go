package metasploit

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/codebooker/vulna/scout/internal/processutil"
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

var resourceTokenRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/@,+?&=%\[\]()-]*$`)

func (c *ConsoleRunner) binary() string {
	if c.Binary != "" {
		return c.Binary
	}
	return "msfconsole"
}

// RunModule runs the module and returns the console output as evidence. Teardown
// happens IN the one msfconsole process: the resource script kills sessions and,
// crucially, that process exiting closes any it opened (sessions are owned by the
// instance that created them). So there are no sessions for the worker to chase,
// and cleanup is verified from this same instance's post-teardown session list —
// not a second msfconsole, which could never see this one's sessions.
func (c *ConsoleRunner) RunModule(ctx context.Context, spec ModuleSpec) (RunResult, error) {
	script, err := buildResourceScript(spec)
	if err != nil {
		return RunResult{}, err
	}
	dir, err := os.MkdirTemp("", "vulnascout-msf-*")
	if err != nil {
		return RunResult{}, err
	}
	defer func() { _ = os.RemoveAll(dir) }()
	f, err := os.Create(filepath.Join(dir, "module.rc"))
	if err != nil {
		return RunResult{}, err
	}
	if _, err := f.WriteString(script); err != nil {
		_ = f.Close()
		return RunResult{}, err
	}
	_ = f.Close()

	cmd := processutil.ScannerCommandContext(ctx, dir, c.binary(), "-q", "-n", "-r", f.Name())
	out, runErr := cmd.CombinedOutput()
	res := RunResult{
		Evidence: map[string]any{"console": string(out)},
		Success:  runErr == nil,
	}
	if ctx.Err() != nil {
		// Timed out/cancelled: CommandContext killed the process (which closes its
		// sessions), but the in-band "sessions -K; sessions -l" may not have run, so
		// we cannot CONFIRM cleanup. Leave CleanupVerified false -> backend flags it
		// cleanup_pending for manual verification.
		return res, ctx.Err()
	}
	// Verified only when this same instance's post-teardown session list showed none.
	res.CleanupVerified = noActiveSessions(string(out))
	return res, runErr
}

// StopSession kills one session by id.
func (c *ConsoleRunner) StopSession(ctx context.Context, id string) error {
	args, err := stopSessionArgs(id)
	if err != nil {
		return err
	}
	dir, err := os.MkdirTemp("", "vulnascout-msf-cleanup-*")
	if err != nil {
		return err
	}
	defer func() { _ = os.RemoveAll(dir) }()
	return processutil.ScannerCommandContext(ctx, dir, c.binary(), args...).Run()
}

// buildResourceScript renders a safe msfconsole resource script: use the module,
// set the (already scope-validated) target, payload, and options, run without
// interacting, then kill all sessions. Every interpolated value must match a
// conservative single-token grammar so it cannot become ERB or console source.
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
		// Never let an option re-set the validated target or approved payload: those
		// are written above from scope-checked fields, and a later `set RHOSTS ...`
		// would silently override the authorized target. Defense in depth — policy
		// validation already rejects these keys before we get here.
		switch strings.ToLower(strings.TrimSpace(k)) {
		case "rhosts", "rhost", "payload":
			return "", fmt.Errorf("option %q may not override the validated target/payload", k)
		}
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
	// Confirm teardown IN THE SAME console instance: sessions belong to the process
	// that opened them, so a separate msfconsole cannot see (or kill) them. After
	// "sessions -K", an empty session table prints "No active sessions"; RunModule
	// matches that to verify cleanup. If any session survived the kill, this instead
	// lists it, so the phrase is absent and cleanup is reported unverified.
	b.WriteString("sessions -l\n")
	b.WriteString("exit -y\n")
	return b.String(), nil
}

// noActiveSessions reports whether msfconsole's session list showed none. Only the
// empty "sessions -l" table prints this phrase, so its presence after teardown
// confirms — within the same instance — that no session remained.
func noActiveSessions(consoleOutput string) bool {
	return strings.Contains(consoleOutput, "No active sessions")
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

// safeToken accepts only a conservative single-token grammar. Metasploit parses
// resource files as ERB before executing console commands, so newline filtering
// alone cannot make interpolated text safe.
func safeToken(what, s string) error {
	if strings.ContainsAny(s, "\r\n") {
		return fmt.Errorf("%s contains a newline", what)
	}
	for _, r := range s {
		if r < 0x20 && r != '\t' {
			return fmt.Errorf("%s contains a control character", what)
		}
	}
	if !resourceTokenRE.MatchString(s) {
		return fmt.Errorf("%s is not a safe resource-file token", what)
	}
	return nil
}

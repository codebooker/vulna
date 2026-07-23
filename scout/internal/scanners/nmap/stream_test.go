package nmap

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/codebooker/vulna/scout/internal/policy"
)

const twoHostXML = `<?xml version="1.0"?>
<nmaprun scanner="nmap">
<host><status state="up"/><address addr="10.0.0.1" addrtype="ipv4"/>
<ports><port protocol="tcp" portid="22"><state state="open"/></port></ports>
<hostnames><hostname name="a.example"/></hostnames></host>
<host><status state="up"/><address addr="10.0.0.2" addrtype="ipv4"/>
<ports><port protocol="tcp" portid="80"><state state="open"/></port></ports></host>
</nmaprun>
`

func TestExtractCompleteHosts(t *testing.T) {
	// Two complete hosts plus a partially-written third (no closing tag yet).
	partial := twoHostXML[:len(twoHostXML)-len("</nmaprun>\n")] +
		`<host><status state="up"/><address addr="10.0.0.3"`
	hosts := extractCompleteHosts([]byte(partial))
	if len(hosts) != 2 {
		t.Fatalf("expected 2 complete hosts (partial third skipped), got %d", len(hosts))
	}
	if !bytes.Contains(hosts[0], []byte("10.0.0.1")) || !bytes.Contains(hosts[1], []byte("10.0.0.2")) {
		t.Errorf("hosts out of order or wrong: %q | %q", hosts[0], hosts[1])
	}
	// The <hostnames>/<hostname> inside host 1 must not be split out as its own host.
	if bytes.Count(hosts[0], []byte("</host>")) != 1 {
		t.Errorf("host 1 boundary wrong (hostnames mistaken for a host?): %q", hosts[0])
	}
}

func TestWrapHostsIsParseableNmaprun(t *testing.T) {
	doc := wrapHosts([][]byte{[]byte(`<host><address addr="10.0.0.9"/></host>`)})
	if !bytes.HasPrefix(bytes.TrimSpace(doc), []byte("<?xml")) {
		t.Errorf("missing xml prolog: %s", doc)
	}
	if !bytes.Contains(doc, []byte("<nmaprun>")) || !bytes.Contains(doc, []byte("</nmaprun>")) {
		t.Errorf("not wrapped in an nmaprun element: %s", doc)
	}
	if !bytes.Contains(doc, []byte("10.0.0.9")) {
		t.Errorf("host content missing: %s", doc)
	}
}

// writeFakeNmap installs a tiny stand-in that writes body to the path given after
// -oX, so Stream can be exercised without a real nmap binary.
func writeFakeNmap(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "fake-nmap")
	script := "#!/bin/sh\n" +
		"while [ $# -gt 0 ]; do if [ \"$1\" = \"-oX\" ]; then shift; OUT=\"$1\"; fi; shift; done\n" +
		"cat > \"$OUT\" <<'XMLEOF'\n" + body + "XMLEOF\n"
	if err := os.WriteFile(p, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return p
}

// writeTwoPassFakeNmap records each invocation, emits responsivenessXML for
// QuickPorts, and emits scanXML for the thorough pass. When failResponsive is
// true, the first invocation fails so fallback behavior can be tested.
func writeTwoPassFakeNmap(
	t *testing.T,
	responsivenessXML string,
	scanXML string,
	failResponsive bool,
) (string, string) {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "fake-nmap")
	logPath := filepath.Join(dir, "args.log")
	fail := "false"
	if failResponsive {
		fail = "true"
	}
	script := "#!/bin/sh\n" +
		"ORIGINAL=\"$*\"\nPORTS=\"\"\nOUT=\"\"\n" +
		"while [ $# -gt 0 ]; do\n" +
		"  if [ \"$1\" = \"-p\" ]; then shift; PORTS=\"$1\"; fi\n" +
		"  if [ \"$1\" = \"-oX\" ]; then shift; OUT=\"$1\"; fi\n" +
		"  shift\n" +
		"done\n" +
		"printf '%s\\n' \"$ORIGINAL\" >> \"" + logPath + "\"\n" +
		"if [ \"$PORTS\" = \"" + QuickPorts + "\" ]; then\n" +
		"  if " + fail + "; then exit 2; fi\n" +
		"  cat > \"$OUT\" <<'RESPONSIVENESS_EOF'\n" +
		strings.TrimSuffix(responsivenessXML, "\n") + "\n" +
		"RESPONSIVENESS_EOF\n" +
		"else\n" +
		"  cat > \"$OUT\" <<'SCAN_EOF'\n" +
		strings.TrimSuffix(scanXML, "\n") + "\n" +
		"SCAN_EOF\n" +
		"fi\n"
	if err := os.WriteFile(p, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return p, logPath
}

const mixedResponsivenessXML = `<?xml version="1.0"?>
<nmaprun scanner="nmap">
<host><status state="up"/><address addr="10.0.0.1" addrtype="ipv4"/>
<ports><port protocol="tcp" portid="22"><state state="open"/></port></ports></host>
<host><status state="up"/><address addr="10.0.0.2" addrtype="ipv4"/>
<ports><port protocol="tcp" portid="80"><state state="closed"/></port></ports></host>
<host><status state="up"/><address addr="10.0.0.3" addrtype="ipv4"/>
<ports><port protocol="tcp" portid="443"><state state="filtered"/></port></ports></host>
</nmaprun>
`

func TestStreamHarvestsAndEmitsHosts(t *testing.T) {
	w := &Worker{
		Binary:  writeFakeNmap(t, twoHostXML),
		Profile: SafeDiscoveryProfile(),
		Timeout: 30 * time.Second,
	}
	job := &policy.Job{JobID: "j1", Targets: []string{"10.0.0.0/30"}}

	var batches [][]byte
	var lastProgress int
	err := w.Stream(context.Background(), job,
		func(raw []byte) error { batches = append(batches, raw); return nil },
		func(done int) { lastProgress = done },
	)
	if err != nil {
		t.Fatal(err)
	}
	if lastProgress != 2 {
		t.Errorf("progress should report 2 completed hosts, got %d", lastProgress)
	}
	joined := bytes.Join(batches, nil)
	if !bytes.Contains(joined, []byte("10.0.0.1")) || !bytes.Contains(joined, []byte("10.0.0.2")) {
		t.Errorf("both hosts should have been emitted: %s", joined)
	}
	for _, b := range batches {
		if !bytes.Contains(b, []byte("<nmaprun>")) {
			t.Errorf("each emitted batch must be a wrapped nmaprun doc: %s", b)
		}
	}
}

func TestResponsiveTargetsRequiresAnActualTCPAnswer(t *testing.T) {
	targets, err := responsiveTargets([]byte(mixedResponsivenessXML))
	if err != nil {
		t.Fatal(err)
	}
	if got, want := strings.Join(targets, ","), "10.0.0.1,10.0.0.2"; got != want {
		t.Fatalf("responsive targets = %q, want %q", got, want)
	}
	if _, err := responsiveTargets([]byte("<not-closed")); err == nil {
		t.Fatal("malformed XML should fail instead of returning an empty target set")
	}
}

func TestRunUsesFastPassThenScansOnlyResponsiveHosts(t *testing.T) {
	binary, logPath := writeTwoPassFakeNmap(
		t,
		mixedResponsivenessXML,
		twoHostXML,
		false,
	)
	w := &Worker{Binary: binary, Profile: SafeDiscoveryProfile(), Timeout: 30 * time.Second}
	job := &policy.Job{
		JobID:   "j-two-pass",
		Targets: []string{"10.0.0.0/29"},
		Workflow: []map[string]any{{
			"stage":  "discovery",
			"plugin": "nmap",
			"config": map[string]any{"discovery_strategy": responsiveHostsStrategy},
		}},
	}
	raw, err := w.Run(context.Background(), job)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(raw, []byte("10.0.0.1")) {
		t.Fatalf("thorough output was not returned: %s", raw)
	}
	logged, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(logged)), "\n")
	if len(lines) != 2 {
		t.Fatalf("nmap invocations = %d, want 2: %q", len(lines), logged)
	}
	if !strings.Contains(lines[0], QuickPorts) || strings.Contains(lines[0], "-sV") {
		t.Errorf("first pass was not compact/non-versioned: %s", lines[0])
	}
	if !strings.Contains(lines[1], ImportantPorts) || !strings.Contains(lines[1], "-sV") {
		t.Errorf("second pass was not the thorough service scan: %s", lines[1])
	}
	for _, target := range []string{"10.0.0.1", "10.0.0.2"} {
		if !strings.Contains(lines[1], target) {
			t.Errorf("thorough pass missing responsive target %s: %s", target, lines[1])
		}
	}
	for _, skipped := range []string{"10.0.0.0/29", "10.0.0.3"} {
		if strings.Contains(lines[1], skipped) {
			t.Errorf("thorough pass retained non-responsive target %s: %s", skipped, lines[1])
		}
	}
}

func TestRunFallsBackToExhaustiveTargetsWhenFastPassFails(t *testing.T) {
	binary, logPath := writeTwoPassFakeNmap(t, mixedResponsivenessXML, twoHostXML, true)
	w := &Worker{Binary: binary, Profile: SafeDiscoveryProfile(), Timeout: 30 * time.Second}
	job := &policy.Job{
		JobID:   "j-fallback",
		Targets: []string{"10.0.0.0/29"},
		Workflow: []map[string]any{{
			"stage":  "discovery",
			"plugin": "nmap",
			"config": map[string]any{"discovery_strategy": responsiveHostsStrategy},
		}},
	}
	if _, err := w.Run(context.Background(), job); err != nil {
		t.Fatal(err)
	}
	logged, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(logged)), "\n")
	if len(lines) != 2 || !strings.Contains(lines[1], "10.0.0.0/29") {
		t.Fatalf("failed fast pass did not fall back to original scope: %q", logged)
	}
}

func TestStreamUsesTwoPassTargets(t *testing.T) {
	binary, logPath := writeTwoPassFakeNmap(
		t,
		mixedResponsivenessXML,
		twoHostXML,
		false,
	)
	w := &Worker{Binary: binary, Profile: SafeDiscoveryProfile(), Timeout: 30 * time.Second}
	job := &policy.Job{
		JobID:   "j-stream-two-pass",
		Targets: []string{"10.0.0.0/29"},
		Workflow: []map[string]any{{
			"stage":  "discovery",
			"plugin": "nmap",
			"config": map[string]any{"discovery_strategy": responsiveHostsStrategy},
		}},
	}
	var batches [][]byte
	err := w.Stream(
		context.Background(),
		job,
		func(raw []byte) error {
			batches = append(batches, raw)
			return nil
		},
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	if joined := bytes.Join(batches, nil); !bytes.Contains(joined, []byte("10.0.0.1")) {
		t.Fatalf("stream did not emit thorough scan output: %s", joined)
	}
	logged, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(logged)), "\n")
	if len(lines) != 2 || strings.Contains(lines[1], "10.0.0.0/29") {
		t.Fatalf("stream did not narrow its thorough pass: %q", logged)
	}
}

func TestStreamSkipsThoroughPassWhenNoHostAnswers(t *testing.T) {
	filteredOnly := `<?xml version="1.0"?><nmaprun><host><status state="up"/>
<address addr="10.0.0.3" addrtype="ipv4"/><ports><port protocol="tcp" portid="443">
<state state="filtered"/></port></ports></host></nmaprun>`
	binary, logPath := writeTwoPassFakeNmap(t, filteredOnly, twoHostXML, false)
	w := &Worker{Binary: binary, Profile: SafeDiscoveryProfile(), Timeout: 30 * time.Second}
	job := &policy.Job{
		JobID:   "j-no-response",
		Targets: []string{"10.0.0.0/29"},
		Workflow: []map[string]any{{
			"stage":  "discovery",
			"plugin": "nmap",
			"config": map[string]any{"discovery_strategy": responsiveHostsStrategy},
		}},
	}
	emitted := 0
	if err := w.Stream(
		context.Background(),
		job,
		func([]byte) error {
			emitted++
			return nil
		},
		nil,
	); err != nil {
		t.Fatal(err)
	}
	if emitted != 0 {
		t.Fatalf("filtered-only scope emitted %d thorough result batches", emitted)
	}
	logged, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	if lines := strings.Split(strings.TrimSpace(string(logged)), "\n"); len(lines) != 1 {
		t.Fatalf("filtered-only scope invoked nmap %d times, want 1: %q", len(lines), logged)
	}
}

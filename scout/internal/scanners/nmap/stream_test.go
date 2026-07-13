package nmap

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
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

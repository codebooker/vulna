package nuclei

import (
	"context"
	"testing"

	"github.com/codebooker/vulna/scout/internal/policy"
)

func TestScanIntegrityFailure(t *testing.T) {
	cases := []struct {
		name   string
		stderr string
		broken bool
	}{
		{"zero templates loaded", "[INF] Templates loaded for current scan: 0\n", true},
		{
			"genuine scan that matched nothing",
			"[INF] Templates loaded for current scan: 71\n" +
				`{"duration":"0:00:03","errors":"2","requests":"350","matched":"0","templates":"71"}` + "\n",
			false,
		},
		{
			"every request errored",
			"[INF] Templates loaded for current scan: 71\n" + `{"errors":"74","requests":"74"}` + "\n",
			true,
		},
		{
			"zero requests sent",
			"[INF] Templates loaded for current scan: 71\n" + `{"errors":"0","requests":"0"}` + "\n",
			true,
		},
		{"no parseable signals is trusted", "some unrelated output\n", false},
	}
	for _, c := range cases {
		got := scanIntegrityFailure([]byte(c.stderr))
		if c.broken && got == "" {
			t.Errorf("%s: expected an integrity failure, got none", c.name)
		}
		if !c.broken && got != "" {
			t.Errorf("%s: expected a trusted run, got failure %q", c.name, got)
		}
	}
}

// fakeNucleiEmitting installs a stand-in that creates the (empty) -output file and
// writes the given content to stderr, so Run's integrity check can be exercised.
func fakeNucleiEmitting(t *testing.T, stderrContent string) string {
	body := "while [ $# -gt 0 ]; do if [ \"$1\" = \"-output\" ]; then shift; OUT=\"$1\"; fi; shift; done\n" +
		": > \"$OUT\"\n" +
		"cat >&2 <<'STDERREOF'\n" + stderrContent + "STDERREOF"
	return writeFakeNuclei(t, body)
}

func TestRunFailsLoudlyWhenNoTemplatesLoad(t *testing.T) {
	w := &Worker{
		Binary:     fakeNucleiEmitting(t, "[INF] Templates loaded for current scan: 0\n"),
		Severities: safeSeverities,
	}
	_, err := w.Run(context.Background(), &policy.Job{JobID: "j", Targets: []string{"10.0.0.1"}})
	if err == nil {
		t.Fatal("a scan that loaded 0 templates must fail, not report a clean result")
	}
}

func TestRunSucceedsOnGenuineCleanScan(t *testing.T) {
	stderr := "[INF] Templates loaded for current scan: 71\n" + `{"requests":"350","errors":"1"}` + "\n"
	w := &Worker{Binary: fakeNucleiEmitting(t, stderr), Severities: safeSeverities}
	out, err := w.Run(context.Background(), &policy.Job{JobID: "j", Targets: []string{"10.0.0.1"}})
	if err != nil {
		t.Fatalf("a genuine clean scan must succeed: %v", err)
	}
	if len(out) != 0 {
		t.Errorf("expected empty no-findings output, got %d bytes", len(out))
	}
}

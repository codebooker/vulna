package processutil

import (
	"strings"
	"testing"
	"unicode/utf8"
)

func TestBoundedDiagnosticPreservesStartupAndTerminalFailure(t *testing.T) {
	input := "startup warning\n" + strings.Repeat("progress\n", 200) + "fatal: killed by signal"
	got := BoundedDiagnostic(input, 180)
	if utf8.RuneCountInString(got) > 180 {
		t.Fatalf("diagnostic contains %d runes", utf8.RuneCountInString(got))
	}
	if !strings.Contains(got, "startup warning") ||
		!strings.Contains(got, "scanner output truncated") ||
		!strings.Contains(got, "fatal: killed by signal") {
		t.Fatalf("diagnostic did not retain useful boundaries: %q", got)
	}
}

func TestBoundedDiagnosticLeavesShortOutputUntouched(t *testing.T) {
	if got := BoundedDiagnostic("  short failure\n", 100); got != "short failure" {
		t.Fatalf("got %q", got)
	}
}

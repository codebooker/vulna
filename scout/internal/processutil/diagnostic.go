package processutil

import (
	"strings"
	"unicode/utf8"
)

const diagnosticMarker = "\n… scanner output truncated; final output follows …\n"

// BoundedDiagnostic keeps both startup errors and the final failure from a
// noisy scanner. Keeping only the prefix hid terminal messages after long
// Nuclei runs because the API correctly bounds stored diagnostics.
func BoundedDiagnostic(value string, limit int) string {
	value = strings.TrimSpace(value)
	if limit <= 0 || value == "" {
		return ""
	}
	if utf8.RuneCountInString(value) <= limit {
		return value
	}
	marker := []rune(diagnosticMarker)
	if limit <= len(marker)+2 {
		return string([]rune(value)[:limit])
	}
	remaining := limit - len(marker)
	headCount := remaining / 3
	tailCount := remaining - headCount
	runes := []rune(value)
	return string(runes[:headCount]) + diagnosticMarker + string(runes[len(runes)-tailCount:])
}

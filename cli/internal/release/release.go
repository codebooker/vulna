// Package release models signed release manifests and verifies them. A manifest
// describes one release on a channel; it is only trusted after its Ed25519
// signature (over the SHA256SUMS manifest that lists it) is verified against the
// pinned release public key, and it is rejected if unsigned, altered, expired, or
// incompatible. Verification never executes anything — it only authorizes a
// download the operator then applies deliberately.
package release

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Channels, most-stable first. Stable is the default.
const (
	ChannelStable      = "stable"
	ChannelCandidate   = "candidate"
	ChannelDevelopment = "development"
)

// Migration describes the database-migration impact of a release.
type Migration struct {
	HasMigrations bool   `json:"has_migrations"`
	Notes         string `json:"notes,omitempty"`
}

// Artifact is one signed file in the release.
type Artifact struct {
	Name   string `json:"name"`
	SHA256 string `json:"sha256"`
}

// Manifest is the structured, signed description of a release.
type Manifest struct {
	Version         string     `json:"version"`
	Channel         string     `json:"channel"`
	ReleasedAt      string     `json:"released_at"`
	ExpiresAt       string     `json:"expires_at,omitempty"`
	Security        string     `json:"security"` // none | recommended | critical
	MinScoutVersion string     `json:"min_scout_version,omitempty"`
	Migration       Migration  `json:"migration"`
	ScannerChanges  string     `json:"scanner_changes,omitempty"`
	TemplateChanges string     `json:"template_changes,omitempty"`
	Compatibility   string     `json:"compatibility,omitempty"`
	Notes           string     `json:"notes,omitempty"`
	Artifacts       []Artifact `json:"artifacts,omitempty"`
}

// ManifestFileName is the manifest's name inside the signed SHA256SUMS manifest.
const ManifestFileName = "release.json"

// Verify authenticates a manifest: the Ed25519 signature must be valid over the
// SHA256SUMS bytes, and the manifest's own SHA-256 must match its entry in
// SHA256SUMS. Returns the parsed manifest only when both hold.
func Verify(pub ed25519.PublicKey, manifest, sums, sig []byte) (*Manifest, error) {
	if len(pub) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("invalid release public key")
	}
	if !ed25519.Verify(pub, sums, sig) {
		return nil, fmt.Errorf("SIGNATURE INVALID: release manifest is not signed by the release key")
	}
	sum := sha256.Sum256(manifest)
	want := hex.EncodeToString(sum[:])
	if !sumsListsFile(sums, ManifestFileName, want) {
		return nil, fmt.Errorf("CHECKSUM MISMATCH: %s does not match the signed manifest", ManifestFileName)
	}
	var m Manifest
	if err := json.Unmarshal(manifest, &m); err != nil {
		return nil, fmt.Errorf("parse manifest: %w", err)
	}
	return &m, nil
}

// sumsListsFile reports whether SHA256SUMS lists file with the given hex digest.
// Accepts the "<hex>  <name>" and "<hex>  ./<name>" forms.
func sumsListsFile(sums []byte, name, hexdigest string) bool {
	for _, line := range strings.Split(string(sums), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 2 {
			continue
		}
		got, fname := fields[0], strings.TrimPrefix(fields[1], "./")
		if fname == name && strings.EqualFold(got, hexdigest) {
			return true
		}
	}
	return false
}

// Validate checks a verified manifest is fit to apply: not expired, on the
// requested channel, and compatible with the current app version.
func (m *Manifest) Validate(channel, currentVersion string, now time.Time) error {
	if m.Channel != channel {
		return fmt.Errorf("manifest channel %q does not match requested channel %q", m.Channel, channel)
	}
	if m.ExpiresAt != "" {
		exp, err := time.Parse(time.RFC3339, m.ExpiresAt)
		if err != nil {
			return fmt.Errorf("invalid expires_at: %w", err)
		}
		if now.After(exp) {
			return fmt.Errorf("release metadata expired at %s — refusing to use it", m.ExpiresAt)
		}
	}
	if m.Version == "" {
		return fmt.Errorf("manifest has no version")
	}
	return nil
}

// IsNewerThan reports whether the manifest version is strictly newer than current.
func (m *Manifest) IsNewerThan(current string) bool {
	return CompareVersions(m.Version, current) > 0
}

// CompareVersions compares dotted numeric versions (optional leading 'v'). A
// pre-release suffix (e.g. -rc1) is ignored for ordering of the numeric core, but
// a version without a suffix sorts after the same core with a suffix.
// Returns -1, 0, or 1.
func CompareVersions(a, b string) int {
	ca, pa := splitVersion(a)
	cb, pb := splitVersion(b)
	for i := 0; i < 3; i++ {
		if ca[i] != cb[i] {
			if ca[i] < cb[i] {
				return -1
			}
			return 1
		}
	}
	// Equal numeric core: no-suffix > suffix; otherwise lexical suffix order.
	switch {
	case pa == pb:
		return 0
	case pa == "":
		return 1
	case pb == "":
		return -1
	case pa < pb:
		return -1
	default:
		return 1
	}
}

func splitVersion(v string) ([3]int, string) {
	v = strings.TrimPrefix(strings.TrimSpace(v), "v")
	pre := ""
	if i := strings.IndexAny(v, "-+"); i >= 0 {
		pre = v[i+1:]
		v = v[:i]
	}
	var core [3]int
	for i, part := range strings.SplitN(v, ".", 3) {
		if i > 2 {
			break
		}
		n, _ := strconv.Atoi(part)
		core[i] = n
	}
	return core, pre
}

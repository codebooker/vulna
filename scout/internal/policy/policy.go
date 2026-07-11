package policy

import (
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"net/netip"
	"slices"
)

// Limits are the resource limits carried in the local policy.
type Limits struct {
	MaxHosts            int `json:"max_hosts"`
	MaxParallelHosts    int `json:"max_parallel_hosts"`
	MaxPacketsPerSecond int `json:"max_packets_per_second"`
	MaxDurationSeconds  int `json:"max_duration_seconds"`
}

// Policy is a verified local policy document.
type Policy struct {
	PolicyVersion        int      `json:"policy_version"`
	ProbeID              string   `json:"probe_id"`
	SiteID               string   `json:"site_id"`
	ApprovedCIDRs        []string `json:"approved_cidrs"`
	DeniedCIDRs          []string `json:"denied_cidrs"`
	AllowPublicAddresses bool     `json:"allow_public_addresses"`
	AllowedModes         []string `json:"allowed_modes"`
	AllowedPlugins       []string `json:"allowed_plugins"`
	Limits               Limits   `json:"limits"`

	approved []netip.Prefix
	denied   []netip.Prefix
}

// Parse verifies a signed policy document with pub and returns the Policy.
func Parse(raw []byte, pub ed25519.PublicKey) (*Policy, error) {
	doc, err := VerifyDocument(raw, pub)
	if err != nil {
		return nil, err
	}
	// Re-marshal the verified document into the typed struct. json.Number values
	// marshal back to their literal digits, so integer fields parse cleanly.
	b, err := json.Marshal(doc)
	if err != nil {
		return nil, err
	}
	var p Policy
	if err := json.Unmarshal(b, &p); err != nil {
		return nil, fmt.Errorf("parse policy fields: %w", err)
	}
	if err := p.compile(); err != nil {
		return nil, err
	}
	return &p, nil
}

func (p *Policy) compile() error {
	for _, c := range p.ApprovedCIDRs {
		pfx, err := netip.ParsePrefix(c)
		if err != nil {
			return fmt.Errorf("approved cidr %q: %w", c, err)
		}
		p.approved = append(p.approved, pfx.Masked())
	}
	for _, c := range p.DeniedCIDRs {
		pfx, err := netip.ParsePrefix(c)
		if err != nil {
			return fmt.Errorf("denied cidr %q: %w", c, err)
		}
		p.denied = append(p.denied, pfx.Masked())
	}
	return nil
}

// AllowsMode reports whether the given assessment mode is permitted.
func (p *Policy) AllowsMode(mode string) error {
	if slices.Contains(p.AllowedModes, mode) {
		return nil
	}
	return fmt.Errorf("mode %q is not permitted by local policy", mode)
}

// AllowsPlugins reports whether every plugin named in the job workflow is
// permitted by the local policy. An empty AllowedPlugins list permits none: a
// policy that grants no plugins cannot run a workflow that names any.
func (p *Policy) AllowsPlugins(workflow []map[string]any) error {
	for _, stage := range workflow {
		name, ok := stage["plugin"].(string)
		if !ok || name == "" {
			continue
		}
		if !slices.Contains(p.AllowedPlugins, name) {
			return fmt.Errorf("plugin %q is not permitted by local policy", name)
		}
	}
	return nil
}

// AllowsTarget reports whether an IP or CIDR target is within approved scope,
// not within a denied range, and (unless allowed) not a public address.
func (p *Policy) AllowsTarget(target string) error {
	t, err := parseTargetPrefix(target)
	if err != nil {
		return err
	}
	if !p.contains(t) {
		return fmt.Errorf("target %s is outside the approved scope", target)
	}
	for _, d := range p.denied {
		if d.Overlaps(t) {
			return fmt.Errorf("target %s is within a denied range", target)
		}
	}
	if !p.AllowPublicAddresses && !isPrivatePrefix(t) {
		return fmt.Errorf("target %s is a public address and public scanning is disabled", target)
	}
	return nil
}

func (p *Policy) contains(t netip.Prefix) bool {
	for _, a := range p.approved {
		// t is fully contained in a iff a is not more specific and a covers t's
		// network address.
		if a.Bits() <= t.Bits() && a.Contains(t.Addr()) {
			return true
		}
	}
	return false
}

// parseTargetPrefix accepts a bare IP (treated as /32 or /128) or a CIDR.
func parseTargetPrefix(target string) (netip.Prefix, error) {
	if addr, err := netip.ParseAddr(target); err == nil {
		return netip.PrefixFrom(addr, addr.BitLen()), nil
	}
	pfx, err := netip.ParsePrefix(target)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("invalid target %q: %w", target, err)
	}
	return pfx.Masked(), nil
}

func isPrivatePrefix(t netip.Prefix) bool {
	a := t.Addr()
	return a.IsPrivate() || a.IsLoopback() || a.IsLinkLocalUnicast() || a.IsLinkLocalMulticast()
}

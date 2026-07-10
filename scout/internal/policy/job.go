package policy

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// ErrExpired indicates a job's expiry time has passed.
var ErrExpired = errors.New("job has expired")

// ErrNotYetValid indicates a job's not_before time is in the future.
var ErrNotYetValid = errors.New("job is not yet valid")

// Job is a verified job envelope (build plan Section 11.3).
type Job struct {
	JobID         string           `json:"job_id"`
	ProbeID       string           `json:"probe_id"`
	SiteID        string           `json:"site_id"`
	Mode          string           `json:"mode"`
	PolicyVersion int              `json:"policy_version"`
	NotBefore     string           `json:"not_before"`
	ExpiresAt     string           `json:"expires_at"`
	Targets       []string         `json:"targets"`
	Workflow      []map[string]any `json:"workflow"`
	Limits        Limits           `json:"limits"`
}

// VerifyJob verifies a signed job envelope and enforces it against the local
// policy: the signature must be valid (rejecting altered jobs), the current
// time must be within [not_before, expires_at] (rejecting expired jobs), the
// mode must be permitted, and every target must be within the approved scope
// (rejecting out-of-scope targets). Pass the current time for deterministic
// tests.
func VerifyJob(raw []byte, pub ed25519.PublicKey, p *Policy, now time.Time) (*Job, error) {
	doc, err := VerifyDocument(raw, pub)
	if err != nil {
		return nil, err
	}
	b, err := json.Marshal(doc)
	if err != nil {
		return nil, err
	}
	var job Job
	if err := json.Unmarshal(b, &job); err != nil {
		return nil, fmt.Errorf("parse job fields: %w", err)
	}

	notBefore, err := time.Parse(time.RFC3339, job.NotBefore)
	if err != nil {
		return nil, fmt.Errorf("invalid not_before %q: %w", job.NotBefore, err)
	}
	expiresAt, err := time.Parse(time.RFC3339, job.ExpiresAt)
	if err != nil {
		return nil, fmt.Errorf("invalid expires_at %q: %w", job.ExpiresAt, err)
	}
	if now.After(expiresAt) {
		return nil, ErrExpired
	}
	if now.Before(notBefore) {
		return nil, ErrNotYetValid
	}

	if p != nil {
		if err := p.AllowsMode(job.Mode); err != nil {
			return nil, err
		}
		if len(job.Targets) == 0 {
			return nil, errors.New("job has no targets")
		}
		for _, t := range job.Targets {
			if err := p.AllowsTarget(t); err != nil {
				return nil, err
			}
		}
	}
	return &job, nil
}

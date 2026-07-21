package policy

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
)

// ErrExpired indicates a job's expiry time has passed.
var ErrExpired = errors.New("job has expired")

// ErrNotYetValid indicates a job's not_before time is in the future.
var ErrNotYetValid = errors.New("job is not yet valid")

// ErrNoPolicy indicates no local policy is loaded. The Scout is an independent
// safety boundary: without a policy it cannot enforce scope, mode, or limits, so
// it refuses to run any job rather than trusting the orchestrator's word.
var ErrNoPolicy = errors.New("no local policy is loaded; refusing to run jobs (fail closed)")

// hostSaturation caps host-count arithmetic so a huge (e.g. IPv6) target range
// can't overflow. Any realistic max_hosts limit is far below this.
const hostSaturation = 1 << 30

// Job is a verified job envelope (build plan Section 11.3).
type Job struct {
	SchemaVersion      int                 `json:"schema_version"`
	JobID              string              `json:"job_id"`
	ProbeID            string              `json:"probe_id"`
	SiteID             string              `json:"site_id"`
	Mode               string              `json:"mode"`
	ProfileVersion     int                 `json:"profile_version"`
	PolicyVersion      int                 `json:"policy_version"`
	NotBefore          string              `json:"not_before"`
	ExpiresAt          string              `json:"expires_at"`
	Targets            []string            `json:"targets"`
	Workflow           []map[string]any    `json:"workflow"`
	Limits             Limits              `json:"limits"`
	CredentialEnvelope *CredentialEnvelope `json:"credential_envelope,omitempty"`
	Credentials        []Credential        `json:"-"`
	// ScopeTargets is populated only in memory by the workflow runner before a
	// service-aware adapter replaces Targets with discovered endpoints. It retains
	// the original, signed and policy-verified IP/CIDR scope for adapters such as
	// ZAP to re-check derived URLs immediately before execution.
	ScopeTargets []string `json:"-"`
}

// CredentialEnvelope is signed with the job but encrypted to one Scout's
// enrollment key. It never contains plaintext credential material.
type CredentialEnvelope struct {
	Version               string `json:"version"`
	Algorithm             string `json:"algorithm"`
	EphemeralPublicKeyB64 string `json:"ephemeral_public_key_b64"`
	NonceB64              string `json:"nonce_b64"`
	CiphertextB64         string `json:"ciphertext_b64"`
}

// Credential exists only in memory for the lifetime of one verified job.
type Credential struct {
	CredentialID    string         `json:"credential_id"`
	SecretVersionID string         `json:"secret_version_id"`
	Protocol        string         `json:"protocol"`
	AuthType        string         `json:"auth_type"`
	Username        string         `json:"username"`
	Secret          string         `json:"secret"`
	Metadata        map[string]any `json:"metadata"`
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
	if job.SchemaVersion != 1 {
		return nil, fmt.Errorf("unsupported job schema_version %d", job.SchemaVersion)
	}
	if job.ProfileVersion < 1 {
		return nil, fmt.Errorf("invalid job profile_version %d", job.ProfileVersion)
	}

	notBefore, err := time.Parse(time.RFC3339, job.NotBefore)
	if err != nil {
		return nil, fmt.Errorf("invalid not_before %q: %w", job.NotBefore, err)
	}
	expiresAt, err := time.Parse(time.RFC3339, job.ExpiresAt)
	if err != nil {
		return nil, fmt.Errorf("invalid expires_at %q: %w", job.ExpiresAt, err)
	}
	if !now.Before(expiresAt) {
		return nil, ErrExpired
	}
	if now.Before(notBefore) {
		return nil, ErrNotYetValid
	}

	// Fail closed: with no local policy the Scout cannot enforce its own scope,
	// mode, or resource limits, so it refuses the job outright rather than
	// trusting a correctly-signed-but-unbounded orchestrator response.
	if p == nil {
		return nil, ErrNoPolicy
	}

	// The job must be for this probe/site and match the policy the Scout holds;
	// a version skew means the two disagree on scope and the job is refused.
	if job.PolicyVersion != p.PolicyVersion {
		return nil, fmt.Errorf(
			"job policy_version %d does not match local policy version %d",
			job.PolicyVersion, p.PolicyVersion,
		)
	}
	if p.ProbeID != "" && job.ProbeID != p.ProbeID {
		return nil, fmt.Errorf(
			"job probe_id %q is not this probe (%q)", job.ProbeID, p.ProbeID,
		)
	}
	if p.SiteID != "" && job.SiteID != p.SiteID {
		return nil, fmt.Errorf(
			"job site_id %q does not match local policy site %q", job.SiteID, p.SiteID,
		)
	}

	if err := p.AllowsMode(job.Mode); err != nil {
		return nil, err
	}
	if len(job.Targets) == 0 {
		return nil, errors.New("job has no targets")
	}

	total := 0
	for _, t := range job.Targets {
		if err := p.AllowsTarget(t); err != nil {
			return nil, err
		}
		n, err := hostCount(t)
		if err != nil {
			return nil, err
		}
		total += n
		if total > hostSaturation {
			total = hostSaturation
		}
	}
	if p.Limits.MaxHosts > 0 && total > p.Limits.MaxHosts {
		return nil, fmt.Errorf(
			"job spans %d hosts, exceeding the local policy limit of %d",
			total, p.Limits.MaxHosts,
		)
	}

	// The job's own declared limits may not exceed the policy's ceilings.
	if err := enforceLimits(job.Limits, p.Limits); err != nil {
		return nil, err
	}
	// Every workflow stage and its safety profile must be permitted by the local
	// policy. In particular, the presence of the ZAP binary/plugin does not grant
	// permission to use its limited-active profile.
	if err := p.AllowsWorkflow(job.Workflow); err != nil {
		return nil, err
	}
	if job.CredentialEnvelope != nil && !p.CredentialedScansAllowed {
		return nil, errors.New("credentialed scans are not permitted by local policy")
	}
	return &job, nil
}

// DecryptCredentialEnvelope decrypts a signed envelope after VerifyJob has
// already enforced signature, expiry, scope, mode, limits, and plugin policy.
// The returned values are attached only to the in-memory Job.
func DecryptCredentialEnvelope(job *Job, privateKeyBytes []byte) error {
	if job.CredentialEnvelope == nil {
		return nil
	}
	if len(privateKeyBytes) == 0 {
		return errors.New("credential envelope present but Scout has no encryption key")
	}
	envelope := job.CredentialEnvelope
	if envelope.Version != "1" || envelope.Algorithm != "X25519-HKDF-SHA256-CHACHA20POLY1305" {
		return errors.New("unsupported credential envelope")
	}
	privateKey, err := ecdh.X25519().NewPrivateKey(privateKeyBytes)
	if err != nil {
		return fmt.Errorf("invalid Scout credential key: %w", err)
	}
	publicBytes, err := base64.StdEncoding.DecodeString(envelope.EphemeralPublicKeyB64)
	if err != nil {
		return errors.New("invalid credential envelope public key")
	}
	publicKey, err := ecdh.X25519().NewPublicKey(publicBytes)
	if err != nil {
		return errors.New("invalid credential envelope public key")
	}
	shared, err := privateKey.ECDH(publicKey)
	if err != nil {
		return errors.New("credential envelope key agreement failed")
	}
	key, err := hkdf.Key(
		sha256.New,
		shared,
		nil,
		"vulna-scout-credential-envelope-v1",
		chacha20poly1305.KeySize,
	)
	if err != nil {
		return errors.New("credential envelope key derivation failed")
	}
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return errors.New("credential envelope cipher unavailable")
	}
	nonce, err := base64.StdEncoding.DecodeString(envelope.NonceB64)
	if err != nil {
		return errors.New("invalid credential envelope nonce")
	}
	ciphertext, err := base64.StdEncoding.DecodeString(envelope.CiphertextB64)
	if err != nil {
		return errors.New("invalid credential envelope ciphertext")
	}
	aad := []byte(job.JobID + ":" + job.ProbeID)
	plaintext, err := aead.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		return errors.New("credential envelope authentication failed")
	}
	defer func() {
		for i := range plaintext {
			plaintext[i] = 0
		}
	}()
	var payload struct {
		Version     int          `json:"version"`
		JobID       string       `json:"job_id"`
		ProbeID     string       `json:"probe_id"`
		ExpiresAt   string       `json:"expires_at"`
		Credentials []Credential `json:"credentials"`
	}
	if err := json.Unmarshal(plaintext, &payload); err != nil {
		return errors.New("credential envelope payload is invalid")
	}
	if payload.Version != 1 || payload.JobID != job.JobID || payload.ProbeID != job.ProbeID || payload.ExpiresAt != job.ExpiresAt {
		return errors.New("credential envelope is not bound to this job")
	}
	seen := make(map[string]bool, len(payload.Credentials))
	for _, credential := range payload.Credentials {
		if credential.Protocol != "ssh" && credential.Protocol != "winrm" {
			return errors.New("credential envelope contains an unsupported protocol")
		}
		if credential.Secret == "" || credential.Username == "" || seen[credential.Protocol] {
			return errors.New("credential envelope contains invalid or duplicate credentials")
		}
		seen[credential.Protocol] = true
	}
	if len(payload.Credentials) == 0 {
		return errors.New("credential envelope contains no credentials")
	}
	job.Credentials = payload.Credentials
	return nil
}

// ClearCredentials drops in-memory references as soon as the collector exits.
func (j *Job) ClearCredentials() {
	for i := range j.Credentials {
		j.Credentials[i].Secret = ""
		j.Credentials[i].Username = ""
		j.Credentials[i].Metadata = nil
	}
	j.Credentials = nil
}

// hostCount returns the number of addresses a target IP or CIDR spans, saturated
// at hostSaturation so an oversized range can't overflow the running total.
func hostCount(target string) (int, error) {
	t, err := parseTargetPrefix(target)
	if err != nil {
		return 0, err
	}
	hostBits := t.Addr().BitLen() - t.Bits()
	if hostBits >= 30 {
		return hostSaturation, nil
	}
	return 1 << hostBits, nil
}

// enforceLimits rejects a job whose declared limits exceed the policy ceilings.
// A zero policy ceiling means "unset" and is not enforced.
func enforceLimits(job, pol Limits) error {
	checks := []struct {
		name       string
		job, limit int
	}{
		{"max_hosts", job.MaxHosts, pol.MaxHosts},
		{"max_parallel_hosts", job.MaxParallelHosts, pol.MaxParallelHosts},
		{"max_packets_per_second", job.MaxPacketsPerSecond, pol.MaxPacketsPerSecond},
		{"max_duration_seconds", job.MaxDurationSeconds, pol.MaxDurationSeconds},
	}
	for _, c := range checks {
		if c.limit > 0 && c.job > c.limit {
			return fmt.Errorf(
				"job %s (%d) exceeds the local policy limit (%d)", c.name, c.job, c.limit,
			)
		}
	}
	return nil
}

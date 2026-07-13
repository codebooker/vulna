package policy

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"

	"golang.org/x/crypto/chacha20poly1305"
)

func encryptedCredentialEnvelope(t *testing.T, job *Job, recipient *ecdh.PublicKey) *CredentialEnvelope {
	t.Helper()
	ephemeral, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	shared, err := ephemeral.ECDH(recipient)
	if err != nil {
		t.Fatal(err)
	}
	key, err := hkdf.Key(
		sha256.New,
		shared,
		nil,
		"vulna-scout-credential-envelope-v1",
		chacha20poly1305.KeySize,
	)
	if err != nil {
		t.Fatal(err)
	}
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		t.Fatal(err)
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(map[string]any{
		"version":    1,
		"job_id":     job.JobID,
		"probe_id":   job.ProbeID,
		"expires_at": job.ExpiresAt,
		"credentials": []map[string]any{{
			"credential_id":     "credential-1",
			"secret_version_id": "version-1",
			"protocol":          "ssh",
			"auth_type":         "password",
			"username":          "inventory",
			"secret":            "never-persist-this",
			"metadata": map[string]any{
				"host_key_fingerprint": "SHA256:test",
			},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	ciphertext := aead.Seal(nil, nonce, payload, []byte(job.JobID+":"+job.ProbeID))
	return &CredentialEnvelope{
		Version:               "1",
		Algorithm:             "X25519-HKDF-SHA256-CHACHA20POLY1305",
		EphemeralPublicKeyB64: base64.StdEncoding.EncodeToString(ephemeral.PublicKey().Bytes()),
		NonceB64:              base64.StdEncoding.EncodeToString(nonce),
		CiphertextB64:         base64.StdEncoding.EncodeToString(ciphertext),
	}
}

func TestCredentialEnvelopeHKDFMatchesBackendProtocolVector(t *testing.T) {
	shared := make([]byte, 32)
	for index := range shared {
		shared[index] = byte(index)
	}
	key, err := hkdf.Key(
		sha256.New,
		shared,
		nil,
		"vulna-scout-credential-envelope-v1",
		chacha20poly1305.KeySize,
	)
	if err != nil {
		t.Fatal(err)
	}
	const want = "bed740552102e98381b710f2f78c9b3f078c5b219c485c049a31df8d61d54946"
	if got := hex.EncodeToString(key); got != want {
		t.Fatalf("credential-envelope HKDF changed: got %s want %s", got, want)
	}
}

func TestDecryptCredentialEnvelopeAndClear(t *testing.T) {
	privateKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	job := &Job{JobID: "job-1", ProbeID: "probe-1", ExpiresAt: "2030-01-01T00:00:00Z"}
	job.CredentialEnvelope = encryptedCredentialEnvelope(t, job, privateKey.PublicKey())

	if err := DecryptCredentialEnvelope(job, privateKey.Bytes()); err != nil {
		t.Fatalf("decrypt envelope: %v", err)
	}
	if len(job.Credentials) != 1 || job.Credentials[0].Secret != "never-persist-this" {
		t.Fatalf("unexpected credentials: %+v", job.Credentials)
	}
	job.ClearCredentials()
	if job.Credentials != nil {
		t.Fatal("credentials were not cleared")
	}
}

func TestDecryptCredentialEnvelopeRejectsTamperingAndWrongBinding(t *testing.T) {
	privateKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	job := &Job{JobID: "job-1", ProbeID: "probe-1", ExpiresAt: "2030-01-01T00:00:00Z"}
	job.CredentialEnvelope = encryptedCredentialEnvelope(t, job, privateKey.PublicKey())

	ciphertext, err := base64.StdEncoding.DecodeString(job.CredentialEnvelope.CiphertextB64)
	if err != nil {
		t.Fatal(err)
	}
	ciphertext[len(ciphertext)-1] ^= 0xff
	job.CredentialEnvelope.CiphertextB64 = base64.StdEncoding.EncodeToString(ciphertext)
	if err := DecryptCredentialEnvelope(job, privateKey.Bytes()); err == nil {
		t.Fatal("tampered envelope was accepted")
	}

	wrongBinding := &Job{JobID: "job-2", ProbeID: "probe-1", ExpiresAt: job.ExpiresAt}
	wrongBinding.CredentialEnvelope = encryptedCredentialEnvelope(t, job, privateKey.PublicKey())
	if err := DecryptCredentialEnvelope(wrongBinding, privateKey.Bytes()); err == nil {
		t.Fatal("envelope bound to another job was accepted")
	}
}

func TestVerifyJobRequiresLocalCredentialedScanOptIn(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	payload := map[string]any{
		"job_id":         "job-credentialed",
		"probe_id":       "p1",
		"site_id":        "s1",
		"mode":           "vulnerability_assessment",
		"policy_version": 4,
		"not_before":     "2020-01-01T00:00:00Z",
		"expires_at":     "2030-01-01T00:00:00Z",
		"targets":        []any{"10.20.0.5/32"},
		"workflow": []any{map[string]any{
			"stage": "inventory", "plugin": "ssh_inventory", "config": map[string]any{},
		}},
		"limits": map[string]any{
			"max_hosts": 1, "max_parallel_hosts": 1,
			"max_packets_per_second": 100, "max_duration_seconds": 120,
		},
		"credential_envelope": map[string]any{
			"version": "1", "algorithm": "X25519-HKDF-SHA256-CHACHA20POLY1305",
			"ephemeral_public_key_b64": "unused", "nonce_b64": "unused", "ciphertext_b64": "unused",
		},
	}
	message, err := canonicalBytes(payload)
	if err != nil {
		t.Fatal(err)
	}
	payload["signature"] = base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey, message))
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}

	localPolicy := jobVectorPolicyParsed(t)
	localPolicy.AllowedPlugins = append(localPolicy.AllowedPlugins, "ssh_inventory")
	_, err = VerifyJob(raw, publicKey, localPolicy, withinWindow)
	if err == nil || !strings.Contains(err.Error(), "credentialed scans are not permitted") {
		t.Fatalf("expected local opt-in refusal, got %v", err)
	}
	localPolicy.CredentialedScansAllowed = true
	if _, err := VerifyJob(raw, publicKey, localPolicy, withinWindow); err != nil {
		t.Fatalf("opted-in credentialed job was rejected: %v", err)
	}
}

// Package enrollment implements probe enrollment: local key generation, CSR
// creation, and the token-gated enrollment exchange with the orchestrator.
//
// The probe's private key is generated locally and never transmitted; only a
// certificate-signing request is sent. The orchestrator returns a signed client
// certificate, its CA certificate, and the assigned probe identity, which are
// persisted to the local state store.
package enrollment

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/codebooker/vulna/scout/internal/storage"
)

const maxResponseBytes = 1 << 20 // 1 MiB

// GenerateKey creates a new P-256 private key and its PKCS#8 PEM encoding.
func GenerateKey() (*ecdsa.PrivateKey, []byte, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generate key: %w", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, nil, fmt.Errorf("marshal key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	return key, keyPEM, nil
}

// CreateCSR builds a PEM-encoded PKCS#10 certificate-signing request. The
// subject is a placeholder; the orchestrator assigns the real identity.
func CreateCSR(key *ecdsa.PrivateKey) ([]byte, error) {
	tmpl := &x509.CertificateRequest{Subject: pkix.Name{CommonName: "vulnascout"}}
	der, err := x509.CreateCertificateRequest(rand.Reader, tmpl, key)
	if err != nil {
		return nil, fmt.Errorf("create csr: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}), nil
}

type enrollRequest struct {
	Token                  string `json:"token"`
	CSRPEM                 string `json:"csr_pem"`
	EncryptionPublicKeyB64 string `json:"encryption_public_key_b64"`
}

type enrollResponse struct {
	ProbeID                string `json:"probe_id"`
	SiteID                 string `json:"site_id"`
	CertificatePEM         string `json:"certificate_pem"`
	CACertificatePEM       string `json:"ca_certificate_pem"`
	CertificateFingerprint string `json:"certificate_fingerprint"`
	CertificateExpiresAt   string `json:"certificate_expires_at"`
	SigningPublicKeyB64    string `json:"signing_public_key_b64"`
}

// Enroll generates a key pair, submits a CSR with the given token, and persists
// the issued material. It returns the resulting enrollment state.
func Enroll(
	ctx context.Context,
	client *http.Client,
	serverURL, token string,
	store *storage.Store,
) (storage.State, error) {
	var state storage.State

	key, keyPEM, err := GenerateKey()
	if err != nil {
		return state, err
	}
	csrPEM, err := CreateCSR(key)
	if err != nil {
		return state, err
	}

	credentialPrivateKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return state, fmt.Errorf("generate credential encryption key: %w", err)
	}
	payload, err := json.Marshal(enrollRequest{
		Token:  token,
		CSRPEM: string(csrPEM),
		EncryptionPublicKeyB64: base64.StdEncoding.EncodeToString(
			credentialPrivateKey.PublicKey().Bytes(),
		),
	})
	if err != nil {
		return state, fmt.Errorf("encode enroll request: %w", err)
	}

	url := strings.TrimRight(serverURL, "/") + "/api/v1/probes/enroll"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(payload))
	if err != nil {
		return state, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return state, fmt.Errorf("enroll request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if resp.StatusCode != http.StatusCreated {
		return state, fmt.Errorf("enrollment rejected: status %d: %s", resp.StatusCode, string(body))
	}

	var er enrollResponse
	if err := json.Unmarshal(body, &er); err != nil {
		return state, fmt.Errorf("parse enroll response: %w", err)
	}
	if er.ProbeID == "" || er.CertificatePEM == "" {
		return state, fmt.Errorf("enrollment response missing certificate or probe id")
	}

	// Persist the locally-generated key alongside the issued certificate and CA.
	if err := store.SaveKey(keyPEM); err != nil {
		return state, err
	}
	if err := store.SaveCert([]byte(er.CertificatePEM)); err != nil {
		return state, err
	}
	if err := store.SaveCA([]byte(er.CACertificatePEM)); err != nil {
		return state, err
	}
	if err := store.SaveCredentialKey(credentialPrivateKey.Bytes()); err != nil {
		return state, err
	}

	state = storage.State{
		ProbeID:          er.ProbeID,
		SiteID:           er.SiteID,
		Fingerprint:      er.CertificateFingerprint,
		EnrolledAt:       time.Now().UTC().Format(time.RFC3339),
		ServerURL:        strings.TrimRight(serverURL, "/"),
		SigningPublicKey: er.SigningPublicKeyB64,
	}
	if err := store.SaveState(state); err != nil {
		return state, err
	}
	return state, nil
}

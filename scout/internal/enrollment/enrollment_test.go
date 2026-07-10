package enrollment

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/codebooker/vulna/scout/internal/storage"
)

func TestGenerateKeyAndCSR(t *testing.T) {
	key, keyPEM, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	if block, _ := pem.Decode(keyPEM); block == nil || block.Type != "PRIVATE KEY" {
		t.Fatal("key PEM did not decode to a PRIVATE KEY block")
	}
	csrPEM, err := CreateCSR(key)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(csrPEM)
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		t.Fatal("csr PEM did not decode to a CERTIFICATE REQUEST block")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if err := csr.CheckSignature(); err != nil {
		t.Errorf("CSR signature invalid: %v", err)
	}
}

func TestEnrollPersistsMaterial(t *testing.T) {
	var got enrollRequest
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/probes/enroll" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_ = json.NewDecoder(r.Body).Decode(&got)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(enrollResponse{
			ProbeID:                "probe-1",
			SiteID:                 "site-1",
			CertificatePEM:         "CERTPEM",
			CACertificatePEM:       "CAPEM",
			CertificateFingerprint: "abc123",
		})
	}))
	defer srv.Close()

	store, err := storage.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	state, err := Enroll(context.Background(), srv.Client(), srv.URL, "tok123", store)
	if err != nil {
		t.Fatal(err)
	}
	if state.ProbeID != "probe-1" || state.SiteID != "site-1" {
		t.Errorf("unexpected state: %+v", state)
	}
	if got.Token != "tok123" {
		t.Errorf("token not sent: %q", got.Token)
	}
	if got.CSRPEM == "" {
		t.Error("CSR was not sent")
	}
	if !store.IsEnrolled() {
		t.Error("store should be enrolled after successful enroll")
	}
}

func TestEnrollRejectsErrorStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"detail":"invalid token"}`))
	}))
	defer srv.Close()

	store, err := storage.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Enroll(context.Background(), srv.Client(), srv.URL, "tok", store); err == nil {
		t.Error("expected error for non-201 status")
	}
	if store.IsEnrolled() {
		t.Error("store must not be enrolled after a failed enroll")
	}
}

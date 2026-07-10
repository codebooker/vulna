package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHeartbeatSuccess(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/probes/probe-1/heartbeat" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(HeartbeatResponse{
			ServerTime:               "2026-07-10T00:00:00Z",
			ProbeStatus:              "enrolled",
			HeartbeatIntervalSeconds: 30,
			PendingJobCount:          0,
		})
	}))
	defer srv.Close()

	c := newClient(srv.URL, "probe-1", srv.Client())
	resp, err := c.Heartbeat(context.Background(), HeartbeatRequest{AgentVersion: "0.2.0"})
	if err != nil {
		t.Fatal(err)
	}
	if resp.ProbeStatus != "enrolled" {
		t.Errorf("ProbeStatus = %q", resp.ProbeStatus)
	}
	if resp.HeartbeatIntervalSeconds != 30 {
		t.Errorf("HeartbeatIntervalSeconds = %d", resp.HeartbeatIntervalSeconds)
	}
}

func TestHeartbeatRejectedIsTyped(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()

	c := newClient(srv.URL, "p", srv.Client())
	_, err := c.Heartbeat(context.Background(), HeartbeatRequest{})
	var rejected ErrRejected
	if !errors.As(err, &rejected) {
		t.Fatalf("expected ErrRejected, got %v", err)
	}
	if rejected.Status != http.StatusForbidden {
		t.Errorf("status = %d", rejected.Status)
	}
}

func TestNewMTLSClientMissingCert(t *testing.T) {
	if _, err := NewMTLSClient("https://x", "p", "/no/cert.pem", "/no/key.pem", "", false); err == nil {
		t.Error("expected error for missing client certificate")
	}
}

func TestNewEnrollHTTPClient(t *testing.T) {
	if _, err := NewEnrollHTTPClient("", false); err != nil {
		t.Errorf("system-roots client should build: %v", err)
	}
	if _, err := NewEnrollHTTPClient("/no/such/ca.pem", false); err == nil {
		t.Error("expected error for missing CA file")
	}
}

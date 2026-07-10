package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
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

func TestFetchPolicy(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/probes/p1/policy" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_, _ = w.Write([]byte(`{"policy_version":1,"signature":"x"}`))
	}))
	defer srv.Close()
	c := newClient(srv.URL, "p1", srv.Client())
	body, err := c.FetchPolicy(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), "policy_version") {
		t.Errorf("unexpected policy body: %s", body)
	}
}

func TestPollJob(t *testing.T) {
	var serve int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/probes/p1/jobs/next" || r.Method != http.MethodPost {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if serve == 0 {
			serve++
			_, _ = w.Write([]byte(`{"job_id":"j1"}`))
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()
	c := newClient(srv.URL, "p1", srv.Client())

	body, ok, err := c.PollJob(context.Background())
	if err != nil || !ok {
		t.Fatalf("expected a job, ok=%v err=%v", ok, err)
	}
	if !strings.Contains(string(body), "j1") {
		t.Errorf("unexpected job body: %s", body)
	}
	_, ok, err = c.PollJob(context.Background())
	if err != nil || ok {
		t.Fatalf("expected no job on second poll, ok=%v err=%v", ok, err)
	}
}

func TestReportJobStatus(t *testing.T) {
	var got JobStatusReport
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/probes/p1/jobs/j1/status" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_ = json.NewDecoder(r.Body).Decode(&got)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()
	c := newClient(srv.URL, "p1", srv.Client())
	err := c.ReportJobStatus(context.Background(), "j1", JobStatusReport{Status: "completed"})
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != "completed" {
		t.Errorf("status not received: %q", got.Status)
	}
}

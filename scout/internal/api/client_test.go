package api

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

var agentAPIAttempt = AttemptRef{
	AttemptID: "11111111-1111-1111-1111-111111111111",
	LeaseID:   "22222222-2222-2222-2222-222222222222", FencingToken: 7,
}

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
			w.Header().Set("X-Vulna-Attempt-ID", "11111111-1111-1111-1111-111111111111")
			w.Header().Set("X-Vulna-Lease-ID", "22222222-2222-2222-2222-222222222222")
			w.Header().Set("X-Vulna-Fencing-Token", "7")
			_, _ = w.Write([]byte(`{"job_id":"j1"}`))
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()
	c := newClient(srv.URL, "p1", srv.Client())

	offer, ok, err := c.PollJob(context.Background())
	if err != nil || !ok {
		t.Fatalf("expected a job, ok=%v err=%v", ok, err)
	}
	if !strings.Contains(string(offer.Envelope), "j1") || offer.Attempt.FencingToken != 7 {
		t.Errorf("unexpected job offer: %+v", offer)
	}
	_, ok, err = c.PollJob(context.Background())
	if err != nil || ok {
		t.Fatalf("expected no job on second poll, ok=%v err=%v", ok, err)
	}
}

func TestUploadResults(t *testing.T) {
	var gotBody []byte
	var gotQuery string
	var gotContentType string
	var gotIdempotencyKey string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/probes/p1/jobs/j1/results" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		gotQuery = r.URL.RawQuery
		gotContentType = r.Header.Get("Content-Type")
		gotIdempotencyKey = r.Header.Get("Idempotency-Key")
		gotBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusCreated)
	}))
	defer srv.Close()
	c := newClient(srv.URL, "p1", srv.Client())
	if err := c.UploadResults(
		context.Background(), "j1", agentAPIAttempt,
		[]byte("<nmaprun/>"), "discovery", "nmap",
	); err != nil {
		t.Fatal(err)
	}
	var envelope resultEnvelope
	if err := json.Unmarshal(gotBody, &envelope); err != nil {
		t.Fatalf("decode result envelope: %v", err)
	}
	if gotContentType != resultContentType || envelope.SchemaVersion != 1 ||
		envelope.JobID != "j1" || envelope.ProbeID != "p1" || envelope.Stage != "discovery" ||
		envelope.Scanner != "nmap" || envelope.ResultFormat != "nmap_xml" ||
		envelope.Payload != "PG5tYXBydW4vPg==" || envelope.ByteLength != len("<nmaprun/>") {
		t.Errorf("unexpected upload envelope/header: content-type=%q envelope=%+v", gotContentType, envelope)
	}
	if gotIdempotencyKey != ResultKey("j1", "discovery", "nmap", []byte("<nmaprun/>")) {
		t.Errorf("unexpected idempotency key: %q", gotIdempotencyKey)
	}
	if !strings.Contains(gotQuery, "scanner=nmap") || !strings.Contains(gotQuery, "stage=discovery") {
		t.Errorf("query missing stage/scanner: %q", gotQuery)
	}
}

func TestResultKeyCrossLanguageVector(t *testing.T) {
	jobID := "00000000-0000-0000-0000-000000000001"
	if got := ResultKey(jobID, "discovery", "nmap", []byte("<nmaprun/>")); got != "7925f9328a62d64b5240bf5f03dc567a49605b7cef1f0f27e8f9456158fb9bee" {
		t.Fatalf("raw result key drifted: %s", got)
	}
	if got := ResultKey(jobID, "discovery", "nmap", []byte("<nmaprun/>"), true); got != "144aaa9e7646833b5767f7b303ad6e65ef4ea9e3b005819d7106d358dd7f5274" {
		t.Fatalf("completion result key drifted: %s", got)
	}
}

func TestUploadScannerCompletion(t *testing.T) {
	var gotQuery string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotQuery = r.URL.RawQuery
		w.WriteHeader(http.StatusCreated)
	}))
	defer srv.Close()
	c := newClient(srv.URL, "p1", srv.Client())
	if err := c.UploadResults(
		context.Background(), "j1", agentAPIAttempt, nil, "vuln", "nuclei", true,
	); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(gotQuery, "complete=true") {
		t.Fatalf("completion query flag missing: %q", gotQuery)
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
	eta := 30
	err := c.ReportJobStatus(context.Background(), "j1", agentAPIAttempt, JobStatusReport{
		Status: "running",
		Progress: &JobProgressReport{
			Percent: 50, CurrentStage: "vulnerability", CurrentPlugin: "nuclei",
			StagesTotal: 2, StagesCompleted: 1, StagesRun: 1,
			TargetGroups: 1, TargetAddresses: 256, ElapsedSeconds: 30, ETASeconds: &eta,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != "running" {
		t.Errorf("status not received: %q", got.Status)
	}
	if got.Progress == nil || got.Progress.Percent != 50 || got.Progress.ETASeconds == nil ||
		*got.Progress.ETASeconds != 30 {
		t.Errorf("progress not received: %+v", got.Progress)
	}
}

// Package api handles authenticated communication with the VulnaDash
// orchestrator over mutual TLS: the probe presents its enrollment client
// certificate and sends heartbeats.
package api

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

// ResultKey is the stable idempotency key for a result upload. It is derived
// only from the job, stage, scanner, completion marker, and payload, so a Scout that re-uploads the
// same batch after a lost acknowledgement produces the same key and the server
// treats the retry as a no-op — no duplicate observations on resume.
func ResultKey(jobID, stage, scanner string, raw []byte, complete ...bool) string {
	h := sha256.New()
	h.Write([]byte(jobID + "\x00" + stage + "\x00" + scanner + "\x00"))
	if len(complete) > 0 && complete[0] {
		h.Write([]byte("1\x00"))
	} else {
		h.Write([]byte("0\x00"))
	}
	h.Write(raw)
	return hex.EncodeToString(h.Sum(nil))
}

const (
	maxResponseBytes  = 1 << 20 // 1 MiB
	requestTimeout    = 30 * time.Second
	resultContentType = "application/vnd.vulna.result+json"
)

type resultEnvelope struct {
	SchemaVersion   int    `json:"schema_version"`
	JobID           string `json:"job_id"`
	ProbeID         string `json:"probe_id"`
	Stage           string `json:"stage"`
	Scanner         string `json:"scanner"`
	Complete        bool   `json:"complete"`
	ContentHash     string `json:"content_hash"`
	PayloadEncoding string `json:"payload_encoding"`
	ResultFormat    string `json:"result_format"`
	ByteLength      int    `json:"byte_length"`
	Payload         string `json:"payload"`
}

func resultFormat(scanner string) string {
	switch scanner {
	case "nmap":
		return "nmap_xml"
	case "nuclei":
		return "nuclei_jsonl"
	case "testssl":
		return "testssl_json"
	case "zap":
		return "zap_json"
	case "metasploit":
		return "metasploit_json"
	default:
		return "software_inventory_json"
	}
}

// Client talks to the orchestrator using the probe's client certificate.
type Client struct {
	serverURL string
	probeID   string
	http      *http.Client
}

// newClient is the shared constructor (used by NewMTLSClient and tests).
func newClient(serverURL, probeID string, hc *http.Client) *Client {
	return &Client{
		serverURL: strings.TrimRight(serverURL, "/"),
		probeID:   probeID,
		http:      hc,
	}
}

// NewMTLSClient builds a client that presents the given client certificate/key
// and trusts the given server CA (or the system trust store when serverCAPath
// is empty). insecure disables server verification and must be used only in
// development or lab environments.
func NewMTLSClient(
	serverURL, probeID, certPath, keyPath, serverCAPath string, insecure bool,
) (*Client, error) {
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, fmt.Errorf("load client certificate: %w", err)
	}
	tlsCfg := &tls.Config{
		Certificates:       []tls.Certificate{cert},
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: insecure, //nolint:gosec // dev/lab opt-in only
	}
	if serverCAPath != "" {
		caPEM, err := os.ReadFile(serverCAPath) //nolint:gosec // operator-provided CA path
		if err != nil {
			return nil, fmt.Errorf("read server CA: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caPEM) {
			return nil, fmt.Errorf("server CA %s: no certificates parsed", serverCAPath)
		}
		tlsCfg.RootCAs = pool
	}
	hc := &http.Client{
		Timeout:   requestTimeout,
		Transport: &http.Transport{TLSClientConfig: tlsCfg},
	}
	return newClient(serverURL, probeID, hc), nil
}

// NewEnrollHTTPClient builds the HTTP client used for the token-gated
// enrollment call, before the probe has a client certificate. It trusts the
// given server CA (or the system trust store when serverCAPath is empty).
func NewEnrollHTTPClient(serverCAPath string, insecure bool) (*http.Client, error) {
	tlsCfg := &tls.Config{
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: insecure, //nolint:gosec // dev/lab opt-in only
	}
	if serverCAPath != "" {
		caPEM, err := os.ReadFile(serverCAPath) //nolint:gosec // operator-provided CA path
		if err != nil {
			return nil, fmt.Errorf("read server CA: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caPEM) {
			return nil, fmt.Errorf("server CA %s: no certificates parsed", serverCAPath)
		}
		tlsCfg.RootCAs = pool
	}
	return &http.Client{
		Timeout:   requestTimeout,
		Transport: &http.Transport{TLSClientConfig: tlsCfg},
	}, nil
}

// HeartbeatRequest mirrors the orchestrator's heartbeat schema.
type HeartbeatRequest struct {
	AgentVersion    string         `json:"agent_version,omitempty"`
	Hostname        string         `json:"hostname,omitempty"`
	OperatingSystem string         `json:"operating_system,omitempty"`
	Architecture    string         `json:"architecture,omitempty"`
	Capabilities    []string       `json:"capabilities,omitempty"`
	Health          map[string]any `json:"health,omitempty"`
	PolicyHash      string         `json:"policy_hash,omitempty"`
}

// PolicyStatus is the policy section of a heartbeat response.
type PolicyStatus struct {
	Version         int    `json:"version"`
	Hash            string `json:"hash"`
	UpdateAvailable bool   `json:"update_available"`
}

// HeartbeatResponse captures the fields the agent acts on.
type HeartbeatResponse struct {
	ServerTime               string       `json:"server_time"`
	ProbeStatus              string       `json:"probe_status"`
	HeartbeatIntervalSeconds int          `json:"heartbeat_interval_seconds"`
	PendingJobCount          int          `json:"pending_job_count"`
	Cancellations            []string     `json:"cancellations"`
	Policy                   PolicyStatus `json:"policy"`
}

// ErrRejected indicates the orchestrator refused the probe (revoked/disabled).
type ErrRejected struct{ Status int }

func (e ErrRejected) Error() string {
	return fmt.Sprintf("orchestrator rejected probe (status %d): revoked or disabled", e.Status)
}

// ErrStaleAttempt means the server fenced or expired this execution. The Scout
// must stop reporting it and may discard queued output carrying the stale fence.
type ErrStaleAttempt struct{ Status int }

func (e ErrStaleAttempt) Error() string {
	return fmt.Sprintf("job attempt is stale or fenced (status %d)", e.Status)
}

// AttemptRef is the server-issued lease identity for one immutable job offer.
type AttemptRef struct {
	AttemptID    string
	LeaseID      string
	FencingToken int64
}

// JobOffer combines the signed envelope with its unsigned delivery lease.
type JobOffer struct {
	Envelope []byte
	Attempt  AttemptRef
}

func setAttemptHeaders(req *http.Request, attempt AttemptRef) {
	req.Header.Set("X-Vulna-Attempt-ID", attempt.AttemptID)
	req.Header.Set("X-Vulna-Lease-ID", attempt.LeaseID)
	req.Header.Set("X-Vulna-Fencing-Token", strconv.FormatInt(attempt.FencingToken, 10))
}

// FetchPolicy retrieves the probe's signed local policy document (raw JSON).
func (c *Client) FetchPolicy(ctx context.Context) ([]byte, error) {
	url := fmt.Sprintf("%s/api/v1/probes/%s/policy", c.serverURL, c.probeID)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch policy: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusUnauthorized {
		return nil, ErrRejected{Status: resp.StatusCode}
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetch policy: status %d: %s", resp.StatusCode, string(body))
	}
	return body, nil
}

// PollJob polls for the next signed job envelope. It returns (envelope, true,
// nil) when a job is available, (nil, false, nil) when none is (HTTP 204), and
// an error otherwise.
func (c *Client) PollJob(ctx context.Context) (JobOffer, bool, error) {
	var offer JobOffer
	url := fmt.Sprintf("%s/api/v1/probes/%s/jobs/next", c.serverURL, c.probeID)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, nil)
	if err != nil {
		return offer, false, err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return offer, false, fmt.Errorf("poll job: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	switch {
	case resp.StatusCode == http.StatusOK:
		fence, err := strconv.ParseInt(resp.Header.Get("X-Vulna-Fencing-Token"), 10, 64)
		if err != nil || fence < 1 || resp.Header.Get("X-Vulna-Attempt-ID") == "" ||
			resp.Header.Get("X-Vulna-Lease-ID") == "" {
			return offer, false, errors.New("poll job: response is missing valid attempt lease headers")
		}
		offer = JobOffer{Envelope: body, Attempt: AttemptRef{
			AttemptID: resp.Header.Get("X-Vulna-Attempt-ID"),
			LeaseID:   resp.Header.Get("X-Vulna-Lease-ID"), FencingToken: fence,
		}}
		return offer, true, nil
	case resp.StatusCode == http.StatusNoContent:
		return offer, false, nil
	case resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusUnauthorized:
		return offer, false, ErrRejected{Status: resp.StatusCode}
	default:
		return offer, false, fmt.Errorf("poll job: status %d: %s", resp.StatusCode, string(body))
	}
}

// JobStatusReport is a status update a probe sends about a job.
type JobStatusReport struct {
	Status         string             `json:"status"`
	ErrorCode      string             `json:"error_code,omitempty"`
	ErrorMessage   string             `json:"error_message,omitempty"`
	Summary        map[string]any     `json:"summary,omitempty"`
	Progress       *JobProgressReport `json:"progress,omitempty"`
	FailureDetails []JobFailureDetail `json:"failure_details,omitempty"`
}

// JobProgressReport is the bounded progress payload accepted by the API.
type JobProgressReport struct {
	Percent         int     `json:"percent"`
	CurrentStage    string  `json:"current_stage,omitempty"`
	CurrentPlugin   string  `json:"current_plugin,omitempty"`
	StagesTotal     int     `json:"stages_total"`
	StagesCompleted int     `json:"stages_completed"`
	StagesRun       int     `json:"stages_run"`
	StagesFailed    int     `json:"stages_failed"`
	StagesSkipped   int     `json:"stages_skipped"`
	WorkUnitsTotal  int     `json:"work_units_total"`
	WorkUnitsDone   float64 `json:"work_units_done"`
	TargetGroups    int     `json:"target_groups"`
	TargetAddresses int     `json:"target_addresses"`
	ElapsedSeconds  int     `json:"elapsed_seconds"`
	ETASeconds      *int    `json:"eta_seconds,omitempty"`
}

// JobFailureDetail is one stage-specific failure sent for server sanitization.
type JobFailureDetail struct {
	Code    string `json:"code"`
	Stage   string `json:"stage,omitempty"`
	Plugin  string `json:"plugin,omitempty"`
	Message string `json:"message"`
}

// ReportJobStatus reports a job's status back to the orchestrator.
func (c *Client) ReportJobStatus(
	ctx context.Context, jobID string, attempt AttemptRef, report JobStatusReport,
) error {
	payload, err := json.Marshal(report)
	if err != nil {
		return fmt.Errorf("encode status: %w", err)
	}
	url := fmt.Sprintf("%s/api/v1/probes/%s/jobs/%s/status", c.serverURL, c.probeID, jobID)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	setAttemptHeaders(req, attempt)
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("report status: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode == http.StatusConflict {
		return ErrStaleAttempt{Status: resp.StatusCode}
	}
	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
		return fmt.Errorf("report status: status %d: %s", resp.StatusCode, string(body))
	}
	return nil
}

// UploadResults uploads raw scanner output (e.g. Nmap XML) for a job.
func (c *Client) UploadResults(
	ctx context.Context, jobID string, attempt AttemptRef, raw []byte, stage, scanner string,
	complete ...bool,
) error {
	if stage == "" {
		stage = "discovery"
	}
	if scanner == "" {
		scanner = "nmap"
	}
	url := fmt.Sprintf(
		"%s/api/v1/probes/%s/jobs/%s/results?stage=%s&scanner=%s",
		c.serverURL, c.probeID, jobID, stage, scanner,
	)
	isComplete := len(complete) > 0 && complete[0]
	if isComplete {
		url += "&complete=true"
	}
	digest := sha256.Sum256(raw)
	envelope, err := json.Marshal(resultEnvelope{
		SchemaVersion: 1, JobID: jobID, ProbeID: c.probeID, Stage: stage, Scanner: scanner,
		Complete: isComplete, ContentHash: "sha256:" + hex.EncodeToString(digest[:]),
		PayloadEncoding: "base64", ResultFormat: resultFormat(scanner), ByteLength: len(raw),
		Payload: base64.StdEncoding.EncodeToString(raw),
	})
	if err != nil {
		return fmt.Errorf("encode result envelope: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(envelope))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", resultContentType)
	req.Header.Set("Idempotency-Key", ResultKey(jobID, stage, scanner, raw, isComplete))
	setAttemptHeaders(req, attempt)
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("upload results: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode == http.StatusConflict {
		return ErrStaleAttempt{Status: resp.StatusCode}
	}
	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
		return fmt.Errorf("upload results: status %d: %s", resp.StatusCode, string(body))
	}
	return nil
}

// RenewJobLease keeps a long-running attempt current independently of scanner
// progress, so a quiet Nmap process cannot be mistaken for a dead Scout.
func (c *Client) RenewJobLease(ctx context.Context, jobID string, attempt AttemptRef) error {
	url := fmt.Sprintf("%s/api/v1/probes/%s/jobs/%s/lease", c.serverURL, c.probeID, jobID)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, nil)
	if err != nil {
		return err
	}
	setAttemptHeaders(req, attempt)
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("renew job lease: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode == http.StatusConflict {
		return ErrStaleAttempt{Status: resp.StatusCode}
	}
	if resp.StatusCode != http.StatusNoContent {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
		return fmt.Errorf("renew job lease: status %d: %s", resp.StatusCode, string(body))
	}
	return nil
}

// Heartbeat sends a heartbeat and returns the server's response.
func (c *Client) Heartbeat(ctx context.Context, hb HeartbeatRequest) (HeartbeatResponse, error) {
	var out HeartbeatResponse
	payload, err := json.Marshal(hb)
	if err != nil {
		return out, fmt.Errorf("encode heartbeat: %w", err)
	}
	url := fmt.Sprintf("%s/api/v1/probes/%s/heartbeat", c.serverURL, c.probeID)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(payload))
	if err != nil {
		return out, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return out, fmt.Errorf("heartbeat request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	switch {
	case resp.StatusCode == http.StatusOK:
		// fall through to decode
	case resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusUnauthorized:
		return out, ErrRejected{Status: resp.StatusCode}
	default:
		return out, fmt.Errorf("heartbeat failed: status %d: %s", resp.StatusCode, string(body))
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return out, fmt.Errorf("parse heartbeat response: %w", err)
	}
	return out, nil
}

// CheckReachable verifies the authenticated result-upload channel is reachable:
// it makes a GET to the policy endpoint over mTLS and returns an error only on a
// transport failure (any HTTP status means the channel is open).
func (c *Client) CheckReachable(ctx context.Context) error {
	url := fmt.Sprintf("%s/api/v1/probes/%s/policy", c.serverURL, c.probeID)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	_ = resp.Body.Close()
	return nil
}

// SelfRevoke asks the orchestrator to revoke this Scout's own identity (used by
// `vulnascout reset`). After success the certificate can no longer poll or upload.
func (c *Client) SelfRevoke(ctx context.Context) error {
	url := fmt.Sprintf("%s/api/v1/probes/self-revoke", c.serverURL)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("self-revoke request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
		return fmt.Errorf("self-revoke failed: status %d: %s", resp.StatusCode, string(body))
	}
	return nil
}

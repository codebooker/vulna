// Package api handles authenticated communication with the VulnaDash
// orchestrator over mutual TLS: the probe presents its enrollment client
// certificate and sends heartbeats.
package api

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

const (
	maxResponseBytes = 1 << 20 // 1 MiB
	requestTimeout   = 30 * time.Second
)

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

// HeartbeatResponse captures the fields the agent acts on.
type HeartbeatResponse struct {
	ServerTime               string `json:"server_time"`
	ProbeStatus              string `json:"probe_status"`
	HeartbeatIntervalSeconds int    `json:"heartbeat_interval_seconds"`
	PendingJobCount          int    `json:"pending_job_count"`
}

// ErrRejected indicates the orchestrator refused the probe (revoked/disabled).
type ErrRejected struct{ Status int }

func (e ErrRejected) Error() string {
	return fmt.Sprintf("orchestrator rejected probe (status %d): revoked or disabled", e.Status)
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

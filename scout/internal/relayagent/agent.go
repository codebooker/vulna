// Package relayagent implements the scanner-free VulnaRelay endpoint.
package relayagent

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/codebooker/vulna/scout/internal/buildinfo"
	"github.com/codebooker/vulna/scout/internal/enrollment"
)

const (
	defaultStateDir = "/var/lib/vulna-relay"
	interfaceName   = "vulna-wg0"
	maxResponse     = 1 << 20
)

type state struct {
	RelayID  string `json:"relay_id"`
	Server   string `json:"server"`
	Enrolled string `json:"enrolled_at"`
}

type enrollRequest struct {
	Token           string `json:"token"`
	CSRPEM          string `json:"csr_pem"`
	TunnelPublicKey string `json:"tunnel_public_key"`
}

type enrollResponse struct {
	RelayID        string `json:"relay_id"`
	CertificatePEM string `json:"certificate_pem"`
	CAPEM          string `json:"ca_pem"`
}

type relayConfig struct {
	Active          bool     `json:"active"`
	Endpoint        string   `json:"endpoint"`
	ServerPublicKey string   `json:"server_public_key"`
	ServerAddress   string   `json:"server_address"`
	TunnelAddress   string   `json:"tunnel_address"`
	ApprovedCIDRs   []string `json:"approved_cidrs"`
	DeniedCIDRs     []string `json:"denied_cidrs"`
	RefreshSeconds  int      `json:"refresh_seconds"`
}

type heartbeatRequest struct {
	TunnelUp bool           `json:"tunnel_up"`
	Health   map[string]any `json:"health"`
}

// Execute runs the relay CLI.
func Execute(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		usage(stderr)
		return 2
	}
	switch args[0] {
	case "version", "--version", "-v":
		fmt.Fprintf(stdout, "vulnarelay %s (%s)\n", buildinfo.Version, buildinfo.Commit)
		return 0
	case "enroll":
		return enrollCommand(args[1:], stdout, stderr)
	case "run":
		return runCommand(args[1:], stdout, stderr)
	case "status":
		return statusCommand(args[1:], stdout, stderr)
	case "stop":
		if os.Geteuid() != 0 {
			fmt.Fprintln(stderr, "stop: root is required")
			return 1
		}
		if err := teardown(); err != nil {
			fmt.Fprintln(stderr, "stop:", err)
			return 1
		}
		fmt.Fprintln(stdout, "relay tunnel removed")
		return 0
	default:
		usage(stderr)
		return 2
	}
}

func usage(w io.Writer) {
	fmt.Fprintln(w, "usage: vulnarelay <enroll|run|status|stop|version>")
}

func enrollCommand(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("enroll", flag.ContinueOnError)
	fs.SetOutput(stderr)
	server := fs.String("server", os.Getenv("VULNA_SERVER"), "VulnaDash mTLS base URL")
	stateDir := fs.String("state-dir", envOr("VULNA_RELAY_STATE_DIR", defaultStateDir), "state directory")
	serverCA := fs.String("server-ca", os.Getenv("VULNA_SERVER_CA"), "optional server TLS CA PEM")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	token := os.Getenv("VULNA_RELAY_TOKEN")
	if token == "" || *server == "" {
		fmt.Fprintln(stderr, "enroll: VULNA_RELAY_TOKEN and --server/VULNA_SERVER are required")
		return 2
	}
	if err := enrollRelay(context.Background(), *server, token, *stateDir, *serverCA); err != nil {
		fmt.Fprintln(stderr, "enroll:", err)
		return 1
	}
	fmt.Fprintln(stdout, "relay enrolled; starting the service will bring up its scoped tunnel")
	return 0
}

func enrollRelay(ctx context.Context, server, token, dir, serverCA string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	key, keyPEM, err := enrollment.GenerateKey()
	if err != nil {
		return err
	}
	csr, err := enrollment.CreateCSR(key)
	if err != nil {
		return err
	}
	wgPrivate, err := commandInput(nil, "wg", "genkey")
	if err != nil {
		return fmt.Errorf("generate WireGuard key: %w", err)
	}
	wgPrivate = bytes.TrimSpace(wgPrivate)
	wgPublic, err := commandInput(append(wgPrivate, '\n'), "wg", "pubkey")
	if err != nil {
		return fmt.Errorf("derive WireGuard public key: %w", err)
	}
	payload, err := json.Marshal(enrollRequest{
		Token: token, CSRPEM: string(csr), TunnelPublicKey: strings.TrimSpace(string(wgPublic)),
	})
	if err != nil {
		return err
	}
	hc, err := tlsHTTPClient("", "", serverCA)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		strings.TrimRight(server, "/")+"/api/v1/relays/register", bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := hc.Do(req)
	if err != nil {
		return fmt.Errorf("registration request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxResponse))
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("registration rejected: status %d: %s", resp.StatusCode, body)
	}
	var registered enrollResponse
	if err := json.Unmarshal(body, &registered); err != nil {
		return fmt.Errorf("parse registration response: %w", err)
	}
	if registered.RelayID == "" || registered.CertificatePEM == "" {
		return errors.New("registration response is missing relay identity or certificate")
	}
	for path, data := range map[string][]byte{
		"client.key": keyPEM, "client.crt": []byte(registered.CertificatePEM),
		"client-ca.pem": []byte(registered.CAPEM), "wireguard.key": append(wgPrivate, '\n'),
	} {
		if err := writeSecret(filepath.Join(dir, path), data); err != nil {
			return err
		}
	}
	return writeJSON(filepath.Join(dir, "state.json"), state{
		RelayID: registered.RelayID, Server: strings.TrimRight(server, "/"),
		Enrolled: time.Now().UTC().Format(time.RFC3339),
	})
}

func runCommand(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	fs.SetOutput(stderr)
	stateDir := fs.String("state-dir", envOr("VULNA_RELAY_STATE_DIR", defaultStateDir), "state directory")
	serverCA := fs.String("server-ca", os.Getenv("VULNA_SERVER_CA"), "optional server TLS CA PEM")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if os.Geteuid() != 0 {
		fmt.Fprintln(stderr, "run: root is required to configure WireGuard and firewall rules")
		return 1
	}
	st, err := loadState(*stateDir)
	if err != nil {
		fmt.Fprintln(stderr, "run:", err)
		return 1
	}
	hc, err := tlsHTTPClient(
		filepath.Join(*stateDir, "client.crt"), filepath.Join(*stateDir, "client.key"), *serverCA,
	)
	if err != nil {
		fmt.Fprintln(stderr, "run:", err)
		return 1
	}
	fmt.Fprintln(stdout, "vulnarelay running; no scanners are installed on this endpoint")
	for {
		interval := 5 * time.Second
		cfg, fetchErr := fetchConfig(context.Background(), hc, st.Server)
		if fetchErr != nil {
			_ = teardown()
			fmt.Fprintln(stderr, "relay configuration unavailable; tunnel removed (fail closed):", fetchErr)
		} else if !cfg.Active {
			_ = teardown()
			_ = sendHeartbeat(context.Background(), hc, st.Server, false, "disabled")
		} else {
			if cfg.RefreshSeconds > 0 {
				interval = time.Duration(cfg.RefreshSeconds) * time.Second
			}
			configureErr := configure(*stateDir, cfg)
			up := configureErr == nil && tunnelReachable(cfg.ServerAddress)
			if configureErr != nil {
				_ = teardown()
				fmt.Fprintln(stderr, "tunnel configuration failed:", configureErr)
			}
			_ = sendHeartbeat(context.Background(), hc, st.Server, up, healthDetail(configureErr))
		}
		time.Sleep(interval)
	}
}

func statusCommand(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("status", flag.ContinueOnError)
	fs.SetOutput(stderr)
	stateDir := fs.String("state-dir", envOr("VULNA_RELAY_STATE_DIR", defaultStateDir), "state directory")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	st, err := loadState(*stateDir)
	if err != nil {
		fmt.Fprintln(stdout, "status: not enrolled")
		return 1
	}
	fmt.Fprintf(stdout, "status: enrolled\nrelay_id: %s\nserver: %s\n", st.RelayID, st.Server)
	if err := exec.Command("wg", "show", interfaceName).Run(); err == nil {
		fmt.Fprintln(stdout, "tunnel: configured")
	} else {
		fmt.Fprintln(stdout, "tunnel: down")
	}
	return 0
}

func fetchConfig(ctx context.Context, hc *http.Client, server string) (relayConfig, error) {
	var cfg relayConfig
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		strings.TrimRight(server, "/")+"/api/v1/relays/config", nil)
	if err != nil {
		return cfg, err
	}
	resp, err := hc.Do(req)
	if err != nil {
		return cfg, err
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxResponse))
	if resp.StatusCode != http.StatusOK {
		return cfg, fmt.Errorf("status %d: %s", resp.StatusCode, body)
	}
	if err := json.Unmarshal(body, &cfg); err != nil {
		return cfg, err
	}
	return cfg, validateConfig(cfg)
}

func validateConfig(cfg relayConfig) error {
	if !cfg.Active {
		return nil
	}
	if cfg.Endpoint == "" || cfg.ServerPublicKey == "" {
		return errors.New("active relay configuration is missing endpoint or server key")
	}
	if net.ParseIP(strings.Split(cfg.ServerAddress, "/")[0]) == nil {
		return errors.New("invalid relay server address")
	}
	if net.ParseIP(strings.Split(cfg.TunnelAddress, "/")[0]) == nil {
		return errors.New("invalid relay tunnel address")
	}
	for _, value := range append(append([]string{}, cfg.ApprovedCIDRs...), cfg.DeniedCIDRs...) {
		if ip, _, err := net.ParseCIDR(value); err != nil || ip.To4() == nil {
			return fmt.Errorf("invalid/non-IPv4 relay scope %q", value)
		}
	}
	return nil
}

func configure(stateDir string, cfg relayConfig) error {
	serverIP := strings.Split(cfg.ServerAddress, "/")[0]
	if err := run("ip", "link", "show", interfaceName); err != nil {
		if err := run("ip", "link", "add", "dev", interfaceName, "type", "wireguard"); err != nil {
			return err
		}
	}
	commands := [][]string{
		{"ip", "address", "replace", cfg.TunnelAddress, "dev", interfaceName},
		{"wg", "set", interfaceName, "private-key", filepath.Join(stateDir, "wireguard.key"),
			"peer", cfg.ServerPublicKey, "endpoint", cfg.Endpoint, "allowed-ips", serverIP + "/32",
			"persistent-keepalive", "25"},
		{"ip", "link", "set", "up", "dev", interfaceName},
		{"ip", "route", "replace", serverIP + "/32", "dev", interfaceName},
		{"sysctl", "-w", "net.ipv4.ip_forward=1"},
	}
	for _, command := range commands {
		if err := run(command[0], command[1:]...); err != nil {
			return err
		}
	}
	routes := make(map[string]string, len(cfg.ApprovedCIDRs))
	for _, cidr := range cfg.ApprovedCIDRs {
		iface, err := routeInterface(cidr)
		if err != nil {
			return fmt.Errorf("resolve egress interface for %s: %w", cidr, err)
		}
		routes[cidr] = iface
	}
	return configureFirewall(routes, serverIP, cfg)
}

func configureFirewall(routes map[string]string, serverIP string, cfg relayConfig) error {
	ensureChain("filter", "VULNA_RELAY_FWD", "FORWARD")
	ensureChain("nat", "VULNA_RELAY_NAT", "POSTROUTING")
	for _, cidr := range cfg.DeniedCIDRs {
		if err := run("iptables", "-A", "VULNA_RELAY_FWD", "-i", interfaceName, "-d", cidr, "-j", "REJECT"); err != nil {
			return err
		}
	}
	returnIfaces := make(map[string]bool, len(routes))
	for _, cidr := range cfg.ApprovedCIDRs {
		lan := routes[cidr]
		if lan == "" {
			return fmt.Errorf("approved CIDR %s has no egress interface", cidr)
		}
		returnIfaces[lan] = true
		if err := run("iptables", "-A", "VULNA_RELAY_FWD", "-i", interfaceName,
			"-o", lan, "-d", cidr, "-j", "ACCEPT"); err != nil {
			return err
		}
		if err := run("iptables", "-t", "nat", "-A", "VULNA_RELAY_NAT",
			"-s", serverIP+"/32", "-d", cidr, "-o", lan, "-j", "MASQUERADE"); err != nil {
			return err
		}
	}
	for lan := range returnIfaces {
		if err := run("iptables", "-A", "VULNA_RELAY_FWD", "-i", lan, "-o", interfaceName,
			"-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"); err != nil {
			return err
		}
	}
	return run("iptables", "-A", "VULNA_RELAY_FWD", "-i", interfaceName, "-j", "DROP")
}

func ensureChain(table, chain, parent string) {
	prefix := []string{}
	if table != "filter" {
		prefix = []string{"-t", table}
	}
	_ = run("iptables", append(prefix, "-N", chain)...)
	_ = run("iptables", append(prefix, "-F", chain)...)
	check := append(append([]string{}, prefix...), "-C", parent, "-j", chain)
	if run("iptables", check...) != nil {
		_ = run("iptables", append(prefix, "-I", parent, "1", "-j", chain)...)
	}
}

func teardown() error {
	_ = removeChain("filter", "VULNA_RELAY_FWD", "FORWARD")
	_ = removeChain("nat", "VULNA_RELAY_NAT", "POSTROUTING")
	if err := run("ip", "link", "del", interfaceName); err != nil {
		return nil // already absent is the desired fail-closed state
	}
	return nil
}

func removeChain(table, chain, parent string) error {
	prefix := []string{}
	if table != "filter" {
		prefix = []string{"-t", table}
	}
	_ = run("iptables", append(prefix, "-D", parent, "-j", chain)...)
	_ = run("iptables", append(prefix, "-F", chain)...)
	return run("iptables", append(prefix, "-X", chain)...)
}

func routeInterface(cidr string) (string, error) {
	ip, _, err := net.ParseCIDR(cidr)
	if err != nil {
		return "", err
	}
	out, err := exec.Command("ip", "route", "get", ip.String()).Output()
	if err != nil {
		return "", err
	}
	return ParseRouteInterface(string(out))
}

// ParseRouteInterface extracts the `dev` field from `ip route get` output.
func ParseRouteInterface(output string) (string, error) {
	fields := strings.Fields(output)
	for i := 0; i+1 < len(fields); i++ {
		if fields[i] == "dev" {
			return fields[i+1], nil
		}
	}
	return "", errors.New("route has no interface")
}

func tunnelReachable(serverAddress string) bool {
	ip := strings.Split(serverAddress, "/")[0]
	return exec.Command("ping", "-c", "1", "-W", "2", ip).Run() == nil
}

func sendHeartbeat(ctx context.Context, hc *http.Client, server string, up bool, detail string) error {
	payload, _ := json.Marshal(heartbeatRequest{TunnelUp: up, Health: map[string]any{
		"agent_version": buildinfo.Version, "os": runtime.GOOS, "arch": runtime.GOARCH,
		"detail": detail,
	}})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		strings.TrimRight(server, "/")+"/api/v1/relays/heartbeat", bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := hc.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("heartbeat status %d", resp.StatusCode)
	}
	return nil
}

func healthDetail(err error) string {
	if err == nil {
		return "configured"
	}
	return err.Error()
}

func tlsHTTPClient(certPath, keyPath, caPath string) (*http.Client, error) {
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
	if certPath != "" {
		cert, err := tls.LoadX509KeyPair(certPath, keyPath)
		if err != nil {
			return nil, err
		}
		tlsConfig.Certificates = []tls.Certificate{cert}
	}
	if caPath != "" {
		pemData, err := os.ReadFile(caPath) //nolint:gosec // operator-selected trust root
		if err != nil {
			return nil, err
		}
		pool, err := x509.SystemCertPool()
		if err != nil || pool == nil {
			pool = x509.NewCertPool()
		}
		if !pool.AppendCertsFromPEM(pemData) {
			return nil, errors.New("server CA file contains no certificates")
		}
		tlsConfig.RootCAs = pool
	}
	return &http.Client{Timeout: 15 * time.Second,
		Transport: &http.Transport{TLSClientConfig: tlsConfig}}, nil
}

func loadState(dir string) (state, error) {
	var st state
	data, err := os.ReadFile(filepath.Join(dir, "state.json")) //nolint:gosec
	if err != nil {
		return st, err
	}
	err = json.Unmarshal(data, &st)
	return st, err
}

func writeSecret(path string, data []byte) error {
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return err
	}
	return os.Chmod(path, 0o600)
}

func writeJSON(path string, value any) error {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	return writeSecret(path, append(data, '\n'))
}

func commandInput(input []byte, name string, args ...string) ([]byte, error) {
	cmd := exec.Command(name, args...)
	cmd.Stdin = bytes.NewReader(input)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("%s: %w: %s", name, err, strings.TrimSpace(string(out)))
	}
	return out, nil
}

func run(name string, args ...string) error {
	_, err := commandInput(nil, name, args...)
	return err
}

func envOr(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}

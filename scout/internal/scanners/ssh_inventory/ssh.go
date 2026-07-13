// Package ssh_inventory collects read-only Linux OS and package inventory over SSH.
package ssh_inventory

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/codebooker/vulna/scout/internal/policy"
)

const maxOutputBytes = 8 << 20

var fixedCommands = []string{
	"cat /etc/os-release",
	`if command -v dpkg-query >/dev/null 2>&1; then dpkg-query -W -f='${binary:Package}\t${Version}\t${Architecture}\n'; elif command -v rpm >/dev/null 2>&1; then rpm -qa --qf '%{NAME}\t%{VERSION}-%{RELEASE}\t%{ARCH}\n'; else exit 42; fi`,
}

// Transport executes only commands supplied by this package. The interface is
// injectable so container-lab behavior is tested without embedding credentials.
type Transport interface {
	Run(context.Context, string, policy.Credential, string) ([]byte, error)
}

// Worker is the authenticated Linux inventory scanner.
type Worker struct{ transport Transport }

func NewWorker() *Worker { return &Worker{transport: &SSHTransport{}} }

func NewWorkerWithTransport(transport Transport) *Worker { return &Worker{transport: transport} }

func (w *Worker) Stage() string { return "inventory" }

func (w *Worker) Name() string { return "ssh_inventory" }

func (w *Worker) Run(ctx context.Context, job *policy.Job) ([]byte, error) {
	target, err := singleHost(job.Targets)
	if err != nil {
		return nil, err
	}
	credential, err := credentialFor(job, "ssh")
	if err != nil {
		return nil, err
	}
	commandCtx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	osRelease, err := w.transport.Run(commandCtx, target, credential, fixedCommands[0])
	if err != nil {
		return nil, fmt.Errorf("read operating-system inventory: %w", err)
	}
	packages, err := w.transport.Run(commandCtx, target, credential, fixedCommands[1])
	if err != nil {
		return nil, fmt.Errorf("read package inventory: %w", err)
	}
	payload := map[string]any{
		"operating_system": parseOSRelease(osRelease),
		"packages":         parsePackages(packages),
	}
	return json.Marshal(payload)
}

func credentialFor(job *policy.Job, protocol string) (policy.Credential, error) {
	for _, credential := range job.Credentials {
		if credential.Protocol == protocol {
			return credential, nil
		}
	}
	return policy.Credential{}, fmt.Errorf("job has no %s credential", protocol)
}

func singleHost(targets []string) (string, error) {
	if len(targets) != 1 {
		return "", errors.New("authenticated inventory requires exactly one target")
	}
	if address, err := netip.ParseAddr(targets[0]); err == nil {
		return address.String(), nil
	}
	prefix, err := netip.ParsePrefix(targets[0])
	if err != nil || prefix.Bits() != prefix.Addr().BitLen() {
		return "", errors.New("authenticated inventory target must be one IP address")
	}
	return prefix.Addr().String(), nil
}

func parseOSRelease(raw []byte) map[string]string {
	values := map[string]string{}
	for _, line := range strings.Split(string(raw), "\n") {
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		value = strings.Trim(strings.TrimSpace(value), `"`)
		values[key] = value
	}
	return map[string]string{
		"name":    firstNonempty(values["PRETTY_NAME"], values["NAME"], "Linux"),
		"version": firstNonempty(values["VERSION_ID"], values["VERSION"], "unknown"),
	}
}

func firstNonempty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

func parsePackages(raw []byte) []map[string]string {
	packages := make([]map[string]string, 0)
	for _, line := range strings.Split(string(raw), "\n") {
		fields := strings.Split(line, "\t")
		if len(fields) < 3 || fields[0] == "" || fields[1] == "" {
			continue
		}
		packages = append(packages, map[string]string{
			"name":         fields[0],
			"package_key":  strings.ToLower(fields[0]),
			"version":      fields[1],
			"architecture": fields[2],
			"product_key":  strings.ToLower(fields[0]),
		})
	}
	return packages
}

// SSHTransport uses the Go SSH implementation so passwords/private keys never
// appear in argv, environment variables, or temporary files.
type SSHTransport struct{}

func (t *SSHTransport) Run(
	ctx context.Context, target string, credential policy.Credential, command string,
) ([]byte, error) {
	if !isFixedCommand(command) {
		return nil, errors.New("SSH command is not in the collector allowlist")
	}
	port, err := metadataInt(credential.Metadata, "port", 22)
	if err != nil {
		return nil, err
	}
	fingerprint, _ := credential.Metadata["host_key_fingerprint"].(string)
	if !strings.HasPrefix(fingerprint, "SHA256:") {
		return nil, errors.New("SSH host-key fingerprint is required")
	}
	auth, err := sshAuth(credential)
	if err != nil {
		return nil, err
	}
	config := &ssh.ClientConfig{
		User:            credential.Username,
		Auth:            []ssh.AuthMethod{auth},
		HostKeyCallback: verifyFingerprint(fingerprint),
		Timeout:         30 * time.Second,
	}
	address := net.JoinHostPort(target, strconv.Itoa(port))
	connection, err := (&net.Dialer{Timeout: 30 * time.Second}).DialContext(ctx, "tcp", address)
	if err != nil {
		return nil, errors.New("SSH connection failed")
	}
	defer connection.Close()
	clientConn, channels, requests, err := ssh.NewClientConn(connection, address, config)
	if err != nil {
		return nil, errors.New("SSH authentication or host-key verification failed")
	}
	client := ssh.NewClient(clientConn, channels, requests)
	defer client.Close()
	session, err := client.NewSession()
	if err != nil {
		return nil, errors.New("SSH session creation failed")
	}
	defer session.Close()
	output := &limitedBuffer{maximum: maxOutputBytes}
	session.Stdout = output
	session.Stderr = output
	if err := session.Start(command); err != nil {
		return nil, errors.New("SSH inventory command could not start")
	}
	done := make(chan error, 1)
	go func() { done <- session.Wait() }()
	select {
	case <-ctx.Done():
		_ = session.Close()
		return nil, ctx.Err()
	case err := <-done:
		if err != nil {
			return nil, errors.New("SSH inventory command failed")
		}
	}
	return output.Bytes(), nil
}

func isFixedCommand(command string) bool {
	for _, allowed := range fixedCommands {
		if command == allowed {
			return true
		}
	}
	return false
}

func sshAuth(credential policy.Credential) (ssh.AuthMethod, error) {
	switch credential.AuthType {
	case "password":
		return ssh.Password(credential.Secret), nil
	case "ssh_private_key":
		signer, err := ssh.ParsePrivateKey([]byte(credential.Secret))
		if err != nil {
			return nil, errors.New("SSH private key could not be parsed")
		}
		return ssh.PublicKeys(signer), nil
	default:
		return nil, errors.New("unsupported SSH authentication type")
	}
}

func verifyFingerprint(expected string) ssh.HostKeyCallback {
	return func(_ string, _ net.Addr, key ssh.PublicKey) error {
		if ssh.FingerprintSHA256(key) != expected {
			return errors.New("SSH host-key fingerprint mismatch")
		}
		return nil
	}
}

func metadataInt(metadata map[string]any, key string, fallback int) (int, error) {
	value, exists := metadata[key]
	if !exists {
		return fallback, nil
	}
	switch typed := value.(type) {
	case float64:
		return int(typed), nil
	case int:
		return typed, nil
	case json.Number:
		parsed, err := strconv.Atoi(typed.String())
		return parsed, err
	default:
		return 0, fmt.Errorf("credential metadata %s is invalid", key)
	}
}

type limitedBuffer struct {
	buffer  bytes.Buffer
	maximum int
}

func (w *limitedBuffer) Write(data []byte) (int, error) {
	if w.buffer.Len()+len(data) > w.maximum {
		return 0, errors.New("inventory output exceeded the configured limit")
	}
	return w.buffer.Write(data)
}

func (w *limitedBuffer) Bytes() []byte { return w.buffer.Bytes() }

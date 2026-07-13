// Package winrm_inventory collects read-only Windows OS and installed-software inventory.
package winrm_inventory

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"time"

	"github.com/masterzen/winrm"

	"github.com/codebooker/vulna/scout/internal/policy"
)

const (
	maxOutputBytes  = 8 << 20
	fixedPowerShell = `$ErrorActionPreference = 'Stop'
$os = Get-CimInstance -ClassName Win32_OperatingSystem | Select-Object Caption, Version
$packages = @(
  Get-ItemProperty 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*', 'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*' -ErrorAction SilentlyContinue |
    Where-Object { $_.DisplayName -and $_.DisplayVersion } |
    ForEach-Object {
      [pscustomobject]@{
        name = [string]$_.DisplayName
        package_key = ([string]$_.DisplayName).ToLowerInvariant()
        version = [string]$_.DisplayVersion
        architecture = if ($_.PSPath -like '*WOW6432Node*') { 'x86' } else { 'x64' }
        publisher = [string]$_.Publisher
        product_key = ([string]$_.DisplayName).ToLowerInvariant()
        install_date = if ($_.InstallDate -match '^\d{8}$') { $_.InstallDate.Substring(0,4) + '-' + $_.InstallDate.Substring(4,2) + '-' + $_.InstallDate.Substring(6,2) } else { $null }
      }
    }
)
[pscustomobject]@{
  operating_system = [pscustomobject]@{ name = [string]$os.Caption; version = [string]$os.Version }
  packages = $packages
} | ConvertTo-Json -Compress -Depth 5`
)

// Transport is injectable for supported Windows release-test VMs.
type Transport interface {
	Collect(context.Context, string, policy.Credential) ([]byte, error)
}

type Worker struct{ transport Transport }

func NewWorker() *Worker { return &Worker{transport: &WinRMTransport{}} }

func NewWorkerWithTransport(transport Transport) *Worker { return &Worker{transport: transport} }

func (w *Worker) Stage() string { return "inventory" }

func (w *Worker) Name() string { return "winrm_inventory" }

func (w *Worker) Run(ctx context.Context, job *policy.Job) ([]byte, error) {
	target, err := singleHost(job.Targets)
	if err != nil {
		return nil, err
	}
	credential, err := credentialFor(job)
	if err != nil {
		return nil, err
	}
	commandCtx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	raw, err := w.transport.Collect(commandCtx, target, credential)
	if err != nil {
		return nil, err
	}
	var payload struct {
		OperatingSystem map[string]any   `json:"operating_system"`
		Packages        []map[string]any `json:"packages"`
	}
	if err := json.Unmarshal(raw, &payload); err != nil {
		return nil, errors.New("WinRM inventory output is not valid JSON")
	}
	if len(payload.Packages) > 50_000 {
		return nil, errors.New("WinRM inventory exceeded the package limit")
	}
	return json.Marshal(payload)
}

func credentialFor(job *policy.Job) (policy.Credential, error) {
	for _, credential := range job.Credentials {
		if credential.Protocol == "winrm" {
			if credential.AuthType != "password" {
				return policy.Credential{}, errors.New("WinRM requires password authentication")
			}
			return credential, nil
		}
	}
	return policy.Credential{}, errors.New("job has no WinRM credential")
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

// WinRMTransport uses WinRM/WinRS with TLS verification always enabled. The
// fixed PowerShell script is read-only and cannot be influenced by job fields.
type WinRMTransport struct{}

func (t *WinRMTransport) Collect(
	ctx context.Context, target string, credential policy.Credential,
) ([]byte, error) {
	https, _ := credential.Metadata["https"].(bool)
	if !https {
		return nil, errors.New("WinRM collector requires HTTPS")
	}
	port, err := metadataInt(credential.Metadata, "port", 5986)
	if err != nil {
		return nil, err
	}
	tlsServerName, _ := credential.Metadata["tls_server_name"].(string)
	caCertificate, _ := credential.Metadata["ca_certificate_pem"].(string)
	if tlsServerName == "" && caCertificate == "" {
		return nil, errors.New("WinRM TLS verification metadata is required")
	}
	endpoint := winrm.NewEndpoint(
		target,
		port,
		true,
		false,
		[]byte(caCertificate),
		nil,
		nil,
		30*time.Second,
	)
	endpoint.TLSServerName = tlsServerName
	parameters := winrm.NewParameters("PT120S", "en-US", 153600)
	authentication, _ := credential.Metadata["authentication"].(string)
	if authentication == "ntlm" || authentication == "" {
		parameters.TransportDecorator = func() winrm.Transporter { return &winrm.ClientNTLM{} }
	} else if authentication != "basic" {
		return nil, errors.New("unsupported WinRM authentication method")
	}
	client, err := winrm.NewClientWithParameters(
		endpoint, credential.Username, credential.Secret, parameters,
	)
	if err != nil {
		return nil, errors.New("WinRM client configuration failed")
	}
	stdout := &limitedBuffer{maximum: maxOutputBytes}
	stderr := &limitedBuffer{maximum: 64 << 10}
	exitCode, err := client.RunWithContext(ctx, winrm.Powershell(fixedPowerShell), stdout, stderr)
	if err != nil || exitCode != 0 {
		return nil, errors.New("WinRM inventory command failed")
	}
	return stdout.Bytes(), nil
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

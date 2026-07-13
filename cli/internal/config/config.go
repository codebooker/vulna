// Package config models the small set of installer choices and the versioned
// answer file used for non-interactive installs. Interactive prompts are
// limited to these fields (roadmap: no required YAML for ordinary use).
package config

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
)

// SchemaVersion is the current answer-file schema version.
const SchemaVersion = 2

// DeploymentProfile controls the initial dashboard experience. It changes
// discoverability and recommendations only; it never disables capabilities or
// security controls.
type DeploymentProfile string

const (
	DeploymentSmallBusiness DeploymentProfile = "small_business"
	DeploymentEnterprise    DeploymentProfile = "enterprise"
	DeploymentCustom        DeploymentProfile = "custom"
)

// AccessMode is how the dashboard is reached.
type AccessMode string

const (
	// AccessLocalhost serves on this host with an internal (self-signed) CA.
	AccessLocalhost AccessMode = "localhost"
	// AccessLAN serves to a private network with an internal CA.
	AccessLAN AccessMode = "lan"
	// AccessPublic serves on a public hostname with automatic TLS.
	AccessPublic AccessMode = "public"
)

// Options is the complete, non-secret installer configuration.
type Options struct {
	SchemaVersion     int               `json:"schema_version"`
	InstallDir        string            `json:"install_dir"`
	DataDir           string            `json:"data_dir"`
	ConfigDir         string            `json:"config_dir"`
	AccessMode        AccessMode        `json:"access_mode"`
	URL               string            `json:"url,omitempty"` // hostname for lan/public
	AdminEmail        string            `json:"admin_email"`
	UpdateChecks      bool              `json:"update_checks"`
	ACMEEmail         string            `json:"acme_email,omitempty"` // for public TLS (Let's Encrypt)
	DeploymentProfile DeploymentProfile `json:"deployment_profile"`
}

// optionsV1 is retained only to load existing answer files. Save always emits
// the current schema.
type optionsV1 struct {
	SchemaVersion int        `json:"schema_version"`
	InstallDir    string     `json:"install_dir"`
	DataDir       string     `json:"data_dir"`
	ConfigDir     string     `json:"config_dir"`
	AccessMode    AccessMode `json:"access_mode"`
	URL           string     `json:"url,omitempty"`
	AdminEmail    string     `json:"admin_email"`
	UpdateChecks  bool       `json:"update_checks"`
	ACMEEmail     string     `json:"acme_email,omitempty"`
}

// Defaults returns a localhost single-host configuration rooted under baseDir.
func Defaults(baseDir string) Options {
	return Options{
		SchemaVersion:     SchemaVersion,
		InstallDir:        baseDir,
		DataDir:           filepath.Join(baseDir, "data"),
		ConfigDir:         filepath.Join(baseDir, "config"),
		AccessMode:        AccessLocalhost,
		UpdateChecks:      true,
		DeploymentProfile: DeploymentSmallBusiness,
	}
}

// Load reads and validates a versioned answer file.
func Load(path string) (Options, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Options{}, fmt.Errorf("read answer file: %w", err)
	}
	var envelope struct {
		SchemaVersion int `json:"schema_version"`
	}
	if err := json.Unmarshal(data, &envelope); err != nil {
		return Options{}, fmt.Errorf("parse answer file %s: %w", path, err)
	}

	var o Options
	switch envelope.SchemaVersion {
	case 1:
		var legacy optionsV1
		if err := decodeStrict(data, &legacy); err != nil {
			return o, fmt.Errorf("parse answer file %s: %w", path, err)
		}
		o = Options{
			SchemaVersion: SchemaVersion, InstallDir: legacy.InstallDir,
			DataDir: legacy.DataDir, ConfigDir: legacy.ConfigDir,
			AccessMode: legacy.AccessMode, URL: legacy.URL,
			AdminEmail: legacy.AdminEmail, UpdateChecks: legacy.UpdateChecks,
			ACMEEmail: legacy.ACMEEmail, DeploymentProfile: DeploymentSmallBusiness,
		}
	case SchemaVersion:
		if err := decodeStrict(data, &o); err != nil {
			return o, fmt.Errorf("parse answer file %s: %w", path, err)
		}
	default:
		return o, fmt.Errorf(
			"answer file schema_version %d is not supported (expected 1 or %d)",
			envelope.SchemaVersion, SchemaVersion)
	}
	if err := o.Validate(); err != nil {
		return o, err
	}
	return o, nil
}

func decodeStrict(data []byte, value any) error {
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(value); err != nil {
		return err
	}
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		if err == nil {
			return fmt.Errorf("answer file contains more than one JSON value")
		}
		return err
	}
	return nil
}

// Save writes the answer file (non-secret) for reproducible re-runs.
func Save(path string, o Options) error {
	o.SchemaVersion = SchemaVersion
	if o.DeploymentProfile == "" {
		o.DeploymentProfile = DeploymentSmallBusiness
	}
	data, err := json.MarshalIndent(o, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(data, '\n'), 0o644)
}

// Normalize fills defaults and resolves directories to absolute paths.
func (o *Options) Normalize() error {
	if o.SchemaVersion == 0 {
		o.SchemaVersion = SchemaVersion
	}
	if o.AccessMode == "" {
		o.AccessMode = AccessLocalhost
	}
	if o.DeploymentProfile == "" {
		o.DeploymentProfile = DeploymentSmallBusiness
	}
	for _, p := range []*string{&o.InstallDir, &o.DataDir, &o.ConfigDir} {
		if *p == "" {
			continue
		}
		abs, err := filepath.Abs(*p)
		if err != nil {
			return fmt.Errorf("resolve path %q: %w", *p, err)
		}
		*p = abs
	}
	return nil
}

// Validate reports whether the options are internally consistent.
func (o Options) Validate() error {
	switch o.DeploymentProfile {
	case DeploymentSmallBusiness, DeploymentEnterprise, DeploymentCustom:
	default:
		return fmt.Errorf(
			"deployment_profile %q is not one of small_business, enterprise, custom",
			o.DeploymentProfile,
		)
	}
	switch o.AccessMode {
	case AccessLocalhost, AccessLAN, AccessPublic:
	default:
		return fmt.Errorf("access_mode %q is not one of localhost, lan, public", o.AccessMode)
	}
	if o.InstallDir == "" {
		return fmt.Errorf("install_dir is required")
	}
	if o.DataDir == "" {
		return fmt.Errorf("data_dir is required")
	}
	if o.AdminEmail == "" || !strings.Contains(o.AdminEmail, "@") {
		return fmt.Errorf("admin_email must be a valid email address")
	}
	// Public mode uses automatic TLS (Let's Encrypt), which needs a real domain: a
	// certificate cannot be issued for a bare IP. LAN mode uses the internal CA
	// and works by hostname OR raw IP — the single-host profile serves probe mTLS
	// on its own :8443 listener, so the browser :443 accepts a no-SNI (IP)
	// handshake (see deploy/single-host/Caddyfile).
	if o.AccessMode == AccessPublic {
		if o.URL == "" {
			return fmt.Errorf("url (public hostname) is required for access_mode public")
		}
		if isIPHost(o.URL) {
			return fmt.Errorf(
				"url %q is an IP address, but public mode uses Let's Encrypt, which cannot "+
					"issue a certificate for a bare IP; use a domain name", o.URL)
		}
		if o.ACMEEmail == "" || !strings.Contains(o.ACMEEmail, "@") {
			return fmt.Errorf("acme_email is required for public TLS (Let's Encrypt)")
		}
	}
	return nil
}

// isIPHost reports whether s (a hostname, host:port, or URL) is a raw IP literal
// rather than a DNS name.
func isIPHost(s string) bool {
	h := s
	if i := strings.Index(h, "://"); i >= 0 {
		h = h[i+3:]
	}
	if i := strings.IndexAny(h, "/"); i >= 0 {
		h = h[:i]
	}
	if host, _, err := net.SplitHostPort(h); err == nil {
		h = host
	}
	h = strings.Trim(h, "[]") // unwrap an IPv6 literal
	return net.ParseIP(h) != nil
}

// Domain returns the value for VULNA_DOMAIN given the access mode.
func (o Options) Domain() string {
	switch o.AccessMode {
	case AccessPublic, AccessLAN:
		if o.URL != "" {
			return o.URL
		}
	}
	return "localhost"
}

// CaddyTLS returns the value for CADDY_TLS: an ACME email for public mode, or
// "internal" (self-signed CA) otherwise.
func (o Options) CaddyTLS() string {
	if o.AccessMode == AccessPublic && o.ACMEEmail != "" {
		return o.ACMEEmail
	}
	return "internal"
}

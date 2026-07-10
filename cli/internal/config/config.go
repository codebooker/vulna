// Package config models the small set of installer choices and the versioned
// answer file used for non-interactive installs. Interactive prompts are
// limited to these fields (roadmap: no required YAML for ordinary use).
package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// SchemaVersion is the current answer-file schema version.
const SchemaVersion = 1

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
	SchemaVersion int        `json:"schema_version"`
	InstallDir    string     `json:"install_dir"`
	DataDir       string     `json:"data_dir"`
	ConfigDir     string     `json:"config_dir"`
	AccessMode    AccessMode `json:"access_mode"`
	URL           string     `json:"url,omitempty"` // hostname for lan/public
	AdminEmail    string     `json:"admin_email"`
	UpdateChecks  bool       `json:"update_checks"`
	ACMEEmail     string     `json:"acme_email,omitempty"` // for public TLS (Let's Encrypt)
}

// Defaults returns a localhost single-host configuration rooted under baseDir.
func Defaults(baseDir string) Options {
	return Options{
		SchemaVersion: SchemaVersion,
		InstallDir:    baseDir,
		DataDir:       filepath.Join(baseDir, "data"),
		ConfigDir:     filepath.Join(baseDir, "config"),
		AccessMode:    AccessLocalhost,
		UpdateChecks:  true,
	}
}

// Load reads and validates a versioned answer file.
func Load(path string) (Options, error) {
	var o Options
	data, err := os.ReadFile(path)
	if err != nil {
		return o, fmt.Errorf("read answer file: %w", err)
	}
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&o); err != nil {
		return o, fmt.Errorf("parse answer file %s: %w", path, err)
	}
	if o.SchemaVersion != SchemaVersion {
		return o, fmt.Errorf(
			"answer file schema_version %d is not supported (expected %d)",
			o.SchemaVersion, SchemaVersion)
	}
	if err := o.Validate(); err != nil {
		return o, err
	}
	return o, nil
}

// Save writes the answer file (non-secret) for reproducible re-runs.
func Save(path string, o Options) error {
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
	if o.AccessMode == AccessPublic {
		if o.URL == "" {
			return fmt.Errorf("url (public hostname) is required for access_mode public")
		}
		if o.ACMEEmail == "" || !strings.Contains(o.ACMEEmail, "@") {
			return fmt.Errorf("acme_email is required for public TLS (Let's Encrypt)")
		}
	}
	return nil
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

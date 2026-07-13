package config

import (
	"os"
	"path/filepath"
	"testing"
)

func writeFile(path, content string) error {
	return os.WriteFile(path, []byte(content), 0o644)
}

func validLocalhost() Options {
	o := Defaults("/opt/vulna")
	o.AdminEmail = "admin@example.com"
	return o
}

func TestRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "answers.json")
	o := validLocalhost()
	if err := Save(path, o); err != nil {
		t.Fatal(err)
	}
	got, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if got.AccessMode != o.AccessMode || got.AdminEmail != o.AdminEmail ||
		got.DeploymentProfile != DeploymentSmallBusiness {
		t.Fatalf("round trip mismatch: %+v vs %+v", got, o)
	}
}

func TestSchemaVersionMismatch(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "answers.json")
	content := `{"schema_version":999,"install_dir":"/opt/vulna","data_dir":"/opt/vulna/data",` +
		`"config_dir":"/opt/vulna/config","access_mode":"localhost",` +
		`"admin_email":"a@b.com","update_checks":true,"deployment_profile":"small_business"}`
	if err := writeFile(path, content); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("expected schema version mismatch error")
	}
}

func TestValidateAccessMode(t *testing.T) {
	o := validLocalhost()
	o.AccessMode = "carrier-pigeon"
	if err := o.Validate(); err == nil {
		t.Fatal("expected invalid access mode error")
	}
}

func TestValidatePublicRequiresURLAndACME(t *testing.T) {
	o := validLocalhost()
	o.AccessMode = AccessPublic
	if err := o.Validate(); err == nil {
		t.Fatal("public without url/acme should fail")
	}
	o.URL = "vulna.example.com"
	if err := o.Validate(); err == nil {
		t.Fatal("public without acme email should fail")
	}
	o.ACMEEmail = "ops@example.com"
	if err := o.Validate(); err != nil {
		t.Fatalf("valid public config should pass: %v", err)
	}
}

func TestValidateLANAllowsHostnameOrIP(t *testing.T) {
	// The single-host profile serves probe mTLS on its own :8443 listener, so the
	// browser :443 accepts a no-SNI (raw IP) handshake — LAN access works by
	// hostname or IP, and an empty URL (defaults to the localhost site) is fine.
	o := validLocalhost()
	o.AccessMode = AccessLAN
	for _, url := range []string{"", "vulna.lan", "192.168.1.10", "[2001:db8::1]"} {
		o.URL = url
		if err := o.Validate(); err != nil {
			t.Fatalf("LAN mode with url %q should pass: %v", url, err)
		}
	}
}

func TestValidatePublicRejectsIPHost(t *testing.T) {
	// Public mode uses Let's Encrypt, which cannot issue for a bare IP.
	o := validLocalhost()
	o.AccessMode = AccessPublic
	o.ACMEEmail = "ops@example.com"
	o.URL = "203.0.113.5"
	if err := o.Validate(); err == nil {
		t.Fatal("public mode with an IP host should fail")
	}
}

func TestValidateAdminEmail(t *testing.T) {
	o := validLocalhost()
	o.AdminEmail = "not-an-email"
	if err := o.Validate(); err == nil {
		t.Fatal("bad admin email should fail")
	}
}

func TestDomainAndCaddyTLS(t *testing.T) {
	o := validLocalhost()
	if o.Domain() != "localhost" || o.CaddyTLS() != "internal" {
		t.Fatalf("localhost mode wrong: domain=%s tls=%s", o.Domain(), o.CaddyTLS())
	}
	o.AccessMode = AccessPublic
	o.URL = "vulna.example.com"
	o.ACMEEmail = "ops@example.com"
	if o.Domain() != "vulna.example.com" || o.CaddyTLS() != "ops@example.com" {
		t.Fatalf("public mode wrong: domain=%s tls=%s", o.Domain(), o.CaddyTLS())
	}
}

func TestLoadRejectsUnknownFields(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "answers.json")
	// hand-write JSON with an unexpected key
	content := `{"schema_version":2,"install_dir":"/opt/vulna","data_dir":"/opt/vulna/data",` +
		`"access_mode":"localhost","admin_email":"a@b.com","surprise":true}`
	if err := writeFile(path, content); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("unknown field should be rejected")
	}
}

func TestLoadV1DefaultsDeploymentProfile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "answers-v1.json")
	content := `{"schema_version":1,"install_dir":"/opt/vulna","data_dir":"/opt/vulna/data",` +
		`"config_dir":"/opt/vulna/config","access_mode":"localhost",` +
		`"admin_email":"a@b.com","update_checks":true}`
	if err := writeFile(path, content); err != nil {
		t.Fatal(err)
	}
	got, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if got.SchemaVersion != SchemaVersion || got.DeploymentProfile != DeploymentSmallBusiness {
		t.Fatalf("v1 migration mismatch: %+v", got)
	}
}

func TestValidateDeploymentProfile(t *testing.T) {
	o := validLocalhost()
	o.DeploymentProfile = "security-off"
	if err := o.Validate(); err == nil {
		t.Fatal("expected invalid deployment profile error")
	}
}

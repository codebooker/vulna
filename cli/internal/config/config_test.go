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
	if got.AccessMode != o.AccessMode || got.AdminEmail != o.AdminEmail {
		t.Fatalf("round trip mismatch: %+v vs %+v", got, o)
	}
}

func TestSchemaVersionMismatch(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "answers.json")
	o := validLocalhost()
	o.SchemaVersion = 999
	if err := Save(path, o); err != nil {
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
	content := `{"schema_version":1,"install_dir":"/opt/vulna","data_dir":"/opt/vulna/data",` +
		`"access_mode":"localhost","admin_email":"a@b.com","surprise":true}`
	if err := writeFile(path, content); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("unknown field should be rejected")
	}
}

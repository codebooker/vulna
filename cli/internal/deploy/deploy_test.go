package deploy

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/codebooker/vulna/cli/internal/config"
)

func opts(dir string) config.Options {
	o := config.Defaults(dir)
	o.AdminEmail = "admin@example.com"
	_ = o.Normalize()
	return o
}

func TestApplyWritesRestrictiveEnv(t *testing.T) {
	dir := t.TempDir()
	o := opts(dir)
	if err := Apply(o); err != nil {
		t.Fatal(err)
	}
	envPath := filepath.Join(o.InstallDir, EnvFile)
	info, err := os.Stat(envPath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("env file must be 0600, got %o", info.Mode().Perm())
	}
	env, _ := ReadEnv(envPath)
	for _, k := range []string{"POSTGRES_PASSWORD", "VULNA_SECRET_KEY", "VULNA_ADMIN_PASSWORD", "VULNA_MASTER_KEY"} {
		if env[k] == "" {
			t.Fatalf("missing generated secret %s", k)
		}
	}
	if env["VULNA_ADMIN_EMAIL"] != "admin@example.com" {
		t.Fatalf("admin email not written: %q", env["VULNA_ADMIN_EMAIL"])
	}
}

func TestRerunDoesNotRotateSecrets(t *testing.T) {
	dir := t.TempDir()
	o := opts(dir)
	if err := Apply(o); err != nil {
		t.Fatal(err)
	}
	before, _ := ReadEnv(filepath.Join(o.InstallDir, EnvFile))
	if err := Apply(o); err != nil {
		t.Fatal(err)
	}
	after, _ := ReadEnv(filepath.Join(o.InstallDir, EnvFile))
	for _, k := range []string{"POSTGRES_PASSWORD", "VULNA_SECRET_KEY", "VULNA_ADMIN_PASSWORD", "VULNA_MASTER_KEY"} {
		if before[k] != after[k] {
			t.Fatalf("secret %s was rotated on re-run", k)
		}
	}
}

func TestRerunPreservesManualEdits(t *testing.T) {
	dir := t.TempDir()
	o := opts(dir)
	if err := Apply(o); err != nil {
		t.Fatal(err)
	}
	// Operator edits a non-secret setting by hand.
	envPath := filepath.Join(o.InstallDir, EnvFile)
	env, _ := ReadEnv(envPath)
	env["VULNA_DOMAIN"] = "custom.example.internal"
	if err := WriteEnv(envPath, env); err != nil {
		t.Fatal(err)
	}
	if err := Apply(o); err != nil {
		t.Fatal(err)
	}
	got, _ := ReadEnv(envPath)
	if got["VULNA_DOMAIN"] != "custom.example.internal" {
		t.Fatalf("manual edit overwritten: %q", got["VULNA_DOMAIN"])
	}
}

func TestPlanReflectsKeepOnRerun(t *testing.T) {
	dir := t.TempDir()
	o := opts(dir)
	if err := Apply(o); err != nil {
		t.Fatal(err)
	}
	plan, err := PlanInstall(o)
	if err != nil {
		t.Fatal(err)
	}
	var envAction Action
	for _, a := range plan.Actions {
		if a.Path == filepath.Join(o.InstallDir, EnvFile) {
			envAction = a
		}
	}
	if envAction.Kind != ActionKeep {
		t.Fatalf("re-run plan should keep the env file, got %q", envAction.Kind)
	}
}

func TestPlanDoesNotWriteAnything(t *testing.T) {
	dir := t.TempDir()
	o := opts(dir)
	if _, err := PlanInstall(o); err != nil {
		t.Fatal(err)
	}
	// A plan must not create the env file.
	if _, err := os.Stat(filepath.Join(o.InstallDir, EnvFile)); !os.IsNotExist(err) {
		t.Fatal("PlanInstall must not write the env file")
	}
}

func TestRemoveGeneratedFilesLeavesDataDir(t *testing.T) {
	dir := t.TempDir()
	o := opts(dir)
	if err := Apply(o); err != nil {
		t.Fatal(err)
	}
	// Simulate persistent data present in the data dir.
	dataMarker := filepath.Join(o.DataDir, "keep.me")
	if err := os.WriteFile(dataMarker, []byte("data"), 0o600); err != nil {
		t.Fatal(err)
	}
	removed, err := RemoveGeneratedFiles(o.InstallDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(removed) != 2 {
		t.Fatalf("expected env + record removed, got %v", removed)
	}
	if _, err := os.Stat(dataMarker); err != nil {
		t.Fatalf("data must be preserved: %v", err)
	}
}

func TestReadEnvIgnoresCommentsAndBlanks(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, ".env")
	content := "# comment\n\nFOO=bar\n  BAZ = qux \n"
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	m, _ := ReadEnv(p)
	if m["FOO"] != "bar" || m["BAZ"] != "qux" {
		t.Fatalf("parse failed: %+v", m)
	}
}

func TestSetEnvVersionRewritesVersion(t *testing.T) {
	dir := t.TempDir()
	if err := Apply(opts(dir)); err != nil {
		t.Fatal(err)
	}
	before, _ := ReadEnv(filepath.Join(dir, EnvFile))
	if before["VULNA_VERSION"] == "" {
		t.Fatal("install must pin a VULNA_VERSION")
	}
	if err := SetEnvVersion(dir, "v9.9.9"); err != nil {
		t.Fatal(err)
	}
	after, _ := ReadEnv(filepath.Join(dir, EnvFile))
	if after["VULNA_VERSION"] != "v9.9.9" {
		t.Fatalf("VULNA_VERSION not updated: %q", after["VULNA_VERSION"])
	}
	// Other secrets are untouched by a version change.
	if after["POSTGRES_PASSWORD"] != before["POSTGRES_PASSWORD"] {
		t.Fatal("SetEnvVersion must not disturb other env values")
	}
}

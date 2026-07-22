package scannersandbox

import (
	"os"
	"path/filepath"
	"testing"
)

func TestPrepareWorkspaceSeedsPackagedNucleiIgnore(t *testing.T) {
	config := t.TempDir()
	templates := t.TempDir()
	workspace := t.TempDir()
	if err := os.MkdirAll(filepath.Join(config, "nuclei"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(
		filepath.Join(config, "nuclei", ".templates-config.json"),
		[]byte(`{"nuclei-templates-directory":"/opt/nuclei-templates"}`),
		0o600,
	); err != nil {
		t.Fatal(err)
	}
	want := []byte("tags:\n  - dos\nfiles:\n  - weak-template.yaml\n")
	if err := os.WriteFile(filepath.Join(templates, nucleiIgnoreFile), want, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("XDG_CONFIG_HOME", config)
	t.Setenv(nucleiTemplatesEnv, templates)

	if err := prepareWorkspace(workspace); err != nil {
		t.Fatal(err)
	}
	destination := filepath.Join(workspace, ".config", "nuclei", nucleiIgnoreFile)
	got, err := os.ReadFile(destination)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(want) {
		t.Fatalf("ignore policy = %q, want %q", got, want)
	}
	info, err := os.Stat(destination)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("ignore policy mode = %o, want 600", info.Mode().Perm())
	}
}

package main

import "testing"

func TestMergeRestoredEnvPreservesHostDatabaseSettings(t *testing.T) {
	// This host uses assembled POSTGRES_* (no DATABASE_URL). The backup came from a
	// host that used a DATABASE_URL and prefixed vars pointing at a different DB.
	current := map[string]string{
		"POSTGRES_USER":     "vuser",
		"POSTGRES_DB":       "vdb",
		"POSTGRES_PASSWORD": "hostpw",
		"VULNA_MASTER_KEY":  "host-key-ignored",
	}
	restored := map[string]string{
		"DATABASE_URL":            "postgresql+asyncpg://olduser:oldpw@oldhost:5432/olddb",
		"VULNA_POSTGRES_USER":     "olduser",
		"VULNA_POSTGRES_PASSWORD": "oldpw",
		"POSTGRES_USER":           "olduser",
		"POSTGRES_DB":             "olddb",
		"POSTGRES_PASSWORD":       "oldpw",
		"VULNA_MASTER_KEY":        "backup-master-key", // must be restored from backup
		"VULNA_DOMAIN":            "old.example.com",
	}
	out := mergeRestoredEnv(current, restored)

	// The stale DATABASE_URL and prefixed variants must NOT survive.
	if _, ok := out["DATABASE_URL"]; ok {
		t.Error("stale DATABASE_URL from the backup must be removed (host has none)")
	}
	if _, ok := out["VULNA_POSTGRES_USER"]; ok {
		t.Error("stale VULNA_POSTGRES_USER must be removed")
	}
	if _, ok := out["VULNA_POSTGRES_PASSWORD"]; ok {
		t.Error("stale VULNA_POSTGRES_PASSWORD must be removed")
	}
	// The host's DB credentials win.
	if out["POSTGRES_USER"] != "vuser" || out["POSTGRES_DB"] != "vdb" || out["POSTGRES_PASSWORD"] != "hostpw" {
		t.Errorf("host DB creds not preserved: %v", out)
	}
	// Non-DB secrets come from the backup.
	if out["VULNA_MASTER_KEY"] != "backup-master-key" {
		t.Errorf("master key must come from the backup, got %q", out["VULNA_MASTER_KEY"])
	}
	if out["VULNA_DOMAIN"] != "old.example.com" {
		t.Errorf("non-DB app settings should come from the backup, got %q", out["VULNA_DOMAIN"])
	}
}

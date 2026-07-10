package update

import (
	"testing"
	"time"

	"github.com/codebooker/vulna/cli/internal/release"
)

func healthyDeps() Deps {
	return Deps{
		MinFreeBytes:           1 << 30,
		DataDir:                "/data",
		FreeDisk:               func(string) (uint64, error) { return 50 << 30, nil },
		ActiveIncompatibleJobs: func() (int, error) { return 0, nil },
		BackupPresent:          func() (bool, string) { return true, "recent backup present" },
		DBHealthy:              func() (bool, string) { return true, "ok" },
		LocalModifications:     func() (bool, string) { return false, "" },
	}
}

func find(cs []Check, name string) Check {
	for _, c := range cs {
		if c.Name == name {
			return c
		}
	}
	return Check{Name: "MISSING"}
}

func TestPreflightHealthy(t *testing.T) {
	if Blocking(Preflight(healthyDeps(), nil)) {
		t.Fatal("healthy deps should not block")
	}
}

func TestActiveJobsBlock(t *testing.T) {
	d := healthyDeps()
	d.ActiveIncompatibleJobs = func() (int, error) { return 2, nil }
	cs := Preflight(d, nil)
	if !Blocking(cs) || find(cs, "active-jobs").Status != Fail {
		t.Fatal("active incompatible jobs must block the update")
	}
}

func TestInsufficientDiskBlocks(t *testing.T) {
	d := healthyDeps()
	d.FreeDisk = func(string) (uint64, error) { return 1 << 20, nil }
	if !Blocking(Preflight(d, nil)) {
		t.Fatal("insufficient disk must block")
	}
}

func TestUnhealthyDBBlocks(t *testing.T) {
	d := healthyDeps()
	d.DBHealthy = func() (bool, string) { return false, "cannot connect" }
	if !Blocking(Preflight(d, nil)) {
		t.Fatal("unhealthy database must block")
	}
}

func TestNoBackupWarnsNotBlocks(t *testing.T) {
	d := healthyDeps()
	d.BackupPresent = func() (bool, string) { return false, "" }
	cs := Preflight(d, nil)
	if Blocking(cs) {
		t.Fatal("missing backup should warn, not block (auto-backup covers it)")
	}
	if find(cs, "backup").Status != Warn {
		t.Fatal("backup should warn")
	}
}

func TestMigrationWarns(t *testing.T) {
	m := &release.Manifest{Migration: release.Migration{HasMigrations: true}}
	cs := Preflight(healthyDeps(), m)
	if find(cs, "migration").Status != Warn {
		t.Fatal("schema-changing release should surface a migration warning")
	}
}

func TestStateRoundTripAndRollback(t *testing.T) {
	dir := t.TempDir()
	s := State{Channel: "stable", CurrentVersion: "1.0.0"}
	if err := SaveState(dir, s); err != nil {
		t.Fatal(err)
	}
	got, err := LoadState(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got.CurrentVersion != "1.0.0" {
		t.Fatalf("round trip mismatch: %+v", got)
	}

	// No prior version yet -> cannot roll back.
	if _, _, _, err := PrepareRollback(got); err == nil {
		t.Fatal("rollback with no prior version should error")
	}

	applied := RecordApplied(got, "1.1.0", "/backups/pre-1.1.0.tar.gz", true, time.Now())
	if applied.PriorVersion != "1.0.0" || applied.CurrentVersion != "1.1.0" {
		t.Fatalf("record applied wrong: %+v", applied)
	}
	version, backup, hadMigr, err := PrepareRollback(applied)
	if err != nil || version != "1.0.0" || backup == "" || !hadMigr {
		t.Fatalf("rollback prep wrong: v=%s b=%s m=%v err=%v", version, backup, hadMigr, err)
	}
}

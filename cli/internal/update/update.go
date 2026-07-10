// Package update runs pre-update safety checks and tracks the applied/rollback
// version so an interrupted or unhealthy update can be reverted to the prior
// known-good version. Nothing here downloads or executes code; it gates and
// records an update the operator applies deliberately.
package update

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/codebooker/vulna/cli/internal/release"
)

// Status of a pre-update check.
type Status string

const (
	OK   Status = "ok"
	Warn Status = "warn"
	Fail Status = "fail"
)

// Check is one pre-update safety result.
type Check struct {
	Name        string
	Status      Status
	Detail      string
	Remediation string
}

// Deps are the injectable probes for pre-update checks.
type Deps struct {
	MinFreeBytes           uint64
	DataDir                string
	FreeDisk               func(path string) (uint64, error)
	ActiveIncompatibleJobs func() (int, error)
	BackupPresent          func() (bool, string)
	DBHealthy              func() (bool, string)
	LocalModifications     func() (bool, string)
}

// Preflight runs the pre-update checks against a verified manifest.
func Preflight(d Deps, m *release.Manifest) []Check {
	var out []Check

	// Active incompatible assessment: an update must not start while one runs.
	if d.ActiveIncompatibleJobs != nil {
		n, err := d.ActiveIncompatibleJobs()
		switch {
		case err != nil:
			out = append(out, Check{"active-jobs", Warn, "could not check active jobs",
				"verify no incompatible assessment is running before updating"})
		case n > 0:
			out = append(out, Check{"active-jobs", Fail,
				fmt.Sprintf("%d incompatible assessment(s) running", n),
				"wait for them to finish or cancel them, then retry the update"})
		default:
			out = append(out, Check{"active-jobs", OK, "no blocking assessments", ""})
		}
	}

	// Free disk for the backup + new version.
	if d.FreeDisk != nil {
		free, err := d.FreeDisk(d.DataDir)
		if err != nil {
			out = append(out, Check{"disk", Warn, "could not read free disk", "ensure adequate free space"})
		} else if free < d.MinFreeBytes {
			out = append(out, Check{"disk", Fail, "insufficient free disk",
				"free space for the pre-update backup and the new version, then retry"})
		} else {
			out = append(out, Check{"disk", OK, "sufficient free disk", ""})
		}
	}

	// Backup status (a backup is taken automatically unless overridden).
	if d.BackupPresent != nil {
		present, detail := d.BackupPresent()
		if present {
			out = append(out, Check{"backup", OK, detail, ""})
		} else {
			out = append(out, Check{"backup", Warn, "no recent backup found",
				"an automatic pre-update backup will be taken (use --no-backup only if you have your own)"})
		}
	}

	// Database health.
	if d.DBHealthy != nil {
		ok, detail := d.DBHealthy()
		if ok {
			out = append(out, Check{"database", OK, detail, ""})
		} else {
			out = append(out, Check{"database", Fail, detail,
				"resolve database health before updating (see `vulna preflight` and logs)"})
		}
	}

	// Local modifications to generated deployment files.
	if d.LocalModifications != nil {
		modified, detail := d.LocalModifications()
		if modified {
			out = append(out, Check{"local-mods", Warn, detail,
				"review your local changes; the update may overwrite generated files"})
		} else {
			out = append(out, Check{"local-mods", OK, "no local modifications", ""})
		}
	}

	// Migration impact is advisory (the backup covers rollback).
	if m != nil && m.Migration.HasMigrations {
		note := m.Migration.Notes
		if note == "" {
			note = "this release changes the database schema"
		}
		out = append(out, Check{"migration", Warn, note,
			"a pre-update backup will be taken so the change is reversible"})
	}
	return out
}

// Blocking reports whether any check is a hard failure.
func Blocking(checks []Check) bool {
	for _, c := range checks {
		if c.Status == Fail {
			return true
		}
	}
	return false
}

// State records the applied and prior versions so a rollback is possible.
type State struct {
	Channel          string `json:"channel"`
	CurrentVersion   string `json:"current_version"`
	PriorVersion     string `json:"prior_version,omitempty"`
	LastAppliedAt    string `json:"last_applied_at,omitempty"`
	RollbackBackup   string `json:"rollback_backup,omitempty"`
	RollbackHadMigr  bool   `json:"rollback_had_migrations,omitempty"`
	LastAvailable    string `json:"last_available,omitempty"`
	LastCheckedAt    string `json:"last_checked_at,omitempty"`
	LastAvailableSec string `json:"last_available_security,omitempty"`
}

const stateFile = ".vulna-update.json"

// LoadState reads the update state from dir (empty state if absent).
func LoadState(dir string) (State, error) {
	var s State
	data, err := os.ReadFile(filepath.Join(dir, stateFile))
	if err != nil {
		if os.IsNotExist(err) {
			return s, nil
		}
		return s, err
	}
	if err := json.Unmarshal(data, &s); err != nil {
		return s, fmt.Errorf("parse update state: %w", err)
	}
	return s, nil
}

// SaveState writes the update state to dir (0644; contains no secrets).
func SaveState(dir string, s State) error {
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, stateFile), append(data, '\n'), 0o644)
}

// RecordApplied advances the state after a successful update, preserving the
// prior version and the backup taken so rollback can restore a known-good state.
func RecordApplied(s State, newVersion, backupPath string, hadMigrations bool, now time.Time) State {
	s.PriorVersion = s.CurrentVersion
	s.CurrentVersion = newVersion
	s.LastAppliedAt = now.Format(time.RFC3339)
	s.RollbackBackup = backupPath
	s.RollbackHadMigr = hadMigrations
	return s
}

// PrepareRollback returns the version to roll back to and the backup to restore,
// or an error if no rollback point is recorded.
func PrepareRollback(s State) (version, backup string, hadMigrations bool, err error) {
	if s.PriorVersion == "" {
		return "", "", false, fmt.Errorf("no prior version recorded; nothing to roll back to")
	}
	return s.PriorVersion, s.RollbackBackup, s.RollbackHadMigr, nil
}

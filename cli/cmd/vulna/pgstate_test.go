package main

import "testing"

func TestPgBackupActionClassifiesEveryComposeState(t *testing.T) {
	cases := map[string]pgAction{
		// Definitively inactive -> safe to start for the backup and stop after.
		"exited":  pgStart,
		"created": pgStart,
		"absent":  pgStart,
		// Up or auto-recovering -> preserve; NEVER stop (the restarting bug).
		"running":    pgLeave,
		"restarting": pgLeave,
		// Transitional / broken -> refuse, don't guess.
		"paused":   pgReject,
		"removing": pgReject,
		"dead":     pgReject,
		"weird":    pgReject,
		"":         pgReject,
	}
	for state, want := range cases {
		if got := pgBackupAction(state); got != want {
			t.Errorf("pgBackupAction(%q) = %d, want %d", state, got, want)
		}
	}
}

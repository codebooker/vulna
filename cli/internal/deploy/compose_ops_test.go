package deploy

import "testing"

func TestNotReadyClassification(t *testing.T) {
	// expected: long-running services + one one-shot (scout-ca-export).
	expected := map[string]bool{
		"api": false, "postgres": false, "redis": false,
		"local-scout": false, "scout-ca-export": true,
	}
	healthy := []composePS{
		{Service: "api", State: "running", Health: "healthy"},
		{Service: "postgres", State: "running", Health: "healthy"},
		{Service: "redis", State: "running", Health: ""},                       // no healthcheck, running -> ok
		{Service: "local-scout", State: "running", Health: ""},                 // long-running, ok
		{Service: "scout-ca-export", State: "exited", Health: "", ExitCode: 0}, // one-shot done -> ok
	}
	if bad := notReady(expected, healthy); len(bad) != 0 {
		t.Errorf("fully-up stack should report none not-ready, got %v", bad)
	}

	// A dead LONG-RUNNING service that exited 0 must still be flagged (finding 7);
	// only the one-shot may be exited.
	badStates := []composePS{
		{Service: "api", State: "running", Health: "starting"}, // still starting
		{Service: "postgres", State: "running", Health: "healthy"},
		{Service: "redis", State: "running", Health: ""},
		{Service: "local-scout", State: "exited", Health: "", ExitCode: 0}, // long-running, dead -> bad
		{Service: "scout-ca-export", State: "exited", Health: "", ExitCode: 0},
	}
	bad := notReady(expected, badStates)
	if len(bad) != 2 {
		t.Errorf("expected 2 not-ready (api starting, local-scout exited), got %v", bad)
	}

	// A MISSING expected service (empty project) is NOT ready (finding 7).
	if bad := notReady(expected, nil); len(bad) != 5 {
		t.Errorf("empty project must report all 5 expected services missing, got %v", bad)
	}
}

func TestPgCredsDefaults(t *testing.T) {
	dir := t.TempDir()
	// No .env -> compose defaults.
	if u, d, _ := pgCreds(dir); u != "vulna" || d != "vulna" {
		t.Errorf("expected default user/db vulna/vulna, got %s/%s", u, d)
	}
	// .env overrides.
	if err := WriteEnv(dir+"/"+EnvFile, map[string]string{
		"POSTGRES_USER": "u1", "POSTGRES_DB": "d1", "POSTGRES_PASSWORD": "pw",
	}); err != nil {
		t.Fatal(err)
	}
	u, d, p := pgCreds(dir)
	if u != "u1" || d != "d1" || p != "pw" {
		t.Errorf("env creds not read: %s/%s/%s", u, d, p)
	}
}

func TestNonPostgresWritersToQuiesce(t *testing.T) {
	t.Run("running writers are stopped and inactive services are ignored", func(t *testing.T) {
		states := []composePS{
			{Service: "postgres", State: PgRestarting}, // handled separately by the caller
			{Service: "api", State: PgRunning},
			{Service: "local-scout", State: PgRunning},
			{Service: "scout-ca-export", State: PgExited},
			{Service: "not-created-yet", State: PgCreated},
		}
		got, err := nonPostgresWritersToQuiesce(states)
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != 2 || got[0] != "api" || got[1] != "local-scout" {
			t.Fatalf("writers = %v, want [api local-scout]", got)
		}
	})

	for _, state := range []string{PgRestarting, "paused", "removing", "dead", "", "weird"} {
		t.Run("reject_"+state, func(t *testing.T) {
			if _, err := nonPostgresWritersToQuiesce([]composePS{
				{Service: "api", State: state},
			}); err == nil {
				t.Fatalf("state %q must fail closed", state)
			}
		})
	}
}

package deploy

import "testing"

func TestUnhealthyClassification(t *testing.T) {
	// A service with a health check must be "healthy"; one without must be "running".
	states := []composePS{
		{Service: "api", State: "running", Health: "healthy"},
		{Service: "postgres", State: "running", Health: "healthy"},
		{Service: "redis", State: "running", Health: ""},                       // no healthcheck, running -> ok
		{Service: "scout-ca-export", State: "exited", Health: "", ExitCode: 0}, // one-shot done -> ok
	}
	if bad := unhealthy(states); len(bad) != 0 {
		t.Errorf("all-healthy stack (incl. a completed one-shot) should report none unhealthy, got %v", bad)
	}

	states = []composePS{
		{Service: "api", State: "running", Health: "starting"}, // still starting -> not yet
		{Service: "frontend", State: "running", Health: "unhealthy"},
		{Service: "caddy", State: "exited", Health: "", ExitCode: 1}, // crashed -> bad
		{Service: "redis", State: "running", Health: ""},
	}
	bad := unhealthy(states)
	if len(bad) != 3 {
		t.Errorf("expected 3 unhealthy (api starting, frontend unhealthy, caddy exited nonzero), got %v", bad)
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

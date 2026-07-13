package zap

import (
	"context"
	"slices"
	"testing"

	"github.com/codebooker/vulna/scout/internal/policy"
)

func zapJob(cfg map[string]any, targets []string) *policy.Job {
	return &policy.Job{
		JobID:    "j1",
		Targets:  targets,
		Workflow: []map[string]any{{"stage": "web", "plugin": "zap", "config": cfg}},
	}
}

func TestStageAndName(t *testing.T) {
	w := NewWorker()
	if w.Stage() != "web" || w.Name() != "zap" {
		t.Errorf("unexpected stage/name %s/%s", w.Stage(), w.Name())
	}
}

func TestBuildArgs(t *testing.T) {
	args := BuildArgs("/tmp/plan.yaml")
	if !slices.Equal(args, []string{"-cmd", "-autorun", "/tmp/plan.yaml"}) {
		t.Errorf("unexpected args: %v", args)
	}
}

func TestScopeFromConfig(t *testing.T) {
	cfg := map[string]any{
		"profile":    "limited_active",
		"start_urls": []any{"http://10.20.0.5/", "http://10.20.0.5/app"},
		"max_depth":  float64(3),
	}
	scope, err := scopeFromConfig(cfg, []string{"10.20.0.0/24"})
	if err != nil {
		t.Fatal(err)
	}
	if scope.Profile != ProfileLimitedActive {
		t.Errorf("profile=%q", scope.Profile)
	}
	if !slices.Equal(scope.InScopeHosts, []string{"10.20.0.5"}) {
		t.Errorf("in-scope hosts=%v (should dedupe to the single host)", scope.InScopeHosts)
	}
	if scope.MaxDepth != 3 {
		t.Errorf("max_depth not read from config: %d", scope.MaxDepth)
	}
	if scope.MaxChildren != defaultMaxChildren {
		t.Errorf("missing max_children should default: %d", scope.MaxChildren)
	}
	// Safe excludes are always applied.
	if len(scope.ExcludeURLs) == 0 {
		t.Error("expected default safe exclude URLs")
	}
}

func TestScopeFromConfigRejectsOutOfScopeStartURL(t *testing.T) {
	cfg := map[string]any{"start_urls": []any{"http://10.99.0.5/"}}
	if _, err := scopeFromConfig(cfg, []string{"10.20.0.0/24"}); err == nil {
		t.Error("a start URL whose IP is outside the approved scope must be rejected")
	}
}

func TestScopeFromConfigRejectsDNSNames(t *testing.T) {
	cfg := map[string]any{"start_urls": []any{"http://rebind.example/"}}
	if _, err := scopeFromConfig(cfg, []string{"10.20.0.0/24"}); err == nil {
		t.Error("a DNS hostname must be rejected until address pinning is implemented")
	}
}

func TestRunNoZapStageIsNoOp(t *testing.T) {
	job := &policy.Job{
		JobID:    "j1",
		Targets:  []string{"10.20.0.5"},
		Workflow: []map[string]any{{"stage": "discovery", "plugin": "nmap", "config": map[string]any{}}},
	}
	out, err := NewWorker().Run(context.Background(), job)
	if err != nil {
		t.Fatalf("no zap stage should be a no-op, got %v", err)
	}
	if out != nil {
		t.Errorf("expected no output, got %d bytes", len(out))
	}
}

func TestRunFailsWithMissingBinary(t *testing.T) {
	w := &Worker{Binary: "definitely-not-a-real-binary-xyz"}
	cfg := map[string]any{"profile": "passive_baseline", "start_urls": []any{"http://10.20.0.5/"}}
	out, err := w.Run(context.Background(), zapJob(cfg, []string{"10.20.0.5"}))
	if err == nil {
		t.Fatal("expected an error when the zap binary is missing")
	}
	if out != nil {
		t.Errorf("expected no output on failure, got %d bytes", len(out))
	}
}

func TestRunRejectsOutOfScopeBeforeExec(t *testing.T) {
	w := &Worker{Binary: "definitely-not-a-real-binary-xyz"}
	cfg := map[string]any{"profile": "passive_baseline", "start_urls": []any{"http://10.99.0.5/"}}
	if _, err := w.Run(context.Background(), zapJob(cfg, []string{"10.20.0.0/24"})); err == nil {
		t.Error("an out-of-scope start URL must be rejected before running zap")
	}
}

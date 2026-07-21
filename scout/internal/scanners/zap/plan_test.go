package zap

import (
	"encoding/json"
	"regexp"
	"testing"
)

func unmarshalPlan(t *testing.T, data []byte) map[string]any {
	t.Helper()
	var plan map[string]any
	if err := json.Unmarshal(data, &plan); err != nil {
		t.Fatalf("plan is not valid JSON/YAML: %v", err)
	}
	return plan
}

func jobTypes(t *testing.T, plan map[string]any) []string {
	t.Helper()
	jobs, ok := plan["jobs"].([]any)
	if !ok {
		t.Fatal("plan has no jobs list")
	}
	var types []string
	for _, j := range jobs {
		m, _ := j.(map[string]any)
		if s, ok := m["type"].(string); ok {
			types = append(types, s)
		}
	}
	return types
}

func findJob(t *testing.T, plan map[string]any, jobType string) map[string]any {
	t.Helper()
	for _, j := range plan["jobs"].([]any) {
		m, _ := j.(map[string]any)
		if m["type"] == jobType {
			return m
		}
	}
	return nil
}

func passiveScope() ScopeConfig {
	return ScopeConfig{
		Profile:            ProfilePassiveBaseline,
		StartURLs:          []string{"http://10.20.0.5/"},
		InScopeHosts:       []string{"10.20.0.5"},
		ExcludeURLs:        []string{"(?i).*/logout.*"},
		MaxDepth:           4,
		MaxChildren:        8,
		MaxDurationMinutes: 6,
		RequestsPerSecond:  10,
	}
}

func TestPassivePlanHasNoActiveScan(t *testing.T) {
	data, err := BuildAutomationPlan(passiveScope(), "/out", "zap-report")
	if err != nil {
		t.Fatal(err)
	}
	if planHasActiveScan(data) {
		t.Fatal("passive profile must not contain an activeScan job")
	}
	types := jobTypes(t, unmarshalPlan(t, data))
	want := []string{"spider", "passiveScan-wait", "report", "exitStatus"}
	if len(types) != len(want) {
		t.Fatalf("unexpected jobs %v, want %v", types, want)
	}
	for i := range want {
		if types[i] != want[i] {
			t.Errorf("job[%d]=%q, want %q", i, types[i], want[i])
		}
	}
	exitStatus := findJob(t, unmarshalPlan(t, data), "exitStatus")
	params := exitStatus["parameters"].(map[string]any)
	if params["warnExitValue"] != float64(0) || params["errorExitValue"] != float64(1) {
		t.Errorf("exitStatus must ignore warnings but retain errors: %v", params)
	}
}

func TestLimitedActivePlanUsesRuleAllowlist(t *testing.T) {
	scope := passiveScope()
	scope.Profile = ProfileLimitedActive
	data, err := BuildAutomationPlan(scope, "/out", "zap-report")
	if err != nil {
		t.Fatal(err)
	}
	plan := unmarshalPlan(t, data)
	active := findJob(t, plan, "activeScan")
	if active == nil {
		t.Fatal("limited-active profile must contain an activeScan job")
	}
	pol, ok := active["policyDefinition"].(map[string]any)
	if !ok {
		t.Fatal("activeScan has no policyDefinition")
	}
	if pol["defaultThreshold"] != "off" {
		t.Errorf("defaultThreshold=%v, want off (allowlist only)", pol["defaultThreshold"])
	}
	rules, ok := pol["rules"].([]any)
	if !ok || len(rules) == 0 {
		t.Fatal("policyDefinition has no allowlisted rules")
	}
	allow := map[int]bool{}
	for _, id := range safeActiveRules {
		allow[id] = true
	}
	for _, r := range rules {
		m := r.(map[string]any)
		id := int(m["id"].(float64))
		if !allow[id] {
			t.Errorf("rule %d is not in the safe allowlist", id)
		}
	}
}

func TestPlanScopeIncludePathsBoundToHosts(t *testing.T) {
	data, err := BuildAutomationPlan(passiveScope(), "/out", "zap-report")
	if err != nil {
		t.Fatal(err)
	}
	plan := unmarshalPlan(t, data)
	env := plan["env"].(map[string]any)
	ctx := env["contexts"].([]any)[0].(map[string]any)
	includes := ctx["includePaths"].([]any)
	if len(includes) != 1 {
		t.Fatalf("expected one include path, got %v", includes)
	}
	re := regexp.MustCompile(includes[0].(string))
	if !re.MatchString("http://10.20.0.5/admin") {
		t.Error("in-scope URL should match the include path")
	}
	// A redirect target outside scope must NOT be in scope.
	if re.MatchString("http://evil.example.com/") {
		t.Error("out-of-scope host must not match the include path")
	}
	// A different in-scope-looking host must not match (dots are literal).
	if re.MatchString("http://10x20x0x5/") {
		t.Error("regex dots must be escaped so only the exact IP matches")
	}
}

func TestBuildPlanRejectsBadInput(t *testing.T) {
	base := passiveScope()

	bad := base
	bad.Profile = "full_active"
	if _, err := BuildAutomationPlan(bad, "/o", "r"); err == nil {
		t.Error("unknown profile should be rejected")
	}

	bad = base
	bad.StartURLs = nil
	if _, err := BuildAutomationPlan(bad, "/o", "r"); err == nil {
		t.Error("missing start URLs should be rejected")
	}

	bad = base
	bad.StartURLs = []string{"http://10.99.0.9/"} // host not in InScopeHosts
	if _, err := BuildAutomationPlan(bad, "/o", "r"); err == nil {
		t.Error("out-of-scope start URL should be rejected")
	}
}

func TestValidateStartURLs(t *testing.T) {
	if err := ValidateStartURLs([]string{"http://10.0.0.5/app"}, []string{"10.0.0.5"}); err != nil {
		t.Errorf("in-scope URL rejected: %v", err)
	}
	if err := ValidateStartURLs([]string{"http://10.0.0.6/"}, []string{"10.0.0.5"}); err == nil {
		t.Error("out-of-scope URL should be rejected")
	}
	if err := ValidateStartURLs([]string{"::not a url"}, []string{"10.0.0.5"}); err == nil {
		t.Error("malformed URL should be rejected")
	}
}

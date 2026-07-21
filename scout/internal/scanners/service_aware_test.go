package scanners

import (
	"context"
	"slices"
	"testing"

	"github.com/codebooker/vulna/scout/internal/discovery"
	"github.com/codebooker/vulna/scout/internal/executor"
	"github.com/codebooker/vulna/scout/internal/policy"
)

// targetRecorder is a Scanner that records the targets its Run receives, and
// optionally acts as an EndpointTargeter (when targetsFor is set) so a test can
// prove the executor feeds discovered services to the stages that follow.
type targetRecorder struct {
	stage, name string
	raw         []byte
	gotTargets  *[]string
	gotScope    *[]string
	targetsFor  func([]discovery.Endpoint) []string
}

func (s targetRecorder) Stage() string { return s.stage }
func (s targetRecorder) Name() string  { return s.name }
func (s targetRecorder) Run(_ context.Context, job *policy.Job) ([]byte, error) {
	if s.gotTargets != nil {
		*s.gotTargets = append([]string(nil), job.Targets...)
	}
	if s.gotScope != nil {
		*s.gotScope = append([]string(nil), job.ScopeTargets...)
	}
	return s.raw, nil
}
func (s targetRecorder) TargetsFor(eps []discovery.Endpoint) []string {
	if s.targetsFor == nil {
		return nil
	}
	return s.targetsFor(eps)
}

const twoServiceHostXML = `<nmaprun><host><status state="up"/>` +
	`<address addr="10.0.0.1" addrtype="ipv4"/><ports>` +
	`<port protocol="tcp" portid="443"><state state="open"/><service name="https" tunnel="ssl"/></port>` +
	`<port protocol="tcp" portid="80"><state state="open"/><service name="http"/></port>` +
	`</ports></host></nmaprun>`

func uniqueIPs(eps []discovery.Endpoint) []string {
	seen := map[string]bool{}
	var out []string
	for _, e := range eps {
		if !seen[e.IP] {
			seen[e.IP] = true
			out = append(out, e.IP)
		}
	}
	return out
}

func tlsAddrs(eps []discovery.Endpoint) []string {
	var out []string
	for _, e := range eps {
		if e.TLS {
			out = append(out, e.Addr())
		}
	}
	return out
}

func TestRunStreamingTargetsDiscoveredServices(t *testing.T) {
	var vulnTargets, tlsTargets []string
	disco := targetRecorder{stage: "discovery", name: "nmap", raw: []byte(twoServiceHostXML)}
	vuln := targetRecorder{stage: "vulnerability", name: "nuclei", gotTargets: &vulnTargets, targetsFor: uniqueIPs}
	tls := targetRecorder{stage: "tls", name: "testssl", gotTargets: &tlsTargets, targetsFor: tlsAddrs}

	wf := NewWorkflow(disco, vuln, tls)
	job := jobWith("nmap", "nuclei", "testssl")
	job.Targets = []string{"10.0.0.0/30"} // a range the later stages must NOT re-scan

	_, err := wf.RunStreaming(context.Background(), job, nil, func(executor.StageOutput) error { return nil })
	if err != nil {
		t.Fatalf("RunStreaming: %v", err)
	}
	if want := []string{"10.0.0.1"}; !slices.Equal(vulnTargets, want) {
		t.Errorf("vulnerability stage targeted %v, want discovered host %v (not the range)", vulnTargets, want)
	}
	if want := []string{"10.0.0.1:443"}; !slices.Equal(tlsTargets, want) {
		t.Errorf("TLS stage targeted %v, want discovered TLS endpoint %v", tlsTargets, want)
	}
}

func TestRunStreamingFallsBackToRangeWithoutDiscovery(t *testing.T) {
	var vulnTargets []string
	// Discovery yields nothing usable (empty output) -> no endpoints derived.
	disco := targetRecorder{stage: "discovery", name: "nmap", raw: nil}
	vuln := targetRecorder{stage: "vulnerability", name: "nuclei", gotTargets: &vulnTargets, targetsFor: uniqueIPs}

	wf := NewWorkflow(disco, vuln)
	job := jobWith("nmap", "nuclei")
	job.Targets = []string{"10.0.0.0/30"}

	if _, err := wf.RunStreaming(context.Background(), job, nil, func(executor.StageOutput) error { return nil }); err != nil {
		t.Fatalf("RunStreaming: %v", err)
	}
	if want := []string{"10.0.0.0/30"}; !slices.Equal(vulnTargets, want) {
		t.Errorf("with no discovered services the stage must scan the range %v, got %v", want, vulnTargets)
	}
}

func TestRunWithProgressTargetsDiscoveredServices(t *testing.T) {
	var vulnTargets []string
	disco := targetRecorder{stage: "discovery", name: "nmap", raw: []byte(twoServiceHostXML)}
	vuln := targetRecorder{stage: "vulnerability", name: "nuclei", gotTargets: &vulnTargets, targetsFor: uniqueIPs}

	wf := NewWorkflow(disco, vuln)
	job := jobWith("nmap", "nuclei")
	job.Targets = []string{"10.0.0.0/30"}

	if _, err := wf.RunWithProgress(context.Background(), job, nil); err != nil {
		t.Fatalf("RunWithProgress: %v", err)
	}
	if want := []string{"10.0.0.1"}; !slices.Equal(vulnTargets, want) {
		t.Errorf("non-streaming path also must target discovered services: got %v, want %v", vulnTargets, want)
	}
}

func TestServiceAwareStageRetainsOriginalSignedScope(t *testing.T) {
	var gotTargets, gotScope []string
	disco := targetRecorder{stage: "discovery", name: "nmap", raw: []byte(twoServiceHostXML)}
	web := targetRecorder{
		stage: "web", name: "zap", gotTargets: &gotTargets, gotScope: &gotScope,
		targetsFor: func(eps []discovery.Endpoint) []string {
			var urls []string
			for _, endpoint := range eps {
				if endpoint.HTTP {
					urls = append(urls, endpoint.URL())
				}
			}
			return urls
		},
	}

	wf := NewWorkflow(disco, web)
	job := jobWith("nmap", "zap")
	job.Targets = []string{"10.0.0.0/30"}
	if _, err := wf.RunWithProgress(context.Background(), job, nil); err != nil {
		t.Fatalf("RunWithProgress: %v", err)
	}
	if want := []string{"https://10.0.0.1:443", "http://10.0.0.1:80"}; !slices.Equal(gotTargets, want) {
		t.Errorf("web targets = %v, want %v", gotTargets, want)
	}
	if !slices.Equal(gotScope, job.Targets) {
		t.Errorf("web scope = %v, want original signed targets %v", gotScope, job.Targets)
	}
}

// Package doctor runs a staged connection test between a VulnaScout and its
// orchestrator: DNS, TLS, time, enrollment, heartbeat, policy delivery, scanner
// health, and result-upload reachability. Every failure carries a concrete
// remediation covering the common causes (proxy, custom CA, DNS, clock, MTU,
// outbound firewall). No token or key material is ever included in output.
package doctor

// Status is the outcome of a single check.
type Status string

const (
	// OK means the check passed.
	OK Status = "ok"
	// Warn means a non-blocking concern.
	Warn Status = "warn"
	// Fail means a blocking problem.
	Fail Status = "fail"
)

// Result is one connection-test outcome with plain-language remediation.
type Result struct {
	Name        string
	Status      Status
	Detail      string
	Remediation string
}

// Deps are the injectable probes. A nil probe yields a "could not check" warning
// rather than a crash, so the doctor degrades gracefully on odd hosts.
type Deps struct {
	Host          string
	MaxClockSkew  float64 // seconds
	ResolveDNS    func(host string) error
	DialTLS       func() error
	ServerSkew    func() (seconds float64, known bool, err error)
	Enrolled      func() (bool, string)
	Heartbeat     func() error
	PolicyPresent func() bool
	MissingScan   func() []string
	UploadReach   func() error
}

// Run executes the connection test in order and returns the results.
func Run(d Deps) []Result {
	var out []Result
	out = append(out, checkDNS(d))
	out = append(out, checkTLS(d))
	out = append(out, checkTime(d))
	enrolled, enrollRes := checkEnrollment(d)
	out = append(out, enrollRes)
	out = append(out, checkHeartbeat(d, enrolled))
	out = append(out, checkPolicy(d))
	out = append(out, checkScanners(d))
	out = append(out, checkUpload(d))
	return out
}

// Blocking reports whether any result is a hard failure.
func Blocking(results []Result) bool {
	for _, r := range results {
		if r.Status == Fail {
			return true
		}
	}
	return false
}

func checkDNS(d Deps) Result {
	const name = "dns"
	if d.ResolveDNS == nil {
		return Result{name, Warn, "not checked", "verify the orchestrator hostname resolves"}
	}
	if err := d.ResolveDNS(d.Host); err != nil {
		return Result{name, Fail, "cannot resolve " + d.Host,
			"DNS resolution failed. Check the site's resolver and that the hostname is " +
				"correct; if the site uses a forward proxy, configure it for the Scout."}
	}
	return Result{name, OK, "resolved " + d.Host, ""}
}

func checkTLS(d Deps) Result {
	const name = "tls"
	if d.DialTLS == nil {
		return Result{name, Warn, "not checked", "verify TLS to the orchestrator on 443"}
	}
	if err := d.DialTLS(); err != nil {
		return Result{name, Fail, "TLS handshake failed",
			"Could not complete TLS. If the orchestrator uses a private CA, install it " +
				"(enroll/run with --server-ca). Otherwise check outbound TCP 443 through " +
				"the firewall/proxy, and if large-packet TLS stalls, lower the interface MTU."}
	}
	return Result{name, OK, "TLS handshake ok", ""}
}

func checkTime(d Deps) Result {
	const name = "time"
	if d.ServerSkew == nil {
		return Result{name, Warn, "not checked", "ensure NTP is enabled"}
	}
	skew, known, err := d.ServerSkew()
	if err != nil || !known {
		return Result{name, Warn, "could not verify clock",
			"Ensure system time is NTP-synchronized (e.g. `timedatectl set-ntp true`)."}
	}
	if abs(skew) > d.MaxClockSkew {
		return Result{name, Fail, "clock skew high",
			"The system clock differs from the server. TLS and certificate validation " +
				"fail with a skewed clock — enable NTP (`timedatectl set-ntp true`)."}
	}
	return Result{name, OK, "clock in sync", ""}
}

func checkEnrollment(d Deps) (bool, Result) {
	const name = "enrollment"
	if d.Enrolled == nil {
		return false, Result{name, Warn, "not checked", "run `vulnascout status`"}
	}
	ok, detail := d.Enrolled()
	if !ok {
		return false, Result{name, Fail, detail,
			"Not enrolled. Add this Scout from VulnaDash (Add VulnaScout) and run the " +
				"install command, or `vulnascout enroll --server <url> --token <token>`."}
	}
	return true, Result{name, OK, detail, ""}
}

func checkHeartbeat(d Deps, enrolled bool) Result {
	const name = "heartbeat"
	if !enrolled {
		return Result{name, Warn, "skipped (not enrolled)", "enroll first"}
	}
	if d.Heartbeat == nil {
		return Result{name, Warn, "not checked", ""}
	}
	if err := d.Heartbeat(); err != nil {
		return Result{name, Fail, "heartbeat rejected or unreachable",
			"The orchestrator rejected or could not receive the heartbeat. The identity " +
				"may be revoked/disabled — `vulnascout reset` then re-enroll — or outbound " +
				"443 is blocked."}
	}
	return Result{name, OK, "heartbeat accepted", ""}
}

func checkPolicy(d Deps) Result {
	const name = "policy"
	if d.PolicyPresent == nil {
		return Result{name, Warn, "not checked", ""}
	}
	if !d.PolicyPresent() {
		return Result{name, Warn, "no local policy yet",
			"The signed local policy syncs on the first successful heartbeat; re-check after `run`."}
	}
	return Result{name, OK, "local signed policy present", ""}
}

func checkScanners(d Deps) Result {
	const name = "scanners"
	if d.MissingScan == nil {
		return Result{name, Warn, "not checked", ""}
	}
	missing := d.MissingScan()
	if len(missing) > 0 {
		return Result{name, Warn, "missing: " + join(missing),
			"Some scanners are not installed; those stages are skipped with an explanation. " +
				"Install the standard pack (nmap, nuclei, testssl.sh) for full coverage."}
	}
	return Result{name, OK, "scanner pack present", ""}
}

func checkUpload(d Deps) Result {
	const name = "upload"
	if d.UploadReach == nil {
		return Result{name, Warn, "not checked", ""}
	}
	if err := d.UploadReach(); err != nil {
		return Result{name, Fail, "result upload path unreachable",
			"Results could not be uploaded. Check outbound TCP 443 to the orchestrator " +
				"through any proxy/firewall; uploads retry after a temporary outage."}
	}
	return Result{name, OK, "result upload path reachable", ""}
}

func abs(f float64) float64 {
	if f < 0 {
		return -f
	}
	return f
}

func join(s []string) string {
	out := ""
	for i, v := range s {
		if i > 0 {
			out += ", "
		}
		out += v
	}
	return out
}

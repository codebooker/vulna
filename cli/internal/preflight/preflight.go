// Package preflight runs environment checks before the installer changes any
// files or starts any services. Every non-passing result names the problem, its
// impact, and a next step (roadmap cross-phase rule: no mystery failures).
package preflight

import "fmt"

// Status is the outcome of a single check.
type Status string

const (
	// OK means the check passed.
	OK Status = "ok"
	// Warn means a non-blocking concern the operator should know about.
	Warn Status = "warn"
	// Fail means a blocking problem; installation should not proceed.
	Fail Status = "fail"
)

// Result is the outcome of one preflight check.
type Result struct {
	Name     string
	Status   Status
	Detail   string // short factual observation
	Problem  string // what is wrong (empty when OK)
	Impact   string // why it matters (empty when OK)
	NextStep string // what to do about it (empty when OK)
}

func ok(name, detail string) Result {
	return Result{Name: name, Status: OK, Detail: detail}
}

func warn(name, detail, problem, impact, next string) Result {
	return Result{Name: name, Status: Warn, Detail: detail, Problem: problem, Impact: impact, NextStep: next}
}

func fail(name, detail, problem, impact, next string) Result {
	return Result{Name: name, Status: Fail, Detail: detail, Problem: problem, Impact: impact, NextStep: next}
}

// HostPort is an outbound endpoint to test for reachability.
type HostPort struct {
	Label string
	Host  string
	Port  int
}

// Params tunes the checks for the target host and deployment.
type Params struct {
	DataDir       string
	InstallDir    string
	Ports         []int
	OutboundHosts []HostPort
	MinCPU        int
	MinMemBytes   uint64
	MinDiskBytes  uint64
}

// DefaultParams returns conservative thresholds for a modest single host.
func DefaultParams(installDir, dataDir string) Params {
	return Params{
		DataDir:      dataDir,
		InstallDir:   installDir,
		Ports:        []int{80, 443},
		MinCPU:       2,
		MinMemBytes:  2 << 30, // 2 GiB
		MinDiskBytes: 5 << 30, // 5 GiB
		OutboundHosts: []HostPort{
			{Label: "NVD CVE feed", Host: "services.nvd.nist.gov", Port: 443},
			{Label: "CISA KEV feed", Host: "www.cisa.gov", Port: 443},
			{Label: "EPSS feed", Host: "epss.cyentia.com", Port: 443},
			{Label: "GitHub (updates)", Host: "github.com", Port: 443},
		},
	}
}

// Env abstracts every system probe so the checks are deterministic under test.
// Each field is a function; a nil function means "unable to probe" and yields a
// warning rather than a crash.
type Env struct {
	GOOS                  string
	GOARCH                string
	Docker                func() (string, error)
	Compose               func() (string, error)
	CPUCount              func() int
	TotalMemory           func() (uint64, error)
	FreeDisk              func(path string) (uint64, error)
	PortInUse             func(port int) (bool, error)
	Reach                 func(host string, port int) error
	ClockSynced           func() (synced bool, known bool)
	WritableDir           func(path string) error
	DetectExistingInstall func(dir string) (installed bool, detail string)
	KernelFeatures        func() (ok bool, detail string)
}

// Run executes every check and returns their results in a stable order.
func Run(env Env, p Params) []Result {
	return []Result{
		checkOSArch(env),
		checkContainerRuntime(env),
		checkCompose(env),
		checkCPU(env, p),
		checkMemory(env, p),
		checkDisk(env, p),
		checkKernel(env),
		checkPorts(env, p),
		checkClock(env),
		checkOutbound(env, p),
		checkPermissions(env, p),
		checkExistingInstall(env, p),
	}
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

// Counts returns how many results are OK, warnings, and failures.
func Counts(results []Result) (okN, warnN, failN int) {
	for _, r := range results {
		switch r.Status {
		case OK:
			okN++
		case Warn:
			warnN++
		case Fail:
			failN++
		}
	}
	return
}

func checkOSArch(env Env) Result {
	const name = "os-arch"
	detail := fmt.Sprintf("%s/%s", env.GOOS, env.GOARCH)
	if env.GOOS != "linux" {
		return warn(name, detail,
			"host is not Linux",
			"the single-host stack is supported on Linux; other systems are for development only",
			"run the installer on a supported Linux host (amd64 or arm64)")
	}
	if env.GOARCH != "amd64" && env.GOARCH != "arm64" {
		return fail(name, detail,
			"unsupported CPU architecture",
			"Vulna images are published for amd64 and arm64 only",
			"use an amd64 or arm64 host")
	}
	return ok(name, detail)
}

func checkContainerRuntime(env Env) Result {
	const name = "container-runtime"
	if env.Docker == nil {
		return warn(name, "unknown", "could not probe the container runtime", "", "ensure Docker is installed")
	}
	v, err := env.Docker()
	if err != nil {
		return fail(name, "not found",
			"Docker is not installed or not reachable",
			"the stack runs as containers and cannot start without a container runtime",
			"install Docker Engine and ensure the current user can run it")
	}
	return ok(name, v)
}

func checkCompose(env Env) Result {
	const name = "compose"
	if env.Compose == nil {
		return warn(name, "unknown", "could not probe Compose", "", "ensure the Docker Compose plugin is installed")
	}
	v, err := env.Compose()
	if err != nil {
		return fail(name, "not found",
			"the Docker Compose v2 plugin is missing",
			"the deployment is defined as a Compose project and cannot be started without it",
			"install the docker-compose-plugin package (`docker compose version` must work)")
	}
	return ok(name, v)
}

func checkCPU(env Env, p Params) Result {
	const name = "cpu"
	if env.CPUCount == nil {
		return warn(name, "unknown", "could not read CPU count", "", "verify the host has at least 2 CPUs")
	}
	n := env.CPUCount()
	detail := fmt.Sprintf("%d vCPU", n)
	if n < p.MinCPU {
		return warn(name, detail,
			fmt.Sprintf("only %d vCPU (recommended %d+)", n, p.MinCPU),
			"scans and report generation may be slow",
			"allocate more CPU for a smoother experience")
	}
	return ok(name, detail)
}

func checkMemory(env Env, p Params) Result {
	const name = "memory"
	if env.TotalMemory == nil {
		return warn(name, "unknown", "could not read total memory", "", "verify the host has at least 2 GiB RAM")
	}
	b, err := env.TotalMemory()
	if err != nil {
		return warn(name, "unknown", "could not read total memory", "", "verify the host has at least 2 GiB RAM")
	}
	detail := humanBytes(b)
	if b < p.MinMemBytes {
		return warn(name, detail,
			fmt.Sprintf("%s RAM (recommended %s+)", humanBytes(b), humanBytes(p.MinMemBytes)),
			"the database, API, and scanners may be memory-constrained",
			"add memory or expect reduced concurrency")
	}
	return ok(name, detail)
}

func checkDisk(env Env, p Params) Result {
	const name = "disk"
	if env.FreeDisk == nil {
		return warn(name, "unknown", "could not read free disk space", "", "verify at least 5 GiB is free")
	}
	free, err := env.FreeDisk(p.DataDir)
	if err != nil {
		return warn(name, "unknown",
			fmt.Sprintf("could not read free space at %s", p.DataDir), "",
			"verify at least 5 GiB is free on the data volume")
	}
	detail := fmt.Sprintf("%s free at %s", humanBytes(free), p.DataDir)
	if free < p.MinDiskBytes {
		return fail(name, detail,
			fmt.Sprintf("only %s free at %s (need %s)", humanBytes(free), p.DataDir, humanBytes(p.MinDiskBytes)),
			"images, the database, evidence, and reports will not fit and the stack may fail to start",
			"free space or choose a data directory with more room (--data-dir)")
	}
	return ok(name, detail)
}

func checkKernel(env Env) Result {
	const name = "kernel"
	if env.KernelFeatures == nil {
		return ok(name, "not applicable")
	}
	okFeat, detail := env.KernelFeatures()
	if !okFeat {
		return warn(name, detail,
			"a recommended kernel/network feature is unavailable",
			"some network operations may be limited",
			"see the documented supported host matrix")
	}
	return ok(name, detail)
}

func checkPorts(env Env, p Params) Result {
	const name = "ports"
	if env.PortInUse == nil {
		return warn(name, "unknown", "could not check port availability", "", "ensure the required ports are free")
	}
	var busy []int
	for _, port := range p.Ports {
		inUse, err := env.PortInUse(port)
		if err == nil && inUse {
			busy = append(busy, port)
		}
	}
	if len(busy) > 0 {
		return fail(name, fmt.Sprintf("in use: %v", busy),
			fmt.Sprintf("required port(s) %v are already in use", busy),
			"the reverse proxy cannot bind and the UI/API would be unreachable",
			"stop the conflicting service or choose different published ports")
	}
	return ok(name, fmt.Sprintf("%v free", p.Ports))
}

func checkClock(env Env) Result {
	const name = "time-sync"
	if env.ClockSynced == nil {
		return warn(name, "unknown", "could not verify time synchronization", "",
			"ensure NTP is enabled so certificates and logs use an accurate clock")
	}
	synced, known := env.ClockSynced()
	if !known {
		return warn(name, "unknown", "could not verify time synchronization", "",
			"ensure NTP is enabled (e.g. `timedatectl set-ntp true`)")
	}
	if !synced {
		return warn(name, "not synchronized",
			"the system clock is not NTP-synchronized",
			"TLS certificate validation and scan timestamps can be wrong with a skewed clock",
			"enable time sync (e.g. `timedatectl set-ntp true`)")
	}
	return ok(name, "synchronized")
}

func checkOutbound(env Env, p Params) Result {
	const name = "outbound"
	if env.Reach == nil || len(p.OutboundHosts) == 0 {
		return ok(name, "not checked")
	}
	var unreachable []string
	for _, hp := range p.OutboundHosts {
		if err := env.Reach(hp.Host, hp.Port); err != nil {
			unreachable = append(unreachable, hp.Label)
		}
	}
	if len(unreachable) > 0 {
		return warn(name, fmt.Sprintf("unreachable: %v", unreachable),
			fmt.Sprintf("could not reach %v", unreachable),
			"CVE intelligence feeds and update checks will be unavailable until connectivity is restored",
			"Vulna still runs offline; configure a mirror or check DNS/egress firewall if this is unexpected")
	}
	return ok(name, "intelligence/update sources reachable")
}

func checkPermissions(env Env, p Params) Result {
	const name = "permissions"
	if env.WritableDir == nil {
		return warn(name, "unknown", "could not check filesystem permissions", "", "ensure the install and data directories are writable")
	}
	for _, dir := range []string{p.InstallDir, p.DataDir} {
		if dir == "" {
			continue
		}
		if err := env.WritableDir(dir); err != nil {
			return fail(name, err.Error(),
				fmt.Sprintf("cannot create or write %s", dir),
				"the installer cannot lay down deployment files or persistent data",
				"choose a writable path or run with sufficient permissions")
		}
	}
	return ok(name, "install and data directories writable")
}

func checkExistingInstall(env Env, p Params) Result {
	const name = "existing-install"
	if env.DetectExistingInstall == nil {
		return ok(name, "none detected")
	}
	installed, detail := env.DetectExistingInstall(p.InstallDir)
	if installed {
		return warn(name, detail,
			"an existing Vulna deployment was found at this location",
			"a fresh install could conflict with it; a rerun will repair generated files without touching data",
			"rerun to repair in place, choose a different --dir, or uninstall first")
	}
	return ok(name, "none detected")
}

func humanBytes(b uint64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := uint64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(b)/float64(div), "KMGTPE"[exp])
}

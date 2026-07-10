package preflight

import (
	"context"
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"
)

var errMemNotFound = errors.New("MemTotal not found in /proc/meminfo")

// RealEnv returns an Env wired to real system probes. Probes that cannot run on
// a given host are left resilient: they return an error the checks translate
// into a warning rather than crashing.
func RealEnv() Env {
	return Env{
		GOOS:                  runtime.GOOS,
		GOARCH:                runtime.GOARCH,
		Docker:                probeDocker,
		Compose:               probeCompose,
		CPUCount:              runtime.NumCPU,
		TotalMemory:           probeTotalMemory,
		FreeDisk:              probeFreeDisk,
		PortInUse:             probePortInUse,
		Reach:                 probeReach,
		ClockSynced:           probeClockSynced,
		WritableDir:           probeWritableDir,
		DetectExistingInstall: probeExistingInstall,
		KernelFeatures:        nil, // no hard kernel requirement for connect-scan single-host
	}
}

func runTool(name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

func probeDocker() (string, error) {
	if _, err := exec.LookPath("docker"); err != nil {
		return "", err
	}
	out, err := runTool("docker", "version", "--format", "{{.Server.Version}}")
	if err != nil {
		return "", err
	}
	return "docker " + firstLine(out), nil
}

func probeCompose() (string, error) {
	out, err := runTool("docker", "compose", "version", "--short")
	if err != nil {
		return "", err
	}
	return "compose " + firstLine(out), nil
}

func probeTotalMemory() (uint64, error) {
	data, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return 0, err
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "MemTotal:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				kb, perr := strconv.ParseUint(fields[1], 10, 64)
				if perr != nil {
					return 0, perr
				}
				return kb * 1024, nil
			}
		}
	}
	return 0, errMemNotFound
}

func probeFreeDisk(path string) (uint64, error) {
	dir := nearestExisting(path)
	var st syscall.Statfs_t
	if err := syscall.Statfs(dir, &st); err != nil {
		return 0, err
	}
	return uint64(st.Bavail) * uint64(st.Bsize), nil
}

func probePortInUse(port int) (bool, error) {
	ln, err := net.Listen("tcp", net.JoinHostPort("", strconv.Itoa(port)))
	if err != nil {
		return true, nil // could not bind: most likely already in use
	}
	_ = ln.Close()
	return false, nil
}

func probeReach(host string, port int) error {
	d := net.Dialer{Timeout: 4 * time.Second}
	conn, err := d.Dial("tcp", net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		return err
	}
	return conn.Close()
}

func probeClockSynced() (bool, bool) {
	if _, err := exec.LookPath("timedatectl"); err != nil {
		return false, false // unknown
	}
	out, err := runTool("timedatectl", "show", "-p", "NTPSynchronized", "--value")
	if err != nil {
		return false, false
	}
	return strings.EqualFold(strings.TrimSpace(out), "yes"), true
}

func probeWritableDir(path string) error {
	if path == "" {
		return nil
	}
	target := path
	if _, err := os.Stat(path); err != nil {
		target = nearestExisting(path)
	}
	f, err := os.CreateTemp(target, ".vulna-preflight-*")
	if err != nil {
		return err
	}
	name := f.Name()
	_ = f.Close()
	return os.Remove(name)
}

func probeExistingInstall(dir string) (bool, string) {
	if dir == "" {
		return false, ""
	}
	// Only a prior install *record* proves a previous `vulna install`. The
	// Compose files are part of the source tree and are always present, so they
	// must not be treated as evidence of an existing install.
	if _, err := os.Stat(filepath.Join(dir, ".vulna-install.json")); err == nil {
		return true, "found .vulna-install.json"
	}
	return false, ""
}

func nearestExisting(path string) string {
	dir := path
	for dir != "" {
		if _, err := os.Stat(dir); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return dir
		}
		dir = parent
	}
	return "."
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}

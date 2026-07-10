package preflight

import (
	"errors"
	"testing"
)

// goodEnv returns an Env where every probe reports a healthy host.
func goodEnv() Env {
	return Env{
		GOOS:                  "linux",
		GOARCH:                "amd64",
		Docker:                func() (string, error) { return "docker 27.0", nil },
		Compose:               func() (string, error) { return "compose 2.29", nil },
		CPUCount:              func() int { return 4 },
		TotalMemory:           func() (uint64, error) { return 8 << 30, nil },
		FreeDisk:              func(string) (uint64, error) { return 50 << 30, nil },
		PortInUse:             func(int) (bool, error) { return false, nil },
		Reach:                 func(string, int) error { return nil },
		ClockSynced:           func() (bool, bool) { return true, true },
		WritableDir:           func(string) error { return nil },
		DetectExistingInstall: func(string) (bool, string) { return false, "" },
	}
}

func find(results []Result, name string) Result {
	for _, r := range results {
		if r.Name == name {
			return r
		}
	}
	return Result{Name: "MISSING"}
}

func TestAllOK(t *testing.T) {
	results := Run(goodEnv(), DefaultParams("/opt/vulna", "/opt/vulna/data"))
	if Blocking(results) {
		t.Fatalf("healthy host should not block: %+v", results)
	}
	_, warnN, failN := Counts(results)
	if warnN != 0 || failN != 0 {
		t.Fatalf("expected all ok, got warnN=%d failN=%d", warnN, failN)
	}
}

func TestUnsupportedArchFails(t *testing.T) {
	env := goodEnv()
	env.GOARCH = "riscv64"
	r := find(Run(env, DefaultParams("/opt/vulna", "/d")), "os-arch")
	if r.Status != Fail {
		t.Fatalf("riscv64 should fail, got %s", r.Status)
	}
}

func TestNonLinuxWarns(t *testing.T) {
	env := goodEnv()
	env.GOOS = "darwin"
	r := find(Run(env, DefaultParams("/opt/vulna", "/d")), "os-arch")
	if r.Status != Warn {
		t.Fatalf("darwin should warn, got %s", r.Status)
	}
}

func TestMissingDockerFails(t *testing.T) {
	env := goodEnv()
	env.Docker = func() (string, error) { return "", errors.New("not found") }
	results := Run(env, DefaultParams("/opt/vulna", "/d"))
	if !Blocking(results) {
		t.Fatal("missing Docker must block")
	}
	r := find(results, "container-runtime")
	if r.NextStep == "" || r.Impact == "" {
		t.Fatalf("failure must name impact and next step: %+v", r)
	}
}

func TestOccupiedPortFails(t *testing.T) {
	env := goodEnv()
	env.PortInUse = func(p int) (bool, error) { return p == 443, nil }
	r := find(Run(env, DefaultParams("/opt/vulna", "/d")), "ports")
	if r.Status != Fail {
		t.Fatalf("occupied 443 should fail, got %s", r.Status)
	}
}

func TestInsufficientDiskFails(t *testing.T) {
	env := goodEnv()
	env.FreeDisk = func(string) (uint64, error) { return 1 << 30, nil } // 1 GiB
	r := find(Run(env, DefaultParams("/opt/vulna", "/d")), "disk")
	if r.Status != Fail {
		t.Fatalf("1 GiB free should fail, got %s", r.Status)
	}
}

func TestClockSkewWarns(t *testing.T) {
	env := goodEnv()
	env.ClockSynced = func() (bool, bool) { return false, true }
	r := find(Run(env, DefaultParams("/opt/vulna", "/d")), "time-sync")
	if r.Status != Warn {
		t.Fatalf("unsynced clock should warn, got %s", r.Status)
	}
}

func TestOfflineWarnsButDoesNotBlock(t *testing.T) {
	env := goodEnv()
	env.Reach = func(string, int) error { return errors.New("no route") }
	results := Run(env, DefaultParams("/opt/vulna", "/d"))
	if Blocking(results) {
		t.Fatal("offline host should warn, not block (offline is supported)")
	}
	if find(results, "outbound").Status != Warn {
		t.Fatal("outbound should warn when unreachable")
	}
}

func TestUnwritableDirFails(t *testing.T) {
	env := goodEnv()
	env.WritableDir = func(string) error { return errors.New("permission denied") }
	r := find(Run(env, DefaultParams("/opt/vulna", "/d")), "permissions")
	if r.Status != Fail {
		t.Fatalf("unwritable dir should fail, got %s", r.Status)
	}
}

func TestExistingInstallWarns(t *testing.T) {
	env := goodEnv()
	env.DetectExistingInstall = func(string) (bool, string) { return true, "found .env" }
	r := find(Run(env, DefaultParams("/opt/vulna", "/d")), "existing-install")
	if r.Status != Warn {
		t.Fatalf("existing install should warn, got %s", r.Status)
	}
}

func TestNilProbesDoNotPanic(t *testing.T) {
	// A zero Env (all nil probes) must produce warnings, not panics.
	env := Env{GOOS: "linux", GOARCH: "amd64"}
	results := Run(env, DefaultParams("/opt/vulna", "/d"))
	if len(results) == 0 {
		t.Fatal("expected results")
	}
}

package telemetry

import (
	"runtime"
	"testing"
)

func TestProbeReportsCPUAndNonNegative(t *testing.T) {
	r := Probe(t.TempDir())
	if r.CPUCount < 1 {
		t.Fatalf("cpu_count should be >= 1, got %d", r.CPUCount)
	}
	if r.MemoryMB < 0 || r.DiskFreeMB < 0 || r.DiskTotalMB < 0 {
		t.Fatalf("resource figures must be non-negative: %+v", r)
	}
	// On Linux the probe should read real memory and disk figures.
	if runtime.GOOS == "linux" {
		if r.MemoryMB <= 0 {
			t.Errorf("expected memory_mb > 0 on linux, got %d", r.MemoryMB)
		}
		if r.DiskTotalMB <= 0 {
			t.Errorf("expected disk_total_mb > 0 on linux, got %d", r.DiskTotalMB)
		}
	}
}

func TestAsHealthKeys(t *testing.T) {
	h := Resources{CPUCount: 4, MemoryMB: 2048, DiskFreeMB: 100, DiskTotalMB: 500}.AsHealth()
	for _, k := range []string{"cpu_count", "memory_mb", "disk_free_mb", "disk_total_mb"} {
		if _, ok := h[k]; !ok {
			t.Errorf("missing health key %q", k)
		}
	}
}

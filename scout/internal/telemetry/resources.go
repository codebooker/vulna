// Package telemetry measures the host resources VulnaScout reports in its
// heartbeat so VulnaDash can pick a Lite/Standard/Full operating profile and warn
// when a preset exceeds the Scout's capability. Measurement is best-effort and
// stdlib-only; on platforms where a figure cannot be read it is reported as 0
// ("unknown"), which the dashboard treats conservatively.
package telemetry

import "runtime"

// Resources is a point-in-time measurement of the host running the Scout.
type Resources struct {
	CPUCount    int   `json:"cpu_count"`
	MemoryMB    int64 `json:"memory_mb"`
	DiskFreeMB  int64 `json:"disk_free_mb"`
	DiskTotalMB int64 `json:"disk_total_mb"`
}

// Probe measures CPU, memory, and free/total disk for the given data directory.
func Probe(dataDir string) Resources {
	free, total := diskMB(dataDir)
	return Resources{
		CPUCount:    runtime.NumCPU(),
		MemoryMB:    totalMemoryMB(),
		DiskFreeMB:  free,
		DiskTotalMB: total,
	}
}

// AsHealth returns the resource fields for merging into the heartbeat health map.
func (r Resources) AsHealth() map[string]any {
	return map[string]any{
		"cpu_count":     r.CPUCount,
		"memory_mb":     r.MemoryMB,
		"disk_free_mb":  r.DiskFreeMB,
		"disk_total_mb": r.DiskTotalMB,
	}
}

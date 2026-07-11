//go:build !linux

package telemetry

// On non-Linux hosts (Linux is the supported deployment OS) memory and disk are
// reported as unknown (0); the dashboard treats unknown conservatively.
func totalMemoryMB() int64 { return 0 }

func diskMB(_ string) (free, total int64) { return 0, 0 }

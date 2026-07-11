//go:build linux

package telemetry

import (
	"bufio"
	"os"
	"strconv"
	"strings"
	"syscall"
)

// totalMemoryMB reads MemTotal from /proc/meminfo (kB) and returns whole MB.
func totalMemoryMB() int64 {
	f, err := os.Open("/proc/meminfo")
	if err != nil {
		return 0
	}
	defer func() { _ = f.Close() }()

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if !strings.HasPrefix(line, "MemTotal:") {
			continue
		}
		fields := strings.Fields(line) // "MemTotal: 8123456 kB"
		if len(fields) >= 2 {
			if kb, err := strconv.ParseInt(fields[1], 10, 64); err == nil {
				return kb / 1024
			}
		}
		break
	}
	return 0
}

// diskMB returns the free and total megabytes on the filesystem holding path.
func diskMB(path string) (free, total int64) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(path, &st); err != nil {
		return 0, 0
	}
	const mib = 1024 * 1024
	bsize := int64(st.Bsize)
	free = int64(st.Bavail) * bsize / mib
	total = int64(st.Blocks) * bsize / mib
	return free, total
}

//go:build linux

package scannersandbox

import (
	"fmt"
	"os"
	"path/filepath"
	"unsafe"

	"golang.org/x/sys/unix"
)

const (
	landlockCreateRulesetVersion = 1
	landlockRulePathBeneath      = 1

	landlockAccessExecute    = uint64(1 << 0)
	landlockAccessWriteFile  = uint64(1 << 1)
	landlockAccessReadFile   = uint64(1 << 2)
	landlockAccessReadDir    = uint64(1 << 3)
	landlockAccessRemoveDir  = uint64(1 << 4)
	landlockAccessRemoveFile = uint64(1 << 5)
	landlockAccessMakeChar   = uint64(1 << 6)
	landlockAccessMakeDir    = uint64(1 << 7)
	landlockAccessMakeReg    = uint64(1 << 8)
	landlockAccessMakeSock   = uint64(1 << 9)
	landlockAccessMakeFIFO   = uint64(1 << 10)
	landlockAccessMakeBlock  = uint64(1 << 11)
	landlockAccessMakeSym    = uint64(1 << 12)
	landlockAccessRefer      = uint64(1 << 13)
	landlockAccessTruncate   = uint64(1 << 14)
)

type landlockRulesetAttr struct {
	HandledAccessFS uint64
}

type landlockPathBeneathAttr struct {
	AllowedAccess uint64
	ParentFD      int32
	_             uint32
}

func applyPlatformSandbox(workspace string) error {
	abi, _, errno := unix.Syscall(
		unix.SYS_LANDLOCK_CREATE_RULESET, 0, 0, landlockCreateRulesetVersion,
	)
	if errno != 0 {
		return fmt.Errorf("query Landlock ABI: %w", errno)
	}
	if abi < 1 {
		return fmt.Errorf("kernel returned invalid Landlock ABI %d", abi)
	}

	handled := landlockAccessExecute | landlockAccessWriteFile |
		landlockAccessReadFile | landlockAccessReadDir | landlockAccessRemoveDir |
		landlockAccessRemoveFile | landlockAccessMakeChar | landlockAccessMakeDir |
		landlockAccessMakeReg | landlockAccessMakeSock | landlockAccessMakeFIFO |
		landlockAccessMakeBlock | landlockAccessMakeSym
	if abi >= 2 {
		handled |= landlockAccessRefer
	}
	if abi >= 3 {
		handled |= landlockAccessTruncate
	}
	attr := landlockRulesetAttr{HandledAccessFS: handled}
	rulesetFD, _, errno := unix.Syscall(
		unix.SYS_LANDLOCK_CREATE_RULESET,
		uintptr(unsafe.Pointer(&attr)),
		unsafe.Sizeof(attr),
		0,
	)
	if errno != 0 {
		return fmt.Errorf("create Landlock ruleset: %w", errno)
	}
	defer unix.Close(int(rulesetFD))

	readOnly := landlockAccessExecute | landlockAccessReadFile | landlockAccessReadDir
	for _, path := range []string{"/bin", "/sbin", "/usr", "/lib", "/lib64", "/opt", "/etc", "/proc", "/sys"} {
		if err := addPathRule(int(rulesetFD), path, readOnly); err != nil && !os.IsNotExist(err) {
			return err
		}
	}
	if err := addPathRule(int(rulesetFD), "/dev", handled); err != nil {
		return err
	}
	if err := addPathRule(int(rulesetFD), workspace, handled); err != nil {
		return err
	}

	var limits unix.Rlimit
	limits.Cur = 0
	limits.Max = 0
	if err := unix.Setrlimit(unix.RLIMIT_CORE, &limits); err != nil {
		return fmt.Errorf("disable core dumps: %w", err)
	}
	if err := protectCurrentProcess(); err != nil {
		return err
	}
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		return fmt.Errorf("set no-new-privileges: %w", err)
	}
	_, _, errno = unix.Syscall(unix.SYS_LANDLOCK_RESTRICT_SELF, rulesetFD, 0, 0)
	if errno != 0 {
		return fmt.Errorf("restrict process with Landlock: %w", errno)
	}
	return nil
}

func protectCurrentProcess() error {
	if err := unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0); err != nil {
		return fmt.Errorf("disable same-UID process inspection: %w", err)
	}
	return nil
}

func addPathRule(rulesetFD int, path string, allowed uint64) error {
	clean := filepath.Clean(path)
	fd, err := unix.Open(clean, unix.O_PATH|unix.O_CLOEXEC, 0)
	if err != nil {
		return &os.PathError{Op: "open sandbox path", Path: clean, Err: err}
	}
	defer unix.Close(fd)
	attr := landlockPathBeneathAttr{AllowedAccess: allowed, ParentFD: int32(fd)}
	_, _, errno := unix.Syscall6(
		unix.SYS_LANDLOCK_ADD_RULE,
		uintptr(rulesetFD),
		landlockRulePathBeneath,
		uintptr(unsafe.Pointer(&attr)),
		0, 0, 0,
	)
	if errno != 0 {
		return &os.PathError{Op: "add sandbox rule", Path: clean, Err: errno}
	}
	return nil
}

package dlp

import (
	"context"
	"os/exec"
	"strconv"
	"syscall"
	"time"
)

// ProcLimits caps a sandboxed external process. Zero fields are left unset.
type ProcLimits struct {
	AddressSpaceMB int // virtual memory (RLIMIT_AS)
	CPUSeconds     int // CPU time (RLIMIT_CPU)
	OutputFileMB   int // largest file it may write (RLIMIT_FSIZE)
}

// DefaultProcLimits bounds the untrusted converters/extractors. Generous
// enough for large scans, tight enough to stop a decompression bomb or a
// malicious file from exhausting the host.
var DefaultProcLimits = ProcLimits{AddressSpaceMB: 2048, CPUSeconds: 120, OutputFileMB: 512}

// prlimitPath is empty when prlimit is not installed; the process-group kill
// and context timeout still apply, only the memory/CPU caps are skipped.
var prlimitPath, _ = exec.LookPath("prlimit")

// sandboxCmd builds a command for an untrusted external tool. It:
//   - wraps the tool in prlimit (when available) to cap memory, CPU and
//     output size;
//   - runs it in its own process group and kills the whole group on context
//     cancel, so no child (e.g. a codec plugin) is left orphaned;
//   - forces SIGKILL shortly after cancel if it ignores the signal;
//   - runs with a minimal environment.
func sandboxCmd(ctx context.Context, lim ProcLimits, extraEnv []string, name string, args ...string) *exec.Cmd {
	argv0, argv := name, append([]string{name}, args...)
	if prlimitPath != "" {
		pre := []string{prlimitPath}
		if lim.AddressSpaceMB > 0 {
			pre = append(pre, "--as="+strconv.Itoa(lim.AddressSpaceMB<<20))
		}
		if lim.CPUSeconds > 0 {
			pre = append(pre, "--cpu="+strconv.Itoa(lim.CPUSeconds))
		}
		if lim.OutputFileMB > 0 {
			pre = append(pre, "--fsize="+strconv.Itoa(lim.OutputFileMB<<20))
		}
		argv = append(pre, argv...)
		argv0 = prlimitPath
	}
	cmd := exec.CommandContext(ctx, argv0, argv[1:]...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		if cmd.Process != nil {
			// Negative PID targets the whole process group.
			_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		}
		return nil
	}
	cmd.WaitDelay = 5 * time.Second
	// Minimal, predictable environment; PLAYWRIGHT/etc are irrelevant here.
	cmd.Env = append([]string{"PATH=/usr/local/bin:/usr/bin:/bin", "LC_ALL=C.UTF-8", "OMP_THREAD_LIMIT=1"}, extraEnv...)
	return cmd
}

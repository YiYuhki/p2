package dlp

import (
	"context"
	"os/exec"
	"testing"
	"time"
)

func TestSandboxKillsProcessGroupOnTimeout(t *testing.T) {
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("sh not available")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	// A shell that spawns a child and waits; both must be killed on timeout.
	start := time.Now()
	cmd := sandboxCmd(ctx, DefaultProcLimits, nil, "sh", "-c", "sleep 30 & sleep 30")
	err := cmd.Run()
	if err == nil {
		t.Fatal("expected the sandboxed command to be killed")
	}
	if elapsed := time.Since(start); elapsed > 8*time.Second {
		t.Fatalf("process not killed promptly: %s", elapsed)
	}
}

func TestSandboxSetsProcessGroup(t *testing.T) {
	cmd := sandboxCmd(context.Background(), ProcLimits{}, nil, "true")
	if cmd.SysProcAttr == nil || !cmd.SysProcAttr.Setpgid {
		t.Fatal("child must run in its own process group")
	}
	if cmd.WaitDelay == 0 {
		t.Fatal("WaitDelay must be set so an unresponsive child is force-killed")
	}
}

//go:build linux || android

package agh

import (
	"errors"
	"os"
	"os/exec"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestWatchProcessExitAndCancel(t *testing.T) {
	if os.Getenv("NETPROXY_PIDFD_CHILD") == "1" {
		for {
			time.Sleep(time.Minute)
		}
	}
	child := exec.Command(os.Args[0], "-test.run=^TestWatchProcessExitAndCancel$")
	child.Env = append(os.Environ(), "NETPROXY_PIDFD_CHILD=1")
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = child.Process.Kill(); _ = child.Wait() })
	exited, stop, err := WatchProcess(child.Process.Pid)
	if errors.Is(err, unix.ENOSYS) || errors.Is(err, unix.EPERM) {
		t.Skipf("pidfd unavailable: %v", err)
	}
	if err != nil {
		t.Fatal(err)
	}
	defer stop()
	canceled, cancel, err := WatchProcess(child.Process.Pid)
	if err != nil {
		t.Fatal(err)
	}
	cancelDone := make(chan struct{})
	go func() { cancel(); cancel(); close(cancelDone) }()
	select {
	case <-cancelDone:
	case <-time.After(3 * time.Second):
		t.Fatal("cancel did not release the process observer")
	}
	select {
	case <-canceled:
		t.Fatal("cancellation was mistaken for process exit")
	default:
	}
	if err := child.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-exited:
	case <-time.After(3 * time.Second):
		t.Fatal("process exit was not observed")
	}
}

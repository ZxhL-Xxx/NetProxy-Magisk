//go:build linux || android

package agh

import (
	"sync"

	"golang.org/x/sys/unix"
)

// WatchProcess 在内核中等待进程退出，通过 eventfd 取消等待。
func WatchProcess(pid int) (<-chan struct{}, func(), error) {
	fd, err := unix.PidfdOpen(pid, 0)
	if err != nil {
		return nil, nil, err
	}
	cancelFD, err := unix.Eventfd(0, unix.EFD_CLOEXEC|unix.EFD_NONBLOCK)
	if err != nil {
		unix.Close(fd)
		return nil, nil, err
	}
	exited, done := make(chan struct{}, 1), make(chan struct{})
	var descriptorMu sync.Mutex
	closed := false
	go func() {
		defer close(done)
		defer func() {
			descriptorMu.Lock()
			closed = true
			unix.Close(fd)
			unix.Close(cancelFD)
			descriptorMu.Unlock()
		}()
		fds := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}, {Fd: int32(cancelFD), Events: unix.POLLIN}}
		for {
			_, err := unix.Poll(fds, -1)
			if err == unix.EINTR {
				continue
			}
			if err != nil || fds[0].Revents != 0 {
				exited <- struct{}{}
			}
			return
		}
	}()
	var once sync.Once
	stop := func() {
		once.Do(func() {
			descriptorMu.Lock()
			if !closed {
				_, _ = unix.Write(cancelFD, []byte{1, 0, 0, 0, 0, 0, 0, 0})
			}
			descriptorMu.Unlock()
			<-done
		})
	}
	return exited, stop, nil
}

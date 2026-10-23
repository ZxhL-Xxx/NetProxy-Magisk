package module

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/Fanju6/NetProxy-Magisk/src/native/netproxy/internal/agh"
	"github.com/Fanju6/NetProxy-Magisk/src/native/netproxy/internal/inbound"
	"github.com/Fanju6/NetProxy-Magisk/src/native/netproxy/internal/paths"
	"github.com/Fanju6/NetProxy-Magisk/src/native/netproxy/internal/service"
	"github.com/Fanju6/NetProxy-Magisk/src/native/netproxy/internal/serviceapi"
	"github.com/fsnotify/fsnotify"
)

func pairedDNSGuard(options Options) *agh.Guard {
	layout := paths.New(options.ModuleDir)
	if info, err := os.Stat(layout.AGHProfile()); err != nil || !info.IsDir() {
		return nil
	}
	return &agh.Guard{LockFile: layout.AGHHandoffLock()}
}

func preparedServiceIdentity(prepared PrepareResult, startedAt int64) (ServiceIdentity, error) {
	content, err := os.ReadFile(prepared.Inbound)
	if err != nil {
		return ServiceIdentity{}, err
	}
	ipv4, ipv6, err := inbound.RuntimeLocalDNSHijack(content)
	if err != nil {
		return ServiceIdentity{}, err
	}
	return ServiceIdentity{Backend: prepared.Backend, StartedAtMillis: startedAt, DNSHandoff: &agh.Scope{IPv4: ipv4, IPv6: ipv6}}, nil
}

func setDNSHandoff(ctx context.Context, options Options, scope agh.Scope) error {
	guard := pairedDNSGuard(options)
	if guard == nil {
		return nil
	}
	bounded, cancel := context.WithTimeout(context.WithoutCancel(ctx), 8*time.Second)
	defer cancel()
	if err := guard.Sync(bounded, true, func(context.Context) (agh.Scope, bool, error) { return scope, false, nil }); err != nil {
		return fmt.Errorf("AGH DNS 接管交接失败: %w", err)
	}
	return nil
}

// 临时 API 故障保留当前接管，不能把它误判为停服而回退国内解析。
func resolveDNSHandoff(ctx context.Context, options Options) (agh.Scope, bool, error) {
	state, err := ReadServiceState(options.StateFile)
	if err != nil {
		if !service.ProcessRunning(options.SingBoxPath) {
			return agh.Scope{}, false, nil
		}
		return agh.Scope{}, true, err
	}
	pid := service.FindProcess(options.SingBoxPath, int(state.PID))
	return resolveDNSHandoffState(ctx, options, state, pid)
}

func resolveDNSHandoffState(ctx context.Context, options Options, state ServiceState, pid int) (agh.Scope, bool, error) {
	if state.PID > 0 && pid != int(state.PID) || pid <= 0 || state.State == "stopping" {
		return agh.Scope{}, false, nil
	}
	if state.State != "ready" || state.DNSHandoff == nil {
		return agh.Scope{}, true, nil
	}
	client, err := serviceapi.New(options.ServiceAddress, options.ServiceSecret)
	if err != nil {
		return agh.Scope{}, true, err
	}
	defer client.Close()
	bounded, cancel := context.WithTimeout(ctx, 300*time.Millisecond)
	defer cancel()
	started, err := client.Ready(bounded)
	if err != nil {
		return agh.Scope{}, true, err
	}
	if started.UnixMilli != state.CoreStartedAtMillis {
		return agh.Scope{}, true, fmt.Errorf("核心启动身份发生变化，保留现有 DNS 接管")
	}
	mode, err := client.Mode(bounded)
	if err != nil {
		return agh.Scope{}, true, err
	}
	if mode.Current == "" {
		return agh.Scope{}, true, fmt.Errorf("核心未报告当前出站模式，保留现有 DNS 接管")
	}
	if mode.Current == "Direct" {
		return agh.Scope{}, false, nil
	}
	return *state.DNSHandoff, false, nil
}

// 核心运行期间消费模式事件，兼顾面板直接切换 Direct；断线只重连，不更改 DNS 归属。
func watchDNSModes(ctx context.Context, options Options, wake chan<- struct{}) {
	client, err := serviceapi.New(options.ServiceAddress, options.ServiceSecret)
	if err != nil {
		return
	}
	defer client.Close()
	delay := time.Second
	for ctx.Err() == nil {
		started := time.Now()
		_ = client.SubscribeClashMode(ctx, func(string) error {
			select {
			case wake <- struct{}{}:
			default:
			}
			return ctx.Err()
		})
		if ctx.Err() != nil {
			return
		}
		if time.Since(started) > 30*time.Second {
			delay = time.Second
		}
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
		delay = min(30*time.Second, delay*2)
	}
}

// RunDNSHandoff 复用现有 Worker；正常空闲时不启动轮询计时器。
// fsnotify 处理规则重建与生命周期变化，pidfd 处理核心异常退出。
func RunDNSHandoff(ctx context.Context, options Options) {
	guard := pairedDNSGuard(options)
	if guard == nil {
		return
	}
	layout := paths.New(options.ModuleDir)
	var watcher *fsnotify.Watcher
	delay := time.Second
	for {
		var err error
		watcher, err = fsnotify.NewWatcher()
		if err == nil {
			break
		}
		logService(options, "WARN", "dns.handoff", "retry", "无法监听 DNS 接管状态，将重试: %v", err)
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
		delay = min(30*time.Second, delay*2)
	}
	defer watcher.Close()
	statePath := filepath.Clean(options.StateFile)
	aghDir := layout.AGHDir()
	relevant := map[string]bool{
		statePath:                               false,
		filepath.Join(aghDir, "history.log"):    true,
		filepath.Join(aghDir, "settings.conf"):  true,
		filepath.Join(aghDir, "bin", "agh.pid"): true,
	}
	refreshWatches := func() error {
		var watchErr error
		for _, target := range []string{filepath.Dir(statePath), aghDir, filepath.Join(aghDir, "bin")} {
			for {
				if _, err := os.Stat(target); err == nil {
					break
				}
				parent := filepath.Dir(target)
				if parent == target {
					break
				}
				target = parent
			}
			watchErr = errors.Join(watchErr, watcher.Add(target))
		}
		return watchErr
	}
	watchErr := refreshWatches()
	var exited <-chan struct{}
	var stopProcess func()
	var fallback *time.Ticker
	var fallbackEvents <-chan time.Time
	modeWake := make(chan struct{}, 1)
	var modeCancel context.CancelFunc
	var modeDone chan struct{}
	defer func() {
		if modeCancel != nil {
			modeCancel()
			<-modeDone
		}
		if stopProcess != nil {
			stopProcess()
		}
		if fallback != nil {
			fallback.Stop()
		}
	}()
	observedPID := 0
	observeProcess := func() {
		state, err := ReadServiceState(statePath)
		if err != nil {
			return
		}
		pid := service.FindProcess(options.SingBoxPath, int(state.PID))
		if state.PID <= 0 || pid != int(state.PID) {
			pid = 0
		}
		if pid == observedPID {
			return
		}
		if stopProcess != nil {
			stopProcess()
			stopProcess = nil
		}
		if modeCancel != nil {
			modeCancel()
			<-modeDone
			modeCancel = nil
		}
		if fallback != nil {
			fallback.Stop()
			fallback = nil
			fallbackEvents = nil
		}
		exited, observedPID = nil, pid
		if pid <= 0 {
			return
		}
		modeContext, cancel := context.WithCancel(ctx)
		modeCancel, modeDone = cancel, make(chan struct{})
		done := modeDone
		go func() { defer close(done); watchDNSModes(modeContext, options, modeWake) }()
		exited, stopProcess, err = agh.WatchProcess(pid)
		if err != nil {
			// 厂商内核可能拒绝 pidfd；兜底只读进程状态，不轮询 Shell 或防火墙。
			fallback = time.NewTicker(2 * time.Second)
			fallbackEvents = fallback.C
		}
	}
	timer := time.NewTimer(0)
	defer timer.Stop()
	var pending <-chan time.Time = timer.C
	due := time.Now()
	force, retry, lastError := true, time.Second, ""
	schedule := func(delay time.Duration) {
		next := time.Now().Add(delay)
		if pending == nil || next.Before(due) {
			timer.Reset(delay)
			pending = timer.C
			due = next
		}
	}
	for {
		select {
		case <-ctx.Done():
			return
		case event, ok := <-watcher.Events:
			if !ok {
				return
			}
			if event.Has(fsnotify.Create) || event.Has(fsnotify.Rename) || event.Has(fsnotify.Remove) {
				watchErr = refreshWatches()
			}
			if rebuild, exists := relevant[filepath.Clean(event.Name)]; exists {
				force = force || rebuild
				schedule(10 * time.Millisecond)
			}
			if event.Name == aghDir || event.Name == filepath.Join(aghDir, "bin") {
				force = true
				schedule(10 * time.Millisecond)
			}
		case err, ok := <-watcher.Errors:
			if !ok {
				return
			}
			logService(options, "WARN", "dns.handoff", "retry", "DNS 状态监听需要重新校准: %v", err)
			force = true
			watchErr = refreshWatches()
			schedule(time.Second)
		case <-modeWake:
			schedule(0)
		case <-exited:
			exited = nil
			observedPID = -1
			schedule(0)
		case <-fallbackEvents:
			state, _ := ReadServiceState(statePath)
			if service.FindProcess(options.SingBoxPath, int(state.PID)) != observedPID {
				schedule(0)
			}
		case <-pending:
			pending = nil
			if watchErr != nil {
				watchErr = refreshWatches()
			}
			observeProcess()
			bounded, cancel := context.WithTimeout(ctx, 8*time.Second)
			err := errors.Join(watchErr, guard.Sync(bounded, force, func(ctx context.Context) (agh.Scope, bool, error) { return resolveDNSHandoff(ctx, options) }))
			cancel()
			if err != nil {
				if err.Error() != lastError {
					logService(options, "WARN", "dns.handoff", "retry", "DNS 接管未完成，将重试: %v", err)
					lastError = err.Error()
				}
				schedule(retry)
				retry = min(30*time.Second, retry*2)
				continue
			}
			force, retry, lastError = false, time.Second, ""
		}
	}
}

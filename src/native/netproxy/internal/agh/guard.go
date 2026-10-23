// Package agh 协调配套解析器与代理核心的 DNS 接管。
package agh

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"sync"

	"github.com/Fanju6/NetProxy-Magisk/src/native/netproxy/internal/processlock"
)

const owner = "netproxy-agh-handoff"

type chain struct{ binary, table, name string }

var chains = []chain{
	{"iptables", "nat", "ADGUARD_REDIRECT_DNS"},
	{"ip6tables", "nat", "ADGUARD_REDIRECT_DNS6"},
	{"ip6tables", "filter", "ADGUARD_BLOCK_DNS"},
}

// Runner 直接传递固定参数，不经 Shell 解释。
type Runner func(context.Context, string, ...string) ([]byte, error)

// Scope 按实际接管能力分别交接两个地址族，避免放行未接管的 IPv6 DNS。
type Scope struct {
	IPv4 bool `json:"ipv4"`
	IPv6 bool `json:"ipv6"`
}

// Guard 只管理 AGH DNS 链内带本集成标记的两条 RETURN 规则。
type Guard struct {
	LockFile string
	Run      Runner
	mu       sync.Mutex
	known    bool
	scope    Scope
}

func command(ctx context.Context, binary string, args ...string) ([]byte, error) {
	return exec.CommandContext(ctx, binary, args...).CombinedOutput()
}

func rule(protocol string) []string {
	return []string{"-p", protocol, "-m", protocol, "--dport", "53", "-m", "comment", "--comment", owner, "-j", "RETURN"}
}

func (g *Guard) call(ctx context.Context, c chain, args ...string) ([]byte, error) {
	run := g.Run
	if run == nil {
		run = command
	}
	return run(ctx, c.binary, append([]string{"-w", "2", "-t", c.table}, args...)...)
}

func missingChain(output []byte) bool {
	message := strings.ToLower(string(output))
	return strings.Contains(message, "no chain/target/match") ||
		strings.Contains(message, "does not exist") || strings.Contains(message, "chain not found")
}

func normalize(line string) string {
	fields := strings.Fields(line)
	for i := range fields {
		fields[i] = strings.Trim(fields[i], `"`)
	}
	return strings.Join(fields, " ")
}

func (g *Guard) applyChain(ctx context.Context, c chain, bypass bool) error {
	output, err := g.call(ctx, c, "-S", c.name)
	if err != nil {
		if missingChain(output) {
			return nil
		}
		// 防火墙原文可能含有无关设备规则，不能写入错误日志。
		return fmt.Errorf("读取 DNS 链 %s/%s 失败: %w", c.table, c.name, err)
	}
	var rules []string
	for line := range strings.SplitSeq(string(output), "\n") {
		line = normalize(line)
		if strings.HasPrefix(line, "-A "+c.name+" ") {
			rules = append(rules, strings.TrimPrefix(line, "-A "+c.name+" "))
		}
	}
	wanted := []string{strings.Join(rule("udp"), " "), strings.Join(rule("tcp"), " ")}
	owned := 0
	for _, entry := range rules {
		if entry == wanted[0] || entry == wanted[1] {
			owned++
		}
	}
	if bypass && owned == 2 && len(rules) >= 2 && rules[0] == wanted[0] && rules[1] == wanted[1] {
		return nil
	}
	if !bypass && owned == 0 {
		return nil
	}
	for _, entry := range rules {
		if entry != wanted[0] && entry != wanted[1] {
			continue
		}
		if _, err := g.call(ctx, c, append([]string{"-D", c.name}, strings.Fields(entry)...)...); err != nil {
			return fmt.Errorf("撤回 %s 的 DNS 避让失败: %w", c.name, err)
		}
	}
	if bypass {
		// 逆序插入，确保 RETURN 位于 AGH 的重定向或拒绝之前。
		for _, protocol := range []string{"tcp", "udp"} {
			if _, err := g.call(ctx, c, append([]string{"-I", c.name, "1"}, rule(protocol)...)...); err != nil {
				return fmt.Errorf("设置 %s 的 DNS 避让失败: %w", c.name, err)
			}
		}
	}
	return nil
}

// Sync 在状态变化时协调规则；force 用于 AGH 独立重建规则后重新核对。
// resolve 在跨进程锁内读取当前状态，防止旧 Worker 事件覆盖较新的生命周期操作。
func (g *Guard) Sync(ctx context.Context, force bool, resolve func(context.Context) (scope Scope, hold bool, err error)) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	lock, err := processlock.Acquire(ctx, g.LockFile)
	if err != nil {
		return err
	}
	defer lock.Release()
	scope, hold, err := resolve(ctx)
	if err != nil || hold {
		// 重建事件可能恰逢核心重载；保留待核对状态，不能被下一次相同归属缓存吞掉。
		if force {
			g.known = false
		}
		return err
	}
	if g.known && g.scope == scope && !force {
		return nil
	}
	var applyErr error
	for _, c := range chains {
		bypass := scope.IPv6
		if c.binary == "iptables" {
			bypass = scope.IPv4
		}
		// 部分激活失败时保留已生效的避让，不能把国外查询静默送回全局上游。
		// 撤回时也须尝试所有地址族，不能在第一处错误后留下后续规则。
		applyErr = errors.Join(applyErr, g.applyChain(ctx, c, bypass))
	}
	if applyErr != nil {
		g.known = false
		return applyErr
	}
	g.known, g.scope = true, scope
	return nil
}

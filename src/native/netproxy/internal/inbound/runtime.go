package inbound

import (
	"context"
	"encoding/json/jsontext"
	json "encoding/json/v2"
	"fmt"
	"os"
	"path/filepath"
	"slices"

	"github.com/sagernet/sing-box/option"
)

type Runtime struct {
	Inbounds []jsontext.Value `json:"inbounds"`
}

type BuildResult struct {
	Runtime         Runtime
	MissingPackages []PackageRef
	Backend         string
}

// WithDNSBypass 只覆盖运行时副本，不修改用户保存的入站偏好。
func (c Config) WithDNSBypass(bypass bool) (Config, error) {
	if !bypass {
		return c, nil
	}
	var err error
	if c.Backend == "ebpf" {
		native, nativeErr := c.EBPFOptions()
		if nativeErr != nil {
			return c, nativeErr
		}
		local, shared := native.EffectiveEnablement()
		if local {
			native.Local.DNSMode = "off"
		}
		if shared {
			native.Shared.DNSMode = "off"
		}
		c.EBPF, err = marshalNative(ebpfInbound{Type: "ebpf", Tag: Tag, EBPFInboundOptions: native})
	} else {
		native, nativeErr := c.TUNOptions()
		if nativeErr != nil {
			return c, nativeErr
		}
		native.DNSMode = "disabled"
		c.TUN, err = marshalNative(tunInbound{Type: "tun", Tag: Tag, TunInboundOptions: native})
	}
	return c, err
}

func (c Config) DNSState() (string, error) {
	if c.Backend == "ebpf" {
		native, err := c.EBPFOptions()
		if err != nil {
			return "", err
		}
		local, shared := native.EffectiveEnablement()
		if !local {
			native.Local.DNSMode = ""
		}
		if !shared {
			native.Shared.DNSMode = ""
		}
		return fmt.Sprintf("ebpf:%t:%s:%t:%s", local, native.Local.DNSMode, shared, native.Shared.DNSMode), nil
	}
	native, err := c.TUNOptions()
	if err != nil {
		return "", err
	}
	return "tun:" + native.DNSMode, nil
}

func RuntimeDNSState(content []byte) (string, error) {
	var runtime Runtime
	if err := json.Unmarshal(content, &runtime); err != nil {
		return "", err
	}
	if len(runtime.Inbounds) != 1 {
		return "", fmt.Errorf("受管运行时必须只有一个入站")
	}
	var identity struct {
		Type string `json:"type"`
	}
	if err := json.Unmarshal(runtime.Inbounds[0], &identity); err != nil {
		return "", err
	}
	c := Config{Backend: identity.Type, EBPF: runtime.Inbounds[0], TUN: runtime.Inbounds[0]}
	return c.DNSState()
}

// RuntimeLocalDNSHijack 只认可实际运行时的全局本机 DNS 接管。
func RuntimeLocalDNSHijack(content []byte) (ipv4, ipv6 bool, err error) {
	var runtime Runtime
	if err := json.Unmarshal(content, &runtime); err != nil {
		return false, false, err
	}
	if len(runtime.Inbounds) != 1 {
		return false, false, fmt.Errorf("受管运行时必须只有一个入站")
	}
	var entry struct {
		Type    string `json:"type"`
		DNSMode string `json:"dns_mode"`
	}
	if err := json.Unmarshal(runtime.Inbounds[0], &entry); err != nil {
		return false, false, err
	}
	switch entry.Type {
	case "ebpf":
		c := Config{EBPF: runtime.Inbounds[0]}
		native, err := c.EBPFOptions()
		if err != nil {
			return false, false, err
		}
		local, _ := native.EffectiveEnablement()
		networks := native.Network.Build()
		both := len(networks) == 0 || (slices.Contains(networks, "tcp") && slices.Contains(networks, "udp"))
		hijack := local && both && native.Local.DNSMode == "hijack"
		return hijack, hijack && (native.Local.IPv6 == nil || *native.Local.IPv6), nil
	case "tun":
		if entry.DNSMode != "hijack" {
			return false, false, nil
		}
		native, err := (Config{TUN: runtime.Inbounds[0]}).TUNOptions()
		if err != nil {
			return false, false, err
		}
		// TUN 的 UID/目的地址筛选先于 DNS；不能像 eBPF hijack 一样放行所有应用。
		if len(native.IncludeUID)+len(native.IncludeUIDRange)+len(native.ExcludeUID)+len(native.ExcludeUIDRange)+
			len(native.IncludeAndroidUser)+len(native.IncludePackage)+len(native.ExcludePackage)+
			len(native.RouteAddress)+len(native.RouteAddressSet)+len(native.RouteExcludeAddress)+len(native.RouteExcludeAddressSet) > 0 {
			return false, false, nil
		}
		for _, prefix := range native.Address {
			ipv4 = ipv4 || prefix.Addr().Is4()
			ipv6 = ipv6 || prefix.Addr().Is6()
		}
		return ipv4, ipv6, nil
	default:
		return false, false, fmt.Errorf("未知受管入站: %s", entry.Type)
	}
}

func (c Config) Build(ctx context.Context) (BuildResult, error) {
	if err := ctx.Err(); err != nil {
		return BuildResult{}, err
	}
	result, err := c.BuildWithResolver(func(refs []PackageRef) (PackageUIDResolution, error) {
		return ResolvePackageUIDs(ctx, refs)
	})
	if err == nil {
		err = ctx.Err()
	}
	if err != nil {
		return BuildResult{}, err
	}
	return result, nil
}

func (c Config) BuildWithResolver(resolve PackageUIDResolver) (BuildResult, error) {
	if err := c.validateOuter(); err != nil {
		return BuildResult{}, err
	}
	if err := c.validateSection(c.Backend); err != nil {
		return BuildResult{}, err
	}
	var content []byte
	var resolution PackageUIDResolution
	var err error
	switch c.Backend {
	case "ebpf":
		native, nativeErr := c.EBPFOptions()
		if nativeErr != nil {
			return BuildResult{}, nativeErr
		}
		local, _ := native.EffectiveEnablement()
		if local && c.App.Enabled {
			resolution, err = c.resolveApplications(resolve)
			if err != nil {
				return BuildResult{}, err
			}
			if c.App.Mode == "whitelist" {
				native.Local.IncludeUID = append(native.Local.IncludeUID, resolution.UIDs...)
				// 空 include 在内核中表示不限 UID；空白名单须排除全部有效 UID，最大 uint32 是无效 UID。
				if len(native.Local.IncludeUID)+len(native.Local.IncludeUIDRange) == 0 {
					native.Local.ExcludeUIDRange = []string{"0:4294967294"}
				}
			} else {
				native.Local.ExcludeUID = append(native.Local.ExcludeUID, resolution.UIDs...)
			}
		}
		if local {
			if err := c.applyRootPolicy(&native.Local.IncludeUID, native.Local.IncludeUIDRange, &native.Local.ExcludeUID, &native.Local.ExcludeUIDRange,
				len(native.Local.IncludePackage) > 0); err != nil {
				return BuildResult{}, err
			}
		}
		native, err = normalizeEBPF(native)
		if err == nil {
			content, err = marshalNative(ebpfInbound{Type: "ebpf", Tag: Tag, EBPFInboundOptions: native})
		}
	case "tun":
		native, nativeErr := c.TUNOptions()
		if nativeErr != nil {
			return BuildResult{}, nativeErr
		}
		if c.App.Enabled {
			resolution, err = c.resolveApplications(resolve)
			if err != nil {
				return BuildResult{}, err
			}
			if c.App.Mode == "whitelist" {
				native.IncludeUID = append(native.IncludeUID, resolution.UIDs...)
				if len(native.IncludeUID)+len(native.IncludeUIDRange) == 0 {
					native.ExcludeUIDRange = []string{"0:4294967294"}
				}
			} else {
				native.ExcludeUID = append(native.ExcludeUID, resolution.UIDs...)
			}
		}
		if err := c.applyRootPolicy(&native.IncludeUID, native.IncludeUIDRange, &native.ExcludeUID, &native.ExcludeUIDRange,
			len(native.IncludePackage) > 0); err != nil {
			return BuildResult{}, err
		}
		native, err = normalizeTUN(native)
		if err == nil {
			content, err = marshalNative(tunInbound{Type: "tun", Tag: Tag, TunInboundOptions: native})
		}
	}
	if err != nil {
		return BuildResult{}, err
	}
	return BuildResult{Runtime: Runtime{Inbounds: []jsontext.Value{content}}, MissingPackages: resolution.Missing, Backend: c.Backend}, nil
}

func (c Config) resolveApplications(resolve PackageUIDResolver) (PackageUIDResolution, error) {
	values := c.App.BypassApps
	if c.App.Mode == "whitelist" {
		values = c.App.ProxyApps
	}
	refs, err := packageRefs(values)
	if err != nil {
		return PackageUIDResolution{}, err
	}
	resolution := PackageUIDResolution{}
	if len(refs) > 0 {
		if resolve == nil {
			return resolution, validationError("inbound.resolver_required", "app", "分应用策略需要包名 UID 解析器")
		}
		resolution, err = resolve(refs)
		if err != nil {
			return PackageUIDResolution{}, err
		}
	}
	return resolution, nil
}

// EffectiveContent 不查询设备 UID；仅比较会投影到当前入站的配置，应用重装仍由 reload 重新解析。
func (c Config) EffectiveContent() ([]byte, error) {
	if err := c.validateOuter(); err != nil {
		return nil, err
	}
	if err := c.validateSection(c.Backend); err != nil {
		return nil, err
	}
	app := c.App
	var content []byte
	var err error
	switch c.Backend {
	case "ebpf":
		var native option.EBPFInboundOptions
		native, err = c.EBPFOptions()
		if err != nil {
			return nil, err
		}
		local, _ := native.EffectiveEnablement()
		if !local {
			app.Enabled = false
		} else if err := c.applyRootPolicy(&native.Local.IncludeUID, native.Local.IncludeUIDRange, &native.Local.ExcludeUID, &native.Local.ExcludeUIDRange,
			len(native.Local.IncludePackage) > 0); err != nil {
			return nil, err
		}
		native, err = normalizeEBPF(native)
		if err == nil {
			content, err = marshalNative(ebpfInbound{Type: "ebpf", Tag: Tag, EBPFInboundOptions: native})
		}
	case "tun":
		var native option.TunInboundOptions
		native, err = c.TUNOptions()
		if err != nil {
			return nil, err
		}
		if err := c.applyRootPolicy(&native.IncludeUID, native.IncludeUIDRange, &native.ExcludeUID, &native.ExcludeUIDRange,
			len(native.IncludePackage) > 0); err != nil {
			return nil, err
		}
		native, err = normalizeTUN(native)
		if err == nil {
			content, err = marshalNative(tunInbound{Type: "tun", Tag: Tag, TunInboundOptions: native})
		}
	}
	if err != nil {
		return nil, err
	}
	if !app.Enabled {
		app = AppPolicy{}
	} else {
		values := app.BypassApps
		if app.Mode == "whitelist" {
			values = app.ProxyApps
		}
		refs, err := packageRefs(values)
		if err != nil {
			return nil, err
		}
		values = make([]string, 0, len(refs))
		for _, ref := range refs {
			values = append(values, ref.String())
		}
		slices.Sort(values)
		app.ProxyApps, app.BypassApps = nil, nil
		if app.Mode == "whitelist" {
			app.ProxyApps = values
		} else {
			app.BypassApps = values
		}
	}
	return json.Marshal(map[string]any{"backend": c.Backend, "app": app, c.Backend: jsontext.Value(content)}, json.Deterministic(true))
}

func WriteAtomic(ctx context.Context, path string, config Config) ([]PackageRef, error) {
	built, err := config.Build(ctx)
	if err != nil {
		return nil, err
	}
	content, err := json.Marshal(built.Runtime, json.Deterministic(true), jsontext.WithIndent("  "))
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".inbound-")
	if err != nil {
		return nil, err
	}
	defer os.Remove(tmp.Name())
	defer tmp.Close()
	if err = tmp.Chmod(0o600); err == nil {
		_, err = tmp.Write(append(content, '\n'))
	}
	if err == nil {
		err = tmp.Sync()
	}
	if closeErr := tmp.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return nil, err
	}
	return built.MissingPackages, nil
}

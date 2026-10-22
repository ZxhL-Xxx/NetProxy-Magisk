# eBPF 原生参数

eBPF 参数保存在 `config/inbound/inbound.json` 的 `ebpf` 对象。完整结构、共用应用策略与保存方法见 [入站配置](/config/inbound)。通过 `inbound/ebpf` 编辑时，候选文件必须保留 `{"ebpf": {...}}` 包装。

## 默认参数

```json
{
  "ebpf": {
    "type": "ebpf",
    "tag": "netproxy-in",
    "network": ["tcp", "udp"],
    "udp_timeout": "5m",
    "tc_priority": 1,
    "local": {
      "enabled": true,
      "data_plane": "cgroup",
      "dns_mode": "hijack",
      "ipv6": true,
      "bypass_private_address": true,
      "bypass_rule_set": []
    },
    "shared": {
      "enabled": false,
      "data_plane": "packet_rewrite",
      "dns_mode": "hijack",
      "interface": ["wlan2"],
      "ipv6": true,
      "bypass_private_address": true,
      "bypass_rule_set": []
    }
  }
}
```

`type` 固定为 `ebpf`，`tag` 固定为 `netproxy-in`。`network` 可以只选择 `tcp` 或 `udp`；默认两者均接管。`tc_priority` 用于协调同一接口上的 TC filter，通常保持默认值。

## 数据路径

`local.enabled` 与 `shared.enabled` 独立控制本机和共享网络，选择 eBPF 时至少开启一条。关闭的路径仍能保存全部偏好，但生成的 `runtime/inbound.json` 中该路径只包含 `{"enabled": false}`，不会把未启用的接口、DNS 或筛选参数交给核心。

本机 `local.data_plane` 支持：

- `cgroup`：默认值，在 socket 阶段接管本机 TCP/UDP，不依赖默认出口接口，需要 cgroup v2 和相应 socket hook。
- `tc`：跟随默认出口接口处理本机流量。

`local.cgroup_path` 只适用于 `cgroup`，可省略；设置时必须是 cgroup v2 绝对路径。

共享网络 `shared.data_plane` 支持：

- `packet_rewrite`：默认值，适用于普通以太网热点。
- `socket_assign`：适用于 raw-IP、PPP 或隧道接口。

`tc/socket_assign` 这种组合写法分别指本机的 `local.data_plane=tc` 和共享网络的 `shared.data_plane=socket_assign`。两条路径独立启用；只代理手机自身时使用本机 TC 即可，当前配套包的共享网络保持关闭，预存的共享数据平面不会参与本机接管。

本仓库锁定版本的默认配置使用 `cgroup`；RC1.3 TC 诊断包单独覆盖为本机 `tc`。用户已反馈 TC 下问题页面“好像可以了”，仍待继续测试，当前沿 TC 路线验证。锁定核心的[入站文档](https://github.com/reF1nd/sing-box/blob/v1.15.0-alpha.11-reF1nd/docs/configuration/inbound/ebpf.md)说明 Android 厂商 netd 的 cgroup hook 可能影响挂载兼容性，并建议无法安全共享 root cgroup hook 的设备使用本机 TC；这提供排查方向，不足以确认本设备的具体根因。

启用共享网络时，`shared.interface` 必须包含至少一个真实下游接口。`wlan2` 只是保存的默认偏好，不代表所有设备。接口出现、消失或成为默认上游时由 sing-box 管理 attachment；模块不会创建热点、DHCP、NAT、IPv6 RA 或 IP 转发。

## DNS、IPv6 与绕过

本机和共享网络各自设置 `dns_mode`、`ipv6`、`bypass_private_address`、`bypass_rule_set`、`bypass_port` 与 `bypass_port_range`：

- `hijack`：优先接管可见的 TCP/UDP 53 流量。
- `respect_policy`：先应用该路径的筛选与绕过策略，再接管 DNS。
- `off`：不由该路径接管 DNS。

本分支本机默认 `hijack`，与 AGH 的配套方式见 [RC1 配置](./adguardhome)。`ipv6: false` 仅绕过该路径的 IPv6，不关闭系统 IPv6。`bypass_rule_set` 默认空，国内直连在主路由中完成；手工加入绕过规则集时只使用可提取的 IP CIDR，命中流量不会进入普通路由，`Proxy` 模式也不能覆盖提前绕过。

`bypass_port` 使用数字数组，例如 `[22, 443]`；`bypass_port_range` 使用字符串数组，例如 `["1000:2000"]`，不是逗号文本。

## 原生筛选

本机支持 `include_uid`、`exclude_uid`、UID range、`include_android_user`、`include_package` 和 `exclude_package`。共用 `app` 开启时可叠加原生 UID/range，排除优先，UID 0 也可手动加入或排除；原生 package/user 筛选需关闭共用策略后使用。

共享网络支持 `include_source_cidr`、`exclude_source_cidr`、`include_mac_address` 和 `exclude_mac_address`，排除优先。共用应用名单只筛选本机应用，不用来识别热点客户端。

## 能力探测

```sh
su -c '/data/adb/modules/netproxy/netproxyctl ebpf status configured'
su -c '/data/adb/modules/netproxy/netproxyctl ebpf status all --raw'
```

`configured` 按保存的 eBPF 启用路径和数据平面检查，即使当前使用 TUN，也可检查 eBPF 能力。默认 `data.content` 是可读结论、问题与建议，`data.report` 保留结构化报告；`--raw` 让 `data.content` 返回核心原始 JSON。

预检通过只表示所选能力检查通过，不代表已经完成实际挂载或网络接管。探测会加载并关闭临时检测对象，不会挂载程序或改变流量；厂商内核可能关闭或回移单项能力，应以实际探测和启动结果为准。

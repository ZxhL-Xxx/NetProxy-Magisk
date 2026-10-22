# 路由与 DNS

NetProxy 的分流行为由四层共同决定：

1. 主配置 `experimental.clash_api.default_mode` 与规则的 `clash_mode` 条件。
2. sing-box 路由规则与规则集。
3. 所选入站的应用、接口和地址筛选；eBPF 的本机/共享网络提前绕过或 TUN 的原生路由范围。
4. Wi-Fi 自动策略对运行时模式的临时评估。

## 出站模式

### `Rule`（规则）

默认模式。由 sing-box 路由规则决定哪些流量直连、代理、拒绝或交给指定出站。

### `Proxy`（代理）

将进入 sing-box 的流量交给代理出站，适合测试节点或判断规则问题。eBPF 启用路径的 `bypass_rule_set` 或 TUN 的 `route_exclude_address` 等绕过仍会生效。

### `Direct`（直连）

全部直连，常用于临时停用代理。

本分支默认不提供 `RuleAllowAds`。广告和误杀放行由 AGH RC1 统一负责，详见 [配套配置](./adguardhome)。

## 规则集位置

```text
/data/adb/modules/netproxy/config/singbox/rules/
├── local/     # block.json、direct.json、proxy.json 等用户规则
└── remote/    # Ads_AWAvenue.json，geosite/ 与 geoip/ 下的 SRS 规则集
```

`Rule` 模式会同时使用静态路由配置和规则集。远程 JSON/SRS 规则由 sing-box 自动更新，用户编辑器不应修改它们；需要自定义规则时修改 `rules/local/`。

在管理器「设置 → 路由规则」查看全部本地匹配规则，卡片标明代理、直连或拦截。点击右上角「+」，选择规则类型与匹配条件后保存。已有规则保留所属规则集；多条件与高级规则使用 JSON 编辑器。

「Android 包名」填写完整包名，例如 `com.android.chrome`，每行一个，不加用户 ID。路由只处理已经被入站接管的流量；需要按 Android 用户控制接管范围时使用「应用代理」。

希望按地区和流媒体、AI、社交等业务单独选择出口时，可以阅读[策略分组配置教程](/config/policy-groups)，从零建立地区选择器、业务选择器和对应路由规则。

## eBPF 提前绕过

以下只展示 `inbound.json` 中的绕过字段，编辑时保留其他原生参数：

```json
{
  "ebpf": {
    "local": { "bypass_rule_set": ["geoip/cn"] },
    "shared": { "bypass_rule_set": ["geoip/cn"] }
  }
}
```

两项分别控制本机和共享网络，只对对应启用的数据路径生效；多个规则集使用 JSON 字符串数组。只有可提取纯 IP CIDR 的规则集会被 eBPF 使用。提前绕过的流量不会进入 sing-box，因此不会再经过普通路由规则。测试代理模式的路由行为时清空实际启用路径对应的规则集并重启核心。

应用黑白名单、私网绕过和共享网络来源过滤也可能在进入普通路由前改变流量路径，排障时需要一并确认。

TUN 使用 `route_address`、`route_exclude_address` 及对应规则集等原生字段，不把 eBPF bypass 字段转换过去。TUN 端口绕过使用主配置的 `action: "bypass"` pre-match 规则，必须位于 sniff 等终止 pre-match 的规则之前，详见 [TUN 参数](/config/tun)。

## DNS

eBPF 的 `local.dns_mode` 与 `shared.dns_mode` 分别控制两条数据路径是否接管 TCP / UDP 53：

- `hijack`：接管 DNS 请求，交给 sing-box DNS 路由。
- `respect_policy`：仅在流量通过对应数据路径的 UID、来源和地址策略后接管。
- `off`：不由 eBPF 入站接管 DNS。

本分支本机和共享偏好均为 `hijack`，共享网络默认关闭。TUN 使用自己的 `dns_mode`：默认 `hijack`，也有 `disabled` 与高级 `native`；`dns_address` 默认由上游推导，不能把 native 当作 Android 系统全局 DNS 设置。

sing-box 侧 DNS 服务器、域名解析策略和 DNS 路由位于 `config/singbox/config.json` 的 `dns` 分区。本分支默认 DNS A/AAAA 查询使用指向 AGH 的 `dns-proxy` / `dns-direct` 客户端路径，不使用 FakeIP 地址池。DNS 最终出站由 DNS 配置和核心实际模式共同决定；若将兜底 DNS 设置为直连，解析请求可能不经过代理，这是可预期的配置取舍，不等同于核心故障。

本地规则集可同时包含域名和 IP。本分支的 local/direct 和 local/proxy 只用于连接路由，DNS 分流使用纯域名 geosite 规则，不直接引用可能包含 IP 的本地规则集。未来需要在 DNS 中引用这类混合规则时，仍须使用 `evaluate` / `match_response`，不能采用已移除的旧式 DNS 地址过滤。

国内服务例外优先于业务组；七个业务的其他域名使用国外 AGH 客户端，国内域名使用国内 AGH 客户端，未知查询以国外客户端兜底。国内 IP 的提前绕过默认关闭；上面的 geoip/cn 示例是可选修改，加入后会削弱业务组和 Proxy 模式对这部分流量的控制。

## 排查顺序

1. 查看 `service status` 的实际 `outbound_mode` 与 `active_backend`，未确认后端时不要从模板猜测。
2. 确认当前后端的原生绕过、接口、地址筛选和共用应用名单。
3. 检查 `rules/local/` 与 `rules/remote/` 是否存在且可读。
4. 检查 `dns` 分区的 DNS 服务器和最终出站。
5. 查看 sing-box 核心日志和 Service API Dashboard 的连接结果。

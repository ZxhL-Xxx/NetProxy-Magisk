---
description: 本地定制配置：七个常用业务策略、国内外 DNS 分流与 AdGuardHome RC1 共存。
---

# RC1 去广告与精简分流配置

本分支默认配置用于同时安装 NetProxy 和 twoone-3 衍生的 AdGuardHome RC1。下方配套刷机包会自动设置两边的 DNS 通道；主配置依赖 AGH，不适合原样用于没有 AGH 的设备。

## 分流与职责

配置提供 OpenAI、Steam、YouTube、Telegram、GitHub、Microsoft、Google 七个业务选择器。默认均使用 `Proxy`，也可在面板改选 `All Proxies` 中的单个节点或 `direct`。Catalog 分组仍只管理节点与订阅；业务选择器不复制节点。

Steam、Microsoft、Google 的国内规则和 Apple 国内服务优先直连。其余国内域名直连，国外及未知流量默认代理。规则来自 MetaCubeX 的 geosite/geoip 数据，不维护一套零散域名清单。

广告过滤和误杀放行统一交给 AGH。NetProxy 不再引用 AWAvenue、category-ads-all、本地 `block` 拒绝规则或 AllowAds 模式。旧规则文件可以留在磁盘，未被引用不会生效；未来手工添加拒绝规则会改变这个职责分配。

## DNS 路径

```text
NetProxy 正常运行：
普通 53 查询 → eBPF hijack → sing-box DNS 规则
  国内 → 绑定来源 127.0.0.3 → AGH:5591 → 国内 DoH → 直连
  国外/未知 → 绑定来源 127.0.0.2 → AGH:5591 → 国外 DoH → Proxy

Direct / Wi-Fi 绕过 / 停止 NetProxy：
普通 53 查询 → AGH 自身 iptables → AGH 原有全局上游
```

两个来源地址只是本机客户端标识，AGH 仍只监听 `127.0.0.1:5591`。两个客户端都继承 AGH 全局过滤和放行策略，各有独立上游缓存；NetProxy 关闭重复 DNS 缓存，避免切换解析路径或更新规则时继续返回另一层的旧结果。

`dns.final=dns-proxy`；国外解析路径没有失败后改用国内 DNS 的候选服务器。代理节点域名使用独立、加密直连的引导解析器，避免“解析节点先需要代理”的循环。路由中需要补充解析的未知目标明确使用 `dns-proxy`，不使用引导解析器。

国外 DoH 使用 `1.1.1.1:443`、`8.8.8.8:443`，这两个连接在 Rule/Proxy 模式明确送往 `Proxy`。国内 DoH 使用 `223.5.5.5:443`、`1.12.12.12:443`；它们和引导解析地址明确直连。不要仅修改 AGH 国外上游地址而不同时调整 NetProxy 的对应规则。

境外 DNS 出口跟随顶层 `Proxy`，不会自动跟随每一个业务选择器的独立节点。国内 DNS 直连是本方案的明确策略；DNS 检测站可能显示国内解析器，这不等于境外查询一定泄漏。Direct、绕过和停代理时使用 AGH 原有直连解析，保留过滤，不承诺这些模式仍使用代理出口。

## 直接刷入配套模块

配套测试包会自动完成配置，无需手动编辑 YAML、创建客户端或导入 JSON。ADG 基于 RC1 分支，延用官方 AdGuard Home v0.107.79 和完整 DNS 规则，不加入 RC2 文件过滤。

1. 在 Root 管理器中覆盖刷入 **ADG-RC1-NetProxy.1-arm64.zip**。已有用户选“保留配置”（音量上键；不操作 30 秒也会保留）。
2. 不用中途重启，继续刷入 **NetProxy-v8.6.1-AGH-RC1.1-arm64.zip**。已有用户使用默认“保留现有数据”；管理器安装也可使用默认选项。
3. 确认两个模块均已启用，重启手机，等待 ADG 加载规则。打开 NetProxy 管理器，选择已有节点并启动服务；首次使用仍需导入自己的订阅。

普通 ARM64 手机使用上述两个 ARM64 包。ADG 另有 ARMv7 单独包，但 NetProxy 官方 8.6.1 配套包为 ARM64，不能据此认为 32 位手机也能运行两者。

手机的“私人 DNS”和浏览器自带的“安全 DNS”应关闭，让普通查询经过模块。模块内上游仍使用加密 DoH。

### 安装时自动完成的设置

- ADG 添加 `NetProxy Proxy DNS`（127.0.0.2）和 `NetProxy Direct DNS`（127.0.0.3），保留账号、全局上游、用户规则和订阅；保留自身 iptables，并固定配套端口和运行身份。
- NetProxy 保留 Catalog 节点、订阅、模块设置及日志，使用本包 eBPF 入站和业务分流预设；旧主配置、入站设置备份至 `config/agh-compat-backup/`。预设会替换原有自定义核心/入站设置，包括分应用设置；需要时可从备份恢复。
- 远程规则自带离线缓存。后台热更新在同步最新用户数据后再次应用预设，避免被旧配置覆盖。
- 开机等待 AGH 的 5591 UDP 监听，最长 150 秒；超时保留诊断入口，不改用国内解析器兜底国外通道。AGH 未启动时应先排查 ADG。

ADG 兼容升级前的备份为 `/data/adb/agh/bin/AdGuardHome.yaml.before-netproxy.bak` 和 `/data/adb/agh/settings.conf.before-netproxy.bak`。遇到冲突客户端网段、非标准 YAML、关闭过滤或不兼容监听时，安装会明确报错，原 YAML 不会被候选文件替换。

### 包的来源

这是本地测试用的官方发行包配置衍生版。NetProxy 固定使用官方 v8.6.1（源码 3fd2a1c）的核心、Native 程序、原签名管理器和辅助 DEX，逐文件保持字节不变；不改 Native、Android 或 WebUI 源码。构建清单与 SHA-256 随包提供，并移除指向官方包的更新入口，以免覆盖配套设置。今后修改上述组件时须改走完整源码构建与签名流程。

高级用户的离线配置合并工具仍保留在 `tools/prepare_agh_config.py`，普通用户刷入配套包即可。

eBPF 本机使用 `cgroup + hijack`；去掉 `geoip/cn` 的内核提前绕过，国内直连在 sing-box 路由中处理。私网绕过仍保留，Root 接管保持 `include`，否则 AGH 国外上游可能绕过代理。

## 测速

主配置开启 `experimental.urltest_unified_delay=true`。锁定的 reF1nd 核心支持追加一次请求并在成功时使用第二次耗时，思路与 Mihomo 的 `unified-delay` 一致。保留 `https://www.gstatic.com/generate_204`，不通过更换到国内网址制造较小数字，也不更改返回的测量结果。

这衡量的是预热后的请求延迟，不是首次建连耗时或下载速度，不能保证所有节点都会变低。NetProxy 停服时的离线测速由独立临时配置生成，本次没有修改这段 Go 逻辑，离线数值可能采用不同口径。

## 验证与边界

- 在 AGH 查询日志中确认国内查询命中 Direct DNS 客户端，国外查询命中 Proxy DNS 客户端；两类均验证一个拦截域和一个作者放行域。
- 对照 NetProxy 连接记录，确认两个国外 DoH 地址在 Rule/Proxy 下确实经代理；代理故障时，国外查询应失败而不切国内解析器。
- 测试 Direct、Wi-Fi 绕过、停止 NetProxy：AGH 应仍接收普通 DNS，正常国内访问和过滤应保留。
- Android 内核 cgroup、IPv4/IPv6、切网、应用绕过和启停路径仍需真机验证。AGH 原有 IPv6 DNS 拒绝策略继续存在；它不等于覆盖任意 IPv6-only 网络。
- 共享网络默认关闭；本方案不声称停代理后仍过滤热点下游。AGH 的 OUTPUT 规则只接管本机发出的请求。
- 应用自带 DoH/DoT、浏览器安全 DNS、直接 IP 和同域广告不因这套普通 DNS 路径自动受到完整控制。

回退时先恢复旧 NetProxy 配置；两个 AGH 客户端可以保留，也可删除。工具没有改变 AGH 全局上游和规则。始终保留你自己的修改前备份。

## 参考

- [NetProxy 模块配置](https://netproxy.store/config/module) 与 [策略分组](https://netproxy.store/config/policy-groups)
- [sing-box URLTest](https://sing-box.sagernet.org/configuration/outbound/urltest/)
- [DustinWin Android 配置](https://proxy-tutorials.dustinwin.cc.cd/posts/share-android-singboxr-ruleset/) 与 [Windows 配置](https://proxy-tutorials.dustinwin.cc.cd/posts/share-windows-singboxr-ruleset/)
- [Surfing Mihomo 配置](https://github.com/GitMetaio/Surfing/blob/main/box_bll/clash/config.yaml)
- [锁定版本的统一延迟实现](https://github.com/reF1nd/sing-box/blob/v1.15.0-alpha.11-reF1nd/common/urltest/urltest.go)

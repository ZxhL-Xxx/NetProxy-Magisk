---
description: 本地定制配置：11 个业务策略、地区选择、WebRTC 拦截和 AdGuardHome RC1 双通道 DNS。
---

# RC1 去广告与分流配置

本分支默认配置用于同时安装 NetProxy 和 twoone-3 衍生的 AdGuardHome RC1。下方配套刷机包会自动设置两边的 DNS 通道；主配置依赖 AGH，不适合原样用于没有 AGH 的设备。

## 分流与职责

面板业务组按参考配置顺序排列：Steam、Apple、Microsoft、Telegram、TikTok、YouTube、Google、GoogleFCM、OpenAI、GitHub、Twitter(X)。各组默认跟随「总模式」，可以单独选择香港、台湾、日本、美国、新加坡、其他地区、`All Proxies` 或 `direct`。Catalog 分组仍只管理节点与订阅；业务选择器不复制节点。

「总模式」默认使用 NetProxy 的 `Proxy`，复用管理器选择的节点或所属订阅 Auto 测速结果；不额外生成测速、负载均衡、故障转移、订阅更新或 DNS连接组。六个地区组只从订阅中筛选对应地区的真实节点，不包含 `Proxy` 或其他策略组；`All Proxies` 同样只列出节点。有有效历史选择时沿用原节点，否则选列表中的第一个节点，可手动改选。地区由节点名称判断，名称没有地区信息时可能被归入「其他地区」。

**空地区限制：** 锁定版本的核心在没有匹配节点时会自动显示 `Compatible` 占位，它实际直连；这不是可用的地区节点。不要把软件组或「总模式」选到这种空地区，选择有真实节点的地区或保留 `Proxy`。本版未修改核心，不能宣称空地区自动拒绝连接。国外 DNS 经代理的前提是「总模式」指向有效代理出口，选择空地区的直连占位会破坏这个前提。

规则模式中，国内域名、Steam/Apple/Microsoft/Google 的 `@cn` 子集和中国 IP 优先直连；这意味着这些目标会优先于业务组的选择。GoogleFCM、YouTube 的具体规则排在 Google 大类之前。已知国外域名进入「总模式」，其他未命中流量进入「漏网之鱼」，后者默认也跟随「总模式」。全局代理模式按其含义代理普通业务，不应用国内直连规则；手工 proxy/direct 规则仍是规则模式的主动覆盖入口。

全部启用的远程规则改为 [SagerNet sing-geosite](https://github.com/SagerNet/sing-geosite/tree/rule-set) 和 [sing-geoip](https://github.com/SagerNet/sing-geoip/tree/rule-set)。内置 19 份离线快照的来源提交和 SHA-256 记录在 `.github/resources.json`，复用现有资源更新流程；运行时每 24 小时通过代理检查远程规则。官方没有参考配置使用的软件专属 IP 集，纯 IP 连接主要按中国 IP 与兜底处理，不能保证被识别成 Telegram、Google 等业务。

广告过滤和误杀放行统一交给 AGH。NetProxy 不再引用 AWAvenue、category-ads-all、本地 `block` 拒绝规则或 AllowAds 模式。新增的拒绝规则只用于下方 WebRTC 控制。旧规则文件可以留在磁盘，未被引用不会生效。

### WebRTC 拦截

按用户选择开启，使用 STUN 协议嗅探、官方 `geosite-category-stun` 域名集，以及常见 STUN/TURN 目标端口 `3478`、`5349`、`19302–19309`。规则排在全局代理、国内直连与业务规则之前，作用于进入核心的 Rule/Proxy 流量；Direct 优先直连，Wi-Fi/应用/私网绕过和停止代理时不保证拦截。eBPF 的私网提前绕过仍然保留，不能仅凭核心中的规则认定所有路径均被拦截。

它用于减少 STUN 地址探测机会，可能影响 Telegram、微信、会议软件和网页的语音/视频通话。它不等于关闭浏览器 WebRTC API，也不能保证识别所有经 HTTPS 443 中继的 TURN；不会一概拒绝 QUIC 或 UDP 443。需要恢复通话时，可以在内核配置的路由规则中删除这条 WebRTC logical/reject 规则并保存，原有广告过滤继续由 AGH 处理。

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

`dns.final=dns-proxy`；国外解析路径没有失败后改用国内 DNS 的候选服务器。代理节点域名使用独立、加密直连的引导解析器，避免“解析节点先需要代理”的循环。业务路由的 `resolve` 不指定服务器，让核心按 DNS 规则选择 AGH 国内或国外客户端，并保留解析结果供后续连接使用；不使用 `match_only`，避免只为匹配解析后又在出站中重复解析。真实核心测试使用独立模拟引导解析器，验证这些业务解析不会落到引导通道。

国外 DoH 使用 `1.1.1.1:443`、`8.8.8.8:443`，这两个连接在 Rule/Proxy 模式明确送往「总模式」。国内 DoH 使用 `223.5.5.5:443`、`1.12.12.12:443`；它们和引导解析地址明确直连。不要仅修改 AGH 国外上游地址而不同时调整 NetProxy 的对应规则。

境外 DNS 出口跟随「总模式」，不会自动跟随每一个业务选择器的独立节点。国内 DNS 直连是本方案的明确策略；DNS 检测站可能显示国内解析器，这不等于境外查询一定泄漏。Direct、绕过和停代理时使用 AGH 原有直连解析，保留过滤，不承诺这些模式仍使用代理出口。本版继续使用真实 IP，没有启用 FakeIP。

## 直接刷入配套模块

配套测试包会自动完成配置，无需手动编辑 YAML、创建客户端或导入 JSON。ADG 基于 RC1 分支，延用官方 AdGuard Home v0.107.79 和完整 DNS 规则，不加入 RC2 文件过滤。

1. 在 Root 管理器中覆盖刷入 **ADG-RC1-NetProxy.1-arm64.zip**。已有用户选“保留配置”（音量上键；不操作 30 秒也会保留）。
2. 不用中途重启，继续刷入 **NetProxy-v8.6.1-AGH-RC1.3-arm64.zip**。已有用户使用默认“保留现有数据”；管理器安装也可使用默认选项。
3. 确认两个模块均已启用，重启手机，等待 ADG 加载规则。打开 NetProxy 管理器，选择已有节点并启动服务；首次使用仍需导入自己的订阅。

普通 ARM64 手机使用上述两个 ARM64 包。ADG 另有 ARMv7 单独包，但 NetProxy 官方 8.6.1 配套包为 ARM64，不能据此认为 32 位手机也能运行两者。

手机的“私人 DNS”和浏览器自带的“安全 DNS”应关闭，让普通查询经过模块。模块内上游仍使用加密 DoH。

已经装好 RC1.1/RC1.2 配套包的用户，本次只需覆盖刷入 NetProxy RC1.3 并重启；ADG 不需要重刷。RC1.3 去掉地区与全部节点组中的 `Proxy`，此前缓存的 `Proxy` 选择失效后会选择真实节点。同名业务组可能沿用仍有效的原选择，升级后请核对面板。升级会备份并替换主配置与入站预设，原订阅和节点继续保留；为排障临时加入的微信黑名单需要重新设置。Google Play、Via 和微信内腾讯文档问题仍在排查，本版不宣称已经修复这些手机问题。

另有 **NetProxy-v8.6.1-AGH-RC1.3-TC-test-arm64.zip** 诊断版，在同一配置基础上仅将 `ebpf.local.data_plane` 改为 `tc`；后端仍是 eBPF。两种包选择一种覆盖安装，不能作为两个独立模块同时启用。TC 版保留 Root 接管、DNS hijack、AGH 双通道和相同分流。用户已反馈 TC 下“好像可以了”，仍待继续测试，当前继续使用 TC 版验证，不把初步恢复当作全场景稳定。共享网络仍关闭，无需因本机使用 TC 而启用或改动 `socket_assign`。需要恢复已经可用的 TUN 时，在设置 → 入站设置 → 通用设置将代理后端切回 TUN，按提示重启服务即可。

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

### 浏览器与微信内页面排障

本机使用完整 AGH 规则的模拟上游测试确认：`paileactivist.github.io`、`docs.qq.com`、`doc.weixin.qq.com` 均不被该快照拦截；腾讯文档按国内规则直连，测试站进入 GitHub 组。这个结论仅覆盖随包规则与配置，不能替代手机上已更新规则、实际 DNS 响应、入站和 TLS 日志。

用户报告 Via 在关闭自身广告拦截后仍报 `ERR_CONNECTION_CLOSED`，同网址 Firefox 可以打开；微信访问 `docs.qq.com` 时 Direct 模式仍失败，加入应用黑名单后恢复。Direct 通常仍让业务连接经过 sing-box 转发，应用黑名单是在入站绕过，两者不同。用户随后取消微信绕过并切换到 TUN，Via 与微信内腾讯文档均恢复；再对 TC 诊断包反馈“好像可以了”，准备继续测试。这些对照更支持当前设备的 cgroup 接管路径存在兼容性问题，但不能确认是具体哪项内核、IPv6 或核心缺陷。后续继续验证 TC 下的原链接、Wi-Fi/流量切换、重启恢复、DNS 过滤，以及微信发送图片、文件和语音等常用功能；出现问题时记录网络、时刻和核心日志。当前不添加未经证实的域名白名单或修改整体 DNS 隐私策略。

回退时先恢复旧 NetProxy 配置；两个 AGH 客户端可以保留，也可删除。工具没有改变 AGH 全局上游和规则。始终保留你自己的修改前备份。

## 参考

- [NetProxy 模块配置](https://netproxy.store/config/module) 与 [策略分组](https://netproxy.store/config/policy-groups)
- [sing-box URLTest](https://sing-box.sagernet.org/configuration/outbound/urltest/)
- [DustinWin Android 配置](https://proxy-tutorials.dustinwin.cc.cd/posts/share-android-singboxr-ruleset/) 与 [Windows 配置](https://proxy-tutorials.dustinwin.cc.cd/posts/share-windows-singboxr-ruleset/)
- [Surfing Mihomo 配置](https://github.com/GitMetaio/Surfing/blob/main/box_bll/clash/config.yaml)
- [锁定版本的统一延迟实现](https://github.com/reF1nd/sing-box/blob/v1.15.0-alpha.11-reF1nd/common/urltest/urltest.go)

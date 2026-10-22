import assert from 'node:assert/strict'
import { readFileSync, existsSync } from 'node:fs'
import { resolve } from 'node:path'
import test from 'node:test'
import { createHash } from 'node:crypto'

const root = resolve(import.meta.dirname, '..')
const read = path => JSON.parse(readFileSync(resolve(root, path), 'utf8'))
const config = read('src/module/config/singbox/config.json')
const inbound = read('src/module/config/inbound/inbound.json')
const profiles = read('examples/adguardhome/clients.json')
const asArray = value => value === undefined ? [] : Array.isArray(value) ? value : [value]

test('所有策略引用闭合，新增规则具有离线缓存', () => {
  const outputs = new Set(['Proxy', 'direct', 'block'])
  for (const o of config.outbounds) {
    assert(!outputs.has(o.tag), `重复出站 ${o.tag}`)
    outputs.add(o.tag)
  }
  for (const o of config.outbounds) for (const tag of o.outbounds ?? []) assert(outputs.has(tag), tag)
  const dns = new Set(config.dns.servers.map(s => s.tag))
  const ruleSets = new Set()
  for (const set of config.route.rule_set) for (const tag of asArray(set.tag)) {
    assert(!ruleSets.has(tag), tag)
    ruleSets.add(tag)
    const path = resolve(root, 'src/module/config/singbox', set.path.replace('{tag}', tag))
    assert(existsSync(path), path)
    if (set.format === 'binary') assert.equal(readFileSync(path).subarray(0, 3).toString(), 'SRS')
  }
  for (const rule of [...config.route.rules, ...config.dns.rules]) {
    for (const tag of asArray(rule.rule_set)) assert(ruleSets.has(tag), tag)
    if (rule.server) assert(dns.has(rule.server), rule.server)
    if (rule.outbound) assert(outputs.has(rule.outbound), rule.outbound)
  }
  assert(dns.has(config.dns.final))
  assert(dns.has(config.route.default_domain_resolver))
})

test('两个 AGH 解析路径使用独立来源与缓存，均继承完整过滤', () => {
  for (const [tag, id] of [['dns-proxy', '127.0.0.2'], ['dns-direct', '127.0.0.3']]) {
    const dns = config.dns.servers.find(s => s.tag === tag)
    assert.equal(dns.server, '127.0.0.1')
    assert.equal(dns.server_port, 5591)
    const link = config.outbounds.find(o => o.tag === dns.detour)
    assert.equal(link.type, 'direct')
    assert.equal(link.inet4_bind_address, id)
    const profile = profiles.find(p => p.ids.includes(id))
    assert(profile.use_global_settings && profile.upstreams_cache_enabled)
  }
  assert(config.dns.disable_cache)
})

test('国外上游连接固定经过代理，国内上游不被全局代理规则提前吞掉', () => {
  for (const [profile, expected] of [[profiles[0], '总模式'], [profiles[1], 'direct']]) {
    for (const url of profile.upstreams) {
      const ip = new URL(url).hostname
      const idx = config.route.rules.findIndex(r => asArray(r.ip_cidr).includes(`${ip}/32`) && r.port === 443)
      assert(idx >= 0, ip)
      assert.equal(config.route.rules[idx].outbound, expected)
      assert(idx < config.route.rules.findIndex(r => r.clash_mode === 'Proxy'))
    }
  }
  assert.equal(config.dns.final, 'dns-proxy')
  assert(!config.dns.servers.find(s => s.tag === 'dns-proxy').servers)
})

test('eBPF DNS 全局接管与业务筛选分离，没有国内 IP 提前绕过', () => {
  assert.equal(inbound.backend, 'ebpf')
  assert.equal(inbound.root_policy, 'include')
  assert.equal(inbound.ebpf.local.data_plane, 'cgroup')
  assert.equal(inbound.ebpf.local.dns_mode, 'hijack')
  assert.deepEqual(inbound.ebpf.local.bypass_rule_set, [])
  assert.deepEqual(inbound.ebpf.shared.bypass_rule_set, [])
  assert.equal(config.route.rules[0].clash_mode, 'Direct')
})

test('广告和放行交给 AGH，仅拒绝 WebRTC/STUN 相关流量', () => {
  assert(!config.dns.rules.some(r => r.action === 'reject'))
  const rejects = config.route.rules.filter(r => r.action === 'reject')
  assert.equal(rejects.length, 1)
  assert.deepEqual(rejects[0].rules, [
    { protocol: 'stun' }, { rule_set: 'geosite-category-stun' },
    { port: [3478, 5349] }, { port_range: ['19302:19309'] },
  ])
  assert(config.route.rules.indexOf(rejects[0]) < config.route.rules.findIndex(r => r.clash_mode === 'Proxy'))
  const sniff = config.route.rules.find(r => r.action === 'sniff')
  assert(sniff.sniffer.includes('stun'))
  assert.equal(sniff.timeout, '300ms')
  const text = JSON.stringify(config)
  for (const removed of ['Ads_AWAvenue', 'category-ads-all', 'RuleAllowAds', '"block"']) assert(!text.includes(removed), removed)
  assert(config.experimental.urltest_unified_delay)
})

test('11 个业务组按参考显示，国内域名和 IP 先于业务，FCM/YouTube 先于 Google', () => {
  const names = ['Steam', 'Apple', 'Microsoft', 'Telegram', 'TikTok', 'YouTube', 'Google', 'GoogleFCM', 'OpenAI', 'GitHub', 'Twitter(X)']
  const domestic = config.route.rules.findIndex(r => asArray(r.rule_set).includes('geosite-steam@cn'))
  const cnip = config.route.rules.findIndex(r => r.rule_set === 'geoip-cn')
  assert.deepEqual(config.outbounds.filter(o => names.includes(o.tag)).map(o => o.tag), names)
  for (const name of names) {
    const group = config.outbounds.find(o => o.tag === name)
    assert.equal(group.default, '总模式')
    assert(group.outbounds.includes('All Proxies'))
    assert(group.outbounds.includes('direct'))
    assert(config.route.rules.findIndex(r => r.outbound === name) > domestic)
    assert(config.route.rules.findIndex(r => r.outbound === name) > cnip)
  }
  const idx = name => config.route.rules.findIndex(r => r.outbound === name)
  assert(idx('GoogleFCM') < idx('Google') && idx('YouTube') < idx('Google'))
  assert.equal(config.route.final, '漏网之鱼')
  assert.equal(config.outbounds.find(o => o.tag === '漏网之鱼').default, '总模式')
})

test('地区没有匹配节点时明确回到 Proxy，选择器无环且不重复生成测速', () => {
  const regions = ['香港', '台湾', '日本', '美国', '新加坡', '其他地区']
  for (const name of [...regions, 'All Proxies']) {
    const group = config.outbounds.find(o => o.tag === name)
    assert.deepEqual(group.outbounds, ['Proxy'])
    assert.equal(group.default, 'Proxy')
    assert(group.use_all_providers)
  }
  assert(!config.outbounds.some(o => o.type === 'urltest'))
  const visit = (tag, ancestors = []) => {
    assert(!ancestors.includes(tag), [...ancestors, tag].join(' -> '))
    for (const child of config.outbounds.find(o => o.tag === tag)?.outbounds ?? []) visit(child, [...ancestors, tag])
  }
  for (const group of config.outbounds) visit(group.tag)
  assert(!config.outbounds.find(o => o.tag === '总模式').outbounds.includes('direct'))
})

test('路由解析使用 DNS 分流并保留结果，不经 bootstrap 二次解析；没有 FakeIP', () => {
  const resolves = config.route.rules.filter(r => r.action === 'resolve')
  assert.deepEqual(resolves, [{ action: 'resolve' }])
  const resolveIndex = config.route.rules.indexOf(resolves[0])
  assert(resolveIndex < config.route.rules.findIndex(r => r.clash_mode === 'Proxy'))
  assert(config.dns.rules.findIndex(r => asArray(r.rule_set).includes('geosite-cn')) < config.dns.rules.findIndex(r => asArray(r.rule_set).includes('geosite-google')))
  assert(!JSON.stringify(config).includes('fakeip'))
})

test('全部启用规则来自 SagerNet，离线快照纳入既有资源更新清单并校验 SHA-256', () => {
  const resources = read('.github/resources.json').raw
  const live = new Set()
  for (const set of config.route.rule_set.filter(s => s.type === 'remote')) {
    assert(set.url.startsWith('https://raw.githubusercontent.com/SagerNet/'))
    for (const tag of asArray(set.tag)) {
      const path = 'src/module/config/singbox/' + set.path.replace('./', '').replace('{tag}', tag)
      const source = resources.find(r => r.path === path)
      assert(source, tag)
      assert.equal(source.url, set.url.replace('{tag}', tag))
      assert.equal(createHash('sha256').update(readFileSync(resolve(root, path))).digest('hex'), source.currentSha256)
      assert.match(source.currentCommit, /^[0-9a-f]{40}$/)
      live.add(tag)
    }
  }
  assert.equal(live.size, 19)
  assert.equal(resources.length, live.size)
})

import assert from 'node:assert/strict'
import { readFileSync, existsSync } from 'node:fs'
import { resolve } from 'node:path'
import test from 'node:test'

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
  for (const [profile, expected] of [[profiles[0], 'Proxy'], [profiles[1], 'direct']]) {
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

test('默认配置将广告和放行交给 AGH，不引用自动广告或本地拒绝规则', () => {
  for (const rule of [...config.dns.rules, ...config.route.rules]) assert.notEqual(rule.action, 'reject')
  const text = JSON.stringify(config)
  for (const removed of ['Ads_AWAvenue', 'category-ads-all', 'RuleAllowAds', '"block"']) assert(!text.includes(removed), removed)
  assert(config.experimental.urltest_unified_delay)
})

test('七个业务策略保持独立选择，国内服务例外先于业务与兜底', () => {
  const domestic = config.route.rules.findIndex(r => asArray(r.rule_set).includes('geosite/steam@cn'))
  for (const name of ['OpenAI', 'Steam', 'YouTube', 'Telegram', 'GitHub', 'Microsoft', 'Google']) {
    const group = config.outbounds.find(o => o.tag === name)
    assert.equal(group.default, 'Proxy')
    assert(group.outbounds.includes('All Proxies'))
    assert(group.outbounds.includes('direct'))
    assert(config.route.rules.findIndex(r => r.outbound === name) > domestic)
  }
})

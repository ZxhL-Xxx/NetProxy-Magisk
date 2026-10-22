import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { existsSync, readFileSync } from 'node:fs'
import { test } from 'node:test'

const root = new URL('../', import.meta.url)
const readJSON = path => JSON.parse(readFileSync(new URL(path, root), 'utf8'))
const config = readJSON('src/module/config/singbox/config.json')
const managed = readJSON('src/module/config/inbound/inbound.json')
const upstream = readJSON('tests/fixtures/singbox-upstream.json')
const resources = readJSON('.github/resources.json').raw
const list = value => value === undefined ? [] : Array.isArray(value) ? value : [value]

test('模块设置只有 module.json 默认文件，字段使用 JSON 原生类型', () => {
  assert.equal(existsSync(new URL('src/module/config/module.conf', root)), false)
  assert.deepEqual(readJSON('src/module/config/module.json'), {
    auto_start: false,
    selection: { group_id: 'default', node_tag: '' },
    wifi: { enabled: false, mode: 'blacklist', blacklist: [], whitelist: [], proxy_on_non_wifi: true },
  })
})

test('AGH 配套配置保留部署地址和运行时出站边界', () => {
  assert.equal(config.log.output, 'stderr')
  assert.equal(config.experimental.cache_file.path, '/data/adb/modules/netproxy/config/singbox/cache.db')
  assert.equal(config.experimental.clash_api.external_controller, '127.0.0.1:9999')
  assert.equal(config.experimental.clash_api.secret, upstream.experimental.clash_api.secret)
  assert.equal(config.services[0].listen, '127.0.0.1')
  assert.equal(config.services[0].listen_port, 9090)
  assert.equal(config.services[0].dashboard.path, '/data/adb/modules/netproxy/webroot/sing-box-dashboard')
  assert.equal(config.providers, undefined)
  assert(!config.outbounds.some(o => ['Proxy', 'direct', 'block'].includes(o.tag)))
  assert(config.outbounds.filter(o => o.tag.startsWith('agh-')).every(o => o.type === 'direct'))
})

test('默认规则显式提供 Rule，保存其他默认模式后仍可切回', () => {
  const rule = config.route.rules.at(-1)
  assert.deepEqual(rule, { clash_mode: 'Rule', action: 'route', outbound: config.route.final })
  assert.equal(config.experimental.clash_api.default_mode, 'Rule')
  const modes = rules => rules.flatMap(rule => [...list(rule.clash_mode), ...modes(rule.rules ?? [])])
  assert.deepEqual([...new Set([...modes(config.route.rules), ...modes(config.dns.rules)])].sort(),
    ['Direct', 'Proxy', 'Rule'])
})

test('默认远程规则有对应的内置文件与更新来源', () => {
  for (const rule of config.route.rule_set.filter(rule => rule.type === 'remote')) {
    for (const tag of list(rule.tag)) {
      const path = `src/module/config/singbox/${rule.path.replace(/^\.\//, '').replaceAll('{tag}', tag)}`
      const resource = resources.find(resource => resource.path === path)
      assert.ok(resource, `${tag} 未登记资源更新来源`)
      assert.equal(decodeURI(resource.url), decodeURI(rule.url.replaceAll('{tag}', tag)))
      const content = readFileSync(new URL(path, root))
      assert.ok(content.length > 0, `${tag} 内置规则为空`)
      assert.equal(createHash('sha256').update(content).digest('hex'), resource.currentSha256, tag)
      if (rule.format === 'binary') {
        assert.equal(content.subarray(0, 3).toString(), 'SRS', tag)
      }
    }
  }
})

test('AGH 配套 eBPF 不在内核提前绕过中国 IP', () => {
  const localBypass = managed.ebpf.local.bypass_rule_set
  const sharedBypass = managed.ebpf.shared.bypass_rule_set
  assert.deepEqual(localBypass, [])
  assert.deepEqual(sharedBypass, [])
  assert.equal(Object.hasOwn(managed.ebpf, 'bypass_rule_set'), false)
  const tags = config.route.rule_set.flatMap(rule => list(rule.tag))
  for (const tag of [...localBypass, ...sharedBypass]) assert.ok(tags.includes(tag), `${tag} 未在静态配置声明`)
})

test('单一入站默认保留 eBPF 原生语义和禁用共享路径偏好', () => {
  assert.deepEqual(Object.keys(managed), ['backend', 'root_policy', 'app', 'ebpf', 'tun'])
  assert.equal(managed.root_policy, 'include')
  assert.equal(managed.backend, 'ebpf')
  assert.deepEqual(managed.app, { enabled: false, mode: 'blacklist', proxy_apps: [], bypass_apps: [] })
  assert.deepEqual(managed.ebpf, {
    type: 'ebpf', tag: 'netproxy-in', network: ['tcp', 'udp'], udp_timeout: '5m', tc_priority: 1,
    local: {
      enabled: true, data_plane: 'tc', dns_mode: 'hijack', ipv6: true,
      bypass_private_address: true, bypass_rule_set: [],
    },
    shared: {
      enabled: false, data_plane: 'socket_assign', dns_mode: 'hijack',
      interface: ['ap0', 'ap1', 'wlan0', 'wlan1', 'wlan2', 'swlan0', 'softap0', 'rndis0', 'ncm0', 'usb0', 'bt-pan'],
      ipv6: true, bypass_private_address: true, bypass_rule_set: [],
    },
  })
})

test('TUN 默认只固定必需接管参数，不覆盖上游可选默认', () => {
  assert.deepEqual(managed.tun, {
    type: 'tun', tag: 'netproxy-in', interface_name: 'netproxy',
    address: ['172.19.0.1/30', 'fdfe:dcba:9876::1/126'],
    auto_route: true, auto_redirect: true, dns_mode: 'hijack',
  })
  assert.equal(config.route.auto_detect_interface, true)
  assert.ok(config.inbounds.every(inbound => !['ebpf', 'tun'].includes(inbound.type) && inbound.tag !== 'netproxy-in'))
})

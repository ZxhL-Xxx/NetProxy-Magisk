import assert from 'node:assert/strict'
import { readFileSync, writeFileSync, mkdirSync, mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import { spawnSync } from 'node:child_process'
import test from 'node:test'

const root = resolve(import.meta.dirname, '..')
const bash = process.env.TEST_BASH || (process.platform === 'win32' ? undefined : 'bash')

test('配套包开机先等待 AGH，再进入唯一 Go boot；普通包保持原路径', { skip: !bash }, () => {
  const work = mkdtempSync(join(tmpdir(), 'agh-boot-'))
  const posix = path => path.replaceAll('\\', '/').replace(/^([A-Za-z]):/, (_, drive) => `/${drive.toLowerCase()}`)
  try {
    const module = join(work, 'module')
    const mock = join(work, 'mock')
    mkdirSync(join(module, 'bin'), { recursive: true })
    mkdirSync(join(module, 'compat', 'agh'), { recursive: true })
    mkdirSync(mock)
    const log = join(work, 'calls')
    const udp = join(work, 'udp')
    const script = readFileSync(join(root, 'src/module/service.sh'), 'utf8').replaceAll('/proc/net/udp', posix(udp))
    writeFileSync(join(module, 'service.sh'), script)
    const writeExecutable = (path, text) => writeFileSync(path, `#!/bin/sh\n${text}\n`, { mode: 0o755 })
    writeExecutable(join(mock, 'resetprop'), `echo boot-complete >> '${posix(log)}'`)
    writeExecutable(join(mock, 'sleep'), `echo waiting >> '${posix(log)}'; printf 'header\\n0 0100007F:15D7\\n' > '${posix(udp)}'`)
    writeExecutable(join(mock, 'su'), 'sh -c "$2"')
    writeExecutable(join(module, 'bin', 'netproxyctl'), `echo "$1 $2" >> '${posix(log)}'`)
    const run = () => {
      const result = spawnSync(bash, ['-c', `export PATH='${posix(mock)}':"$PATH"; sh '${posix(join(module, 'service.sh'))}'`],
        { encoding: 'utf8', timeout: 12000 })
      assert.equal(result.status, 0, result.stderr)
    }
    writeFileSync(udp, 'header\n')
    run()
    assert.deepEqual(readFileSync(log, 'utf8').trim().split('\n'), ['boot-complete', 'waiting', '__internal boot'])
    rmSync(join(module, 'compat'), { recursive: true })
    writeFileSync(log, '')
    run()
    assert.equal(readFileSync(log, 'utf8').trim(), '__internal boot')
  } finally {
    rmSync(work, { recursive: true, force: true })
  }
})

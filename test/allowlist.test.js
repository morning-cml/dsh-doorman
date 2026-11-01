// The allowlist store: exact matching, dependency binding, blocked entries, shadow mode, atomic writes and hot reload.
import { after, test } from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { createAllowlist, parseAllowlist } from '../lib/store/allowlist.js'
import { identityKey } from '../lib/store/fingerprint.js'
import { WS, host } from './helpers.js'

const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'doorman-allowlist-test-'))
after(() => fs.rmSync(tmp, { recursive: true, force: true }))
let counter = 0
const freshFile = () => path.join(tmp, `case-${counter += 1}`, 'allowlist.json')

const H = c => c.repeat(64)
const pathKey = p => host.tools.key(p)

/** A fingerprint as fingerprintOf would return it. */
function print(command, { tool = 'pwsh', workspace = WS, workdir = WS, dependsOn = [{ path: `${WS}\\package.json`, sha256: H('a') }], eligible = true } = {}) {
  const trimmed = command.trim()
  return { key: identityKey(tool, pathKey(workspace), pathKey(workdir), trimmed), tool, workspace, workdir, command: trimmed, eligible, reasons: eligible ? [] : ['x'], dependsOn, outsideWrites: [] }
}

test('an exact entry whose files are unchanged is a hit; anything else is not', () => {
  const list = createAllowlist({ file: freshFile(), pathKey })
  const added = list.add(print('npm install'), { explanation: '按 package.json 安装依赖', model: 'qwen3.7-plus' })
  assert.match(added.id, /^[a-z0-9]{6}$/)
  assert.equal(added.status, 'active')
  assert.equal(list.lookup(print('npm install')).status, 'hit')
  assert.equal(list.lookup(print('  npm install\n')).status, 'hit')
  // The same directory spelled differently is the same place.
  assert.equal(list.lookup(print('npm install', { workdir: 'c:\\USERS\\alice\\proj\\', workspace: 'C:/Users/alice/proj' })).status, 'hit')
  for (const other of [print('npm  install'), print('npm install *'), print('NPM install'), print('npm i'), print('npm install', { tool: 'bash' }), print('npm install', { workdir: `${WS}\\build` }), print('npm install', { workspace: 'C:\\Users\\alice' })]) {
    assert.equal(list.lookup(other).status, 'miss', `${other.tool} ${other.command} @ ${other.workdir}`)
  }
  assert.equal(list.lookup(null).status, 'miss')
  assert.equal(list.lookup({ ...print('npm install'), key: null }).status, 'miss')
})

test('a changed, appeared or vanished dependency makes the entry stale', () => {
  const list = createAllowlist({ file: freshFile(), pathKey })
  const deps = [{ path: `${WS}\\package.json`, sha256: H('a') }, { path: `${WS}\\.npmrc`, sha256: null }]
  list.add(print('npm install', { dependsOn: deps }))
  // Same files in another order, or the path spelled differently: still the same.
  assert.equal(list.lookup(print('npm install', { dependsOn: [deps[1], { path: `${WS.toUpperCase()}\\PACKAGE.JSON`, sha256: H('a') }] })).status, 'hit')
  for (const changed of [
    [{ ...deps[0], sha256: H('b') }, deps[1]],
    [deps[0], { ...deps[1], sha256: H('c') }],
    [deps[0]],
    [...deps, { path: `${WS}\\binding.gyp`, sha256: H('d') }],
  ]) {
    assert.equal(list.lookup(print('npm install', { dependsOn: changed })).status, 'stale')
  }
})

test('a command that may not be listed never hits, even with a matching active entry', () => {
  const list = createAllowlist({ file: freshFile(), pathKey })
  list.add(print('npm install'))
  assert.equal(list.lookup(print('npm install', { eligible: false })).status, 'ineligible')
  assert.equal(list.add(print('npm test', { eligible: false })), null)
  assert.equal(list.lookup(print('npm test')).status, 'miss')
})

test('a blocked entry always asks, even after its files change, and is never turned back on by add', () => {
  const list = createAllowlist({ file: freshFile(), pathKey })
  list.add(print('npm install'))
  const blocked = list.block(print('npm install'), ['exit-code:1'])
  assert.equal(blocked.status, 'blocked')
  assert.deepEqual(blocked.blockedBecause, ['exit-code:1'])
  assert.equal(list.lookup(print('npm install')).status, 'blocked')
  assert.equal(list.lookup(print('npm install', { dependsOn: [] })).status, 'blocked')
  assert.equal(list.lookup(print('npm install', { eligible: false })).status, 'blocked')
  assert.equal(list.add(print('npm install')), null)
  assert.equal(list.lookup(print('npm install')).status, 'blocked')
  assert.equal(list.touch(print('npm install')), null)
})

test('hits are counted', () => {
  const list = createAllowlist({ file: freshFile(), pathKey, now: () => new Date('2026-11-01T08:00:00Z') })
  list.add(print('npm run build'))
  list.touch(print('npm run build'))
  const touched = list.touch(print('npm run build'))
  assert.equal(touched.hits, 2)
  assert.equal(touched.lastUsedAt, '2026-11-01T08:00:00.000Z')
})

test('shadow mode keeps everything in memory and never writes the file', () => {
  const file = freshFile()
  const list = createAllowlist({ file, pathKey, shadow: true })
  list.add(print('npm install'))
  list.touch(print('npm install'))
  list.block(print('npm test'), ['not-allowed:rejected'])
  assert.equal(fs.existsSync(file), false)
  assert.equal(fs.existsSync(path.dirname(file)), false)
  assert.deepEqual(list.stats(), { file, shadow: true, onDisk: 0, inMemory: 2 })
})

test('writes are atomic and leave a valid file; outside edits are picked up', () => {
  const file = freshFile()
  const list = createAllowlist({ file, pathKey, shadow: false })
  const entry = list.add(print('npm install', { dependsOn: [{ path: `${WS}\\package.json`, sha256: H('a') }, { path: `${WS}\\.npmrc`, sha256: null }] }), { explanation: '安装依赖', model: 'qwen3.7-plus' })
  const saved = JSON.parse(fs.readFileSync(file, 'utf8'))
  assert.equal(saved.version, 1)
  assert.deepEqual(saved.entries, [entry])
  assert.deepEqual(parseAllowlist(fs.readFileSync(file, 'utf8')), [entry])
  assert.deepEqual(fs.readdirSync(path.dirname(file)), ['allowlist.json'])
  // A second process (or the user) blocks the entry: the next lookup sees it without a restart.
  fs.writeFileSync(file, JSON.stringify({ version: 1, entries: [{ ...entry, status: 'blocked' }] }))
  assert.equal(list.lookup(print('npm install', { dependsOn: entry.dependsOn })).status, 'blocked')
  fs.writeFileSync(file, JSON.stringify({ version: 1, entries: [] }))
  assert.equal(list.lookup(print('npm install', { dependsOn: entry.dependsOn })).status, 'miss')
  // Reopening the file reads what was written.
  list.add(print('npm test'))
  const reopened = createAllowlist({ file, pathKey, shadow: false })
  assert.equal(reopened.lookup(print('npm test')).status, 'hit')
})

test('a file that cannot be read or is malformed fails safe: every lookup says error (ask)', () => {
  for (const text of ['not json', '[]', JSON.stringify({ version: 2, entries: [] }), JSON.stringify({ version: 1, entries: [{ id: 'x', status: 'active' }] }), JSON.stringify({ version: 1, entries: [{ id: 'abc123', status: 'maybe', tool: 'pwsh', workspace: WS, workdir: WS, command: 'npm install', dependsOn: [] }] })]) {
    const file = freshFile()
    fs.mkdirSync(path.dirname(file), { recursive: true })
    fs.writeFileSync(file, text)
    const list = createAllowlist({ file, pathKey, shadow: true })
    assert.equal(list.lookup(print('npm install')).status, 'error', text)
    assert.ok(list.stats().error)
  }
  // Writing over a malformed file is refused rather than silently dropping its entries.
  const file = freshFile()
  fs.mkdirSync(path.dirname(file), { recursive: true })
  fs.writeFileSync(file, 'garbage')
  assert.throws(() => createAllowlist({ file, pathKey, shadow: false }).add(print('npm install')))
  assert.equal(fs.readFileSync(file, 'utf8'), 'garbage')
  // A directory where the file should be is unreadable too.
  const dir = freshFile()
  fs.mkdirSync(dir, { recursive: true })
  assert.equal(createAllowlist({ file: dir, pathKey }).lookup(print('npm install')).status, 'error')
})

test('beyond the cap the least recently used active entries go; blocked ones stay', () => {
  let t = 0
  const list = createAllowlist({ file: freshFile(), pathKey, shadow: false, maxEntries: 3, now: () => new Date(Date.UTC(2026, 10, 1, 0, 0, t += 1)) })
  list.block(print('rm-me'), ['exit-code:1'])
  list.add(print('a'))
  list.add(print('b'))
  list.touch(print('a'))
  list.add(print('c'))
  assert.equal(list.lookup(print('b')).status, 'miss')
  assert.equal(list.lookup(print('a')).status, 'hit')
  assert.equal(list.lookup(print('c')).status, 'hit')
  assert.equal(list.lookup(print('rm-me')).status, 'blocked')
})

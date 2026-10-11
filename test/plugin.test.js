// The plugin entry on a fake dsh: listener order, files it creates, and failure behaviour.
import { after, test } from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { createConfigStore, normalizeConfig } from '../lib/config.js'
import { createLog } from '../lib/log.js'
import { recordVersion } from '../lib/state.js'

const home = fs.mkdtempSync(path.join(os.tmpdir(), 'doorman-plugin-test-'))
const workspace = path.join(home, 'ws')
fs.mkdirSync(workspace)
process.env.DSH_HOME = path.join(home, '.dsh')
const { apply } = await import('../index.js')
after(() => fs.rmSync(home, { recursive: true, force: true }))

/** Minimal stand-in for the Cordis event bus (same ordering rules as cordis). */
function fakeContext(services) {
  const hooks = {}
  return {
    hooks,
    get: name => services[name],
    on(name, listener, options) {
      const list = hooks[name] ??= []
      if ((typeof options === 'object' ? options?.prepend : options) === true) list.unshift(listener)
      else list.push(listener)
      return () => {}
    },
    waterfall(name, ...args) {
      const cbs = [...(hooks[name] ?? [])]
      const inner = args.pop()
      const next = () => (cbs.shift() ?? inner)(...args, next)
      return next()
    },
    emit(name, ...args) {
      for (const cb of hooks[name] ?? []) cb(...args)
    },
  }
}

const readLog = () => {
  const dir = path.join(home, '.dsh', 'dsh-doorman', 'logs')
  return fs.readdirSync(dir).flatMap(f => fs.readFileSync(path.join(dir, f), 'utf8').trim().split('\n')).filter(Boolean).map(l => JSON.parse(l))
}

test('the plugin sits before the approval prompt and records a full round trip', async () => {
  const ctx = fakeContext({ sandboxPolicy: { resolve: () => ({ mode: 'workspace-write', workspaceRoot: workspace }) } })
  apply(ctx)
  // The UI answerer registers later, without prepend (as dsh's remote bridge does).
  ctx.on('approval/request', async () => 'allowed-once')
  assert.equal(ctx.hooks['approval/request'].length, 2)

  const agent = { id: 'a', session: { header: { id: 'sess', cwd: workspace } } }
  const args = Object.freeze({ command: 'npm install', sandbox_permissions: 'danger-full-access', justification: 'cache' })
  await ctx.waterfall('tools/pre-execute', { callId: 'k1', name: 'pwsh', arguments: args, agent }, async () => ({ kind: 'allow' }))
  const outcome = await ctx.waterfall('approval/request', { agent, toolName: 'pwsh', callId: 'k1', reason: 'escalate sandbox to danger-full-access: cache' }, async () => 'unavailable')
  assert.equal(outcome, 'allowed-once')
  ctx.emit('tools/result', { callId: 'k1', name: 'pwsh' }, { isError: false, content: [], value: { kind: 'foreground', exitCode: 0, timedOut: false, aborted: false, signal: null, stdout: { text: 'ok' }, stderr: { text: '' } } })

  const lines = readLog()
  const events = lines.map(l => l.event)
  assert.ok(events.includes('startup'))
  const request = lines.find(l => l.event === 'request')
  assert.equal(request.command, 'npm install')
  assert.equal(request.layer, 'model-unavailable')
  assert.equal(lines.find(l => l.event === 'outcome').outcome, 'allowed-once')
  assert.equal(lines.find(l => l.event === 'result').exitCode, 0)

  const config = JSON.parse(fs.readFileSync(path.join(home, '.dsh', 'dsh-doorman', 'config.json'), 'utf8'))
  assert.equal(config.mode, 'observe')
  assert.equal(config.model.keyName, 'DSH_DOORMAN_API_KEY')
  assert.equal(JSON.stringify(config).includes('sk-'), false)
})

test('without dsh services the plugin forwards everything unchanged', async () => {
  const ctx = fakeContext({})
  assert.doesNotThrow(() => apply(ctx))
  ctx.on('approval/request', async () => 'rejected')
  const agent = { id: 'a', session: { header: { id: 's' } } }
  const outcome = await ctx.waterfall('approval/request', { agent, toolName: 'write', callId: 'w', reason: 'escalate sandbox to danger-full-access: x' }, async () => 'unavailable')
  assert.equal(outcome, 'rejected')
})

test('a context whose event registration throws does not break loading', () => {
  const ctx = { get: () => undefined, on: () => { throw new Error('no events here') } }
  assert.doesNotThrow(() => apply(ctx))
})

test('config: invalid values fall back to safe defaults', () => {
  const { config, problems } = normalizeConfig({ mode: 'yolo', model: { baseUrl: 'http://insecure', timeoutMs: 5, maxCallsPerHour: -1, keyName: 'bad name' } })
  assert.equal(config.mode, 'observe')
  assert.equal(config.model.baseUrl, 'https://dashscope.aliyuncs.com/compatible-mode/v1')
  assert.equal(config.model.timeoutMs, 20000)
  assert.equal(config.model.maxCallsPerHour, 100)
  assert.equal(config.model.keyName, 'DSH_DOORMAN_API_KEY')
  assert.equal(problems.length, 5)
})

test('config: a broken file means observe mode, and edits are picked up', () => {
  const dir = fs.mkdtempSync(path.join(home, 'cfg-'))
  const file = path.join(dir, 'config.json')
  const events = []
  const store = createConfigStore(file, (event, data) => events.push({ event, ...data }))
  assert.equal(store.get().mode, 'observe')
  fs.writeFileSync(file, '{ "mode": "off", ')
  assert.equal(store.get().mode, 'observe')
  assert.ok(events.some(e => e.event === 'config-error'))
  fs.writeFileSync(file, '﻿{ "mode": "off" }')
  const stamp = new Date(Date.now() + 5000)
  fs.utimesSync(file, stamp, stamp)
  assert.equal(store.get().mode, 'off')
})

test('state: a dsh version change is reported once', () => {
  const file = path.join(home, 'state-test.json')
  assert.deepEqual(recordVersion(file, '0.2.0-rc.2'), { previous: null, current: '0.2.0-rc.2', changed: false })
  assert.equal(recordVersion(file, '0.2.0-rc.2').changed, false)
  const update = recordVersion(file, '0.2.1-alpha.2')
  assert.equal(update.changed, true)
  assert.equal(update.previous, '0.2.0-rc.2')
  assert.equal(recordVersion(file, '0.2.1-alpha.2').changed, false)
  assert.equal(recordVersion(file, null).changed, false)
})

test('log: monthly files continue in a new part when full', () => {
  const dir = path.join(home, 'log-test')
  const log = createLog({ dir, now: () => new Date(2026, 9, 11), maxFileBytes: () => 300 })
  for (let i = 0; i < 10; i += 1) log.write('x', { i, pad: 'p'.repeat(60) })
  const files = fs.readdirSync(dir).sort()
  assert.ok(files.length >= 2)
  assert.ok(files.every(f => /^decisions-2026-10(-\d+)?\.jsonl$/.test(f)))
  const total = files.flatMap(f => fs.readFileSync(path.join(dir, f), 'utf8').trim().split('\n'))
  assert.equal(total.length, 10)
})

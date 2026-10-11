// The plugin entry on a fake dsh: listener order, files it creates, settings, and failure behaviour.
import { after, test } from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { createLog } from '../lib/log.js'
import { buildConfigSchema, readSettings } from '../lib/settings.js'
import { readState, recordVersion } from '../lib/state.js'

const home = fs.mkdtempSync(path.join(os.tmpdir(), 'doorman-plugin-test-'))
const workspace = path.join(home, 'ws')
fs.mkdirSync(workspace)
process.env.DSH_HOME = path.join(home, '.dsh')
const { apply, Config } = await import('../index.js')
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

const dataDir = path.join(home, '.dsh', 'dsh-doorman')
const readLog = () => {
  const dir = path.join(dataDir, 'logs')
  return fs.readdirSync(dir).flatMap(f => fs.readFileSync(path.join(dir, f), 'utf8').trim().split('\n')).filter(Boolean).map(l => JSON.parse(l))
}
const settle = () => new Promise(resolve => setTimeout(resolve, 10))

test('the plugin sits before the approval prompt and records a full round trip', async () => {
  const ctx = fakeContext({ sandboxPolicy: { resolve: () => ({ mode: 'workspace-write', workspaceRoot: workspace }) } })
  apply(ctx, {})
  // The UI answerer registers later, without prepend (as dsh's remote bridge does).
  ctx.on('approval/request', async () => 'allowed-once')
  assert.equal(ctx.hooks['approval/request'].length, 2)

  const agent = { id: 'a', session: { header: { id: 'sess', cwd: workspace } } }
  const args = Object.freeze({ command: 'npm install', sandbox_permissions: 'danger-full-access', justification: 'cache' })
  await ctx.waterfall('tools/pre-execute', { callId: 'k1', name: 'pwsh', arguments: args, agent }, async () => ({ kind: 'allow' }))
  const outcome = await ctx.waterfall('approval/request', { agent, toolName: 'pwsh', callId: 'k1', reason: 'escalate sandbox to danger-full-access: cache' }, async () => 'unavailable')
  assert.equal(outcome, 'allowed-once')
  ctx.emit('tools/result', { callId: 'k1', name: 'pwsh' }, { isError: false, content: [], value: { kind: 'foreground', exitCode: 0, timedOut: false, aborted: false, signal: null, stdout: { text: 'ok' }, stderr: { text: '' } } })
  await settle()

  const lines = readLog()
  assert.ok(lines.some(l => l.event === 'startup'))
  const request = lines.find(l => l.event === 'request')
  assert.equal(request.command, 'npm install')
  assert.equal(request.layer, 'model')
  assert.equal(lines.find(l => l.event === 'outcome').outcome, 'allowed-once')
  assert.equal(lines.find(l => l.event === 'result').exitCode, 0)
  // No credentials service in this fake dsh: the review reports a missing key and asks.
  const model = lines.find(l => l.event === 'model')
  assert.equal(model.status, 'no-key')
  assert.equal(model.proposed, 'ask')
  assert.equal(fs.existsSync(path.join(dataDir, 'config.json')), false)
})

test('without dsh services the plugin forwards everything unchanged', async () => {
  const ctx = fakeContext({})
  assert.doesNotThrow(() => apply(ctx, undefined))
  ctx.on('approval/request', async () => 'rejected')
  const agent = { id: 'a', session: { header: { id: 's' } } }
  const outcome = await ctx.waterfall('approval/request', { agent, toolName: 'write', callId: 'w', reason: 'escalate sandbox to danger-full-access: x' }, async () => 'unavailable')
  assert.equal(outcome, 'rejected')
})

test('a context whose event registration throws does not break loading', () => {
  const ctx = { get: () => undefined, on: () => { throw new Error('no events here') } }
  assert.doesNotThrow(() => apply(ctx, {}))
})

test('outside dsh there is no schema library, so no settings schema is exported', () => {
  assert.equal(Config, undefined)
})

test('settings: defaults, live references, and invalid values fall back safely', () => {
  const defaults = readSettings(undefined).settings
  assert.equal(defaults.mode, 'observe')
  assert.equal(defaults.model, 'qwen3.7-plus')
  assert.equal(defaults.baseUrl, 'https://dashscope.aliyuncs.com/compatible-mode/v1')
  assert.deepEqual(defaults.extraBody, { enable_thinking: false })

  const live = value => ({ get: () => value })
  const { settings, problems } = readSettings({
    baseUrl: live('https://dashscope-intl.aliyuncs.com/compatible-mode/v1/'),
    model: live(' qwen-plus '),
    timeoutSeconds: live(30),
    maxCallsPerHour: live(0),
    mode: 'yolo',
    keyName: 'bad name',
  })
  assert.equal(settings.baseUrl, 'https://dashscope-intl.aliyuncs.com/compatible-mode/v1')
  assert.equal(settings.model, 'qwen-plus')
  assert.equal(settings.timeoutSeconds, 30)
  assert.equal(settings.maxCallsPerHour, 0)
  assert.equal(settings.mode, 'observe')
  assert.equal(settings.keyName, 'DSH_DOORMAN_API_KEY')
  assert.deepEqual(problems.sort(), ['keyName', 'mode'])

  for (const bad of [{ baseUrl: 'http://insecure.example/v1' }, { timeoutSeconds: 1 }, { maxCallsPerHour: -5 }, { model: 'rm -rf /' }]) {
    assert.equal(readSettings(bad).problems.length, 1, JSON.stringify(bad))
  }
  assert.equal(readSettings({ baseUrl: 'https://api.example.com/v1' }).settings.extraBody, null)
  assert.deepEqual(readSettings({ extraBodyJson: '{"top_p":0.1}' }).settings.extraBody, { top_p: 0.1 })
  assert.deepEqual(readSettings({ extraBodyJson: 'not json' }).problems, ['extraBodyJson'])
})

test('settings: only the model fields are live-editable; the mode needs a file edit', () => {
  const marks = {}
  const field = name => {
    const node = { name, volatileFlag: false, default() { return node }, volatile() { node.volatileFlag = true; return node } }
    return node
  }
  const z = {
    string: () => field('string'),
    natural: () => field('natural'),
    boolean: () => field('boolean'),
    object: (shape) => { Object.assign(marks, shape); return shape },
  }
  buildConfigSchema(z)
  const editable = Object.entries(marks).filter(([, node]) => node.volatileFlag).map(([key]) => key).sort()
  assert.deepEqual(editable, ['baseUrl', 'maxCallsPerHour', 'model', 'timeoutSeconds'])
  assert.equal(buildConfigSchema(undefined), undefined)
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
  assert.equal(readState(file).versionHistory.length, 2)
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

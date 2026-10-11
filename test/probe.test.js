// Stage 0 probe tests: the probe must observe without ever changing an approval outcome.
import { after, test } from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'

const home = fs.mkdtempSync(path.join(os.tmpdir(), 'doorman-probe-test-'))
process.env.DSH_HOME = home
const { apply } = await import('../index.js')
after(() => fs.rmSync(home, { recursive: true, force: true }))

/** Minimal stand-in for the Cordis event bus: same ordering rules as cordis waterfall/emit. */
function fakeContext(services = {}) {
  const hooks = {}
  return {
    hooks,
    get: name => services[name],
    on(name, listener, options) {
      const list = hooks[name] ??= []
      const prepend = typeof options === 'object' ? options?.prepend : options
      if (prepend) list.unshift(listener)
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

function readLog() {
  const file = path.join(home, 'dsh-doorman', 'probe.jsonl')
  return fs.readFileSync(file, 'utf8').trim().split('\n').map(line => JSON.parse(line))
}

const session = { header: { id: 'session-1', cwd: 'C:\\work\\demo' } }
const agent = { id: 'agent-1', session }
const services = {
  approval: { overrideOf: () => undefined },
  sandboxPolicy: { resolve: () => ({ mode: 'workspace-write', workspaceRoot: 'C:\\work\\demo' }) },
}

test('records the escalated command and returns the user outcome unchanged', async () => {
  const ctx = fakeContext(services)
  apply(ctx)
  // The UI answerer registers later and without prepend, like api-remotes does.
  ctx.on('approval/request', async () => 'allowed-once')

  // First attempt: denied by the sandbox.
  const first = { callId: 'call-1', name: 'pwsh', agent, arguments: Object.freeze({ command: 'npm config set cache D:\\cache' }) }
  await ctx.waterfall('tools/pre-execute', first, async () => ({ kind: 'allow' }))
  ctx.emit('tools/result', first, {
    isError: false,
    content: [{ type: 'text', text: "Access to the path 'D:\\cache' is denied.\n[sandbox: file access denied under workspace-write mode]" }],
    value: { kind: 'foreground', exitCode: 1, sandbox: { mode: 'workspace-write', denied: true } },
  })

  // Retry with escalation, then the approval request the tool body would make.
  const retry = {
    callId: 'call-2',
    name: 'pwsh',
    agent,
    arguments: Object.freeze({ command: 'npm config set cache D:\\cache', sandbox_permissions: 'danger-full-access', justification: 'npm needs its cache' }),
  }
  await ctx.waterfall('tools/pre-execute', retry, async () => ({ kind: 'allow' }))
  const outcome = await ctx.waterfall('approval/request', {
    agent,
    toolName: 'pwsh',
    callId: 'call-2',
    reason: 'escalate sandbox to danger-full-access: npm needs its cache',
  }, async () => 'unavailable')

  assert.equal(outcome, 'allowed-once')
  const lines = readLog()
  const request = lines.find(line => line.event === 'approval-request' && line.callId === 'call-2')
  assert.ok(request, 'approval request logged')
  assert.equal(request.args.command, 'npm config set cache D:\\cache')
  assert.equal(request.reasonMatchesArgs, true)
  assert.equal(request.session.sandboxMode, 'workspace-write')
  assert.equal(request.recentDenials.length, 1)
  assert.match(request.recentDenials[0].text, /Access to the path/)
  const decided = lines.find(line => line.event === 'approval-decided' && line.callId === 'call-2')
  assert.equal(decided.outcome, 'allowed-once')
})

test('a rejection from the user passes through untouched', async () => {
  const ctx = fakeContext(services)
  apply(ctx)
  ctx.on('approval/request', async () => 'rejected')
  const outcome = await ctx.waterfall('approval/request', { agent, toolName: 'plugin_manager', callId: 'call-9', reason: 'escalate sandbox to danger-full-access: plugin_manager {}' }, async () => 'unavailable')
  assert.equal(outcome, 'rejected')
})

test('a broken request object still reaches the user', async () => {
  const ctx = fakeContext(services)
  apply(ctx)
  ctx.on('approval/request', async () => 'rejected')
  const hostile = { toolName: 'pwsh', callId: 'call-x', get agent() { throw new Error('boom') }, reason: 'x' }
  const outcome = await ctx.waterfall('approval/request', hostile, async () => 'unavailable')
  assert.equal(outcome, 'rejected')
})

test('an answerer failure propagates exactly as without the plugin', async () => {
  const ctx = fakeContext(services)
  apply(ctx)
  ctx.on('approval/request', async () => { throw new Error('ui crashed') })
  await assert.rejects(
    ctx.waterfall('approval/request', { agent, toolName: 'pwsh', callId: 'call-y', reason: 'x' }, async () => 'unavailable'),
    /ui crashed/,
  )
})

test('missing services do not break loading', async () => {
  const ctx = fakeContext({})
  assert.doesNotThrow(() => apply(ctx))
  ctx.on('approval/request', async () => 'rejected')
  const outcome = await ctx.waterfall('approval/request', { agent, toolName: 'write', callId: 'call-z', reason: 'escalate sandbox to danger-full-access: x' }, async () => 'unavailable')
  assert.equal(outcome, 'rejected')
})

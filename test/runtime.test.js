// Runtime: observe-only behaviour around dsh's events, with a fake event bus.
import { after, test } from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { createRuntime } from '../lib/runtime.js'
import { WS, host } from './helpers.js'

const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'doorman-runtime-test-'))
after(() => fs.rmSync(tmp, { recursive: true, force: true }))

/** Collects log lines in memory. */
function memoryLog() {
  const lines = []
  return { lines, write: (event, data = {}) => lines.push({ event, ...data }) }
}

function makeRuntime({ mode = 'observe', confirmed = null, version = '0.2.0-rc.2', session, autoAvailable = false } = {}) {
  const log = memoryLog()
  const config = { mode, autoModeConfirmedForVersion: confirmed, log: { maxFileBytes: 1 << 20 } }
  const runtime = createRuntime({
    host,
    configStore: { get: () => config },
    log,
    dshVersion: version,
    autoAvailable,
    sessionInfo: () => session ?? { sessionId: 's1', sandboxMode: 'workspace-write', workspaceRoot: WS, cwd: WS },
  })
  return { runtime, log }
}

const agent = { id: 'a1', session: { header: { id: 's1', cwd: WS } } }

/** Simulate the dsh flow: pre-execute, then the approval request the tool body makes. */
async function escalate(runtime, { callId = 'c1', tool = 'pwsh', args, answer = 'allowed-once', reason } = {}) {
  runtime.onPreExecute({ callId, name: tool, arguments: Object.freeze(args), agent })
  const req = { agent, toolName: tool, callId, reason: reason ?? `escalate sandbox to danger-full-access: ${args.justification}` }
  return runtime.onApproval(req, async () => answer)
}

const deleteDocs = { command: 'Remove-Item -Recurse C:\\Users\\alice\\Documents', sandbox_permissions: 'danger-full-access', justification: 'cleanup' }
const harmless = { command: 'npm install', sandbox_permissions: 'danger-full-access', justification: 'npm needs its cache' }

test('observe mode: a hard-denied request still goes to the user, and both sides are logged', async () => {
  const { runtime, log } = makeRuntime()
  const outcome = await escalate(runtime, { args: deleteDocs, answer: 'rejected' })
  assert.equal(outcome, 'rejected')
  const request = log.lines.find(l => l.event === 'request')
  assert.equal(request.layer, 'hard-deny')
  assert.equal(request.proposed, 'reject')
  assert.equal(request.mode, 'observe')
  assert.equal(request.command, deleteDocs.command)
  assert.ok(request.findings.some(f => f.rule === 'deny.recursive-delete-outside'))
  const decided = log.lines.find(l => l.event === 'outcome')
  assert.equal(decided.id, request.id)
  assert.equal(decided.outcome, 'rejected')
  assert.equal(decided.decidedBy, 'user')
})

test('observe mode never answers by itself, even for a request that would pass', async () => {
  const { runtime, log } = makeRuntime()
  let asked = false
  runtime.onPreExecute({ callId: 'c2', name: 'pwsh', arguments: harmless, agent })
  const outcome = await runtime.onApproval({ agent, toolName: 'pwsh', callId: 'c2', reason: `escalate sandbox to danger-full-access: ${harmless.justification}` }, async () => { asked = true; return 'allowed-once' })
  assert.equal(asked, true)
  assert.equal(outcome, 'allowed-once')
  assert.equal(log.lines.find(l => l.event === 'request').layer, 'model-unavailable')
})

test('auto mode is not available in this build: it falls back to observe and says why', async () => {
  const { runtime, log } = makeRuntime({ mode: 'auto', confirmed: '0.2.0-rc.2' })
  let asked = false
  await escalate(runtime, { args: deleteDocs, answer: 'allowed-once' }).then(() => { asked = true })
  assert.equal(asked, true)
  const request = log.lines.find(l => l.event === 'request')
  assert.equal(request.mode, 'observe')
  assert.match(request.modeNote, /阶段 3/)
})

test('auto mode with an unconfirmed dsh version falls back to observe', () => {
  const { runtime } = makeRuntime({ mode: 'auto', confirmed: '0.1.0', autoAvailable: true })
  const m = runtime.mode()
  assert.equal(m.effective, 'observe')
  assert.match(m.note, /还没确认/)
  const confirmed = makeRuntime({ mode: 'auto', confirmed: '0.2.0-rc.2', autoAvailable: true }).runtime.mode()
  assert.equal(confirmed.effective, 'auto')
})

test('plugin_manager, run_code and other askers are out of scope and pass through', async () => {
  const { runtime, log } = makeRuntime()
  for (const toolName of ['plugin_manager', 'run_code', 'some_hook']) {
    const outcome = await runtime.onApproval({ agent, toolName, callId: `x-${toolName}`, reason: 'escalate sandbox to danger-full-access: plugin_manager {}' }, async () => 'rejected')
    assert.equal(outcome, 'rejected')
  }
  const requests = log.lines.filter(l => l.event === 'request')
  assert.equal(requests.length, 3)
  for (const r of requests) {
    assert.equal(r.layer, 'out-of-scope')
    assert.equal(r.scope, 'tool')
    assert.equal(r.command, undefined)
  }
})

test('a reason that does not match the captured arguments is out of scope', async () => {
  const { runtime, log } = makeRuntime()
  await escalate(runtime, { args: harmless, reason: 'escalate sandbox to danger-full-access: something else' })
  assert.equal(log.lines.find(l => l.event === 'request').scope, 'reason-mismatch')
})

test('missing arguments, nested calls and other sandbox modes are out of scope', async () => {
  const { runtime, log } = makeRuntime()
  await runtime.onApproval({ agent, toolName: 'pwsh', callId: 'never-seen', reason: 'escalate sandbox to danger-full-access: x' }, async () => 'rejected')
  runtime.onPreExecute({ callId: 'n1', name: 'pwsh', arguments: harmless, agent, parent: 'token' })
  await runtime.onApproval({ agent, toolName: 'pwsh', callId: 'n1', reason: `escalate sandbox to danger-full-access: ${harmless.justification}` }, async () => 'rejected')
  const readOnly = makeRuntime({ session: { sessionId: 's1', sandboxMode: 'read-only', workspaceRoot: WS, cwd: WS } })
  await escalate(readOnly.runtime, { args: harmless })
  assert.deepEqual(log.lines.filter(l => l.event === 'request').map(l => l.scope), ['args-missing', 'nested'])
  assert.equal(readOnly.log.lines.find(l => l.event === 'request').scope, 'mode')
})

test('a workspace that contains dsh home is contaminated: everything goes to the user', async () => {
  const { runtime, log } = makeRuntime({ session: { sessionId: 's1', sandboxMode: 'workspace-write', workspaceRoot: 'C:\\Users\\alice', cwd: 'C:\\Users\\alice' } })
  await escalate(runtime, { args: harmless })
  const request = log.lines.find(l => l.event === 'request')
  assert.equal(request.layer, 'contaminated')
  assert.equal(request.proposed, 'ask')
  assert.ok(request.contaminatedBy)
})

test('the previous failed attempt is attached, even without dsh\'s sandbox marker', async () => {
  const { runtime, log } = makeRuntime()
  const first = { command: 'Set-Content C:\\Users\\alice\\Desktop\\out\\a.txt hi' }
  runtime.onPreExecute({ callId: 'f1', name: 'pwsh', arguments: first, agent })
  runtime.onResult({ callId: 'f1' }, {
    isError: false,
    content: [{ type: 'text', text: 'Set-Content : 对路径“C:\\Users\\alice\\Desktop\\out\\a.txt”的访问被拒绝。\n[exit code: 1]' }],
    value: { kind: 'foreground', exitCode: 1, timedOut: false, aborted: false, signal: null, stdout: { text: '' }, stderr: { text: 'Set-Content : 对路径“C:\\Users\\alice\\Desktop\\out\\a.txt”的访问被拒绝。' } },
  })
  await escalate(runtime, { callId: 'f2', args: { ...first, sandbox_permissions: 'danger-full-access', justification: 'outside' } })
  const request = log.lines.find(l => l.event === 'request')
  assert.equal(request.previousFailure.sameCommand, true)
  assert.equal(request.previousFailure.exitCode, 1)
  assert.match(request.previousFailure.outputTail, /访问被拒绝/)
})

test('the result of an escalated call is logged against its request', async () => {
  const { runtime, log } = makeRuntime()
  await escalate(runtime, { callId: 'r1', args: harmless })
  runtime.onResult({ callId: 'r1' }, { isError: false, content: [], value: { kind: 'foreground', exitCode: 0, timedOut: false, aborted: false, signal: null, stdout: { text: 'added 1 package' }, stderr: { text: '' } } })
  const request = log.lines.find(l => l.event === 'request')
  const result = log.lines.find(l => l.event === 'result')
  assert.equal(result.id, request.id)
  assert.equal(result.exitCode, 0)
})

test('mode off: nothing is evaluated or logged, requests pass through', async () => {
  const { runtime, log } = makeRuntime({ mode: 'off' })
  const outcome = await escalate(runtime, { args: deleteDocs, answer: 'rejected' })
  assert.equal(outcome, 'rejected')
  assert.equal(log.lines.length, 0)
})

test('internal errors never stop the request from reaching the user', async () => {
  const log = memoryLog()
  const runtime = createRuntime({ host, configStore: { get: () => { throw new Error('config broke') } }, log, dshVersion: null, sessionInfo: () => { throw new Error('boom') } })
  const outcome = await runtime.onApproval({ agent, toolName: 'pwsh', callId: 'e1', reason: 'x' }, async () => 'rejected')
  assert.equal(outcome, 'rejected')
  assert.ok(log.lines.some(l => l.event === 'error'))
})

test('an answerer failure propagates exactly as without the plugin', async () => {
  const { runtime } = makeRuntime()
  await assert.rejects(runtime.onApproval({ agent, toolName: 'pwsh', callId: 'z', reason: 'x' }, async () => { throw new Error('ui crashed') }), /ui crashed/)
  assert.throws(() => runtime.onApproval({ agent, toolName: 'pwsh', callId: 'z2', reason: 'x' }, () => { throw new Error('sync crash') }), /sync crash/)
})

test('a hostile request object still reaches the user', async () => {
  const { runtime } = makeRuntime()
  const hostile = { toolName: 'pwsh', callId: 'h', get agent() { throw new Error('boom') }, get reason() { throw new Error('boom') } }
  assert.equal(await runtime.onApproval(hostile, async () => 'rejected'), 'rejected')
})

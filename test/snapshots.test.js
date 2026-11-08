// Snapshots (auto mode): what is kept before an auto-allowed call runs, the outside-directory listings
// compared afterwards, the store, and the runtime around them — on real temporary files.
import { after, test } from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { realProbe } from '../lib/dsh-env.js'
import { createHost } from '../lib/host.js'
import { createRuntime, postCheckProblems } from '../lib/runtime.js'
import { readSettings } from '../lib/settings.js'
import { LIMITS, capture, captureFile, compareListings, createSnapshots, listDirs } from '../lib/store/snapshots.js'

const base = fs.mkdtempSync(path.join(os.tmpdir(), 'doorman-snapshots-test-'))
after(() => fs.rmSync(base, { recursive: true, force: true }))

const home = path.join(base, 'home')
const ws = path.join(base, 'ws')
const outside = path.join(base, 'outside')
const scratch = path.join(base, 'scratch')
for (const dir of [home, ws, outside, scratch]) fs.mkdirSync(dir, { recursive: true })
// No temp directories: everything under `base` other than the workspace counts as outside.
const host = createHost({ platform: process.platform, home, env: {}, dshHome: path.join(home, '.dsh'), dataDir: path.join(home, '.dsh', 'dsh-doorman'), tempDirs: [], probe: realProbe })

const write = (file, content) => {
  fs.mkdirSync(path.dirname(file), { recursive: true })
  fs.writeFileSync(file, content)
  return file
}

test('a text file is kept exactly — byte-order mark and line endings included; a missing one is noted', () => {
  const file = write(path.join(scratch, 'a.txt'), '﻿line 1\r\nline 2\n')
  const snap = captureFile(file)
  assert.equal(snap.existed, true)
  assert.equal(snap.diffable, true)
  assert.equal(snap.content, '﻿line 1\r\nline 2\n')
  assert.match(snap.sha256, /^[0-9a-f]{64}$/)
  assert.equal(snap.size, Buffer.byteLength('﻿line 1\r\nline 2\n'))
  assert.deepEqual(captureFile(path.join(scratch, 'missing.txt')), { path: path.join(scratch, 'missing.txt'), existed: false, diffable: true })
})

test('a big, binary, non-UTF-8 or non-file target is recorded without content and marked not diffable', () => {
  const big = write(path.join(scratch, 'big.txt'), 'x'.repeat(LIMITS.fileBytes + 1))
  const binary = write(path.join(scratch, 'b.bin'), Buffer.from([0x50, 0x4b, 0x00, 0x03]))
  const latin1 = write(path.join(scratch, 'l.txt'), Buffer.from([0x63, 0x61, 0x66, 0xe9]))
  for (const [file, reason] of [[big, 'too-large'], [binary, 'binary'], [latin1, 'binary'], [scratch, 'not-a-file']]) {
    const snap = captureFile(file)
    assert.equal(snap.diffable, false, file)
    assert.equal(snap.reason, reason, file)
    assert.equal(snap.content, undefined, file)
  }
})

test('directory listings: two levels, sorted, one shared entry budget, and which directories were read in full', () => {
  const root = path.join(base, 'tree')
  write(path.join(root, 'b.txt'), 'b')
  write(path.join(root, 'a', 'x.txt'), 'x')
  write(path.join(root, 'a', 'deep', 'too-deep.txt'), 'z')
  const [listing] = listDirs([root])
  assert.equal(listing.exists, true)
  assert.deepEqual(listing.entries.map(e => e.rel), ['a', 'b.txt', 'a/deep', 'a/x.txt'])
  assert.deepEqual(listing.complete.sort(), ['', 'a'])
  // A tiny budget cuts the walk: whatever was not read in full is not "complete".
  const [cut] = listDirs([root], { depth: 2, entries: 2 })
  assert.deepEqual(cut.entries.map(e => e.rel), ['a', 'b.txt'])
  assert.deepEqual(cut.complete, [''])
  assert.deepEqual(listDirs([path.join(base, 'nowhere')]), [{ path: path.join(base, 'nowhere'), exists: false, entries: [], complete: [] }])
})

test('comparing listings finds what was added, changed and deleted — a deleted directory counts with its contents', () => {
  const root = path.join(base, 'compare')
  write(path.join(root, 'keep.txt'), 'k')
  write(path.join(root, 'change.txt'), 'c')
  write(path.join(root, 'gone.txt'), 'g')
  write(path.join(root, 'olddir', 'inner.txt'), 'i')
  const before = listDirs([root])
  fs.rmSync(path.join(root, 'gone.txt'))
  fs.rmSync(path.join(root, 'olddir'), { recursive: true })
  fs.writeFileSync(path.join(root, 'change.txt'), 'changed!')
  write(path.join(root, 'new.txt'), 'n')
  const diff = compareListings(before, listDirs([root]))
  assert.equal(diff.added, 1)
  assert.equal(diff.modified, 1)
  assert.equal(diff.deleted, 3)
  assert.ok(diff.deletedSample.includes(path.join(root, 'gone.txt')))
  assert.ok(diff.deletedSample.includes(path.join(root, 'olddir', 'inner.txt')))
  assert.equal(diff.partial, false)
  // The whole directory gone: everything listed before is deleted.
  const whole = compareListings(before, listDirs([path.join(base, 'not-there')]).map(l => ({ ...l, path: root })))
  assert.equal(whole.deleted, before[0].entries.length)
  // A cut listing afterwards cannot tell a missing entry from an unread one.
  const partial = compareListings(before, [{ ...listDirs([root])[0], complete: [] }])
  assert.equal(partial.deleted, 0)
  assert.equal(partial.partial, true)
  assert.deepEqual(postCheckProblems({ outcome: 'allowed-once', summary: { exitCode: 0 }, outsideChanges: diff }), ['outside-deleted:3'])
})

test('the store writes records atomically, reads them back and drops the oldest beyond its limits', () => {
  const dir = path.join(base, 'store')
  const store = createSnapshots({ dir, limits: { ...LIMITS, keep: 3 } })
  const ids = ['00000001', '00000002', '00000003', '00000004']
  ids.forEach((id, i) => {
    store.save({ id, files: [] })
    // Distinct, increasing modification times.
    const t = new Date(Date.now() - (10 - i) * 1000)
    fs.utimesSync(path.join(dir, `${id}.json`), t, t)
  })
  store.prune()
  assert.deepEqual(fs.readdirSync(dir).sort(), ['00000002.json', '00000003.json', '00000004.json'])
  assert.deepEqual(store.load('00000004'), { version: 1, id: '00000004', files: [] })
  assert.equal(store.load('../etc/passwd'), undefined)
  assert.throws(() => store.save({ id: '../escape' }), /快照编号/)
  const small = createSnapshots({ dir: path.join(base, 'store-small'), limits: { ...LIMITS, totalBytes: 10 } })
  small.save({ id: '0000000a', files: [] })
  assert.deepEqual(fs.readdirSync(path.join(base, 'store-small')), [])
})

test('what is captured: the file tools\' target; a command\'s outside files and the outside directories it names', () => {
  const target = write(path.join(outside, 'note.txt'), 'old note')
  const fileTool = capture({ tool: 'write', facts: { target }, host, workspaceRoot: ws })
  assert.deepEqual(fileTool.files.map(f => [f.path, f.content]), [[target, 'old note']])
  assert.deepEqual(fileTool.dirs, [])

  const files = [1, 2, 3, 4, 5, 6].map(n => write(path.join(outside, 'many', `f${n}.txt`), `f${n}`))
  const facts = {
    writes: [{ path: target, outside: true, exists: true }, { path: path.join(ws, 'in.txt'), outside: false, exists: true }],
    deletes: files.map(p => ({ path: p, outside: true, recursive: false })),
    moves: [],
    outsidePaths: [target, path.join(outside, 'many'), home, path.join(home, '.dsh', 'x'), ws],
  }
  const taken = capture({ tool: 'pwsh', facts, host, workspaceRoot: ws })
  assert.equal(taken.files.length, LIMITS.files)
  assert.equal(taken.files[0].path, target)
  assert.ok(taken.skipped.some(s => s.reason === 'over-file-limit'))
  // The named file stands for its directory; home, dsh's own area and the workspace are never listed.
  assert.deepEqual(taken.dirs.map(d => d.path), [outside, path.join(outside, 'many')])
})

// ---------------------------------------------------------------- the runtime with snapshots

const session = { sessionId: 's1', sandboxMode: 'workspace-write', workspaceRoot: ws, cwd: ws, preset: 'doorman', presetConfigured: true, trigger: 'human' }
const agent = { id: 'a1', session: { header: { id: 's1', cwd: ws } } }

function autoRuntime({ snapshots, verdict = { status: 'ok', decision: 'allow', risk: 'low', explanation: 'x' } } = {}) {
  const lines = []
  const runtime = createRuntime({
    host,
    getSettings: () => ({ ...readSettings({}).settings, mode: 'auto', autoModeConfirmedForVersion: '0.2.1-rc.5' }),
    log: { write: (event, data = {}) => lines.push({ event, ...data }) },
    dshVersion: '0.2.1-rc.5',
    dshVersionVerified: true,
    autoAvailable: true,
    sessionInfo: () => session,
    getKey: async () => 'sk-test',
    readText: () => undefined,
    osLabel: 'test',
    reviewImpl: async () => verdict,
    snapshots,
  })
  return { runtime, lines }
}

async function escalate(runtime, { callId, tool, args, answer = 'allowed-once' }) {
  runtime.onPreExecute({ callId, name: tool, arguments: args, agent })
  let asked = false
  const outcome = await runtime.onApproval({ agent, toolName: tool, callId, reason: `escalate sandbox to danger-full-access: ${args.justification}` }, async () => { asked = true; return answer })
  return { outcome, asked }
}

test('auto: before an allowed write runs, the file it overwrites is snapshotted', async () => {
  const target = write(path.join(outside, 'report.md'), '# old\n')
  const store = createSnapshots({ dir: path.join(base, 'run-snapshots') })
  const { runtime, lines } = autoRuntime({ snapshots: store })
  const { outcome, asked } = await escalate(runtime, { callId: 'w1', tool: 'write', args: { file_path: target, content: '# new\n', sandbox_permissions: 'danger-full-access', justification: 'update the report' } })
  assert.deepEqual({ outcome, asked }, { outcome: 'allowed-once', asked: false })
  const decided = lines.find(l => l.event === 'outcome')
  assert.equal(decided.decidedBy, 'doorman')
  assert.equal(decided.snapshot.files, 1)
  assert.deepEqual(decided.snapshot.notDiffable, [])
  const request = lines.find(l => l.event === 'request')
  assert.equal(decided.snapshot.file, `${request.id}.json`)
  const record = store.load(request.id)
  assert.equal(record.tool, 'write')
  assert.equal(record.filePath, target)
  assert.deepEqual(record.files.map(f => [f.path, f.existed, f.content]), [[target, true, '# old\n']])
})

test('auto: when the snapshot cannot be written, the call goes to the user instead', async () => {
  const target = write(path.join(outside, 'keep.md'), 'keep')
  const broken = { save: () => { throw new Error('disk full') } }
  const { runtime, lines } = autoRuntime({ snapshots: broken })
  const { outcome, asked } = await escalate(runtime, { callId: 'w2', tool: 'write', args: { file_path: target, content: 'x', sandbox_permissions: 'danger-full-access', justification: 'edit' } })
  assert.deepEqual({ outcome, asked }, { outcome: 'allowed-once', asked: true })
  assert.deepEqual([lines.find(l => l.event === 'outcome').decidedBy, lines.find(l => l.event === 'outcome').because], ['user', 'error'])
  assert.ok(lines.some(l => l.event === 'error' && /disk full/.test(l.message)))
  // A file too big to keep is still allowed, and marked as not diffable.
  const big = write(path.join(outside, 'big.log'), 'y'.repeat(LIMITS.fileBytes + 10))
  const store = createSnapshots({ dir: path.join(base, 'run-snapshots-big') })
  const second = autoRuntime({ snapshots: store })
  assert.equal((await escalate(second.runtime, { callId: 'w3', tool: 'write', args: { file_path: big, content: 'x', sandbox_permissions: 'danger-full-access', justification: 'truncate' } })).outcome, 'allowed-once')
  assert.deepEqual(second.lines.find(l => l.event === 'outcome').snapshot.notDiffable, [{ path: big, reason: 'too-large' }])
})

test('auto: an allowed command\'s outside directories are listed before it runs and compared after', async () => {
  const dir = path.join(outside, 'cleanup')
  const old = write(path.join(dir, 'old.txt'), 'old')
  write(path.join(dir, 'other.txt'), 'other')
  const store = createSnapshots({ dir: path.join(base, 'run-snapshots-cmd') })
  const { runtime, lines } = autoRuntime({ snapshots: store })
  const command = `Remove-Item -LiteralPath '${old}'`
  const { outcome } = await escalate(runtime, { callId: 'r1', tool: 'pwsh', args: { command, sandbox_permissions: 'danger-full-access', justification: 'remove the old file' } })
  assert.equal(outcome, 'allowed-once')
  const decided = lines.find(l => l.event === 'outcome')
  assert.equal(decided.snapshot.files, 1)
  assert.equal(decided.snapshot.dirs, 1)
  const record = store.load(lines.find(l => l.event === 'request').id)
  assert.equal(record.command, command)
  assert.equal(record.files[0].content, 'old')
  // The command runs (here: by hand), then its result arrives.
  fs.rmSync(old)
  runtime.onResult({ callId: 'r1' }, { isError: false, content: [], value: { kind: 'foreground', exitCode: 0, timedOut: false, aborted: false, signal: null, stdout: { text: '' }, stderr: { text: '' } } })
  const result = lines.find(l => l.event === 'result')
  assert.deepEqual([result.outsideChanges.deleted, result.outsideChanges.added, result.outsideChanges.partial], [1, 0, false])
  assert.deepEqual(result.outsideChanges.deletedSample, [old])
})

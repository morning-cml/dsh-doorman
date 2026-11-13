import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { test } from 'node:test'
import { fileURLToPath } from 'node:url'

const replay = fileURLToPath(new URL('../tools/replay.mjs', import.meta.url))

test('replay: truncated lines, cancelled approvals and plugin answers do not skew comparisons', (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'doorman-replay-'))
  t.after(() => fs.rmSync(dir, { recursive: true }))
  const workspaceRoot = path.join(dir, 'workspace')
  fs.mkdirSync(workspaceRoot)
  const request = (id, ts, extra = {}) => ({
    event: 'request', scope: 'ok', id, ts, tool: 'pwsh', command: 'Get-Date', justification: 'test',
    workspaceRoot, cwd: workspaceRoot, ...extra,
  })
  const verdict = (id, ts) => ({ event: 'model', id, ts, status: 'ok', decision: 'allow', risk: 'low' })
  const answer = (id, ts, outcome, decidedBy = 'user') => ({ event: 'outcome', id, ts, outcome, decidedBy })
  const result = (id, ts, extra = {}) => ({ event: 'result', id, ts, exitCode: 0, ...extra })
  const write = (part, rows) => {
    fs.writeFileSync(path.join(dir, `decisions-2026-11${part}.jsonl`), rows.map(r => JSON.stringify(r)).join('\n') + '\n')
  }
  const early = '2026-11-02T00:00:00.000Z'
  const late = '2026-11-02T00:01:00.000Z'
  write('-2', [
    request('allowed', early),
    verdict('allowed', early),
    answer('allowed', early, 'allowed-once'),
    result('allowed', early),
  ])
  write('-10', [
    request('cancelled', late),
    verdict('cancelled', late),
    answer('cancelled', late, 'cancelled'),
    request('plugin', late, { command: 'Get-Location' }),
    verdict('plugin', late),
    answer('plugin', late, 'allowed-once', 'doorman'),
    result('plugin', late, { outsideChanges: { deleted: 1 } }),
    request('rejected', late, { command: 'Get-ChildItem' }),
    verdict('rejected', late),
    answer('rejected', late, 'rejected'),
    request('contaminated', late, { extraWritableRoots: [os.homedir()] }),
  ])
  fs.appendFileSync(path.join(dir, 'decisions-2026-11-10.jsonl'), '{"event":"request"')
  const { status, stdout, stderr } = spawnSync(process.execPath, [replay, '--logs', dir], { encoding: 'utf8' })
  assert.equal(status, 0, stderr)
  assert.match(stderr, /skipped 1 malformed log lines/)
  assert.match(stdout, /in-scope requests: 5/)
  assert.match(stdout, /contaminated: 1/)
  assert.match(stdout, /would add: 1, would hit: 1, would remove: 1/)
  assert.match(stdout, /would-hits the user explicitly rejected .*: 0/)
  assert.match(stdout, /misallows .*: 1; needless rejects .*: 0/)
  assert.match(stdout, /answered by the plugin in auto mode .*: 1/)
})

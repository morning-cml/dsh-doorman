// Offline replay of the decision logs through the current code (the check every stage ends with,
// docs/refactor-plan.zh.md §4). Each logged in-scope request is decided again with a real host and a
// simulated shadow allowlist; the logged model verdict, the user's choice and the result drive the
// post-check. It prints the layers, why commands may not be listed, what the allowlist would have
// added, hit and removed, every would-hit next to what the user really did, whether any model
// payload would contain the user's real home path, and what auto mode would have answered next to
// what the user answered (a would-allow the user rejected is a misallow; a would-reject the user
// allowed is a needless refusal). Requests the plugin answered itself in auto mode carry no answer
// of the user's: they are listed apart, for review, and never counted either way.
//
// Dependency hashes come from the files as they are on disk now, as if no bound file changed during
// the logged period: the most permissive assumption, so hits are bounded from above. Auto mode's
// answers use the verdicts logged at the time, from the prompt of that time.
//
// Usage: node tools/replay.mjs [--since YYYY-MM-DD] [--logs <dir>]   (reads only; writes nothing)
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { installedPluginSkillDirs, realProbe } from '../lib/dsh-env.js'
import { decide } from '../lib/engine.js'
import { createHost } from '../lib/host.js'
import { buildPayload } from '../lib/model/payload.js'
import { actionFor } from '../lib/model/verdict.js'
import { detectInjection } from '../lib/rules/injection.js'
import { postCheckProblems } from '../lib/runtime.js'
import { createAllowlist } from '../lib/store/allowlist.js'
import { fingerprintOf, hashFileSync } from '../lib/store/fingerprint.js'

const option = (name) => {
  const i = process.argv.indexOf(name)
  return i === -1 ? undefined : process.argv[i + 1]
}
const home = os.homedir()
const dshHome = process.env.DSH_HOME ?? path.join(home, '.dsh')
const logDir = option('--logs') ?? path.join(dshHome, 'dsh-doorman', 'logs')
const since = option('--since') ?? ''
const installDir = path.join(dshHome, 'profiles', 'desktop', 'node_modules', 'dsh-doorman')
const SECRET_ENV = /KEY|PASSWORD|SECRET|TOKEN|CREDENTIAL|AUTH|COOKIE|SESSION/i

const host = createHost({
  platform: process.platform,
  home,
  env: Object.fromEntries(Object.entries(process.env).filter(([k, v]) => typeof v === 'string' && !SECRET_ENV.test(k) && v.length < 4096)),
  dshHome,
  dataDir: path.join(dshHome, 'dsh-doorman'),
  installDir,
  execPath: process.platform === 'win32' ? path.join(home, 'AppData', 'Local', 'Programs', 'DeepSeek Harness', 'DeepSeek Harness.exe') : undefined,
  tempDirs: [os.tmpdir()],
  pluginSkillDirs: installedPluginSkillDirs(installDir),
  probe: realProbe,
})
const readText = (file) => {
  try {
    if (!fs.statSync(file).isFile()) return undefined
    return fs.readFileSync(file, 'utf8').slice(0, 256 * 1024).replace(/^﻿/, '')
  } catch {
    return undefined
  }
}

const lines = fs.readdirSync(logDir).filter(f => f.endsWith('.jsonl')).sort()
  .flatMap(f => fs.readFileSync(path.join(logDir, f), 'utf8').split('\n').filter(Boolean).map(l => JSON.parse(l)))
  .filter(l => l.ts >= since)
const byId = new Map()
for (const l of lines) {
  if (l.id === undefined) continue
  if (!byId.has(l.id)) byId.set(l.id, {})
  byId.get(l.id)[l.event] = l
}

// The shadow allowlist never writes; its file path only has to be one that does not exist.
const sim = createAllowlist({ file: path.join(os.tmpdir(), `doorman-replay-${process.pid}-none`, 'allowlist.json'), pathKey: p => host.tools.key(p), shadow: true })
const fingerprint = input => fingerprintOf({ ...input, host, hashFile: hashFileSync, readText })
const escaped = home.replace(/[.*+?^${}()|[\]\\]/g, '\\$&').replace(/\\\\/g, '\\\\+')
const userPath = new RegExp(`${escaped.replace(/\\\\\+/g, '[\\\\/]+')}(?![\\w-])`, 'i')

const count = (map, key) => map.set(key, (map.get(key) ?? 0) + 1)
const layers = new Map()
const reasons = new Map()
const events = []
const auto = new Map()
const autoCases = []
const autoDecided = []
let inScope = 0
let eligible = 0
let leaked = 0

for (const r of lines.filter(l => l.event === 'request' && l.scope === 'ok')) {
  inScope += 1
  const g = byId.get(r.id)
  const shell = r.tool === 'pwsh' || r.tool === 'bash'
  const args = shell
    ? { command: r.command, ...(r.workdirArg !== undefined ? { workdir: r.workdirArg } : {}), sandbox_permissions: 'danger-full-access', justification: r.justification }
    : { file_path: r.filePath, content: r.contentHead ?? '', old_string: r.oldHead, new_string: r.newHead, sandbox_permissions: 'danger-full-access', justification: r.justification }
  const decision = decide({
    toolName: r.tool,
    reason: `escalate sandbox to danger-full-access: ${r.justification}`,
    record: { name: r.tool, args, nested: false },
    session: { sessionId: r.sessionId, sandboxMode: 'workspace-write', workspaceRoot: r.workspaceRoot, cwd: r.cwd },
    host,
    allowlist: sim,
    fingerprint,
  })
  let layer = decision.layer
  if (layer === 'hard-pass') {
    const built = buildPayload({ tool: r.tool, args, facts: decision.hard.facts, host, workspaceRoot: r.workspaceRoot, os: 'replay', readText })
    if (built.ok && userPath.test(JSON.stringify(built.payload))) leaked += 1
    // A script deleted since cannot be read today; if the request reached the model back then, it could be.
    if (r.layer === 'model' && g.model !== undefined) layer = 'model'
    else if (!built.ok) layer = 'model-input'
    else if (detectInjection(...built.texts) !== null) layer = 'hard-ask'
    else layer = 'model'
  }
  count(layers, layer)
  const fp = decision.fingerprint
  if (fp?.eligible) eligible += 1
  else for (const reason of fp?.reasons ?? []) count(reasons, reason.replace(/(?:[A-Za-z]:\\|\\\\)[^\s，）]*/g, '<path>').slice(0, 70))

  const problems = postCheckProblems({ outcome: g.outcome?.outcome, summary: g.result, workdirMatches: g.result?.workdirMatches })
  const brief = { ts: r.ts.slice(5, 16), command: (r.command ?? r.filePath ?? '').replace(/\s+/g, ' ').slice(0, 110), user: g.outcome?.outcome ?? '?', exit: g.result?.exitCode }

  // What auto mode would have answered (in a session with the plugin's preset): hard denies and
  // model denies are rejected, model allows allowed once, the rest goes to the user.
  let answer = 'ask'
  if (layer === 'hard-deny') answer = 'reject'
  else if (layer === 'model') answer = g.model === undefined ? 'no-verdict' : actionFor(g.model)
  // In auto mode the plugin itself may have answered: then nobody knows what the user would have done.
  const byPlugin = g.outcome?.decidedBy === 'doorman'
  const user = g.outcome?.outcome === 'allowed-once' ? 'allowed' : g.outcome?.outcome === 'rejected' ? 'rejected' : 'other'
  count(auto, byPlugin ? `${answer} / plugin ${user} (user not asked)` : `${answer} / user ${user}`)
  if (byPlugin) autoDecided.push({ answer, layer, ...brief, why: g.model?.explanation ?? (decision.hard?.findings ?? []).map(f => f.rule).join(',') })
  else if ((answer === 'allow-once' && user !== 'allowed') || (answer === 'reject' && user === 'allowed')) {
    autoCases.push({ kind: answer === 'allow-once' ? 'MISALLOW' : 'NEEDLESS REJECT', layer, ...brief, why: g.model?.explanation ?? (decision.hard?.findings ?? []).map(f => f.rule).join(',') })
  }

  // A shadow hit goes on to the model; for the allowlist it is still a hit.
  if (decision.allowlist?.status === 'hit' || layer === 'allowlist-hit') {
    if (problems.length === 0) sim.touch(fp)
    else sim.block(fp, problems)
    events.push({ kind: problems.length === 0 ? 'HIT' : 'HIT -> REMOVE', ...brief, problems })
  } else if (layer === 'allowlist-blocked') {
    events.push({ kind: 'BLOCKED (asks)', ...brief })
  } else if (layer === 'model' && fp?.eligible) {
    const v = g.model
    const why = []
    if (v === undefined) why.push('no logged verdict (it did not reach the model then)')
    else if (!(v.status === 'ok' && v.decision === 'allow' && v.risk === 'low')) why.push(`model ${v.status === 'ok' ? `${v.decision}/${v.risk}` : v.status}`)
    why.push(...problems)
    if (fp.outsideWrites.some(p => host.exists(p))) why.push('created something outside: a repeat would overwrite it')
    if (why.length === 0) {
      sim.add(fp, { explanation: v.explanation, model: v.model })
      events.push({ kind: 'ADD', ...brief, deps: fp.dependsOn.map(d => `${path.basename(d.path)}${d.sha256 === null ? '(absent)' : ''}`) })
    } else {
      events.push({ kind: 'eligible, not added', ...brief, why })
    }
  }
}

console.log(`in-scope requests: ${inScope}; eligible for the allowlist: ${eligible}`)
console.log('layers under the current code:', Object.fromEntries([...layers].sort((a, b) => b[1] - a[1])))
console.log(`model payloads containing the real home path: ${leaked}`)
console.log('\nwhy not eligible (requests per reason):')
for (const [reason, n] of [...reasons].sort((a, b) => b[1] - a[1]).slice(0, 25)) console.log(`  ${String(n).padStart(4)}  ${reason}`)
console.log('\nallowlist events in order:')
for (const e of events) {
  const extra = e.deps ? `  deps=[${e.deps.join(', ')}]` : e.why ? `  (${e.why.join('; ')})` : e.problems?.length ? `  problems=${e.problems.join(',')}` : ''
  console.log(`  ${e.kind.padEnd(20)} ${e.ts} user=${e.user} exit=${e.exit} ${JSON.stringify(e.command)}${extra}`)
}
const hits = events.filter(e => e.kind.startsWith('HIT'))
console.log(`\nwould add: ${events.filter(e => e.kind === 'ADD').length}, would hit: ${hits.length}, would remove: ${events.filter(e => e.kind === 'HIT -> REMOVE').length}, blocked asks: ${events.filter(e => e.kind.startsWith('BLOCKED')).length}`)
console.log(`would-hits the user did not allow (误放): ${hits.filter(e => e.user !== 'allowed-once').length}`)

console.log('\nauto mode (verdicts as logged at the time) / what the user did:')
for (const [key, n] of [...auto].sort((a, b) => b[1] - a[1])) console.log(`  ${String(n).padStart(4)}  ${key}`)
console.log(`misallows (auto would allow, the user did not): ${autoCases.filter(c => c.kind === 'MISALLOW').length}; needless rejects (auto would reject, the user allowed): ${autoCases.filter(c => c.kind !== 'MISALLOW').length}`)
console.log('  (only requests the user answered; those the plugin answered itself are listed below for review)')
for (const c of autoCases) console.log(`  ${c.kind.padEnd(16)} ${c.ts} layer=${c.layer} user=${c.user} ${JSON.stringify(c.command)}  (${String(c.why).slice(0, 90)})`)
console.log(`\nanswered by the plugin in auto mode (the user was not asked): ${autoDecided.length}`)
for (const c of autoDecided) console.log(`  ${c.answer.padEnd(10)} ${c.ts} layer=${c.layer} ${JSON.stringify(c.command)}  (${String(c.why).slice(0, 90)})`)

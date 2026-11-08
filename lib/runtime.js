/**
 * The stateful glue between dsh's events and the pure decision code:
 * remembers each watched tool call's arguments (tools/pre-execute), recent
 * failed calls per session (tools/result), and handles approval requests
 * (approval/request). dsh-specific lookups are injected so this module can be
 * tested with a fake event bus.
 *
 * Observe mode: every approval request goes on to the user. For a request that
 * passes the hard rules the model review runs alongside the prompt (never
 * delaying it), and its verdict is logged next to the user's choice.
 *
 * Auto mode — only on a dsh version the plugin was checked against and the user
 * confirmed, and only in a session whose permission preset is the plugin's —
 * acts on the hard rules and the model review: a hard deny or a model deny is
 * rejected; a model allow is allowed once, after a snapshot of what it is known
 * to change; everything else still goes to the user, except in a session nobody
 * is watching (a scheduled turn, a subagent), where it is rejected rather than
 * left waiting. Any error on the way goes to the user.
 *
 * The allowlist only shadows, in both modes: it never allows by itself. After
 * an escalated call finishes, its result is checked (deterministic signals, and
 * for an auto-allowed command what changed in the outside directories listed
 * before it ran) to decide what the allowlist would learn: a clean,
 * model-approved, eligible command would be added; a listed one that
 * misbehaved would be blocked. That is logged, never written.
 */

import { randomUUID } from 'node:crypto'
import path from 'node:path'
import { WATCHED_TOOLS, decide } from './engine.js'
import { createLimiter } from './model/limiter.js'
import { buildPayload, selfTestPayload } from './model/payload.js'
import { review as defaultReview } from './model/review.js'
import { actionFor } from './model/verdict.js'
import { detectInjection } from './rules/injection.js'
import { M } from './rules/messages.js'
import { AUTO_PRESET } from './settings.js'
import { capture, compareListings, listDirs } from './store/snapshots.js'
import { clip } from './text.js'

const MAX_CALLS = 500
const MAX_FAILURES_PER_SESSION = 5
const FAILURE_WINDOW_MS = 10 * 60 * 1000
/** Output that says access was refused, in English or Chinese, even when the command itself exited 0. */
const ACCESS_DENIED = /access (is )?denied|access to the path|permission denied|operation not permitted|unauthorizedaccess|permissiondenied|\beperm\b|\beacces\b|拒绝访问|访问被拒绝|没有权限|权限不足/i

/**
 * @typedef {object} SessionFacts
 * @property {string | undefined} sessionId
 * @property {string | undefined} sandboxMode
 * @property {string | undefined} workspaceRoot
 * @property {string | undefined} cwd
 * @property {string | undefined} [preset] - the session's permission preset.
 * @property {boolean | undefined} [presetConfigured] - whether the plugin's preset is in the preset table.
 * @property {string | undefined} [origin] - 'subagent' for a delegated child session.
 * @property {'human' | 'schedule' | 'other' | 'unknown'} [trigger] - what started the current turn.
 */

/**
 * @typedef {object} RuntimeOptions
 * @property {ReturnType<import('./host.js').createHost>} host
 * @property {() => ReturnType<import('./settings.js').readSettings>['settings']} getSettings
 * @property {{ write(event: string, data?: object): void }} log
 * @property {string | null} dshVersion
 * @property {boolean} [dshVersionVerified] - whether the plugin was checked against this dsh version.
 * @property {(agent: any) => SessionFacts | undefined} sessionInfo
 * @property {(keyName: string) => Promise<string | undefined>} getKey
 * @property {(file: string) => string | undefined} readText
 * @property {string} osLabel
 * @property {typeof fetch} [fetchImpl]
 * @property {typeof defaultReview} [reviewImpl]
 * @property {ReturnType<import('./store/allowlist.js').createAllowlist>} [allowlist] - layer 2; without it the layer is skipped.
 * @property {(input: { tool: string, args: any, facts: any, workspaceRoot: string | undefined }) => import('./store/fingerprint.js').Fingerprint} [fingerprint]
 * @property {{ save(record: object): { file: string, bytes: number } }} [snapshots] - where auto mode keeps its snapshots; without it none are taken.
 * @property {boolean} [autoAvailable] - whether this build may act on decisions.
 * @property {() => number} [now]
 */

/**
 * One escalated call between its approval request and its result.
 * @typedef {object} Tracked
 * @property {string} id - the request id in the log.
 * @property {string | undefined} workdir - the directory the rules assumed.
 * @property {string} layer - the layer that judged it.
 * @property {import('./store/fingerprint.js').Fingerprint | undefined} fingerprint
 * @property {boolean} shadowHit - a shadow allowlist entry matched (the call still went to the model).
 * @property {any} [verdict] - the model review's result, once it is in.
 * @property {string} [outcome] - what was answered (by the user, or by the plugin in auto mode).
 * @property {import('./store/snapshots.js').DirListing[]} [listing] - outside directories listed before an auto-allowed call.
 * @property {ReturnType<typeof compareListings>} [outsideChanges] - what changed there afterwards.
 * @property {ReturnType<typeof summarizeResult>} [summary] - the finished call's signals.
 * @property {boolean} [workdirMatches]
 * @property {boolean} done - the post-check ran.
 */

/**
 * Everything one approval request needs after its synchronous evaluation.
 * @typedef {object} Plan
 * @property {string} id
 * @property {number} startedAt
 * @property {'observe' | 'auto'} mode - the mode for this request.
 * @property {'pass' | 'ask' | 'reject' | 'review'} action - what auto mode does next ('pass': never decided by the plugin).
 * @property {string} layer
 * @property {boolean} unattended - nobody is watching this session's turn.
 * @property {{ payload: object, settings: any } | null} review
 * @property {Tracked | null} tracked
 * @property {string | undefined} toolName
 * @property {SessionFacts | undefined} session
 * @property {import('./engine.js').Decision} decision
 * @property {{ args: any } | undefined} record
 */

/**
 * Error text for logs.
 * @param {unknown} error
 */
function message(error) {
  try {
    return clip(error instanceof Error ? `${error.name}: ${error.message}` : String(error), 600)
  } catch {
    return 'unprintable error'
  }
}

/**
 * Deterministic signals of a finished tool call. A shell command that went to the background
 * (`background`, or `promoted` after its foreground wait) has no exit code yet: it is reported
 * with its job id and `exitCode` stays undefined.
 * @param {any} result
 */
export function summarizeResult(result) {
  const value = result && typeof result.value === 'object' && result.value !== null ? result.value : undefined
  const text = Array.isArray(result?.content)
    ? result.content.filter(b => b && b.type === 'text' && typeof b.text === 'string').map(b => b.text).join('\n')
    : ''
  const output = value?.kind === 'foreground'
    ? [value.stdout?.text ?? '', value.stderr?.text ?? ''].filter(Boolean).join('\n[stderr]\n')
    : text
  const kind = typeof value?.kind === 'string' ? value.kind : undefined
  return {
    isError: result?.isError === true,
    errorMessage: result?.isError ? clip(result?.error?.message ?? text, 600) : undefined,
    ...(kind !== undefined ? { kind } : {}),
    ...(typeof value?.jobId === 'string' ? { jobId: value.jobId } : {}),
    // dsh 0.2.1+ reports the directory a shell command actually ran in.
    ...(typeof value?.cwd === 'string' ? { ranIn: value.cwd } : {}),
    exitCode: value?.exitCode,
    timedOut: value?.timedOut === true,
    aborted: value?.aborted === true,
    killed: typeof value?.signal === 'string' || typeof value?.stopped === 'string',
    sandboxDenied: value?.sandbox?.denied === true || text.includes('[sandbox: file access denied'),
    accessDenied: ACCESS_DENIED.test(output) || ACCESS_DENIED.test(text),
    outputTail: clip(output, 1500),
  }
}

/** Whether a finished call failed (including commands that caught the refusal themselves and exited 0). */
function failed(summary) {
  return summary.isError || summary.timedOut || summary.aborted || summary.killed || summary.sandboxDenied || summary.accessDenied
    || (summary.exitCode !== undefined && summary.exitCode !== 0)
}

/**
 * What the deterministic post-check finds wrong with a finished escalated call (design §2 事后检查 1 and 5):
 * not allowed, an error, a timeout or kill, a refusal, a non-zero exit, no exit code at all (it went to
 * the background), a different directory than the rules assumed, or existing entries gone from an
 * outside directory listed before it ran. Empty means clean.
 * @param {Pick<Tracked, 'outcome' | 'summary' | 'workdirMatches' | 'outsideChanges'>} tracked
 * @returns {string[]}
 */
export function postCheckProblems({ outcome, summary, workdirMatches, outsideChanges }) {
  const problems = []
  if (outcome !== 'allowed-once') problems.push(`not-allowed:${outcome ?? 'unknown'}`)
  if (summary === undefined) return [...problems, 'no-result']
  if (summary.isError) problems.push('error')
  if (summary.timedOut) problems.push('timeout')
  if (summary.aborted) problems.push('aborted')
  if (summary.killed) problems.push('killed')
  if (summary.sandboxDenied) problems.push('sandbox-denied')
  if (summary.accessDenied) problems.push('access-denied')
  if (summary.exitCode === undefined) problems.push(`no-exit-code${summary.kind !== undefined ? `:${summary.kind}` : ''}`)
  else if (summary.exitCode !== 0) problems.push(`exit-code:${summary.exitCode}`)
  if (workdirMatches === false) problems.push('ran-elsewhere')
  if (outsideChanges !== undefined && outsideChanges.deleted > 0) problems.push(`outside-deleted:${outsideChanges.deleted}`)
  return problems
}

/** What a watched call is about, for logs. */
function describeArgs(tool, args) {
  if (args === null || typeof args !== 'object') return {}
  if (tool === 'pwsh' || tool === 'bash') {
    return { command: clip(args.command, 20000), workdirArg: args.workdir, description: clip(args.description, 300) }
  }
  if (tool === 'write') {
    return { filePath: args.file_path, contentLength: typeof args.content === 'string' ? args.content.length : undefined, contentHead: clip(args.content, 500) }
  }
  if (tool === 'edit') {
    return { filePath: args.file_path, replaceAll: args.replace_all === true, oldHead: clip(args.old_string, 300), newHead: clip(args.new_string, 300) }
  }
  return {}
}

/** The loggable part of a review result. */
function summarizeReview(result) {
  const out = { status: result.status }
  for (const key of ['decision', 'risk', 'explanation', 'latencyMs', 'usage', 'model', 'kind', 'message', 'httpStatus', 'raw']) {
    if (result[key] !== undefined) out[key] = result[key]
  }
  return out
}

/**
 * Create the runtime.
 * @param {RuntimeOptions} options
 */
export function createRuntime({ host, getSettings, log, dshVersion, dshVersionVerified = false, sessionInfo, getKey, readText, osLabel, fetchImpl, reviewImpl = defaultReview, allowlist, fingerprint, snapshots, autoAvailable = false, now = () => Date.now() }) {
  /** @type {Map<string, { name: string, args: any, sessionId: string | undefined, nested: boolean, at: number }>} */
  const calls = new Map()
  /** @type {Map<string, any[]>} */
  const failures = new Map()
  /** @type {Map<string, Tracked>} escalated call id → what its result is checked against */
  const escalated = new Map()
  const limiter = createLimiter(now)
  // Event names say "would" while the allowlist only shadows.
  const would = name => (allowlist?.shadow === false ? `allowlist-${name}` : `allowlist-would-${name}`)

  /**
   * The mode set for the whole plugin right now (each session may still run observe-only).
   * @returns {{ configured: string, effective: 'observe' | 'auto' | 'off', note?: string }}
   */
  function mode() {
    const settings = getSettings()
    if (settings.mode === 'off') return { configured: 'off', effective: 'off' }
    if (settings.mode === 'auto') {
      if (!autoAvailable) return { configured: 'auto', effective: 'observe', note: '这个版本没有打开自动模式，按只观察运行' }
      if (dshVersion === null || !dshVersionVerified) {
        return { configured: 'auto', effective: 'observe', note: `插件还没对照 dsh ${dshVersion ?? '（版本未知）'} 的源码核实过，自动退回只观察` }
      }
      if (settings.autoModeConfirmedForVersion !== dshVersion) {
        return { configured: 'auto', effective: 'observe', note: `dsh 版本 ${dshVersion} 还没确认过（autoModeConfirmedForVersion），自动退回只观察` }
      }
      return { configured: 'auto', effective: 'auto' }
    }
    return { configured: settings.mode, effective: 'observe' }
  }

  /**
   * Narrow the plugin-wide mode to one session: auto only where the user picked the plugin's preset.
   * @param {ReturnType<typeof mode>} current
   * @param {SessionFacts | undefined} session
   */
  function sessionMode(current, session) {
    if (current.effective !== 'auto') return current
    if (session?.preset === AUTO_PRESET) return current
    let note
    if (session?.preset === undefined) note = '读不到本会话的权限预设，按只观察运行'
    else if (session.presetConfigured === false) note = `权限预设里还没有“${AUTO_PRESET}”（门卫自动审批，见使用说明），按只观察运行`
    else note = `本会话的权限是“${session.preset}”，不是“${AUTO_PRESET}”（门卫自动审批），按只观察运行`
    return { configured: current.configured, effective: 'observe', note }
  }

  /** @param {any} exec */
  function onPreExecute(exec) {
    if (exec === null || typeof exec !== 'object' || !WATCHED_TOOLS.includes(exec.name)) return
    if (calls.size >= MAX_CALLS) calls.delete(calls.keys().next().value)
    calls.set(exec.callId, {
      name: exec.name,
      args: exec.arguments,
      sessionId: exec.agent?.session?.header?.id,
      // A run_code sub-dispatch carries its transport's token and the root call's id.
      nested: exec.parent !== undefined || (exec.rootCallId !== undefined && exec.rootCallId !== exec.callId),
      at: now(),
    })
  }

  /**
   * @param {any} exec
   * @param {any} result
   */
  function onResult(exec, result) {
    const record = exec ? calls.get(exec.callId) : undefined
    if (record === undefined) return
    calls.delete(exec.callId)
    const summary = summarizeResult(result)
    const request = escalated.get(exec.callId)
    if (request !== undefined) {
      escalated.delete(exec.callId)
      // The rules judged relative paths against `workdir`; dsh reports where the command really ran.
      const checked = summary.ranIn !== undefined && request.workdir !== undefined
        ? { workdirMatches: host.tools.key(summary.ranIn) === host.tools.key(request.workdir) }
        : {}
      if (request.listing !== undefined) {
        try {
          request.outsideChanges = compareListings(request.listing, listDirs(request.listing.map(l => l.path)))
        } catch (error) {
          log.write('error', { where: 'snapshot-after', id: request.id, message: message(error) })
        }
      }
      log.write('result', { id: request.id, callId: exec.callId, tool: record.name, ...summary, ...checked, ...(request.outsideChanges ? { outsideChanges: request.outsideChanges } : {}) })
      request.summary = summary
      request.workdirMatches = checked.workdirMatches
      postCheck(request)
      return
    }
    const escalating = typeof record.args?.sandbox_permissions === 'string'
    if (escalating || record.sessionId === undefined || !failed(summary)) return
    const list = failures.get(record.sessionId) ?? []
    list.push({ tool: record.name, args: record.args, at: now(), summary })
    while (list.length > MAX_FAILURES_PER_SESSION) list.shift()
    failures.set(record.sessionId, list)
  }

  /**
   * The most recent failed, non-escalated call of the same tool in this session that is related to
   * this request: the same command, or one touching the same outside path. Unrelated failures are
   * left out rather than shown as misleading context.
   */
  function previousFailure(sessionId, tool, args, facts) {
    const list = (failures.get(sessionId) ?? []).filter(f => f.tool === tool && now() - f.at <= FAILURE_WINDOW_MS)
    if (list.length === 0) return undefined
    const shell = tool === 'pwsh' || tool === 'bash'
    const same = f => shell
      ? String(f.args?.command ?? '').trim() === String(args?.command ?? '').trim()
      : f.args?.file_path === args?.file_path
    const paths = [...(facts?.outsidePaths ?? []), ...(facts?.target ? [facts.target] : [])]
      .filter(p => typeof p === 'string' && p.length > 3)
      .map(p => p.toLowerCase())
    const related = (f) => {
      const text = `${f.args?.command ?? f.args?.file_path ?? ''}\n${f.summary.outputTail ?? ''}`.toLowerCase()
      return paths.some(p => text.includes(p) || text.includes(p.replace(/\\/g, '/')))
    }
    const pick = [...list].reverse().find(same) ?? [...list].reverse().find(related)
    if (pick === undefined) return undefined
    return {
      sameCommand: same(pick),
      secondsAgo: Math.round((now() - pick.at) / 1000),
      ...(tool === 'pwsh' || tool === 'bash' ? { command: clip(pick.args?.command, 4000) } : { filePath: pick.args?.file_path }),
      ...pick.summary,
    }
  }

  /**
   * Run the synchronous layers for one request and log it.
   * @returns {Plan | null} null when the plugin is off.
   */
  function evaluate(req, id, startedAt) {
    const global = mode()
    if (global.effective === 'off') return null
    const toolName = req?.toolName
    const record = req?.callId === undefined ? undefined : calls.get(req.callId)
    const session = WATCHED_TOOLS.includes(toolName) ? sessionInfo(req.agent) : undefined
    const decision = decide({ toolName, reason: req?.reason, record, session, host, allowlist, fingerprint })
    const outOfScope = decision.layer === 'out-of-scope'
    const current = outOfScope ? global : sessionMode(global, session)
    const unattended = !outOfScope && (session?.origin === 'subagent' || session?.trigger === 'schedule')
    /** @type {Plan} */
    const plan = {
      id,
      startedAt,
      mode: current.effective === 'auto' ? 'auto' : 'observe',
      action: outOfScope ? 'pass' : decision.action,
      layer: decision.layer,
      unattended,
      review: null,
      tracked: null,
      toolName,
      session,
      decision,
      record,
    }
    const entry = {
      id,
      tool: toolName,
      callId: req?.callId,
      mode: current.effective,
      configuredMode: current.configured,
      ...(current.note ? { modeNote: current.note } : {}),
      scope: decision.scope,
      layer: decision.layer,
      proposed: decision.action,
    }
    if (outOfScope) {
      entry.reason = clip(req?.reason, 500)
    } else {
      const prior = previousFailure(session?.sessionId, toolName, record?.args, decision.hard?.facts)
      Object.assign(entry, {
        sessionId: session?.sessionId,
        workspaceRoot: session?.workspaceRoot,
        cwd: session?.cwd,
        ...(session?.preset !== undefined ? { preset: session.preset } : {}),
        ...(unattended ? { unattended: true, trigger: session?.trigger, origin: session?.origin } : {}),
        ...describeArgs(toolName, record?.args),
        justification: clip(record?.args?.justification, 2000),
        contaminatedBy: decision.contaminatedBy ?? undefined,
        findings: decision.hard?.findings ?? [],
        facts: compactFacts(decision.hard?.facts),
        previousFailure: prior,
        ...describeAllowlist(decision),
      })
      if (decision.layer === 'hard-pass') {
        const settings = getSettings()
        const built = buildPayload({ tool: toolName, args: record.args, facts: decision.hard.facts, previousFailure: prior, host, workspaceRoot: session.workspaceRoot, os: osLabel, readText })
        if (!built.ok) {
          Object.assign(entry, { layer: 'model-input', proposed: 'ask', modelInputProblem: built.reason })
        } else {
          const injected = detectInjection(...built.texts)
          if (injected !== null) {
            entry.layer = 'hard-ask'
            entry.findings = [...entry.findings, { level: 'ask', rule: 'ask.injection', message: M['ask.injection'], evidence: injected }]
          } else {
            Object.assign(entry, { layer: 'model', proposed: 'pending', sentToModel: built.payload })
            plan.review = { payload: built.payload, settings }
          }
        }
        plan.layer = entry.layer
        plan.action = plan.review !== null ? 'review' : 'ask'
      }
      plan.tracked = { id, workdir: decision.hard?.facts?.workdir, layer: entry.layer, fingerprint: decision.fingerprint, shadowHit: decision.allowlist?.status === 'hit', done: false }
      if (escalated.size >= MAX_CALLS) escalated.delete(escalated.keys().next().value)
      escalated.set(req.callId, plan.tracked)
    }
    entry.evaluateMs = now() - startedAt
    log.write('request', entry)
    return plan
  }

  /**
   * Answer or forward one approval request.
   * @param {any} req
   * @param {() => any} next
   * @returns {Promise<string>}
   */
  function onApproval(req, next) {
    const startedAt = now()
    const id = randomUUID()
    let plan = null
    let broken = false
    try {
      plan = evaluate(req, id, startedAt)
    } catch (error) {
      broken = true
      log.write('error', { where: 'approval', id, message: message(error) })
    }
    if (plan !== null && plan.mode === 'auto' && plan.action !== 'pass') return act(plan, req, next)
    // Observe mode: the review runs alongside the prompt and never delays it.
    if (plan?.review) reviewAlongside(plan)
    return forward({ id, startedAt, tracked: plan?.tracked ?? null, quiet: plan === null && !broken }, next)
  }

  /**
   * Hand the request to the next answerer (the user) and log what came back.
   * @param {{ id: string, startedAt: number, tracked: Tracked | null, quiet: boolean, because?: string }} at
   * @param {() => any} next
   */
  function forward({ id, startedAt, tracked, quiet, because }, next) {
    const note = because !== undefined ? { because } : {}
    let forwarded
    try {
      forwarded = next()
    } catch (error) {
      if (!quiet) log.write('outcome', { id, decidedBy: 'user', ...note, error: message(error) })
      throw error
    }
    return Promise.resolve(forwarded).then(
      (outcome) => {
        if (!quiet) log.write('outcome', { id, decidedBy: 'user', ...note, outcome, waitedMs: now() - startedAt })
        if (tracked !== null) tracked.outcome = outcome
        return outcome
      },
      (error) => {
        if (!quiet) log.write('outcome', { id, decidedBy: 'user', ...note, error: message(error) })
        throw error
      },
    )
  }

  /**
   * Auto mode: decide on the hard rules and the model review, or hand the request to the user.
   * Whatever goes wrong on the way hands it to the user; nothing is ever allowed on an error.
   * @param {Plan} plan
   * @param {any} req
   * @param {() => any} next
   */
  async function act(plan, req, next) {
    let action = plan.action
    let because = plan.layer
    try {
      if (action === 'review') {
        const result = await reviewNow(plan, req?.signal)
        // dsh has withdrawn the question (the call was stopped): its answer no longer matters.
        if (req?.signal?.aborted) return settle(plan, 'cancelled', 'request-cancelled')
        action = actionFor(result)
        because = action === 'allow-once' ? 'model-allow' : action === 'reject' ? 'model-deny' : 'model-ask'
      }
      if (action === 'allow-once') return settle(plan, 'allowed-once', because, snapshotFor(plan))
      if (action === 'reject') return settle(plan, 'rejected', because)
      if (plan.unattended) return settle(plan, 'rejected', 'unattended')
    } catch (error) {
      log.write('error', { where: 'auto', id: plan.id, message: message(error) })
      because = 'error'
    }
    return forward({ id: plan.id, startedAt: plan.startedAt, tracked: plan.tracked, quiet: false, because }, next)
  }

  /**
   * Record the plugin's own answer.
   * @param {Plan} plan
   * @param {'allowed-once' | 'rejected' | 'cancelled'} outcome
   * @param {string} because - the layer or reason behind it.
   * @param {object} [snapshot]
   */
  function settle(plan, outcome, because, snapshot) {
    log.write('outcome', { id: plan.id, decidedBy: 'doorman', outcome, because, ...(snapshot !== undefined ? { snapshot } : {}), waitedMs: now() - plan.startedAt })
    if (plan.tracked !== null) plan.tracked.outcome = outcome
    return outcome
  }

  /**
   * Snapshot what an auto-allowed call is known to change, before it runs. Throws when the
   * snapshot cannot be written: the call then goes to the user instead.
   * @param {Plan} plan
   * @returns {object | undefined} what was kept, for the outcome line.
   */
  function snapshotFor(plan) {
    if (snapshots === undefined) return undefined
    const { toolName, decision, session, record } = plan
    const taken = capture({ tool: toolName, facts: decision.hard?.facts, host, workspaceRoot: session?.workspaceRoot })
    if (taken.files.length === 0 && taken.dirs.length === 0) return taken.skipped.length > 0 ? { skipped: taken.skipped } : undefined
    const shell = toolName === 'pwsh' || toolName === 'bash'
    const saved = snapshots.save({
      id: plan.id,
      at: new Date(now()).toISOString(),
      tool: toolName,
      sessionId: session?.sessionId,
      workspaceRoot: session?.workspaceRoot,
      ...(shell ? { command: record?.args?.command } : { filePath: record?.args?.file_path }),
      files: taken.files,
      dirs: taken.dirs,
      skipped: taken.skipped,
    })
    if (plan.tracked !== null && taken.dirs.length > 0) plan.tracked.listing = taken.dirs
    return {
      file: path.basename(saved.file),
      files: taken.files.length,
      notDiffable: taken.files.filter(f => !f.diffable).map(f => ({ path: f.path, reason: f.reason })),
      dirs: taken.dirs.length,
      entries: taken.dirs.reduce((n, d) => n + d.entries.length, 0),
      ...(taken.skipped.length > 0 ? { skipped: taken.skipped } : {}),
    }
  }

  /**
   * Auto mode's review: the request waits for it (and is withdrawn with it).
   * @param {Plan} plan
   * @param {AbortSignal | undefined} signal
   */
  async function reviewNow(plan, signal) {
    const { payload, settings } = /** @type {NonNullable<Plan['review']>} */ (plan.review)
    let result
    try {
      result = await reviewImpl({ payload, settings, getKey, limiter, fetchImpl, signal })
      log.write('model', { id: plan.id, ...summarizeReview(result), proposed: actionFor(result) })
    } catch (error) {
      result = { status: 'error', kind: 'internal' }
      log.write('model', { id: plan.id, status: 'error', kind: 'internal', message: message(error), proposed: 'ask' })
    }
    if (plan.tracked !== null) {
      plan.tracked.verdict = result
      postCheck(plan.tracked)
    }
    return result
  }

  /**
   * Observe mode's review: it runs alongside the prompt, and its verdict is only logged.
   * @param {Plan} plan
   */
  function reviewAlongside(plan) {
    const { payload, settings } = /** @type {NonNullable<Plan['review']>} */ (plan.review)
    const { id, tracked } = plan
    Promise.resolve()
      .then(() => reviewImpl({ payload, settings, getKey, limiter, fetchImpl }))
      .then(
        (result) => {
          log.write('model', { id, ...summarizeReview(result), proposed: actionFor(result) })
          return result
        },
        (error) => {
          log.write('model', { id, status: 'error', kind: 'internal', message: message(error), proposed: 'ask' })
          return { status: 'error', kind: 'internal' }
        },
      )
      .then((result) => {
        if (tracked === null) return
        tracked.verdict = result
        postCheck(tracked)
      })
      .catch(error => log.write('error', { where: 'model', id, message: message(error) }))
  }

  /**
   * The deterministic post-check of a finished escalated call, and what the allowlist learns from it
   * (design §2 事后检查 and §5; the model's look at the output comes in a later stage). A listed command
   * that misbehaved — or was turned down — is blocked ("以后都弹给我"); an eligible command the model
   * allowed at low risk that finished cleanly is added. It runs once the result and, for a reviewed
   * call, the verdict are both in, whichever comes last.
   * @param {Tracked} tracked
   */
  function postCheck(tracked) {
    if (allowlist === undefined || tracked.done || tracked.fingerprint === undefined) return
    try {
      const fp = tracked.fingerprint
      if (tracked.layer === 'allowlist-hit' || tracked.shadowHit) {
        if (tracked.summary === undefined) return
        tracked.done = true
        const problems = postCheckProblems(tracked)
        if (problems.length === 0) {
          allowlist.touch(fp)
          return
        }
        const entry = allowlist.block(fp, problems)
        log.write(would('remove'), { id: tracked.id, commandKey: fp.key.slice(0, 16), entryId: entry?.id, block: true, problems })
        return
      }
      if (tracked.layer !== 'model' || !fp.eligible) return
      if (tracked.summary === undefined || tracked.verdict === undefined) return
      tracked.done = true
      const verdict = tracked.verdict
      if (verdict.status !== 'ok' || verdict.decision !== 'allow' || verdict.risk !== 'low') return
      if (postCheckProblems(tracked).length > 0) return
      // A repeat would overwrite what this run created outside the workspace.
      if (fp.outsideWrites.some(p => host.exists(p))) return
      const entry = allowlist.add(fp, { explanation: verdict.explanation, model: verdict.model })
      if (entry !== null) {
        log.write(would('add'), { id: tracked.id, commandKey: fp.key.slice(0, 16), entryId: entry.id, dependsOn: entry.dependsOn, explanation: verdict.explanation, model: verdict.model })
      }
    } catch (error) {
      log.write('error', { where: 'allowlist', id: tracked.id, message: message(error) })
    }
  }

  /**
   * Check the model connection with a fixed, harmless request.
   * @param {string} trigger - why the check runs (startup, key-changed, settings-changed).
   */
  async function selfTest(trigger) {
    const settings = getSettings()
    let result
    try {
      result = await reviewImpl({ payload: selfTestPayload(osLabel), settings, getKey, limiter, fetchImpl })
    } catch (error) {
      result = { status: 'error', kind: 'internal', message: message(error) }
    }
    log.write('model-selftest', { trigger, model: settings.model, baseUrl: settings.baseUrl, ...summarizeReview(result) })
    return result
  }

  return { onPreExecute, onResult, onApproval, selfTest, mode }
}

/**
 * The allowlist part of a request log line: the command's evidence hash (the identity key, shortened;
 * the command itself is already on the line), whether it may be listed and why not, the files it is
 * bound to, and what the lookup found.
 */
function describeAllowlist({ fingerprint: fp, allowlist: found }) {
  if (fp === undefined) return found === undefined ? {} : { allowlist: { lookup: found.status, message: found.message } }
  return {
    ...(typeof fp.key === 'string' ? { commandKey: fp.key.slice(0, 16) } : {}),
    allowlist: {
      lookup: found?.status,
      ...(found?.entry !== undefined ? { entryId: found.entry.id } : {}),
      ...(found?.message !== undefined ? { message: found.message } : {}),
      eligible: fp.eligible,
      ...(fp.reasons.length > 0 ? { reasons: fp.reasons } : {}),
      dependsOn: fp.dependsOn,
    },
  }
}

/** Keep facts readable in logs. */
function compactFacts(facts) {
  if (facts === undefined || facts === null) return undefined
  const cap = (list, n = 20) => (Array.isArray(list) ? list.slice(0, n) : undefined)
  return {
    workdir: facts.workdir,
    target: facts.target,
    exists: facts.exists,
    outside: facts.outside,
    opaque: facts.opaque,
    inlineCode: facts.inlineCode,
    deletes: cap(facts.deletes),
    writes: cap(facts.writes),
    moves: cap(facts.moves),
    runs: cap(facts.runs),
    unknownRuns: cap(facts.unknownRuns, 10),
    downloads: facts.downloads,
    packageScripts: facts.packageScripts,
    outsidePaths: cap(facts.outsidePaths),
    commands: cap(facts.commands, 40),
    sessionChanges: cap(facts.sessionChanges, 10),
    parseIssues: cap(facts.parseIssues, 10),
  }
}

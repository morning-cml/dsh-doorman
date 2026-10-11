/**
 * The stateful glue between dsh's events and the pure decision code:
 * remembers each watched tool call's arguments (tools/pre-execute), recent
 * failed calls per session (tools/result), and handles approval requests
 * (approval/request). dsh-specific lookups are injected so this module can be
 * tested with a fake event bus.
 *
 * This build observes only: every approval request goes on to the user. For a
 * request that passes the hard rules, the model review runs alongside the
 * prompt (never delaying it) and its verdict is logged next to the user's choice.
 */

import { randomUUID } from 'node:crypto'
import { WATCHED_TOOLS, decide } from './engine.js'
import { createLimiter } from './model/limiter.js'
import { buildPayload, selfTestPayload } from './model/payload.js'
import { review as defaultReview } from './model/review.js'
import { actionFor } from './model/verdict.js'
import { detectInjection } from './rules/injection.js'
import { M } from './rules/messages.js'
import { clip } from './text.js'

const MAX_CALLS = 500
const MAX_FAILURES_PER_SESSION = 5
const FAILURE_WINDOW_MS = 10 * 60 * 1000

/**
 * @typedef {object} RuntimeOptions
 * @property {ReturnType<import('./host.js').createHost>} host
 * @property {() => ReturnType<import('./settings.js').readSettings>['settings']} getSettings
 * @property {{ write(event: string, data?: object): void }} log
 * @property {string | null} dshVersion
 * @property {(agent: any) => ({ sessionId: string | undefined, sandboxMode: string | undefined, workspaceRoot: string | undefined, cwd: string | undefined } | undefined)} sessionInfo
 * @property {(keyName: string) => Promise<string | undefined>} getKey
 * @property {(file: string) => string | undefined} readText
 * @property {string} osLabel
 * @property {typeof fetch} [fetchImpl]
 * @property {typeof defaultReview} [reviewImpl]
 * @property {boolean} [autoAvailable] - whether this build may act on decisions (later stages).
 * @property {() => number} [now]
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
 * Deterministic signals of a finished tool call.
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
  return {
    isError: result?.isError === true,
    errorMessage: result?.isError ? clip(result?.error?.message ?? text, 600) : undefined,
    exitCode: value?.exitCode,
    timedOut: value?.timedOut === true,
    aborted: value?.aborted === true,
    killed: typeof value?.signal === 'string' || typeof value?.stopped === 'string',
    sandboxDenied: value?.sandbox?.denied === true || text.includes('[sandbox: file access denied'),
    outputTail: clip(output, 1500),
  }
}

/** Whether a finished call failed. */
function failed(summary) {
  return summary.isError || summary.timedOut || summary.aborted || summary.killed || summary.sandboxDenied
    || (summary.exitCode !== undefined && summary.exitCode !== 0)
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
export function createRuntime({ host, getSettings, log, dshVersion, sessionInfo, getKey, readText, osLabel, fetchImpl, reviewImpl = defaultReview, autoAvailable = false, now = () => Date.now() }) {
  /** @type {Map<string, { name: string, args: any, sessionId: string | undefined, nested: boolean, at: number }>} */
  const calls = new Map()
  /** @type {Map<string, any[]>} */
  const failures = new Map()
  /** @type {Map<string, string>} escalated call id → request id */
  const escalated = new Map()
  const limiter = createLimiter(now)

  /**
   * The mode to act in right now.
   * @returns {{ configured: string, effective: 'observe' | 'auto' | 'off', note?: string }}
   */
  function mode() {
    const settings = getSettings()
    if (settings.mode === 'off') return { configured: 'off', effective: 'off' }
    if (settings.mode === 'auto') {
      if (!autoAvailable) return { configured: 'auto', effective: 'observe', note: '这个版本还没有自动模式（阶段 3 才有），按只观察运行' }
      if (dshVersion === null || settings.autoModeConfirmedForVersion !== dshVersion) {
        return { configured: 'auto', effective: 'observe', note: `dsh 版本 ${dshVersion ?? '未知'} 还没确认过，自动退回只观察` }
      }
      return { configured: 'auto', effective: 'auto' }
    }
    return { configured: settings.mode, effective: 'observe' }
  }

  /** @param {any} exec */
  function onPreExecute(exec) {
    if (exec === null || typeof exec !== 'object' || !WATCHED_TOOLS.includes(exec.name)) return
    if (calls.size >= MAX_CALLS) calls.delete(calls.keys().next().value)
    calls.set(exec.callId, {
      name: exec.name,
      args: exec.arguments,
      sessionId: exec.agent?.session?.header?.id,
      nested: exec.parent !== undefined,
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
    const requestId = escalated.get(exec.callId)
    if (requestId !== undefined) {
      escalated.delete(exec.callId)
      log.write('result', { id: requestId, callId: exec.callId, tool: record.name, ...summary })
      return
    }
    const escalating = typeof record.args?.sandbox_permissions === 'string'
    if (escalating || record.sessionId === undefined || !failed(summary)) return
    const list = failures.get(record.sessionId) ?? []
    list.push({ tool: record.name, args: record.args, at: now(), summary })
    while (list.length > MAX_FAILURES_PER_SESSION) list.shift()
    failures.set(record.sessionId, list)
  }

  /** The most recent failed, non-escalated call of the same tool in this session. */
  function previousFailure(sessionId, tool, args) {
    const list = (failures.get(sessionId) ?? []).filter(f => f.tool === tool && now() - f.at <= FAILURE_WINDOW_MS)
    if (list.length === 0) return undefined
    const same = f => (tool === 'pwsh' || tool === 'bash')
      ? String(f.args?.command ?? '').trim() === String(args?.command ?? '').trim()
      : f.args?.file_path === args?.file_path
    const pick = [...list].reverse().find(same) ?? list[list.length - 1]
    return {
      sameCommand: same(pick),
      secondsAgo: Math.round((now() - pick.at) / 1000),
      ...(tool === 'pwsh' || tool === 'bash' ? { command: clip(pick.args?.command, 4000) } : { filePath: pick.args?.file_path }),
      ...pick.summary,
    }
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
    let current = { effective: 'observe' }
    let pending = null
    try {
      current = mode()
      if (current.effective !== 'off') {
        const toolName = req?.toolName
        const record = req?.callId === undefined ? undefined : calls.get(req.callId)
        const session = WATCHED_TOOLS.includes(toolName) ? sessionInfo(req.agent) : undefined
        const decision = decide({ toolName, reason: req?.reason, record, session, host })
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
        if (decision.layer === 'out-of-scope') {
          entry.reason = clip(req?.reason, 500)
        } else {
          const prior = previousFailure(session?.sessionId, toolName, record?.args)
          Object.assign(entry, {
            sessionId: session?.sessionId,
            workspaceRoot: session?.workspaceRoot,
            cwd: session?.cwd,
            ...describeArgs(toolName, record?.args),
            justification: clip(record?.args?.justification, 2000),
            contaminatedBy: decision.contaminatedBy ?? undefined,
            findings: decision.hard?.findings ?? [],
            facts: compactFacts(decision.hard?.facts),
            previousFailure: prior,
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
                pending = { payload: built.payload, settings }
              }
            }
          }
          if (escalated.size >= MAX_CALLS) escalated.delete(escalated.keys().next().value)
          escalated.set(req.callId, id)
        }
        entry.evaluateMs = now() - startedAt
        log.write('request', entry)
      }
    } catch (error) {
      log.write('error', { where: 'approval', id, message: message(error) })
    }

    if (pending !== null) {
      // Observe mode: the review runs alongside the prompt and never delays it.
      const { payload, settings } = pending
      Promise.resolve()
        .then(() => reviewImpl({ payload, settings, getKey, limiter, fetchImpl }))
        .then(
          result => log.write('model', { id, ...summarizeReview(result), proposed: actionFor(result) }),
          error => log.write('model', { id, status: 'error', kind: 'internal', message: message(error), proposed: 'ask' }),
        )
    }

    // This build never answers on its own: every request goes on to the user.
    let forwarded
    try {
      forwarded = next()
    } catch (error) {
      log.write('outcome', { id, decidedBy: 'user', error: message(error) })
      throw error
    }
    return Promise.resolve(forwarded).then(
      (outcome) => {
        if (current.effective !== 'off') log.write('outcome', { id, decidedBy: 'user', outcome, waitedMs: now() - startedAt })
        return outcome
      },
      (error) => {
        if (current.effective !== 'off') log.write('outcome', { id, decidedBy: 'user', error: message(error) })
        throw error
      },
    )
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
    downloads: facts.downloads,
    packageScripts: facts.packageScripts,
    outsidePaths: cap(facts.outsidePaths),
    commands: cap(facts.commands, 40),
    parseIssues: cap(facts.parseIssues, 10),
  }
}

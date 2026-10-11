/**
 * The stateful glue between dsh's events and the pure decision code:
 * remembers each watched tool call's arguments (tools/pre-execute), recent
 * failed calls per session (tools/result), and answers or forwards approval
 * requests (approval/request). dsh-specific lookups are injected so this
 * module can be tested with a fake event bus.
 */

import { randomUUID } from 'node:crypto'
import { WATCHED_TOOLS, decide } from './engine.js'
import { clip } from './text.js'

const MAX_CALLS = 500
const MAX_FAILURES_PER_SESSION = 5
const FAILURE_WINDOW_MS = 10 * 60 * 1000

/**
 * @typedef {object} RuntimeOptions
 * @property {ReturnType<import('./host.js').createHost>} host
 * @property {{ get(): any }} configStore
 * @property {{ write(event: string, data?: object): void }} log
 * @property {string | null} dshVersion
 * @property {(agent: any) => ({ sessionId: string | undefined, sandboxMode: string | undefined, workspaceRoot: string | undefined, cwd: string | undefined } | undefined)} sessionInfo
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

/**
 * Create the runtime.
 * @param {RuntimeOptions} options
 */
export function createRuntime({ host, configStore, log, dshVersion, sessionInfo, autoAvailable = false, now = () => Date.now() }) {
  /** @type {Map<string, { name: string, args: any, sessionId: string | undefined, nested: boolean, at: number }>} */
  const calls = new Map()
  /** @type {Map<string, any[]>} */
  const failures = new Map()
  /** @type {Map<string, string>} escalated call id → request id */
  const escalated = new Map()

  /**
   * The mode to act in right now.
   * @returns {{ configured: string, effective: 'observe' | 'auto' | 'off', note?: string }}
   */
  function mode() {
    const config = configStore.get()
    if (config.mode === 'off') return { configured: 'off', effective: 'off' }
    if (config.mode === 'auto') {
      if (!autoAvailable) return { configured: 'auto', effective: 'observe', note: '这个版本还没有自动模式（阶段 3 才有），按只观察运行' }
      if (dshVersion === null || config.autoModeConfirmedForVersion !== dshVersion) {
        return { configured: 'auto', effective: 'observe', note: `dsh 版本 ${dshVersion ?? '未知'} 还没确认过，自动退回只观察` }
      }
      return { configured: 'auto', effective: 'auto' }
    }
    return { configured: config.mode, effective: 'observe' }
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
          Object.assign(entry, {
            sessionId: session?.sessionId,
            workspaceRoot: session?.workspaceRoot,
            cwd: session?.cwd,
            ...describeArgs(toolName, record?.args),
            justification: clip(record?.args?.justification, 2000),
            contaminatedBy: decision.contaminatedBy ?? undefined,
            findings: decision.hard?.findings ?? [],
            facts: compactFacts(decision.hard?.facts),
            previousFailure: previousFailure(session?.sessionId, toolName, record?.args),
          })
          escalated.set(req.callId, id)
        }
        entry.evaluateMs = now() - startedAt
        log.write('request', entry)
      }
    } catch (error) {
      log.write('error', { where: 'approval', id, message: message(error) })
    }

    // Stage 1 never answers on its own: every request goes on to the user.
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

  return { onPreExecute, onResult, onApproval, mode }
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

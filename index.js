/**
 * dsh-doorman — stage 0 probe.
 *
 * Observe only: this plugin records sandbox-escalation approval requests, the
 * tool arguments behind them, the preceding sandbox denial, and the outcome the
 * user picked. It never answers an approval itself — every request is passed on
 * with next() and the answer is returned unchanged. Any internal error is
 * swallowed so the Host keeps working exactly as without the plugin.
 */

import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

export const name = 'dsh-doorman'

/** Tools whose escalation requests the full plugin will judge; the probe records their arguments. */
const WATCHED_TOOLS = new Set(['bash', 'pwsh', 'write', 'edit'])
/** Upper bound on remembered in-flight calls, so a stuck call can never grow memory without limit. */
const MAX_PENDING = 500
/** Sandbox denials remembered per agent, newest last. */
const MAX_DENIALS_PER_AGENT = 5
const DENIAL_MARKER = '[sandbox: file access denied under'

/**
 * The harness home: $DSH_HOME when the Host has it, else ~/.dsh.
 * @returns absolute directory path.
 */
function dshHome() {
  const fromEnv = process.env.DSH_HOME
  if (typeof fromEnv === 'string' && fromEnv.trim() !== '') return path.resolve(fromEnv)
  return path.join(os.homedir(), '.dsh')
}

/**
 * Shorten long text, keeping head and tail so paths at either end survive.
 * @param {unknown} value - text to shorten; non-strings become ''.
 * @param {number} max - maximum characters kept.
 * @returns {string}
 */
function clip(value, max) {
  if (typeof value !== 'string') return ''
  if (value.length <= max) return value
  const half = Math.floor(max / 2)
  return `${value.slice(0, half)}\n…[${value.length - max} chars omitted]…\n${value.slice(-half)}`
}

/** Error message for a log line, never throwing. */
function errorText(error) {
  try {
    return clip(error instanceof Error ? `${error.name}: ${error.message}` : String(error), 500)
  } catch {
    return 'unprintable error'
  }
}

/**
 * The arguments that matter for judging a watched call, copied into plain data.
 * @param {string} toolName - tool name.
 * @param {any} args - the frozen parsed arguments.
 */
function summarizeArgs(toolName, args) {
  if (args === null || typeof args !== 'object') return { raw: clip(String(args), 2000) }
  const escalation = {
    sandbox_permissions: args.sandbox_permissions,
    justification: clip(args.justification, 2000),
  }
  if (toolName === 'pwsh' || toolName === 'bash') {
    return {
      command: clip(args.command, 20000),
      workdir: args.workdir,
      description: clip(args.description, 500),
      timeoutMs: args.timeoutMs,
      run_in_background: args.run_in_background,
      ...escalation,
    }
  }
  if (toolName === 'write') {
    return {
      file_path: args.file_path,
      contentLength: typeof args.content === 'string' ? args.content.length : undefined,
      contentHead: clip(args.content, 600),
      ...escalation,
    }
  }
  if (toolName === 'edit') {
    return {
      file_path: args.file_path,
      replace_all: args.replace_all,
      oldHead: clip(args.old_string, 400),
      newHead: clip(args.new_string, 400),
      ...escalation,
    }
  }
  return {}
}

/** Concatenated text blocks of a tool result. */
function resultText(result) {
  if (!result || !Array.isArray(result.content)) return ''
  return result.content
    .filter(block => block && block.type === 'text' && typeof block.text === 'string')
    .map(block => block.text)
    .join('\n')
}

/** Deterministic signals of a finished call, in plain data. */
function summarizeResult(result) {
  const value = result && typeof result.value === 'object' && result.value !== null ? result.value : undefined
  return {
    resultKeys: result ? Object.keys(result) : [],
    isError: result?.isError,
    errorMessage: result?.isError ? clip(result.error?.message, 1500) : undefined,
    kind: value?.kind,
    exitCode: value?.exitCode,
    signal: value?.signal,
    timedOut: value?.timedOut,
    aborted: value?.aborted,
    stopped: value?.stopped,
    sandbox: value?.sandbox,
    stderrTail: clip(value?.stderr?.text, 1500),
    stdoutTail: clip(value?.stdout?.text, 800),
    text: clip(resultText(result), 2500),
  }
}

/**
 * Find the dsh runtime version without executing any dsh code: resolve the
 * app-boot package entry, then read the version of its package.json.
 */
function detectDshVersion() {
  const found = {}
  for (const specifier of ['@deepseek-ai/dsh-app-boot', '@deepseek-ai/dsh']) {
    try {
      const entry = fileURLToPath(import.meta.resolve(specifier))
      let dir = path.dirname(entry)
      for (let depth = 0; depth < 6; depth += 1) {
        const manifestPath = path.join(dir, 'package.json')
        if (fs.existsSync(manifestPath)) {
          const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'))
          if (manifest && manifest.name === specifier) {
            found[specifier] = { version: manifest.version, dir }
            break
          }
        }
        const parent = path.dirname(dir)
        if (parent === dir) break
        dir = parent
      }
      if (found[specifier] === undefined) found[specifier] = { entry, version: null }
    } catch (error) {
      found[specifier] = { error: errorText(error) }
    }
  }
  return found
}

/** Facts about where and how this plugin copy is installed. */
function installFacts() {
  const facts = {}
  try {
    const self = fileURLToPath(import.meta.url)
    facts.selfFile = self
    facts.selfNlink = fs.statSync(self).nlink
    const dir = path.dirname(self)
    facts.dirIsSymlink = fs.lstatSync(dir).isSymbolicLink()
    facts.realDir = fs.realpathSync.native(dir)
  } catch (error) {
    facts.error = errorText(error)
  }
  return facts
}

/**
 * Plugin entry. Every step is guarded: a failure here only disables the probe.
 * @param {any} ctx - the Cordis plugin context.
 */
export function apply(ctx) {
  let logFile
  try {
    const dataDir = path.join(dshHome(), 'dsh-doorman')
    fs.mkdirSync(dataDir, { recursive: true })
    logFile = path.join(dataDir, 'probe.jsonl')
  } catch {
    logFile = undefined
  }

  /** Append one JSON line; failures are ignored on purpose. */
  const log = (event, data) => {
    if (logFile === undefined) return
    try {
      fs.appendFileSync(logFile, `${JSON.stringify({ time: new Date().toISOString(), event, ...data })}\n`, 'utf8')
    } catch {
      // Logging must never break the Host.
    }
  }

  /** In-flight watched calls, keyed by call id. */
  const pending = new Map()
  /** Recent sandbox denials per agent id. */
  const denials = new Map()

  const rememberCall = (exec) => {
    if (pending.size >= MAX_PENDING) {
      const oldest = pending.keys().next().value
      pending.delete(oldest)
    }
    pending.set(exec.callId, {
      name: exec.name,
      args: exec.arguments,
      agentId: exec.agent?.id,
      nested: exec.parent !== undefined,
      at: Date.now(),
    })
  }

  const sessionFacts = (agent) => {
    const facts = {}
    try {
      const session = agent?.session
      facts.agentId = agent?.id
      facts.sessionId = session?.header?.id
      facts.cwd = session?.header?.cwd
      facts.origin = session?.header?.origin
      facts.delegationDepth = session?.header?.delegationDepth
      const policyService = ctx.get('sandboxPolicy')
      if (policyService && session) {
        const policy = policyService.resolve({ session })
        facts.sandboxMode = policy?.mode
        facts.workspaceRoot = policy?.workspaceRoot
      }
      const approval = ctx.get('approval')
      if (approval && session && typeof approval.overrideOf === 'function') {
        facts.approvalOverride = approval.overrideOf(session) ?? null
      }
    } catch (error) {
      facts.error = errorText(error)
    }
    return facts
  }

  try {
    log('probe-started', {
      platform: process.platform,
      node: process.versions.node,
      electron: process.versions.electron,
      execPath: process.execPath,
      cwd: process.cwd(),
      home: os.homedir(),
      tmpdir: os.tmpdir(),
      env: {
        DSH_HOME: process.env.DSH_HOME,
        DSH_PROFILE: process.env.DSH_PROFILE,
        DSH_PROFILE_DIR: process.env.DSH_PROFILE_DIR,
      },
      services: {
        approval: ctx.get('approval') !== undefined,
        sandboxPolicy: ctx.get('sandboxPolicy') !== undefined,
        credentials: ctx.get('credentials') !== undefined,
        tools: ctx.get('tools') !== undefined,
      },
      dshVersion: detectDshVersion(),
      install: installFacts(),
    })
  } catch (error) {
    log('probe-start-error', { error: errorText(error) })
  }

  try {
    ctx.on('tools/pre-execute', (exec, next) => {
      try {
        if (exec && WATCHED_TOOLS.has(exec.name)) rememberCall(exec)
      } catch {
        // Recording is best effort; the decision is always delegated.
      }
      return next()
    }, { prepend: true })

    ctx.on('tools/result', (exec, result) => {
      try {
        const record = exec ? pending.get(exec.callId) : undefined
        if (record === undefined) return
        pending.delete(exec.callId)
        const summary = summarizeResult(result)
        const escalated = typeof record.args?.sandbox_permissions === 'string'
        const denied = summary.sandbox?.denied === true || summary.text.includes(DENIAL_MARKER)
        if (denied) {
          const list = denials.get(record.agentId) ?? []
          list.push({ callId: exec.callId, name: record.name, args: summarizeArgs(record.name, record.args), at: Date.now(), summary })
          while (list.length > MAX_DENIALS_PER_AGENT) list.shift()
          denials.set(record.agentId, list)
          log('sandbox-denied', { callId: exec.callId, tool: record.name, nested: record.nested, args: summarizeArgs(record.name, record.args), result: summary })
        }
        if (escalated) {
          log('escalated-call-finished', { callId: exec.callId, tool: record.name, args: summarizeArgs(record.name, record.args), result: summary })
        }
      } catch (error) {
        log('result-observer-error', { error: errorText(error) })
      }
    })

    ctx.on('approval/request', (req, next) => {
      const startedAt = Date.now()
      let entry
      try {
        const record = req?.callId === undefined ? undefined : pending.get(req.callId)
        const watched = WATCHED_TOOLS.has(req?.toolName)
        entry = {
          tool: req?.toolName,
          callId: req?.callId,
          reason: clip(req?.reason, 4000),
          displayReasonZh: clip(req?.displayReason?.zh, 1000),
          session: sessionFacts(req?.agent),
        }
        if (watched) {
          entry.argsFound = record !== undefined
          if (record !== undefined) {
            entry.args = summarizeArgs(record.name, record.args)
            entry.nested = record.nested
            entry.reasonMatchesArgs = req.reason === `escalate sandbox to ${record.args?.sandbox_permissions}: ${record.args?.justification}`
          }
          const recent = denials.get(req?.agent?.id) ?? []
          entry.recentDenials = recent.map(d => ({ callId: d.callId, name: d.name, args: d.args, secondsAgo: Math.round((startedAt - d.at) / 1000), stderrTail: d.summary.stderrTail, text: d.summary.text }))
        }
        log('approval-request', entry)
      } catch (error) {
        log('approval-observer-error', { error: errorText(error) })
      }
      // The decision always belongs to the next answerer (ultimately the user).
      return Promise.resolve(next()).then(
        (outcome) => {
          log('approval-decided', { tool: entry?.tool, callId: entry?.callId, outcome, waitedMs: Date.now() - startedAt })
          return outcome
        },
        (error) => {
          log('approval-next-threw', { tool: entry?.tool, callId: entry?.callId, error: errorText(error) })
          throw error
        },
      )
    }, { prepend: true })

    log('listeners-registered', {})
  } catch (error) {
    log('listener-registration-error', { error: errorText(error) })
  }
}

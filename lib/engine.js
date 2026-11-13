/**
 * The decision pipeline for one approval request, as pure functions:
 * scope → contaminated workspace → hard rules → allowlist → (model review: the runtime).
 * The result says which layer decided and what auto mode would do; the runtime
 * decides whether to act on it (auto) or only record it (observe). The allowlist
 * and the fingerprint function are injected by the runtime. A shadow allowlist
 * never decides an allow: its hit is only recorded and the request goes on to
 * the model review; its blocked entries and its errors still ask.
 */

import { evaluateHardRules } from './rules/hard-rules.js'
import { workspaceContamination, workspaceOf } from './rules/classify.js'

/** Tools whose sandbox escalations the plugin judges. */
export const WATCHED_TOOLS = Object.freeze(['pwsh', 'bash', 'write', 'edit'])

/**
 * Whether an approval request is a standard sandbox escalation the plugin may judge.
 * @param {object} input
 * @param {string} input.toolName
 * @param {unknown} input.reason
 * @param {{ name: string, args: any, nested: boolean } | undefined} input.record - arguments captured at pre-execute.
 * @param {string | undefined} input.sandboxMode - the session's standing sandbox mode.
 * @returns {'ok' | 'tool' | 'args-missing' | 'nested' | 'reason-mismatch' | 'mode'}
 */
export function checkScope({ toolName, reason, record, sandboxMode }) {
  if (!WATCHED_TOOLS.includes(toolName)) return 'tool'
  if (record === undefined || record.name !== toolName || record.args === null || typeof record.args !== 'object') return 'args-missing'
  if (record.nested) return 'nested'
  const { sandbox_permissions: target, justification } = record.args
  if (target !== 'danger-full-access' || typeof justification !== 'string') return 'reason-mismatch'
  if (reason !== `escalate sandbox to danger-full-access: ${justification}`) return 'reason-mismatch'
  if (sandboxMode !== 'workspace-write') return 'mode'
  return 'ok'
}

/**
 * An extra writable directory (dsh 0.2.2+ `additionalWritableRoots`) the agent can write without
 * escalating is as good as the workspace: if it overlaps a protected location, the plugin decides nothing.
 * @param {ReturnType<import('./host.js').createHost>} host
 * @param {string[] | undefined} roots
 * @returns {string | null} the label of the overlapped location, or null.
 */
function extraRootContamination(host, roots) {
  for (const root of roots ?? []) {
    const label = workspaceContamination(host, workspaceOf(host, root))
    if (label !== null) return `额外可写目录：${label}`
  }
  return null
}

/**
 * @typedef {object} Decision
 * @property {'ok' | 'tool' | 'args-missing' | 'nested' | 'reason-mismatch' | 'mode' | 'no-session'} scope
 * @property {'out-of-scope' | 'contaminated' | 'hard-deny' | 'hard-ask' | 'allowlist-hit' | 'allowlist-blocked' | 'allowlist-error' | 'hard-pass'} layer
 *   'hard-pass' continues to the model review.
 * @property {'reject' | 'ask' | 'allow-once'} action - what auto mode does.
 * @property {string | null} contaminatedBy
 * @property {import('./rules/hard-rules.js').HardRuleResult | undefined} hard
 * @property {import('./store/fingerprint.js').Fingerprint | undefined} [fingerprint]
 * @property {import('./store/allowlist.js').Lookup | undefined} [allowlist]
 */

/**
 * Run the synchronous layers for one request.
 * @param {object} input
 * @param {string} input.toolName
 * @param {unknown} input.reason
 * @param {{ name: string, args: any, nested: boolean } | undefined} input.record
 * @param {{ sandboxMode: string | undefined, workspaceRoot: string | undefined, cwd: string | undefined, extraWritableRoots?: string[] } | undefined} input.session
 * @param {ReturnType<import('./host.js').createHost>} input.host
 * @param {{ lookup(fp: any): import('./store/allowlist.js').Lookup, shadow?: boolean }} [input.allowlist] - layer 2; without it the layer is skipped.
 * @param {(input: { tool: string, args: any, facts: any, workspaceRoot: string | undefined }) => import('./store/fingerprint.js').Fingerprint} [input.fingerprint]
 * @returns {Decision}
 */
export function decide({ toolName, reason, record, session, host, allowlist, fingerprint }) {
  if (session === undefined) {
    return { scope: WATCHED_TOOLS.includes(toolName) ? 'no-session' : 'tool', layer: 'out-of-scope', action: 'ask', contaminatedBy: null, hard: undefined }
  }
  const scope = checkScope({ toolName, reason, record, sandboxMode: session.sandboxMode })
  if (scope !== 'ok') return { scope, layer: 'out-of-scope', action: 'ask', contaminatedBy: null, hard: undefined }

  const contaminatedBy = workspaceContamination(host, workspaceOf(host, session.workspaceRoot)) ?? extraRootContamination(host, session.extraWritableRoots)
  const hard = evaluateHardRules({ tool: toolName, args: record.args, host, workspaceRoot: session.workspaceRoot, extraWritableRoots: session.extraWritableRoots, cwd: session.cwd })
  if (contaminatedBy !== null) return { scope, layer: 'contaminated', action: 'ask', contaminatedBy, hard }
  if (hard.verdict === 'deny') return { scope, layer: 'hard-deny', action: 'reject', contaminatedBy, hard }
  if (hard.verdict === 'ask') return { scope, layer: 'hard-ask', action: 'ask', contaminatedBy, hard }
  if (allowlist === undefined || fingerprint === undefined) return { scope, layer: 'hard-pass', action: 'ask', contaminatedBy, hard }

  // Layer 2: an exact entry whose files are unchanged allows without asking the model (unless the list
  // only shadows); a blocked one asks.
  let print
  let found
  try {
    print = fingerprint({ tool: toolName, args: record.args, facts: hard.facts, workspaceRoot: session.workspaceRoot })
    found = allowlist.lookup(print)
  } catch (error) {
    found = { status: 'error', message: error instanceof Error ? error.message : String(error) }
  }
  const base = { scope, contaminatedBy, hard, fingerprint: print, allowlist: found }
  if (found.status === 'error') return { ...base, layer: 'allowlist-error', action: 'ask' }
  if (found.status === 'blocked') return { ...base, layer: 'allowlist-blocked', action: 'ask' }
  if (found.status === 'hit' && allowlist.shadow === false) return { ...base, layer: 'allowlist-hit', action: 'allow-once' }
  return { ...base, layer: 'hard-pass', action: 'ask' }
}

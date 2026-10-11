/**
 * The decision pipeline for one approval request, as pure functions:
 * scope → contaminated workspace → hard rules → (allowlist, model: later stages).
 * The result says which layer decided and what auto mode would do; the runtime
 * decides whether to act on it (auto) or only record it (observe).
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
 * @typedef {object} Decision
 * @property {'ok' | 'tool' | 'args-missing' | 'nested' | 'reason-mismatch' | 'mode' | 'no-session'} scope
 * @property {'out-of-scope' | 'contaminated' | 'hard-deny' | 'hard-ask' | 'allowlist' | 'model' | 'model-unavailable'} layer
 * @property {'reject' | 'ask' | 'allow-once'} action - what auto mode does.
 * @property {string | null} contaminatedBy
 * @property {import('./rules/hard-rules.js').HardRuleResult | undefined} hard
 */

/**
 * Run the synchronous layers for one request.
 * @param {object} input
 * @param {string} input.toolName
 * @param {unknown} input.reason
 * @param {{ name: string, args: any, nested: boolean } | undefined} input.record
 * @param {{ sandboxMode: string | undefined, workspaceRoot: string | undefined, cwd: string | undefined } | undefined} input.session
 * @param {ReturnType<import('./host.js').createHost>} input.host
 * @returns {Decision}
 */
export function decide({ toolName, reason, record, session, host }) {
  if (session === undefined) {
    return { scope: WATCHED_TOOLS.includes(toolName) ? 'no-session' : 'tool', layer: 'out-of-scope', action: 'ask', contaminatedBy: null, hard: undefined }
  }
  const scope = checkScope({ toolName, reason, record, sandboxMode: session.sandboxMode })
  if (scope !== 'ok') return { scope, layer: 'out-of-scope', action: 'ask', contaminatedBy: null, hard: undefined }

  const contaminatedBy = workspaceContamination(host, workspaceOf(host, session.workspaceRoot))
  const hard = evaluateHardRules({ tool: toolName, args: record.args, host, workspaceRoot: session.workspaceRoot, cwd: session.cwd })
  if (contaminatedBy !== null) return { scope, layer: 'contaminated', action: 'ask', contaminatedBy, hard }
  if (hard.verdict === 'deny') return { scope, layer: 'hard-deny', action: 'reject', contaminatedBy, hard }
  if (hard.verdict === 'ask') return { scope, layer: 'hard-ask', action: 'ask', contaminatedBy, hard }
  // Layers 2 (allowlist) and 3 (model review) arrive in later stages.
  return { scope, layer: 'model-unavailable', action: 'ask', contaminatedBy, hard }
}

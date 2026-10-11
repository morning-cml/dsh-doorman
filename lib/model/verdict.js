/**
 * Strict validation of the reviewer's answer. Only one exact JSON object is
 * accepted: {"decision", "risk", "explanation"} with closed values and no
 * contradictions. Anything else counts as "not sure" and goes to the user.
 */

export const DECISIONS = Object.freeze(['allow', 'ask_user', 'deny'])
export const RISKS = Object.freeze(['low', 'medium', 'high'])

/**
 * Number of members of the top-level JSON object (duplicates included),
 * so `{"decision":"deny", …, "decision":"allow"}` cannot pass as three keys.
 * @param {string} text - a JSON object literal.
 */
function topLevelMembers(text) {
  let depth = 0
  let inString = false
  let members = 0
  let sawContent = false
  for (let i = 0; i < text.length; i += 1) {
    const c = text[i]
    if (inString) {
      if (c === '\\') i += 1
      else if (c === '"') inString = false
      continue
    }
    if (c === '"') { inString = true; if (depth === 1) sawContent = true; continue }
    if (c === '{' || c === '[') { depth += 1; continue }
    if (c === '}' || c === ']') { depth -= 1; continue }
    if (c === ',' && depth === 1) members += 1
    else if (depth === 1 && !/\s/.test(c)) sawContent = true
  }
  return sawContent ? members + 1 : 0
}

/**
 * Parse and validate the reviewer's text.
 * @param {unknown} text
 * @returns {{ ok: true, decision: 'allow' | 'ask_user' | 'deny', risk: 'low' | 'medium' | 'high', explanation: string } | { ok: false, reason: string }}
 */
export function parseVerdict(text) {
  if (typeof text !== 'string') return { ok: false, reason: '没有回答内容' }
  let body = text.trim()
  const fenced = /^```(?:json)?[ \t]*\r?\n([\s\S]*?)\r?\n?```$/i.exec(body)
  if (fenced) body = fenced[1].trim()
  if (!body.startsWith('{') || !body.endsWith('}')) return { ok: false, reason: '回答不是单独一个 JSON 对象' }
  let value
  try {
    value = JSON.parse(body)
  } catch {
    return { ok: false, reason: '回答不是有效的 JSON' }
  }
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return { ok: false, reason: '回答不是 JSON 对象' }
  const keys = Object.keys(value).sort().join(',')
  if (keys !== 'decision,explanation,risk' || topLevelMembers(body) !== 3) return { ok: false, reason: `字段不对：${keys}` }
  const { decision, risk } = value
  if (!DECISIONS.includes(decision)) return { ok: false, reason: `decision 取值无效：${String(decision).slice(0, 20)}` }
  if (!RISKS.includes(risk)) return { ok: false, reason: `risk 取值无效：${String(risk).slice(0, 20)}` }
  if (decision === 'allow' && risk === 'high') return { ok: false, reason: '自相矛盾：allow 却是 high' }
  if (decision === 'deny' && risk === 'low') return { ok: false, reason: '自相矛盾：deny 却是 low' }
  if (typeof value.explanation !== 'string') return { ok: false, reason: 'explanation 不是文字' }
  // eslint-disable-next-line no-control-regex
  const explanation = value.explanation.replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/g, '').trim()
  if (explanation === '' || explanation.length > 600) return { ok: false, reason: 'explanation 为空或太长' }
  return { ok: true, decision, risk, explanation }
}

/**
 * What a verdict (or a failure to get one) means for the approval.
 * @param {{ status: string, decision?: string }} result
 * @returns {'allow-once' | 'reject' | 'ask'}
 */
export function actionFor(result) {
  if (result.status !== 'ok') return 'ask'
  if (result.decision === 'allow') return 'allow-once'
  if (result.decision === 'deny') return 'reject'
  return 'ask'
}

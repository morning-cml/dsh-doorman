/**
 * Layer 3: one model review. Checks the hourly budget and the key, sends the
 * sanitised payload, and validates the answer. Every failure — no key, budget
 * spent, timeout, HTTP error, malformed answer — comes back as a non-'ok'
 * status, which always means "ask the user".
 */

import { chatCompletion } from './client.js'
import { buildMessages } from './prompt.js'
import { parseVerdict } from './verdict.js'

const SEED = 7

/**
 * @typedef {{ status: 'ok', decision: 'allow' | 'ask_user' | 'deny', risk: 'low' | 'medium' | 'high', explanation: string, latencyMs: number, usage?: object, model?: string }
 *   | { status: 'disabled' | 'rate-limited' | 'no-key' | 'error' | 'invalid', kind?: string, message?: string, latencyMs?: number, usage?: object }} ReviewResult
 */

/**
 * Review one payload.
 * @param {object} options
 * @param {object} options.payload - the sanitised request data.
 * @param {ReturnType<import('../settings.js').readSettings>['settings']} options.settings
 * @param {(keyName: string) => Promise<string | undefined>} options.getKey
 * @param {ReturnType<import('./limiter.js').createLimiter>} options.limiter
 * @param {typeof fetch} [options.fetchImpl]
 * @param {AbortSignal} [options.signal]
 * @returns {Promise<ReviewResult>}
 */
export async function review({ payload, settings, getKey, limiter, fetchImpl, signal }) {
  if (!(settings.maxCallsPerHour > 0)) return { status: 'disabled', message: '每小时调用上限设为 0，不调用模型' }
  let apiKey
  try {
    apiKey = await getKey(settings.keyName)
  } catch {
    apiKey = undefined
  }
  if (typeof apiKey !== 'string' || apiKey.trim() === '') return { status: 'no-key', message: `没有找到 ${settings.keyName}` }
  if (!limiter.tryAcquire(settings.maxCallsPerHour)) return { status: 'rate-limited', message: `过去一小时已调用 ${limiter.used()} 次，达到上限` }

  const body = {
    model: settings.model,
    messages: buildMessages(payload),
    temperature: 0,
    seed: SEED,
    stream: false,
    ...(settings.jsonMode ? { response_format: { type: 'json_object' } } : {}),
    ...(settings.extraBody ?? {}),
  }
  const call = await chatCompletion({ fetchImpl, baseUrl: settings.baseUrl, apiKey: apiKey.trim(), body, timeoutMs: settings.timeoutSeconds * 1000, signal })
  if (!call.ok) return { status: 'error', kind: call.kind, message: call.message, latencyMs: call.latencyMs, ...(call.status ? { httpStatus: call.status } : {}) }
  const verdict = parseVerdict(call.content)
  if (!verdict.ok) return { status: 'invalid', message: verdict.reason, latencyMs: call.latencyMs, usage: call.usage, raw: call.content.slice(0, 300) }
  return { status: 'ok', decision: verdict.decision, risk: verdict.risk, explanation: verdict.explanation, latencyMs: call.latencyMs, usage: call.usage, model: call.model }
}

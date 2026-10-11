/**
 * One OpenAI-compatible chat-completions call, sent from the Host process.
 * `fetch` is injected so tests can use a stand-in. Every failure becomes a
 * plain result object; nothing here throws, and the API key never appears in
 * a result or an error message.
 */

import { clip } from '../text.js'
import { redactSecrets } from './redact.js'

/**
 * Provider error text, shortened and with anything key-like masked.
 * @param {string} text
 * @param {string} apiKey
 */
function providerMessage(text, apiKey) {
  let message = text
  try {
    const data = JSON.parse(text)
    message = data?.error?.message ?? data?.message ?? data?.error?.code ?? text
  } catch {
    message = text
  }
  let out = redactSecrets(String(message))
  if (apiKey.length >= 8) out = out.split(apiKey).join('[REDACTED]')
  return clip(out, 300)
}

/**
 * @typedef {{ ok: true, content: string, model?: string, usage?: { prompt_tokens?: number, completion_tokens?: number, total_tokens?: number }, latencyMs: number }
 *   | { ok: false, kind: 'timeout' | 'aborted' | 'network' | 'http' | 'format', status?: number, message: string, latencyMs: number }} CallResult
 */

/**
 * Call `<baseUrl>/chat/completions`.
 * @param {object} options
 * @param {typeof fetch} [options.fetchImpl]
 * @param {string} options.baseUrl
 * @param {string} options.apiKey
 * @param {object} options.body - the request body (model, messages, …).
 * @param {number} options.timeoutMs
 * @param {AbortSignal} [options.signal]
 * @param {() => number} [options.now]
 * @returns {Promise<CallResult>}
 */
export async function chatCompletion({ fetchImpl = globalThis.fetch, baseUrl, apiKey, body, timeoutMs, signal, now = () => Date.now() }) {
  const started = now()
  const elapsed = () => now() - started
  if (typeof fetchImpl !== 'function') return { ok: false, kind: 'network', message: 'fetch 不可用', latencyMs: 0 }
  const controller = new AbortController()
  let timedOut = false
  const timer = setTimeout(() => { timedOut = true; controller.abort(new Error('timeout')) }, timeoutMs)
  const onAbort = () => controller.abort(signal?.reason)
  if (signal?.aborted) onAbort()
  else signal?.addEventListener('abort', onAbort, { once: true })
  try {
    const response = await fetchImpl(`${String(baseUrl).replace(/\/+$/, '')}/chat/completions`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${apiKey}`, Accept: 'application/json' },
      body: JSON.stringify(body),
      signal: controller.signal,
    })
    const text = await response.text()
    if (!response.ok) return { ok: false, kind: 'http', status: response.status, message: providerMessage(text, apiKey), latencyMs: elapsed() }
    let data
    try {
      data = JSON.parse(text)
    } catch {
      return { ok: false, kind: 'format', message: '接口返回的不是 JSON', latencyMs: elapsed() }
    }
    const content = data?.choices?.[0]?.message?.content
    if (typeof content !== 'string') return { ok: false, kind: 'format', message: '接口返回里没有回答内容', latencyMs: elapsed() }
    const usage = data.usage && typeof data.usage === 'object'
      ? { prompt_tokens: data.usage.prompt_tokens, completion_tokens: data.usage.completion_tokens, total_tokens: data.usage.total_tokens }
      : undefined
    return { ok: true, content, model: typeof data.model === 'string' ? data.model : undefined, usage, latencyMs: elapsed() }
  } catch (error) {
    if (timedOut) return { ok: false, kind: 'timeout', message: `超过 ${Math.round(timeoutMs / 1000)} 秒没有回应`, latencyMs: elapsed() }
    if (signal?.aborted) return { ok: false, kind: 'aborted', message: '请求被取消', latencyMs: elapsed() }
    const message = error instanceof Error ? `${error.name}: ${error.message}` : String(error)
    return { ok: false, kind: 'network', message: providerMessage(message, apiKey), latencyMs: elapsed() }
  } finally {
    clearTimeout(timer)
    signal?.removeEventListener('abort', onAbort)
  }
}

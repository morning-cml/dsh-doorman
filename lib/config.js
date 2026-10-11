/**
 * The user's settings file (`config.json` in the data directory). Missing or
 * invalid values fall back to safe defaults: observe-only mode, nothing sent
 * anywhere without a key. The file is re-read when it changes, so editing it
 * takes effect at the next approval without restarting dsh.
 */

import fs from 'node:fs'
import path from 'node:path'

export const MODES = Object.freeze(['observe', 'auto', 'off'])

/** Defaults written to a fresh config.json. */
export const DEFAULT_CONFIG = Object.freeze({
  version: 1,
  mode: 'observe',
  autoModeConfirmedForVersion: null,
  model: Object.freeze({
    baseUrl: 'https://dashscope.aliyuncs.com/compatible-mode/v1',
    model: 'qwen3.7-plus',
    keyName: 'DSH_DOORMAN_API_KEY',
    timeoutMs: 20000,
    maxCallsPerHour: 100,
    temperature: 0,
    seed: 7,
    responseFormat: 'json_object',
    extraBody: Object.freeze({ enable_thinking: false }),
  }),
  postCheck: Object.freeze({ diskSnapshot: true }),
  log: Object.freeze({ maxFileBytes: 50 * 1024 * 1024 }),
})

const isObject = v => v !== null && typeof v === 'object' && !Array.isArray(v)

/**
 * Merge a parsed file over the defaults, keeping only well-typed values.
 * @param {unknown} raw
 * @returns {{ config: typeof DEFAULT_CONFIG, problems: string[] }}
 */
export function normalizeConfig(raw) {
  const problems = []
  const src = isObject(raw) ? raw : {}
  if (!isObject(raw)) problems.push('配置文件不是一个 JSON 对象，已使用默认设置')
  const pick = (value, fallback, check, name) => {
    if (value === undefined) return fallback
    if (check(value)) return value
    problems.push(`${name} 的值无效，已使用默认值`)
    return fallback
  }
  const m = isObject(src.model) ? src.model : {}
  if (src.model !== undefined && !isObject(src.model)) problems.push('model 应是对象，已使用默认值')
  const config = {
    version: 1,
    mode: pick(src.mode, DEFAULT_CONFIG.mode, v => MODES.includes(v), 'mode'),
    autoModeConfirmedForVersion: pick(src.autoModeConfirmedForVersion, null, v => v === null || (typeof v === 'string' && v.length < 64), 'autoModeConfirmedForVersion'),
    model: {
      baseUrl: pick(m.baseUrl, DEFAULT_CONFIG.model.baseUrl, v => typeof v === 'string' && /^https:\/\/[^\s]+$/i.test(v), 'model.baseUrl'),
      model: pick(m.model, DEFAULT_CONFIG.model.model, v => typeof v === 'string' && /^[\w.\-/:]{1,100}$/.test(v), 'model.model'),
      keyName: pick(m.keyName, DEFAULT_CONFIG.model.keyName, v => typeof v === 'string' && /^[A-Za-z_][A-Za-z0-9_]{0,99}$/.test(v), 'model.keyName'),
      timeoutMs: pick(m.timeoutMs, DEFAULT_CONFIG.model.timeoutMs, v => Number.isInteger(v) && v >= 1000 && v <= 120000, 'model.timeoutMs'),
      maxCallsPerHour: pick(m.maxCallsPerHour, DEFAULT_CONFIG.model.maxCallsPerHour, v => Number.isInteger(v) && v >= 0 && v <= 10000, 'model.maxCallsPerHour'),
      temperature: pick(m.temperature, DEFAULT_CONFIG.model.temperature, v => typeof v === 'number' && v >= 0 && v <= 2, 'model.temperature'),
      seed: pick(m.seed, DEFAULT_CONFIG.model.seed, v => v === null || (Number.isInteger(v) && v >= 0), 'model.seed'),
      responseFormat: pick(m.responseFormat, DEFAULT_CONFIG.model.responseFormat, v => v === 'json_object' || v === 'none', 'model.responseFormat'),
      extraBody: pick(m.extraBody, { ...DEFAULT_CONFIG.model.extraBody }, v => isObject(v) && JSON.stringify(v).length < 2000, 'model.extraBody'),
    },
    postCheck: {
      diskSnapshot: pick(src.postCheck?.diskSnapshot, DEFAULT_CONFIG.postCheck.diskSnapshot, v => typeof v === 'boolean', 'postCheck.diskSnapshot'),
    },
    log: {
      maxFileBytes: pick(src.log?.maxFileBytes, DEFAULT_CONFIG.log.maxFileBytes, v => Number.isInteger(v) && v >= 1024 * 1024, 'log.maxFileBytes'),
    },
  }
  return { config, problems }
}

/**
 * A config file that is re-read when its modification time changes.
 * @param {string} file - absolute path of config.json.
 * @param {(event: string, data: object) => void} log
 */
export function createConfigStore(file, log) {
  let cached = normalizeConfig(DEFAULT_CONFIG).config
  let stamp = null

  function ensureFile() {
    try {
      if (!fs.existsSync(file)) {
        fs.mkdirSync(path.dirname(file), { recursive: true })
        fs.writeFileSync(file, `${JSON.stringify(DEFAULT_CONFIG, null, 2)}\n`, { encoding: 'utf8', flag: 'wx' })
      }
    } catch (error) {
      log('config-error', { message: `无法创建配置文件：${error instanceof Error ? error.message : String(error)}` })
    }
  }

  /** Current settings; never throws. */
  function get() {
    try {
      const st = fs.statSync(file)
      const next = `${st.mtimeMs}:${st.size}`
      if (next === stamp) return cached
      stamp = next
      const text = fs.readFileSync(file, 'utf8').replace(/^﻿/, '')
      let parsed
      try {
        parsed = JSON.parse(text)
      } catch (error) {
        log('config-error', { message: `配置文件不是有效的 JSON，已改用默认设置（只观察）：${error instanceof Error ? error.message : String(error)}` })
        cached = normalizeConfig(DEFAULT_CONFIG).config
        return cached
      }
      const { config, problems } = normalizeConfig(parsed)
      if (problems.length > 0) log('config-error', { problems })
      cached = config
      log('config-loaded', { mode: config.mode, model: config.model.model, baseUrl: config.model.baseUrl })
      return cached
    } catch {
      return cached
    }
  }

  ensureFile()
  return { get, file }
}

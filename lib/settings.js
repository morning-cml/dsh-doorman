/**
 * The plugin's settings. They live in dsh's own plugin configuration (the
 * profile's cordis.patch.yml, inside dsh's home), declared with a schema so the
 * settings page in dsh's Plugins panel can edit the model fields live.
 * `mode` and `autoModeConfirmedForVersion` are deliberately not live-editable:
 * changing them means editing the profile file, which the agent cannot touch.
 *
 * Values may arrive as plain values or as dsh "volatile" references (with
 * `.get()`); read them through {@link readSettings}, which also replaces every
 * invalid value with its safe default.
 */

export const MODES = Object.freeze(['observe', 'auto', 'off'])

export const ENDPOINT_PRESETS = Object.freeze([
  { id: 'dashscope-cn', url: 'https://dashscope.aliyuncs.com/compatible-mode/v1' },
  { id: 'dashscope-intl', url: 'https://dashscope-intl.aliyuncs.com/compatible-mode/v1' },
])

/** Defaults; a fresh install runs observe-only and calls nothing without a key. */
export const DEFAULTS = Object.freeze({
  mode: 'observe',
  autoModeConfirmedForVersion: '',
  baseUrl: ENDPOINT_PRESETS[0].url,
  model: 'qwen3.7-plus',
  timeoutSeconds: 20,
  maxCallsPerHour: 100,
  keyName: 'DSH_DOORMAN_API_KEY',
  jsonMode: true,
  extraBodyJson: '',
})

/**
 * The dsh config schema, built with dsh's own schema library when it is available.
 * @param {any} z - @deepseek-ai/schemastery, or undefined.
 */
export function buildConfigSchema(z) {
  if (z === undefined || z === null) return undefined
  return z.object({
    baseUrl: z.string().default(DEFAULTS.baseUrl).volatile(),
    model: z.string().default(DEFAULTS.model).volatile(),
    timeoutSeconds: z.natural().default(DEFAULTS.timeoutSeconds).volatile(),
    maxCallsPerHour: z.natural().default(DEFAULTS.maxCallsPerHour).volatile(),
    mode: z.string().default(DEFAULTS.mode),
    autoModeConfirmedForVersion: z.string().default(DEFAULTS.autoModeConfirmedForVersion),
    keyName: z.string().default(DEFAULTS.keyName),
    jsonMode: z.boolean().default(DEFAULTS.jsonMode),
    extraBodyJson: z.string().default(DEFAULTS.extraBodyJson),
  })
}

/** Unwrap a dsh volatile reference. */
function unwrap(value) {
  try {
    if (value !== null && typeof value === 'object' && typeof value.get === 'function') return value.get()
  } catch {
    return undefined
  }
  return value
}

/**
 * Current settings as plain, validated values.
 * @param {unknown} raw - the config object dsh passed to apply().
 * @returns {{ settings: typeof DEFAULTS & { extraBody: object | null }, problems: string[] }}
 */
export function readSettings(raw) {
  const src = raw !== null && typeof raw === 'object' ? raw : {}
  const problems = []
  const pick = (name, check) => {
    const value = unwrap(src[name])
    if (value === undefined || value === null || value === '') return DEFAULTS[name]
    if (check(value)) return value
    problems.push(name)
    return DEFAULTS[name]
  }
  const settings = {
    mode: pick('mode', v => MODES.includes(v)),
    autoModeConfirmedForVersion: pick('autoModeConfirmedForVersion', v => typeof v === 'string' && v.length < 64),
    baseUrl: pick('baseUrl', v => typeof v === 'string' && /^https:\/\/[^\s/]+(\/[^\s]*)?$/i.test(v.trim())).trim().replace(/\/+$/, ''),
    model: pick('model', v => typeof v === 'string' && /^[\w.\-/:]{1,100}$/.test(v.trim())).trim(),
    timeoutSeconds: pick('timeoutSeconds', v => Number.isInteger(v) && v >= 5 && v <= 120),
    maxCallsPerHour: pick('maxCallsPerHour', v => Number.isInteger(v) && v >= 0 && v <= 5000),
    keyName: pick('keyName', v => typeof v === 'string' && /^[A-Za-z_][A-Za-z0-9_]{0,99}$/.test(v)),
    jsonMode: pick('jsonMode', v => typeof v === 'boolean'),
    extraBodyJson: pick('extraBodyJson', v => typeof v === 'string' && v.length < 2000),
  }
  return { settings: { ...settings, extraBody: extraBodyFor(settings, problems) }, problems }
}

/**
 * Extra request fields: the user's JSON when given, else what the endpoint needs.
 * DashScope's Qwen 3 models think by default, which breaks JSON output; turn that off there.
 */
function extraBodyFor(settings, problems) {
  if (settings.extraBodyJson.trim() !== '') {
    try {
      const parsed = JSON.parse(settings.extraBodyJson)
      if (parsed !== null && typeof parsed === 'object' && !Array.isArray(parsed)) return parsed
    } catch {
      // fall through to the problem report
    }
    problems.push('extraBodyJson')
    return null
  }
  return /(^|\.)(dashscope(-intl|-us)?\.aliyuncs\.com|maas\.aliyuncs\.com)$/i.test(hostOf(settings.baseUrl)) ? { enable_thinking: false } : null
}

function hostOf(url) {
  try {
    return new URL(url).hostname
  } catch {
    return ''
  }
}

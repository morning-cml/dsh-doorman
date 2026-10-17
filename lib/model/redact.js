/**
 * Data minimisation before anything leaves the machine: obvious secrets are
 * masked, and personal path prefixes are replaced with placeholders
 * (<WORKSPACE>, <DSH_HOME>, <DSH_APP>, %TEMP%, %USERPROFILE%), which also
 * makes "inside or outside the workspace" and "part of dsh" easier for the
 * reviewer to see.
 */

const MASK = '[REDACTED]'

/** Secret patterns: [regex, replacement]. Order matters (specific before generic). */
const SECRET_PATTERNS = [
  [/-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/g, MASK],
  [/\b(authorization\s*[:=]\s*["']?\s*(?:bearer|basic|token)\s+)[^\s"']+/gi, `$1${MASK}`],
  [/\b(bearer\s+)[A-Za-z0-9._~+/=-]{8,}/gi, `$1${MASK}`],
  [/\b(sk|rk|pk)-[A-Za-z0-9_-]{16,}/g, MASK],
  [/\bsk-ant-[A-Za-z0-9_-]{10,}/g, MASK],
  [/\bgh[pousr]_[A-Za-z0-9]{20,}/g, MASK],
  [/\bgithub_pat_[A-Za-z0-9_]{20,}/g, MASK],
  [/\bglpat-[A-Za-z0-9_-]{16,}/g, MASK],
  [/\bxox[abposr]-[A-Za-z0-9-]{10,}/g, MASK],
  [/\bAKIA[0-9A-Z]{16}\b/g, MASK],
  [/\bAIza[0-9A-Za-z_-]{30,}/g, MASK],
  [/\bnpm_[A-Za-z0-9]{30,}/g, MASK],
  [/\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}/g, MASK],
  // user:password@ in URLs
  [/\b([a-z][a-z0-9+.-]*:\/\/)([^/\s:@]+):([^/\s@]+)@/gi, `$1$2:${MASK}@`],
  // -Password x, --token=x, /p:x, password=x, api_key: x …
  [/((?:^|[\s"'`])--?(?:password|passwd|pwd|pass|token|secret|api[-_]?key|apikey|access[-_]?key|client[-_]?secret|auth)(?:[=:\s]+))("[^"]*"|'[^']*'|[^\s"']+)/gi, `$1${MASK}`],
  [/(\b[\w.-]*(?:password|passwd|pwd|token|secret|api[-_]?key|apikey|access[-_]?key|client[-_]?secret|credential)s?\s*[:=]\s*)("[^"]*"|'[^']*'|[^\s"',;]+)/gi, `$1${MASK}`],
  // $env:SOME_TOKEN = "…" / export SOME_KEY=…
  [/(\$env:[\w]*(?:key|token|secret|password|pwd|credential)[\w]*\s*=\s*)("[^"]*"|'[^']*'|[^\s;]+)/gi, `$1${MASK}`],
  [/(\b(?:export\s+|set\s+)?[A-Z][A-Z0-9_]*(?:KEY|TOKEN|SECRET|PASSWORD|PASSWD|CREDENTIAL)[A-Z0-9_]*\s*=\s*)("[^"]*"|'[^']*'|[^\s;&]+)/g, `$1${MASK}`],
  // ConvertTo-SecureString "plain" -AsPlainText
  [/(ConvertTo-SecureString\s+)("[^"]*"|'[^']*'|\S+)(?=[^\n]*-AsPlainText)/gi, `$1${MASK}`],
  // net user name password /add
  [/(\bnet1?(?:\.exe)?\s+user\s+\S+\s+)(?!\/)(\S+)/gi, `$1${MASK}`],
]

/**
 * Mask obvious secrets in text.
 * @param {unknown} text
 * @returns {string}
 */
export function redactSecrets(text) {
  if (typeof text !== 'string' || text === '') return typeof text === 'string' ? text : ''
  let out = text
  for (const [re, replacement] of SECRET_PATTERNS) out = out.replace(re, replacement)
  return out
}

/** Escape a string for use in a RegExp. */
function escape(s) {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
}

/**
 * Build a function that replaces personal path prefixes with placeholders.
 * @param {object} options
 * @param {string[]} options.workspace - workspace root spellings (spelled and real).
 * @param {string[]} options.temp - temporary directories.
 * @param {string[]} options.homes - the user's home directory spellings.
 * @param {string[]} [options.dshHomes] - dsh's home directory spellings.
 * @param {string[]} [options.dshApps] - the dsh desktop install directories.
 * @param {boolean} options.caseInsensitive
 */
export function pathSubstituter({ workspace, temp, homes, dshHomes = [], dshApps = [], caseInsensitive }) {
  const rules = []
  const add = (prefix, placeholder) => {
    if (typeof prefix !== 'string' || prefix.length < 3) return
    const trimmed = prefix.replace(/[\\/]+$/, '')
    const forms = new Set([trimmed, trimmed.replace(/\\/g, '/'), trimmed.replace(/\//g, '\\')])
    if (/^[a-z]:/i.test(trimmed)) {
      // Git Bash / WSL spellings of the same Windows path.
      const rest = trimmed.slice(2).replace(/\\/g, '/')
      forms.add(`/${trimmed[0].toLowerCase()}${rest}`)
      forms.add(`/mnt/${trimmed[0].toLowerCase()}${rest}`)
    }
    for (const form of forms) rules.push({ form, placeholder })
  }
  for (const w of workspace) add(w, '<WORKSPACE>')
  for (const d of dshHomes) add(d, '<DSH_HOME>')
  for (const a of dshApps) add(a, '<DSH_APP>')
  for (const t of temp) add(t, '%TEMP%')
  for (const h of homes) add(h, '%USERPROFILE%')
  // Longest prefix first, so <WORKSPACE> or <DSH_HOME> wins over %USERPROFILE% for paths inside them.
  rules.sort((a, b) => b.form.length - a.form.length)
  const compiled = rules.map(({ form, placeholder }) => ({
    re: new RegExp(`${escape(form)}(?=$|[\\\\/\\s"'\`;,)|&>]|$)`, caseInsensitive ? 'gi' : 'g'),
    placeholder,
  }))
  /**
   * @param {unknown} text
   * @returns {string}
   */
  return function substitute(text) {
    if (typeof text !== 'string' || text === '') return typeof text === 'string' ? text : ''
    let out = text
    for (const { re, placeholder } of compiled) out = out.replace(re, placeholder)
    return out
  }
}

/**
 * Both protections, in the order that keeps placeholders intact.
 * @param {(text: string) => string} substitute
 */
export function sanitizer(substitute) {
  return (text) => substitute(redactSecrets(text))
}

/**
 * Character classes and text normalization shared by the shell parsers and the
 * textual rule scan. PowerShell accepts several Unicode look-alikes as syntax
 * (dashes for parameters, curly quotes for strings); treating them the same way
 * here is what keeps those spellings from slipping past the rules.
 */

/** Characters PowerShell accepts as the dash that starts a parameter name. */
export const DASHES = new Set(['-', '–', '—', '―'])
/** Characters PowerShell accepts as single quotes. */
export const SINGLE_QUOTES = new Set(["'", '‘', '’', '‚', '‛'])
/** Characters PowerShell accepts as double quotes. */
export const DOUBLE_QUOTES = new Set(['"', '“', '”', '„'])

/**
 * Whether a character separates words (newlines excluded).
 * @param {string | undefined} ch
 */
export function isSpace(ch) {
  if (ch === undefined) return false
  return ch === ' ' || ch === '\t' || ch === '\f' || ch === '\v' || ch === ' ' || ch === '\u0085' || ch === '﻿' || /\p{Zs}/u.test(ch)
}

/**
 * Whether a character ends a line.
 * @param {string | undefined} ch
 */
export function isNewline(ch) {
  return ch === '\n' || ch === '\r' || ch === ' ' || ch === ' '
}

/**
 * Lower-cased, de-obfuscated copy of a command for keyword scanning. It folds
 * Unicode compatibility forms, maps look-alike dashes and quotes to ASCII,
 * drops PowerShell backtick and cmd caret escapes, glues string
 * concatenations such as 'Re' + 'move', unifies path separators to
 * backslashes and collapses whitespace.
 * @param {string} text
 * @returns {string}
 */
export function normalizeForScan(text) {
  let out = String(text).normalize('NFKC')
  out = out.replace(/[–—―]/g, '-')
  out = out.replace(/[‘’‚‛]/g, "'").replace(/[“”„]/g, '"')
  out = out.replace(/`\r?\n/g, ' ').replace(/[`^]/g, '')
  // 'abc' + 'def', "abc"+"def", 'abc' + "def" → joined literals.
  out = out.replace(/(['"])\s*\+\s*(['"])/g, '')
  out = out.replace(/\//g, '\\')
  out = out.toLowerCase()
  out = out.replace(/[\s ﻿]+/g, ' ')
  return out
}

/**
 * Shorten long text for logs, keeping both ends.
 * @param {unknown} value
 * @param {number} max
 * @returns {string}
 */
export function clip(value, max) {
  if (typeof value !== 'string') return ''
  if (value.length <= max) return value
  const half = Math.floor(max / 2)
  return `${value.slice(0, half)}\n…[${value.length - max} chars omitted]…\n${value.slice(-half)}`
}

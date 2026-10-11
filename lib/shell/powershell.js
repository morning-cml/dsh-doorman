/**
 * A forgiving PowerShell parser for rule checks. It does not execute or fully
 * validate PowerShell; it recovers the structure the rules need — statements,
 * pipelines, commands, arguments, redirections — and keeps every embedded
 * piece of code (`$( )`, `( )`, `{ }`, here-strings) so it can be analysed
 * recursively. It never throws; anything it cannot make sense of is reported
 * in `issues` and the affected words are marked dynamic.
 *
 * Model shared with the cmd and POSIX parsers:
 *   Script    { dialect, statements: Statement[], issues: string[] }
 *   Statement { commands: Command[] (one pipeline), chain, raw }
 *   Command   { elements: Element[], redirections, call, raw }
 *   Element   { type: 'word', parts, quoted, raw } | { type: 'array', items, raw }
 *   Part      { k: 'text', v } | { k: 'var', name, splat?, braced? } | { k: 'group', kind, inner, closed } | { k: 'brack', inner }
 */

import { DOUBLE_QUOTES, SINGLE_QUOTES, isNewline, isSpace } from '../text.js'

const ESCAPES = { 0: '\0', a: '\x07', b: '\b', e: '\x1b', f: '\f', n: '\n', r: '\r', t: '\t', v: '\v' }
const NAME_CHAR = /[A-Za-z0-9_?]/
// Characters that end an unquoted word in argument mode.
const WORD_END = new Set([';', '|', '&', ',', ')', '}', '>', '<'])

/**
 * Read a single-quoted string that starts at `i` (doubled quotes are literal quotes).
 * @param {string} s
 * @param {number} i
 * @returns {{ value: string, end: number, closed: boolean }}
 */
function readSingle(s, i) {
  let j = i + 1
  let value = ''
  while (j < s.length) {
    if (SINGLE_QUOTES.has(s[j])) {
      if (SINGLE_QUOTES.has(s[j + 1])) { value += s[j]; j += 2; continue }
      return { value, end: j + 1, closed: true }
    }
    value += s[j]
    j += 1
  }
  return { value, end: s.length, closed: false }
}

/**
 * Index just past a single-quoted string that starts at `i`.
 * @param {string} s
 * @param {number} i
 */
function skipSingle(s, i) {
  return readSingle(s, i).end
}

/**
 * Locate the body of a double-quoted string that starts at `i`.
 * @param {string} s
 * @param {number} i
 * @returns {{ body: string, end: number, closed: boolean }}
 */
function readDouble(s, i) {
  let j = i + 1
  while (j < s.length) {
    const c = s[j]
    if (c === '`') { j += 2; continue }
    if (DOUBLE_QUOTES.has(c)) {
      if (DOUBLE_QUOTES.has(s[j + 1])) { j += 2; continue }
      return { body: s.slice(i + 1, j), end: j + 1, closed: true }
    }
    if (c === '$' && s[j + 1] === '(') { j = scanBalanced(s, j + 2, ')').end; continue }
    j += 1
  }
  return { body: s.slice(i + 1), end: s.length, closed: false }
}

/**
 * Index just past a double-quoted string that starts at `i`.
 * @param {string} s
 * @param {number} i
 */
function skipDouble(s, i) {
  return readDouble(s, i).end
}

/**
 * Whether a here-string header (`@'` / `@"`) at `i` is followed only by spaces and a newline.
 * @param {string} s
 * @param {number} i - index of the quote after `@`.
 */
function isHereStart(s, i) {
  let j = i + 1
  while (j < s.length && isSpace(s[j])) j += 1
  return j < s.length && isNewline(s[j])
}

/**
 * Locate the end of a here-string whose header starts at `i` (the `@`).
 * @returns {{ bodyStart: number, bodyEnd: number, end: number, closed: boolean }}
 */
function scanHere(s, i) {
  const quoteIsSingle = SINGLE_QUOTES.has(s[i + 1])
  let j = i + 2
  while (j < s.length && !isNewline(s[j])) j += 1
  if (s[j] === '\r' && s[j + 1] === '\n') j += 2
  else j += 1
  const bodyStart = j
  while (j < s.length) {
    if (isNewline(s[j])) {
      let k = j + 1
      if (s[j] === '\r' && s[k] === '\n') k += 1
      const q = s[k]
      if ((quoteIsSingle ? SINGLE_QUOTES.has(q) : DOUBLE_QUOTES.has(q)) && s[k + 1] === '@') {
        return { bodyStart, bodyEnd: j, end: k + 2, closed: true }
      }
    }
    j += 1
  }
  return { bodyStart, bodyEnd: s.length, end: s.length, closed: false }
}

/**
 * Whether position `i` starts a token (so `#` begins a comment there).
 * @param {string} s
 * @param {number} i
 * @param {number} floor - first index of the region being scanned.
 */
function atTokenStart(s, i, floor) {
  if (i <= floor) return true
  const p = s[i - 1]
  return isSpace(p) || isNewline(p) || p === ';' || p === '(' || p === '{' || p === '|' || p === '&'
}

/**
 * Find the bracket that closes a group, respecting quotes, here-strings, comments and nesting.
 * @param {string} s
 * @param {number} start - index just after the opening bracket.
 * @param {string} closer - the closing character expected.
 * @returns {{ inner: string, end: number, closed: boolean }}
 */
export function scanBalanced(s, start, closer) {
  const stack = [closer]
  let i = start
  while (i < s.length) {
    const c = s[i]
    if (c === '`') { i += 2; continue }
    if (SINGLE_QUOTES.has(c)) { i = skipSingle(s, i); continue }
    if (DOUBLE_QUOTES.has(c)) { i = skipDouble(s, i); continue }
    if (c === '@' && (SINGLE_QUOTES.has(s[i + 1]) || DOUBLE_QUOTES.has(s[i + 1])) && isHereStart(s, i + 1)) {
      i = scanHere(s, i).end
      continue
    }
    if (c === '<' && s[i + 1] === '#') {
      const close = s.indexOf('#>', i + 2)
      i = close === -1 ? s.length : close + 2
      continue
    }
    if (c === '#' && atTokenStart(s, i, start)) {
      while (i < s.length && !isNewline(s[i])) i += 1
      continue
    }
    if (c === '(') stack.push(')')
    else if (c === '{') stack.push('}')
    else if (c === '[') stack.push(']')
    else if ((c === ')' || c === '}' || c === ']') && c === stack[stack.length - 1]) {
      stack.pop()
      if (stack.length === 0) return { inner: s.slice(start, i), end: i + 1, closed: true }
    }
    i += 1
  }
  return { inner: s.slice(start), end: s.length, closed: false }
}

/**
 * Read a `$…` reference at `i`: variable, braced variable, or `$( )` subexpression.
 * @returns {{ part: object, end: number } | null}
 */
function readDollar(s, i) {
  const n = s[i + 1]
  if (n === '(') {
    const g = scanBalanced(s, i + 2, ')')
    return { part: { k: 'group', kind: '$(', inner: g.inner, closed: g.closed }, end: g.end }
  }
  if (n === '{') {
    let j = i + 2
    let name = ''
    while (j < s.length && s[j] !== '}') {
      if (s[j] === '`' && j + 1 < s.length) { name += s[j + 1]; j += 2; continue }
      name += s[j]
      j += 1
    }
    return { part: { k: 'var', name, braced: true }, end: Math.min(j + 1, s.length) }
  }
  if (n === '$' || n === '^' || n === '?') return { part: { k: 'var', name: n }, end: i + 2 }
  if (n !== undefined && NAME_CHAR.test(n)) {
    let j = i + 1
    while (j < s.length && NAME_CHAR.test(s[j])) j += 1
    // Scope or drive qualifier: $env:Path, $global:x.
    if (s[j] === ':' && NAME_CHAR.test(s[j + 1] ?? '')) {
      j += 1
      while (j < s.length && NAME_CHAR.test(s[j])) j += 1
    }
    return { part: { k: 'var', name: s.slice(i + 1, j) }, end: j }
  }
  return null
}

/**
 * Parts of an expandable string body (double-quoted text or `@"` here-string).
 * @param {string} body
 * @param {boolean} quotesEscape - whether doubled double quotes are an escape (true inside "…").
 */
function expandableParts(body, quotesEscape) {
  const parts = []
  let buf = ''
  let i = 0
  const flush = () => { if (buf !== '') { parts.push({ k: 'text', v: buf }); buf = '' } }
  while (i < body.length) {
    const c = body[i]
    if (c === '`' && i + 1 < body.length) {
      const e = body[i + 1]
      if (e === 'u' && body[i + 2] === '{') {
        const close = body.indexOf('}', i + 3)
        const code = close === -1 ? NaN : Number.parseInt(body.slice(i + 3, close), 16)
        if (Number.isFinite(code) && code <= 0x10FFFF) { buf += String.fromCodePoint(code); i = close + 1; continue }
      }
      buf += Object.hasOwn(ESCAPES, e) ? ESCAPES[e] : e
      i += 2
      continue
    }
    if (quotesEscape && DOUBLE_QUOTES.has(c) && DOUBLE_QUOTES.has(body[i + 1])) { buf += '"'; i += 2; continue }
    if (c === '$') {
      const d = readDollar(body, i)
      if (d !== null) { flush(); parts.push(d.part); i = d.end; continue }
    }
    buf += c
    i += 1
  }
  flush()
  return parts
}

class Lexer {
  /** @param {string} src */
  constructor(src) {
    this.s = src
    this.i = 0
    this.issues = []
    this.tokens = []
  }

  run() {
    const s = this.s
    while (this.i < s.length) {
      const c = s[this.i]
      const start = this.i
      if (c === '`' && isNewline(s[this.i + 1])) {
        this.i += s[this.i + 1] === '\r' && s[this.i + 2] === '\n' ? 3 : 2
        continue
      }
      if (isSpace(c)) { this.i += 1; continue }
      if (isNewline(c)) { this.push({ t: 'op', v: '\n' }, start, this.i + 1); this.i += 1; continue }
      if (c === ';') { this.push({ t: 'op', v: ';' }, start, this.i + 1); this.i += 1; continue }
      if (c === '<' && s[this.i + 1] === '#') {
        const close = s.indexOf('#>', this.i + 2)
        this.i = close === -1 ? s.length : close + 2
        continue
      }
      if (c === '#') {
        while (this.i < s.length && !isNewline(s[this.i])) this.i += 1
        continue
      }
      if (c === '|') {
        const v = s[this.i + 1] === '|' ? '||' : '|'
        this.push({ t: 'op', v }, start, this.i + v.length)
        this.i += v.length
        continue
      }
      if (c === '&') {
        const v = s[this.i + 1] === '&' ? '&&' : '&'
        this.push({ t: 'op', v }, start, this.i + v.length)
        this.i += v.length
        continue
      }
      const redir = /^(?:[1-6*])?>>?(?:&[12])?|^</.exec(s.slice(this.i, this.i + 6))
      if (redir !== null && (c === '>' || c === '<' || /[1-6*]/.test(c))) {
        const op = redir[0]
        if (op === '<' || op.includes('>')) {
          this.push({ t: 'redir', op, merge: op.includes('&') }, start, this.i + op.length)
          this.i += op.length
          continue
        }
      }
      if (c === '-' && s[this.i + 1] === '-' && s[this.i + 2] === '%' && (this.i + 3 >= s.length || isSpace(s[this.i + 3]) || isNewline(s[this.i + 3]))) {
        let j = this.i + 3
        while (j < s.length && !isNewline(s[j])) j += 1
        const rest = s.slice(this.i + 3, j)
        this.push({ t: 'stop', args: rest.split(/\s+/).filter(Boolean), raw: rest }, start, j)
        this.i = j
        continue
      }
      if (c === ',') { this.push({ t: 'comma' }, start, this.i + 1); this.i += 1; continue }
      if (c === ')' || c === '}') {
        this.issues.push(`unbalanced ${c}`)
        this.i += 1
        continue
      }
      const word = this.readWord()
      this.push({ t: 'word', el: word }, start, this.i)
    }
    return this.tokens
  }

  push(token, start, end) {
    token.start = start
    token.end = end
    this.tokens.push(token)
  }

  readWord() {
    const s = this.s
    const start = this.i
    const parts = []
    let quoted = false
    const first = s[start]
    // A word that starts quoted is never a parameter name and never a command keyword.
    const quotedStart = SINGLE_QUOTES.has(first) || DOUBLE_QUOTES.has(first) || (first === '@' && (SINGLE_QUOTES.has(s[start + 1]) || DOUBLE_QUOTES.has(s[start + 1])))
    let buf = ''
    const flush = () => { if (buf !== '') { parts.push({ k: 'text', v: buf }); buf = '' } }
    while (this.i < s.length) {
      const c = s[this.i]
      if (isSpace(c) || isNewline(c) || WORD_END.has(c)) break
      if (c === '`') {
        if (isNewline(s[this.i + 1])) break
        if (this.i + 1 < s.length) buf += s[this.i + 1]
        this.i += 2
        continue
      }
      if (c === '@' && (SINGLE_QUOTES.has(s[this.i + 1]) || DOUBLE_QUOTES.has(s[this.i + 1])) && isHereStart(s, this.i + 1)) {
        flush()
        const h = scanHere(s, this.i)
        if (!h.closed) this.issues.push('unterminated here-string')
        const body = s.slice(h.bodyStart, h.bodyEnd)
        if (SINGLE_QUOTES.has(s[this.i + 1])) parts.push({ k: 'text', v: body })
        else parts.push(...expandableParts(body, false))
        quoted = true
        this.i = h.end
        continue
      }
      if (SINGLE_QUOTES.has(c)) {
        flush()
        const q = readSingle(s, this.i)
        if (!q.closed) this.issues.push('unterminated single quote')
        parts.push({ k: 'text', v: q.value })
        quoted = true
        this.i = q.end
        continue
      }
      if (DOUBLE_QUOTES.has(c)) {
        flush()
        const q = readDouble(s, this.i)
        if (!q.closed) this.issues.push('unterminated double quote')
        parts.push(...expandableParts(q.body, true))
        quoted = true
        this.i = q.end
        continue
      }
      if (c === '$') {
        const d = readDollar(s, this.i)
        if (d !== null) { flush(); parts.push(d.part); this.i = d.end; continue }
      }
      if (c === '@' && (s[this.i + 1] === '(' || s[this.i + 1] === '{')) {
        flush()
        const closer = s[this.i + 1] === '(' ? ')' : '}'
        const g = scanBalanced(s, this.i + 2, closer)
        if (!g.closed) this.issues.push(`unclosed @${s[this.i + 1]}`)
        parts.push({ k: 'group', kind: `@${s[this.i + 1]}`, inner: g.inner, closed: g.closed })
        this.i = g.end
        continue
      }
      if (c === '@' && parts.length === 0 && buf === '' && NAME_CHAR.test(s[this.i + 1] ?? '')) {
        let j = this.i + 1
        while (j < s.length && NAME_CHAR.test(s[j])) j += 1
        parts.push({ k: 'var', name: s.slice(this.i + 1, j), splat: true })
        this.i = j
        continue
      }
      if (c === '(' || c === '{') {
        flush()
        const g = scanBalanced(s, this.i + 1, c === '(' ? ')' : '}')
        if (!g.closed) this.issues.push(`unclosed ${c}`)
        parts.push({ k: 'group', kind: c, inner: g.inner, closed: g.closed })
        this.i = g.end
        continue
      }
      if (c === '[' && parts.length === 0 && buf === '') {
        const g = scanBalanced(s, this.i + 1, ']')
        parts.push({ k: 'brack', inner: g.inner })
        this.i = g.end
        continue
      }
      buf += c
      this.i += 1
    }
    flush()
    return { type: 'word', parts: mergeText(parts), quoted, quotedStart, raw: s.slice(start, this.i) }
  }
}

/** Join adjacent text parts. */
function mergeText(parts) {
  const out = []
  for (const part of parts) {
    const last = out[out.length - 1]
    if (part.k === 'text' && last !== undefined && last.k === 'text') last.v += part.v
    else out.push(part.k === 'text' ? { k: 'text', v: part.v } : part)
  }
  return out
}

/**
 * Parse PowerShell source into the shared script model.
 * @param {string} src
 * @returns {{ dialect: 'powershell', statements: object[], issues: string[] }}
 */
export function parsePowerShell(src) {
  const text = String(src)
  const lexer = new Lexer(text)
  const tokens = lexer.run()
  const statements = []
  let commands = []
  let cmd = newCommand()
  let pendingComma = false
  let stmtStart = -1
  let stmtEnd = -1

  function newCommand() {
    return { elements: [], redirections: [], call: null, start: -1, end: -1, raw: '' }
  }
  function touch(token) {
    if (cmd.start === -1) cmd.start = token.start
    cmd.end = token.end
    if (stmtStart === -1) stmtStart = token.start
    stmtEnd = token.end
  }
  function finishCommand() {
    if (cmd.elements.length > 0 || cmd.redirections.length > 0 || cmd.call !== null) {
      cmd.raw = text.slice(cmd.start, cmd.end)
      commands.push(cmd)
    }
    cmd = newCommand()
    pendingComma = false
  }
  function finishStatement(chain) {
    finishCommand()
    if (commands.length > 0) {
      statements.push({ commands, chain, raw: text.slice(stmtStart, stmtEnd) })
    }
    commands = []
    stmtStart = -1
    stmtEnd = -1
  }

  for (let k = 0; k < tokens.length; k += 1) {
    const token = tokens[k]
    if (token.t === 'op') {
      if (token.v === '\n' || token.v === ';' || token.v === '&&' || token.v === '||') { finishStatement(token.v); continue }
      if (token.v === '|') { finishCommand(); continue }
      // '&': call operator at the start of a command, background operator after it.
      if (cmd.elements.length === 0 && cmd.call === null) { touch(token); cmd.call = '&'; continue }
      finishStatement('&')
      continue
    }
    if (token.t === 'redir') {
      touch(token)
      if (token.merge || token.op === '<') {
        cmd.redirections.push({ op: token.op, target: null })
        continue
      }
      const next = tokens[k + 1]
      if (next !== undefined && next.t === 'word') {
        touch(next)
        cmd.redirections.push({ op: token.op, target: next.el })
        k += 1
      } else {
        cmd.redirections.push({ op: token.op, target: null })
      }
      continue
    }
    if (token.t === 'comma') { touch(token); pendingComma = true; continue }
    if (token.t === 'stop') {
      touch(token)
      for (const arg of token.args) cmd.elements.push({ type: 'word', parts: [{ k: 'text', v: arg }], quoted: false, raw: arg, verbatim: true })
      continue
    }
    // word
    touch(token)
    const el = token.el
    if (cmd.elements.length === 0 && cmd.call === null && el.raw === '.' && tokens[k + 1]?.t === 'word') {
      cmd.call = '.'
      continue
    }
    if (pendingComma && cmd.elements.length > 0) {
      const prev = cmd.elements[cmd.elements.length - 1]
      if (prev.type === 'array') prev.items.push(el)
      else cmd.elements[cmd.elements.length - 1] = { type: 'array', items: [prev, el], raw: `${prev.raw},${el.raw}` }
      pendingComma = false
      continue
    }
    pendingComma = false
    cmd.elements.push(el)
  }
  finishStatement(null)
  return { dialect: 'powershell', statements, issues: lexer.issues }
}

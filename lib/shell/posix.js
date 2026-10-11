/**
 * A forgiving POSIX shell (bash/sh) parser for rule checks: quotes, escapes,
 * `$VAR`, `${VAR}`, `$( )`, backticks, `<( )`, `;` `&&` `||` `|` `&`,
 * redirections and here-documents. Produces the shared script model (see
 * powershell.js). It never throws.
 */

import { isNewline, isSpace } from '../text.js'

const NAME = /[A-Za-z0-9_]/

/**
 * Find the `)` that closes a `$(`, `(` or `<(` group, respecting quotes and nesting.
 * @returns {{ inner: string, end: number, closed: boolean }}
 */
function scanParen(s, start) {
  let depth = 1
  let i = start
  while (i < s.length) {
    const c = s[i]
    if (c === '\\') { i += 2; continue }
    if (c === "'") { const close = s.indexOf("'", i + 1); i = close === -1 ? s.length : close + 1; continue }
    if (c === '"') { i = skipDoubleQuoted(s, i); continue }
    if (c === '(') depth += 1
    else if (c === ')') {
      depth -= 1
      if (depth === 0) return { inner: s.slice(start, i), end: i + 1, closed: true }
    }
    i += 1
  }
  return { inner: s.slice(start), end: s.length, closed: false }
}

/** Index just past a double-quoted string starting at `i`. */
function skipDoubleQuoted(s, i) {
  let j = i + 1
  while (j < s.length) {
    const c = s[j]
    if (c === '\\') { j += 2; continue }
    if (c === '"') return j + 1
    if (c === '$' && s[j + 1] === '(') { j = scanParen(s, j + 2).end; continue }
    j += 1
  }
  return s.length
}

/**
 * Read a `$…` expansion at `i`.
 * @returns {{ part: object, end: number } | null}
 */
function readDollar(s, i) {
  const n = s[i + 1]
  if (n === '(') {
    if (s[i + 2] === '(') {
      // $(( arithmetic )) — evaluate nothing, keep it dynamic.
      const close = s.indexOf('))', i + 3)
      return { part: { k: 'group', kind: '$((', inner: s.slice(i + 3, close === -1 ? s.length : close), closed: close !== -1 }, end: close === -1 ? s.length : close + 2 }
    }
    const g = scanParen(s, i + 2)
    return { part: { k: 'group', kind: '$(', inner: g.inner, closed: g.closed }, end: g.end }
  }
  if (n === '{') {
    const close = s.indexOf('}', i + 2)
    const body = s.slice(i + 2, close === -1 ? s.length : close)
    const name = /^[A-Za-z_][A-Za-z0-9_]*$/.test(body) ? `env:${body}` : body
    return { part: { k: 'var', name, braced: true, complex: !/^[A-Za-z_][A-Za-z0-9_]*$/.test(body) }, end: close === -1 ? s.length : close + 1 }
  }
  if (n !== undefined && /[A-Za-z_]/.test(n)) {
    let j = i + 1
    while (j < s.length && NAME.test(s[j])) j += 1
    return { part: { k: 'var', name: `env:${s.slice(i + 1, j)}` }, end: j }
  }
  if (n !== undefined && /[0-9@*#?$!-]/.test(n)) return { part: { k: 'var', name: n }, end: i + 2 }
  return null
}

/** Parts of a double-quoted body. */
function doubleParts(body) {
  const parts = []
  let buf = ''
  let i = 0
  const flush = () => { if (buf !== '') { parts.push({ k: 'text', v: buf }); buf = '' } }
  while (i < body.length) {
    const c = body[i]
    if (c === '\\' && /[$`"\\\n]/.test(body[i + 1] ?? '')) { if (body[i + 1] !== '\n') buf += body[i + 1]; i += 2; continue }
    if (c === '$') {
      const d = readDollar(body, i)
      if (d !== null) { flush(); parts.push(d.part); i = d.end; continue }
    }
    if (c === '`') {
      const close = body.indexOf('`', i + 1)
      flush()
      parts.push({ k: 'group', kind: '`', inner: body.slice(i + 1, close === -1 ? body.length : close), closed: close !== -1 })
      i = close === -1 ? body.length : close + 1
      continue
    }
    buf += c
    i += 1
  }
  flush()
  return parts
}

/**
 * Parse POSIX shell source into the shared script model.
 * @param {string} src
 * @returns {{ dialect: 'posix', statements: object[], issues: string[] }}
 */
export function parsePosix(src) {
  const s = String(src)
  const issues = []
  const statements = []
  let commands = []
  let cmd = { elements: [], redirections: [], call: null, raw: '', start: -1, end: -1 }
  let stmtStart = -1
  let stmtEnd = -1
  let i = 0
  const pendingHeredocs = []

  const finishCommand = () => {
    if (cmd.elements.length > 0 || cmd.redirections.length > 0) {
      cmd.raw = s.slice(cmd.start, cmd.end)
      commands.push(cmd)
    }
    cmd = { elements: [], redirections: [], call: null, raw: '', start: -1, end: -1 }
  }
  const finishStatement = (chain) => {
    finishCommand()
    if (commands.length > 0) statements.push({ commands, chain, raw: s.slice(stmtStart, stmtEnd) })
    commands = []
    stmtStart = -1
    stmtEnd = -1
  }
  const touch = (start, end) => {
    if (cmd.start === -1) cmd.start = start
    cmd.end = end
    if (stmtStart === -1) stmtStart = start
    stmtEnd = end
  }

  const readWord = () => {
    const start = i
    const parts = []
    let buf = ''
    let quoted = false
    const flush = () => { if (buf !== '') { parts.push({ k: 'text', v: buf }); buf = '' } }
    while (i < s.length) {
      const c = s[i]
      if (isSpace(c) || isNewline(c) || c === ';' || c === '&' || c === '|' || c === ')' || ((c === '>' || c === '<') && s[i + 1] !== '(')) break
      if (c === '\\') {
        if (isNewline(s[i + 1])) { i += 2; continue }
        if (i + 1 < s.length) buf += s[i + 1]
        i += 2
        continue
      }
      if (c === "'") {
        quoted = true
        const close = s.indexOf("'", i + 1)
        if (close === -1) issues.push('unterminated single quote')
        buf += s.slice(i + 1, close === -1 ? s.length : close)
        i = close === -1 ? s.length : close + 1
        continue
      }
      if (c === '$' && s[i + 1] === "'") {
        quoted = true
        const close = s.indexOf("'", i + 2)
        buf += s.slice(i + 2, close === -1 ? s.length : close).replace(/\\x([0-9a-f]{2})/gi, (_, h) => String.fromCharCode(Number.parseInt(h, 16))).replace(/\\(.)/g, '$1')
        i = close === -1 ? s.length : close + 1
        continue
      }
      if (c === '"') {
        quoted = true
        const end = skipDoubleQuoted(s, i)
        if (end >= s.length && s[end - 1] !== '"') issues.push('unterminated double quote')
        flush()
        parts.push(...doubleParts(s.slice(i + 1, end > i + 1 && s[end - 1] === '"' ? end - 1 : end)))
        i = end
        continue
      }
      if (c === '$') {
        const d = readDollar(s, i)
        if (d !== null) { flush(); parts.push(d.part); i = d.end; continue }
      }
      if (c === '`') {
        const close = s.indexOf('`', i + 1)
        flush()
        parts.push({ k: 'group', kind: '`', inner: s.slice(i + 1, close === -1 ? s.length : close), closed: close !== -1 })
        i = close === -1 ? s.length : close + 1
        continue
      }
      if ((c === '<' || c === '>') && s[i + 1] === '(') {
        flush()
        const g = scanParen(s, i + 2)
        parts.push({ k: 'group', kind: `${c}(`, inner: g.inner, closed: g.closed })
        i = g.end
        continue
      }
      if (c === '(' ) {
        flush()
        const g = scanParen(s, i + 1)
        parts.push({ k: 'group', kind: '(', inner: g.inner, closed: g.closed })
        i = g.end
        continue
      }
      if (c === '~' && i === start) { flush(); parts.push({ k: 'var', name: 'home' }); i += 1; continue }
      buf += c
      i += 1
    }
    flush()
    return { type: 'word', parts, quoted, raw: s.slice(start, i) }
  }

  while (i < s.length) {
    const c = s[i]
    if (isSpace(c)) { i += 1; continue }
    if (c === '\\' && isNewline(s[i + 1])) { i += 2; continue }
    if (isNewline(c)) {
      finishStatement('\n')
      i += 1
      // Skip the bodies of here-documents opened on the line just ended.
      while (pendingHeredocs.length > 0) {
        const delim = pendingHeredocs.shift()
        const lines = s.slice(i).split('\n')
        let consumed = 0
        let found = false
        for (const line of lines) {
          consumed += line.length + 1
          if (line.replace(/^\t+/, '').trimEnd() === delim) { found = true; break }
        }
        if (!found) issues.push('unterminated here-document')
        i = Math.min(s.length, i + consumed)
      }
      continue
    }
    if (c === '#' ) { while (i < s.length && !isNewline(s[i])) i += 1; continue }
    if (c === ';') { finishStatement(';'); i += 1; continue }
    if (c === '&' && s[i + 1] === '&') { finishStatement('&&'); i += 2; continue }
    if (c === '|' && s[i + 1] === '|') { finishStatement('||'); i += 2; continue }
    if (c === '|') { finishCommand(); i += s[i + 1] === '&' ? 2 : 1; continue }
    if (c === '&' && s[i + 1] !== '>') { finishStatement('&'); i += 1; continue }
    if (c === ')' ) { issues.push('unbalanced )'); i += 1; continue }
    const redir = /^(?:[0-9]?(?:>>|>\||>&[0-9-]?|>)|&>>|&>|<<<|<<-?|<&[0-9-]?|<>|<)/.exec(s.slice(i, i + 4))
    if (redir !== null && (c === '>' || c === '<' || c === '&' || /[0-9]/.test(c))) {
      const start = i
      const op = redir[0]
      i += op.length
      if (/&[0-9-]$/.test(op)) { touch(start, i); cmd.redirections.push({ op, target: null }); continue }
      while (i < s.length && isSpace(s[i])) i += 1
      const target = i < s.length && !isNewline(s[i]) ? readWord() : null
      touch(start, i)
      if (op.startsWith('<<') && op !== '<<<') {
        const delim = target === null ? '' : target.parts.map(p => (p.k === 'text' ? p.v : '')).join('')
        if (delim !== '') pendingHeredocs.push(delim)
        continue
      }
      cmd.redirections.push({ op, target })
      continue
    }
    const start = i
    const word = readWord()
    if (word.raw === '') { i += 1; continue }
    touch(start, i)
    cmd.elements.push(word)
  }
  finishStatement(null)
  return { dialect: 'posix', statements, issues }
}

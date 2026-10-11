/**
 * A forgiving cmd.exe command-line parser (the text after `cmd /c`). cmd's
 * rules are simple: `^` escapes the next character, double quotes group,
 * `&`, `&&`, `||` separate commands, `|` pipes, `%NAME%` expands variables,
 * and `>`/`>>` redirect. Produces the shared script model (see powershell.js).
 */

import { isNewline, isSpace } from '../text.js'

/**
 * Split one word's text into text and %VAR% parts.
 * @param {string} text
 * @param {boolean} expandVars - false inside the literal tail of a word that had no %…% pairs.
 */
function wordParts(text, expandVars) {
  if (!expandVars) return [{ k: 'text', v: text }]
  const parts = []
  const re = /%([^%\s=]+)%|!([^!\s=]+)!/g
  let last = 0
  for (const m of text.matchAll(re)) {
    if (m.index > last) parts.push({ k: 'text', v: text.slice(last, m.index) })
    parts.push({ k: 'var', name: `env:${m[1] ?? m[2]}` })
    last = m.index + m[0].length
  }
  if (last < text.length) parts.push({ k: 'text', v: text.slice(last) })
  return parts
}

/**
 * Parse a cmd.exe command line into the shared script model.
 * @param {string} src
 * @returns {{ dialect: 'cmd', statements: object[], issues: string[] }}
 */
export function parseCmd(src) {
  const s = String(src)
  const issues = []
  const statements = []
  let commands = []
  let cmd = { elements: [], redirections: [], call: null, raw: '', start: -1, end: -1 }
  let stmtStart = -1
  let stmtEnd = -1
  let i = 0

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
    let text = ''
    let quoted = false
    while (i < s.length) {
      const c = s[i]
      if (c === '^') {
        if (i + 1 < s.length && !isNewline(s[i + 1])) text += s[i + 1]
        i += 2
        continue
      }
      if (c === '"') {
        quoted = true
        const close = s.indexOf('"', i + 1)
        if (close === -1) { issues.push('unterminated double quote'); text += s.slice(i + 1); i = s.length; break }
        text += s.slice(i + 1, close)
        i = close + 1
        continue
      }
      if (isSpace(c) || isNewline(c) || c === '&' || c === '|' || c === '>' || c === '<' || c === ',' || c === ';' || c === '=') {
        // `,` `;` `=` delimit arguments of cmd builtins (`del a,b`). Keep `=` inside a word that
        // already has text so assignments stay whole (`set X=1`, `binPath=`).
        if (c === '=' && text !== '') { text += c; i += 1; continue }
        break
      }
      text += c
      i += 1
    }
    return { type: 'word', parts: wordParts(text, true), quoted, raw: s.slice(start, i) }
  }

  while (i < s.length) {
    const c = s[i]
    if (isSpace(c) || c === ',' || c === ';' || c === '=') { i += 1; continue }
    if (isNewline(c)) { finishStatement('\n'); i += 1; continue }
    if (c === '&') {
      const v = s[i + 1] === '&' ? '&&' : '&'
      finishStatement(v)
      i += v.length
      continue
    }
    if (c === '|') {
      if (s[i + 1] === '|') { finishStatement('||'); i += 2; continue }
      finishCommand()
      i += 1
      continue
    }
    const redir = /^[0-9]?>>?(?:&[0-9])?|^</.exec(s.slice(i, i + 5))
    if (redir !== null && (c === '>' || c === '<' || (/[0-9]/.test(c) && redir[0].length > 1))) {
      const start = i
      i += redir[0].length
      if (redir[0].includes('&') || redir[0] === '<') {
        touch(start, i)
        cmd.redirections.push({ op: redir[0], target: null })
        continue
      }
      while (i < s.length && isSpace(s[i])) i += 1
      const target = i < s.length && !isNewline(s[i]) ? readWord() : null
      touch(start, i)
      cmd.redirections.push({ op: redir[0], target })
      continue
    }
    const start = i
    const word = readWord()
    if (word.raw === '') { i += 1; continue }
    touch(start, i)
    // A leading `@` only suppresses echo.
    if (cmd.elements.length === 0 && word.parts.length > 0 && word.parts[0].k === 'text' && word.parts[0].v.startsWith('@')) {
      word.parts[0] = { k: 'text', v: word.parts[0].v.slice(1) }
      if (word.parts[0].v === '' && word.parts.length === 1) continue
    }
    cmd.elements.push(word)
  }
  finishStatement(null)
  return { dialect: 'cmd', statements, issues }
}

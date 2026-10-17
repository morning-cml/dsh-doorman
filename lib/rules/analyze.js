/**
 * Structural analysis of a shell command for the hard rules. Walks the parsed
 * script statement by statement (tracking `cd`, simple variables and aliases),
 * resolves every path an operation targets, and records findings
 * ('deny' / 'ask') plus facts the later layers use (what is deleted, written,
 * run or downloaded, and whether the command is statically opaque).
 */

import { parsePowerShell } from '../shell/powershell.js'
import { parseCmd } from '../shell/cmd.js'
import { parsePosix } from '../shell/posix.js'
import { DASHES } from '../text.js'
import { CMDLETS, DISK_TOOLS, ELEVATION_TOOLS, INLINE_CODE, PS_ALIASES, RUNNABLE_EXT, SHELLS, paramIndex } from './catalog.js'
import { classify } from './classify.js'
import { M } from './messages.js'

const MAX_DEPTH = 8
const DEFENDER_SERVICES = /^(windefend|wdnissvc|sense|mpssvc|wscsvc|securityhealthservice|bfe|wdfilter|wdboot)$/i
const DSH_PROCESS = /deepseek|harness|^dsh(\.exe)?$|electron/i

/**
 * Parse text in a dialect.
 * @param {'powershell' | 'cmd' | 'posix'} dialect
 * @param {string} text
 */
export function parseDialect(dialect, text) {
  if (dialect === 'cmd') return parseCmd(text)
  if (dialect === 'posix') return parsePosix(text)
  return parsePowerShell(text)
}

/** Everything one analysis learns. */
export class Report {
  constructor() {
    /** @type {{ level: 'deny' | 'ask', rule: string, message: string, evidence: string }[]} */
    this.findings = []
    this.opaque = new Set()
    this.deletes = []
    this.writes = []
    this.moves = []
    this.runs = []
    this.downloads = []
    this.downloadedFiles = []
    this.scriptWrites = []
    this.packageScripts = []
    this.outsidePaths = new Set()
    this.commands = new Set()
    this.issues = []
    this.inlineCode = false
    /** @type {Map<string, string>} spellings of paths in carved-out dsh areas (→ area), kept out of the keyword scan. */
    this.exemptTexts = new Map()
    /** Code given to interpreters inline (`python -c`, `node -e`); '\0' when it is not static text. */
    this.inlineTexts = []
  }

  /**
   * Record a finding once.
   * @param {'deny' | 'ask'} level
   * @param {keyof typeof M} rule
   * @param {string} [evidence]
   */
  add(level, rule, evidence = '') {
    if (this.findings.some(f => f.rule === rule && f.evidence === evidence)) return
    this.findings.push({ level, rule, message: M[rule] ?? rule, evidence })
  }
}

/**
 * @typedef {object} Frame
 * @property {'powershell' | 'cmd' | 'posix'} dialect
 * @property {string | undefined} cwd - effective directory, undefined when unknowable.
 * @property {Map<string, string | null>} vars - tracked variables (null = unknown value).
 * @property {Map<string, string>} varRaws - the source text each tracked variable was assigned from.
 * @property {Map<string, string>} aliases - aliases defined earlier in the command.
 * @property {number} depth
 */

/**
 * Analyse a command text.
 * @param {string} text
 * @param {object} options
 * @param {'powershell' | 'cmd' | 'posix'} options.dialect
 * @param {string | undefined} options.cwd - the directory the command starts in.
 * @param {ReturnType<import('../host.js').createHost>} options.host
 * @param {import('./classify.js').Workspace | undefined} options.workspace
 * @returns {Report}
 */
export function analyzeShell(text, { dialect, cwd, host, workspace }) {
  const report = new Report()
  const ctx = { host, ws: workspace, report }
  const frame = { dialect, cwd, vars: new Map(), varRaws: new Map(), aliases: new Map(), depth: 0 }
  analyzeScript(parseDialect(dialect, text), frame, ctx)
  finishStatementPatterns(ctx)
  return report
}

/** Analyse a parsed script in a frame (mutates the frame's cwd/vars as statements run). */
function analyzeScript(script, frame, ctx) {
  for (const issue of script.issues) ctx.report.issues.push(issue)
  if (script.issues.length > 0) ctx.report.opaque.add('解析不完整')
  for (const statement of script.statements) {
    let previous = null
    for (let index = 0; index < statement.commands.length; index += 1) {
      const cmd = statement.commands[index]
      previous = analyzeCommand(cmd, frame, ctx, { index, previous, size: statement.commands.length })
    }
  }
}

function childFrame(frame, dialect = frame.dialect) {
  return { dialect, cwd: frame.cwd, vars: new Map(frame.vars), varRaws: new Map(frame.varRaws), aliases: new Map(frame.aliases), depth: frame.depth + 1 }
}

/** Analyse nested code text (a group body, `cmd /c` text, `-Command` text, iex string). */
function analyzeNested(text, dialect, frame, ctx) {
  if (frame.depth >= MAX_DEPTH) {
    ctx.report.opaque.add('嵌套过深')
    ctx.report.add('ask', 'ask.too-complex')
    return
  }
  analyzeScript(parseDialect(dialect, text), childFrame(frame, dialect), ctx)
}

// ---------------------------------------------------------------------------------------
// Values
// ---------------------------------------------------------------------------------------

/**
 * Resolve a variable reference, or undefined when its value is unknowable.
 * @returns {string | undefined}
 */
function resolveVar(part, frame, ctx) {
  const { host } = ctx
  const raw = part.name
  if (part.splat) return undefined
  const name = frame.dialect === 'posix' ? raw : raw.toLowerCase()
  if (name.toLowerCase().startsWith('env:')) {
    const envName = raw.slice(4)
    const value = host.tools.envGet(envName)
    if (value !== undefined) return value
    if (/^(home|userprofile)$/i.test(envName)) return host.home
    if (frame.vars.has(`env:${envName.toLowerCase()}`)) return frame.vars.get(`env:${envName.toLowerCase()}`) ?? undefined
    return undefined
  }
  if (frame.dialect === 'posix') {
    if (raw === 'home') return host.home
    return undefined
  }
  if (frame.vars.has(name)) return frame.vars.get(name) ?? undefined
  switch (name) {
    case 'home': return host.home
    case 'pwd': return frame.cwd
    case 'true': return 'True'
    case 'false': return 'False'
    case 'null': return ''
    case 'profile': return host.tools.P.join(host.home, 'Documents', 'WindowsPowerShell', 'Microsoft.PowerShell_profile.ps1')
    case 'pshome': return host.tools.P.join(host.tools.envGet('SystemRoot') ?? 'C:\\Windows', 'System32', 'WindowsPowerShell', 'v1.0')
    default: return undefined
  }
}

/** Fold a `( )` group made only of string literals joined with `+`, or a static Join-Path. */
function foldGroup(part, frame, ctx) {
  if (part.kind !== '(') return undefined
  const inner = part.inner.trim()
  const literal = /^(?:'(?:[^']|'')*'|"[^"$`]*")(?:\s*\+\s*(?:'(?:[^']|'')*'|"[^"$`]*"))*$/
  if (literal.test(inner)) {
    const pieces = inner.match(/'(?:[^']|'')*'|"[^"$`]*"/g) ?? []
    return pieces.map(p => (p.startsWith("'") ? p.slice(1, -1).replace(/''/g, "'") : p.slice(1, -1))).join('')
  }
  if (frame.dialect === 'powershell' && /^join-path\b/i.test(inner) && frame.depth < MAX_DEPTH) {
    const parsed = parsePowerShell(inner)
    const cmd = parsed.statements[0]?.commands[0]
    if (parsed.statements.length === 1 && cmd !== undefined && cmd.elements.length >= 3) {
      const b = bind(cmd.elements.slice(1), 'join-path', frame, ctx)
      const base = firstValue(b.named.get('path'), frame, ctx)
      const child = firstValue(b.named.get('childpath'), frame, ctx)
      if (base !== null && child !== null) return ctx.host.tools.P.join(base, child)
    }
  }
  return undefined
}

/**
 * Values of an element: one per array item. Each also carries the source spellings it came from
 * (the word itself and the assignments of the variables it uses).
 * @returns {{ value: string | null, partial: string, quoted: boolean, sources: string[] }[]}
 */
function valuesOf(el, frame, ctx) {
  if (el === null || el === undefined) return []
  if (el.type === 'array') return el.items.flatMap(item => valuesOf(item, frame, ctx))
  let value = ''
  let dynamic = false
  const sources = typeof el.raw === 'string' && el.raw !== '' ? [el.raw] : []
  for (const part of el.parts) {
    if (part.k === 'text') value += part.v
    else if (part.k === 'brack') value += `[${part.inner}]`
    else if (part.k === 'var') {
      const v = resolveVar(part, frame, ctx)
      if (v === undefined) { dynamic = true; value += '\u0000' } else value += v
      const assigned = frame.varRaws?.get(frame.dialect === 'posix' ? part.name : part.name.toLowerCase())
      if (assigned !== undefined) sources.push(assigned)
    } else if (part.k === 'group') {
      const v = foldGroup(part, frame, ctx)
      if (v === undefined) { dynamic = true; value += '\u0000' } else value += v
    }
  }
  return [{ value: dynamic ? null : value, partial: value.replace(/\u0000/g, '…'), quoted: Boolean(el.quoted), sources }]
}

/** First static value of a list of elements, or null. */
function firstValue(elements, frame, ctx) {
  for (const el of elements ?? []) {
    for (const v of valuesOf(el, frame, ctx)) if (v.value !== null) return v.value
  }
  return null
}

/**
 * Static command-line text of an -ArgumentList value, or null when dynamic.
 * Start-Process passes a single string verbatim and joins array items with spaces.
 */
function joinValues(elements, frame, ctx) {
  const out = []
  for (const el of elements) {
    for (const v of valuesOf(el, frame, ctx)) {
      if (v.value === null) return null
      out.push(v.value)
    }
  }
  return out.join(' ')
}

/** Whether a value looks like a file-system path. */
function looksLikePath(value) {
  return /[\\/]/.test(value) || /^~/.test(value) || /^[A-Za-z]:/.test(value) || /^\.{1,2}$/.test(value) || /^(?:hk(?:cu|lm|cr|u|cc):|hkey_|registry::)/i.test(value)
}

/**
 * Resolve a value to a path description.
 * @returns {{ unknown: true, partial?: string } | { kind: string, abs?: string, text?: string }}
 */
function toPath(v, frame, ctx) {
  if (v.value === null) return { unknown: true, partial: v.partial }
  const { tools } = ctx.host
  const c = tools.clean(v.value)
  if (c.kind === 'empty') return { unknown: true, partial: '' }
  if (c.kind === 'registry' || c.kind === 'provider' || c.kind === 'device') return { kind: c.kind, text: c.path }
  let p = c.path
  if (frame.dialect === 'posix' && tools.win) {
    // Git Bash and WSL spellings of Windows drives.
    const m = /^\/(?:mnt\/)?([a-z])(\/.*)?$/i.exec(p)
    if (m) p = `${m[1].toUpperCase()}:${(m[2] ?? '/').replace(/\//g, '\\')}`
  }
  p = tools.expandTilde(p)
  const abs = tools.absolute(p, frame.cwd)
  if (abs === undefined) return { unknown: true, partial: v.value }
  return { kind: c.kind, abs }
}

// ---------------------------------------------------------------------------------------
// PowerShell parameter binding
// ---------------------------------------------------------------------------------------

/** A parameter token (`-Name` or `-Name:value`), or null. */
function paramToken(el) {
  if (el === undefined || el === null || el.type !== 'word' || el.verbatim || el.quotedStart) return null
  const p0 = el.parts[0]
  if (p0 === undefined || p0.k !== 'text' || !DASHES.has(p0.v[0]) || !/^[A-Za-z_?]/.test(p0.v.slice(1))) return null
  const colon = p0.v.indexOf(':')
  if (colon === -1) return { name: p0.v.slice(1).toLowerCase(), value: null }
  const rest = p0.v.slice(colon + 1)
  const valueParts = [...(rest === '' ? [] : [{ k: 'text', v: rest }]), ...el.parts.slice(1)]
  return { name: p0.v.slice(1, colon).toLowerCase(), value: { type: 'word', parts: valueParts, quoted: false, raw: '' } }
}

/** Boolean value of a switch argument; null when unknowable. */
function switchValue(el, frame, ctx) {
  const v = firstValue([el], frame, ctx)
  if (v === null) return null
  if (/^(true|1|\$?true)$/i.test(v)) return true
  if (/^(false|0|\$?false)$/i.test(v)) return false
  return null
}

/**
 * Bind arguments to a cmdlet's parameters the way PowerShell does (names, aliases, unique prefixes, positions).
 * @returns {{ named: Map<string, object[]>, switches: Map<string, boolean | null>, extra: object[], unknown: string[] }}
 */
function bind(args, cmdlet, frame, ctx) {
  const index = paramIndex(cmdlet)
  const named = new Map()
  const switches = new Map()
  const positional = []
  const unknown = []
  for (let i = 0; i < args.length; i += 1) {
    const el = args[i]
    const p = paramToken(el)
    if (p === null) { positional.push(el); continue }
    let names
    if (index.spellings.has(p.name)) names = [index.spellings.get(p.name)]
    else names = [...new Set([...index.spellings.entries()].filter(([s]) => s.startsWith(p.name)).map(([, c]) => c))]
    if (names.length === 0) { unknown.push(p.name); continue }
    if (names.length > 1) unknown.push(p.name)
    const switchNames = names.filter(n => index.spec[n].switch)
    if (switchNames.length === names.length || (names.length > 1 && switchNames.length > 0)) {
      for (const n of switchNames) switches.set(n, p.value === null ? true : switchValue(p.value, frame, ctx))
      if (switchNames.length === names.length) continue
    }
    let valueEl = p.value
    if (valueEl === null && i + 1 < args.length && paramToken(args[i + 1]) === null) {
      valueEl = args[i + 1]
      i += 1
    }
    for (const n of names.filter(x => !index.spec[x].switch)) {
      if (!named.has(n)) named.set(n, [])
      if (valueEl !== null) named.get(n).push(valueEl)
    }
  }
  const positions = Object.entries(index.spec)
    .filter(([, d]) => d.position !== undefined)
    .sort((a, b) => a[1].position - b[1].position)
    .map(([n]) => n)
  const extra = []
  let next = 0
  for (const el of positional) {
    while (next < positions.length && named.has(positions[next])) next += 1
    if (next < positions.length) { named.set(positions[next], [el]); next += 1 } else extra.push(el)
  }
  return { named, switches, extra, unknown }
}

// ---------------------------------------------------------------------------------------
// Target checks
// ---------------------------------------------------------------------------------------

/**
 * Note a finding for a classified path the command touches. Every protected location is denied,
 * except the parts dsh itself directs the agent to use: a program in its bundled runtime or Office
 * tools may be run (with its arguments), never changed; the user's global instructions and skills
 * always go to the user. Those spellings are kept out of the keyword scan, which would deny them.
 * @param {string} abs
 * @param {object} ctx
 * @param {{ modify?: boolean, run?: boolean, value?: { value: string | null, sources?: string[] } }} [use]
 *   `run`: the path is the program being run, or an argument given to a dsh-bundled program.
 */
function mention(abs, ctx, { modify = false, run = false, value } = {}) {
  const cls = classify(abs, ctx.host, ctx.ws)
  if (cls.protected) {
    const runsBundled = run && !modify && (cls.dshArea === 'runtime' || cls.dshArea === 'tool')
    if (cls.dshArea === 'user') ctx.report.add('ask', 'ask.agent-instructions', abs)
    else if (!runsBundled) ctx.report.add('deny', 'deny.protected', `${cls.protected}：${abs}`)
    if ((cls.dshArea === 'user' || runsBundled) && value !== undefined) {
      for (const text of [value.value, ...(value.sources ?? [])]) if (typeof text === 'string') ctx.report.exemptTexts.set(text, cls.dshArea)
    }
  }
  if (cls.outside) ctx.report.outsidePaths.add(abs)
  return cls
}

/** Checks for a path the command deletes. */
function deleteTarget(v, frame, ctx, { recursive, literal }) {
  const { host, report } = ctx
  const path = toPath(v, frame, ctx)
  if (path.unknown) {
    report.opaque.add('删除目标含变量或表达式')
    report.add('ask', 'ask.unknown-delete-target', path.partial ?? '')
    return
  }
  if (path.kind === 'registry') { report.add('ask', 'ask.registry', path.text); return }
  if (path.kind === 'device') { if (/physicaldrive|harddisk|volume|^\\\\\.\\[a-z]:/i.test(path.text)) report.add('deny', 'deny.disk-tool', path.text); return }
  if (path.kind === 'provider') { if (/^cert:/i.test(path.text)) report.add('ask', 'ask.system-config', path.text); return }
  const wild = !literal && host.tools.hasWildcard(path.abs)
  const base = wild ? host.tools.wildcardBase(path.abs) : path.abs
  if (base === undefined) { report.add('ask', 'ask.unknown-delete-target', path.abs); return }
  const cls = mention(base, ctx, { modify: true, value: v })
  report.deletes.push({ path: path.abs, recursive, outside: cls.outside })
  if (cls.isRoot || cls.isHome || cls.isUsersRoot || cls.systemRoot) report.add('deny', 'deny.root-home', path.abs)
  if (cls.outside && recursive) report.add('deny', 'deny.recursive-delete-outside', path.abs)
  if (cls.sensitive) report.add('ask', `ask.${cls.sensitive}`, path.abs)
  if (cls.system) report.add('ask', 'ask.system-dir', path.abs)
}

/** Checks for a path the command writes or creates. */
function writeTarget(v, frame, ctx, { kind = 'write', literal = false } = {}) {
  const { host, report } = ctx
  const path = toPath(v, frame, ctx)
  if (path.unknown) { report.opaque.add('写入目标含变量或表达式'); return }
  if (path.kind === 'registry') { report.add('ask', 'ask.registry', path.text); return }
  if (path.kind === 'device') { if (/physicaldrive|harddisk|volume|^\\\\\.\\[a-z]:/i.test(path.text)) report.add('deny', 'deny.disk-tool', path.text); return }
  if (path.kind === 'provider') { if (/^cert:/i.test(path.text)) report.add('ask', 'ask.system-config', path.text); return }
  const abs = !literal && host.tools.hasWildcard(path.abs) ? (host.tools.wildcardBase(path.abs) ?? path.abs) : path.abs
  const cls = mention(abs, ctx, { modify: true, value: v })
  report.writes.push({ path: abs, kind, outside: cls.outside, exists: host.exists(abs) })
  if (RUNNABLE_EXT.test(abs)) report.scriptWrites.push(abs)
  if (path.kind === 'unc') report.add('ask', 'ask.unusual-path', abs)
  if (cls.isRoot || cls.isHome || cls.isUsersRoot || cls.systemRoot) {
    if (kind === 'move-source' || kind === 'acl') report.add('deny', 'deny.root-home', abs)
  }
  if (cls.sensitive) report.add('ask', `ask.${cls.sensitive}`, abs)
  if (cls.system) report.add('ask', 'ask.system-dir', abs)
}

/** Checks for permission, owner or attribute changes. */
function aclTarget(v, frame, ctx, rule = 'ask.accounts') {
  const path = toPath(v, frame, ctx)
  if (path.unknown || path.kind !== 'file') { ctx.report.add('ask', rule, v.partial ?? ''); return }
  const base = ctx.host.tools.hasWildcard(path.abs) ? (ctx.host.tools.wildcardBase(path.abs) ?? path.abs) : path.abs
  const cls = mention(base, ctx, { modify: true, value: v })
  if (cls.isRoot || cls.isHome || cls.isUsersRoot || cls.systemRoot) ctx.report.add('deny', 'deny.root-home', path.abs)
  else if (cls.outside) ctx.report.add('ask', rule, path.abs)
}

/**
 * Record a program or script the command runs.
 * @param {object} v
 * @param {object} frame
 * @param {object} ctx
 * @param {{ script?: boolean }} [options] - `script`: the file's text is executed as code whatever its extension.
 */
function runTarget(v, frame, ctx, { script = false } = {}) {
  const path = toPath(v, frame, ctx)
  if (path.unknown) { ctx.report.opaque.add('运行的程序含变量或表达式'); return undefined }
  if (path.kind !== 'file' && path.kind !== 'unc') return undefined
  const cls = mention(path.abs, ctx, { run: true, value: v })
  ctx.report.runs.push({ path: path.abs, agentWritable: cls.agentWritable, ...(script ? { script: true } : {}), ...(cls.dshArea ? { dshArea: cls.dshArea } : {}) })
  return cls
}

// ---------------------------------------------------------------------------------------
// Commands
// ---------------------------------------------------------------------------------------

/** Visit embedded code in an element: subexpressions, groups, script blocks, backticks. */
function visitGroups(el, frame, ctx) {
  if (el === null || el === undefined) return
  if (el.type === 'array') { for (const item of el.items) visitGroups(item, frame, ctx); return }
  for (const part of el.parts) {
    if (part.k === 'var' && part.braced && /[\\/:]/.test(part.name) && !/^env:/i.test(part.name)) {
      // ${C:\path} reads or writes a file through the variable syntax.
      ctx.report.opaque.add('变量语法读写文件')
      const path = toPath({ value: part.name, partial: part.name }, frame, ctx)
      if (!path.unknown && path.abs) writeTarget({ value: part.name, partial: part.name }, frame, ctx, { kind: 'write', literal: true })
    }
    if (part.k !== 'group') continue
    if (part.kind === '$((') continue
    if (part.kind === '(' && foldGroup(part, frame, ctx) !== undefined) continue
    if (part.kind === '$(' || part.kind === '`' || part.kind === '<(' || part.kind === '>(') ctx.report.opaque.add('命令替换')
    else if (part.kind === '{') ctx.report.opaque.add('内联代码块')
    else if (part.kind === '(' || part.kind === '@(') ctx.report.opaque.add('表达式')
    const dialect = frame.dialect === 'cmd' ? 'powershell' : frame.dialect
    analyzeNested(part.inner, dialect, frame, ctx)
  }
}

/**
 * Work out the command name.
 * @returns {{ kind: 'expression' } | { kind: 'dynamic', partial: string } | { kind: 'name', canon: string, exe: string, raw: string, pathy: boolean, nameValue: object }}
 */
function commandName(cmd, frame, ctx) {
  const first = cmd.elements[0]
  if (first === undefined) return { kind: 'expression' }
  if (frame.dialect === 'powershell' && cmd.call === null && first.type === 'word') {
    const p0 = first.parts[0]
    if (first.quotedStart || p0 === undefined) return { kind: 'expression' }
    if (p0.k === 'brack' || p0.k === 'var' || p0.k === 'group') return { kind: 'expression' }
    if (p0.k === 'text' && /^[0-9]/.test(p0.v)) return { kind: 'expression' }
  }
  if (first.type === 'word' && first.parts.length === 1 && first.parts[0].k === 'group' && first.parts[0].kind === '{') {
    return { kind: 'expression' }
  }
  const [v] = valuesOf(first, frame, ctx)
  if (v === undefined || v.value === null) return { kind: 'dynamic', partial: v?.partial ?? first.raw }
  const raw = v.value.trim()
  const pathy = /[\\/]/.test(raw)
  let exe = raw.split(/[\\/]/).pop() ?? raw
  exe = exe.toLowerCase()
  let canon = exe.replace(/\.(exe|com)$/i, '')
  if (frame.dialect === 'powershell' && !pathy) {
    if (frame.aliases.has(canon)) canon = frame.aliases.get(canon)
    else if (Object.hasOwn(PS_ALIASES, canon)) canon = PS_ALIASES[canon]
    if (canon === '?dynamic') return { kind: 'dynamic', partial: raw }
  }
  // Module-qualified cmdlets: Microsoft.PowerShell.Management\Remove-Item.
  if (frame.dialect === 'powershell' && pathy && /^[a-z0-9.]+\\[a-z]+-[a-z]+$/i.test(raw)) {
    canon = exe
  }
  return { kind: 'name', canon, exe, raw, pathy, nameValue: v }
}

/** A quoted literal, or quoted literals joined with `+`, with no expansion inside. */
const LITERAL_CONCAT = /^(?:'(?:[^']|'')*'|"[^"$`]*")(?:\s*\+\s*(?:'(?:[^']|'')*'|"[^"$`]*"))*$/

/** The value of a literal concatenation such as `'C:\a' + "b"`, or undefined. */
function foldLiteralConcat(text) {
  if (!LITERAL_CONCAT.test(text.trim())) return undefined
  const pieces = text.match(/'(?:[^']|'')*'|"[^"$`]*"/g) ?? []
  return pieces.map(p => (p.startsWith("'") ? p.slice(1, -1).replace(/''/g, "'") : p.slice(1, -1))).join('')
}

/**
 * Split `$x='…'` (no spaces) into target, operator and value words, as PowerShell reads it.
 * The lexer keeps such a statement as one word whose first part is the variable.
 * @returns {object[] | null} the elements, or null when the word is not an assignment.
 */
function splitGluedAssignment(els) {
  const first = els[0]
  // `$x ='…'`: the operator is glued to the value instead.
  const second = els[1]
  if (first?.type === 'word' && first.parts.length === 1 && first.parts[0].k === 'var' && second?.type === 'word' && second.parts[0]?.k === 'text') {
    const op = /^(?:[+\-*/%]|\?\?)?=(?!=)/.exec(second.parts[0].v)
    if (op === null || second.raw.indexOf(op[0]) !== 0 || second.raw.length === op[0].length) return null
    const rest = second.parts[0].v.slice(op[0].length)
    const parts = [...(rest === '' ? [] : [{ k: 'text', v: rest }]), ...second.parts.slice(1)]
    return [first, { type: 'word', parts: [{ k: 'text', v: op[0] }], quoted: false, raw: op[0] }, { type: 'word', parts, quoted: second.quoted, raw: second.raw.slice(op[0].length) }, ...els.slice(2)]
  }
  if (first?.type !== 'word' || first.parts.length < 2 || first.parts[0].k !== 'var' || first.parts[0].splat) return null
  const text = first.parts[1]
  const op = text.k === 'text' ? /^(?:[+\-*/%]|\?\?)?=(?!=)/.exec(text.v) : null
  if (op === null) return null
  const at = first.raw.indexOf(op[0])
  if (at < 1) return null
  const rest = text.v.slice(op[0].length)
  const parts = [...(rest === '' ? [] : [{ k: 'text', v: rest }]), ...first.parts.slice(2)]
  const target = { type: 'word', parts: [first.parts[0]], quoted: false, raw: first.raw.slice(0, at) }
  const opWord = { type: 'word', parts: [{ k: 'text', v: op[0] }], quoted: false, raw: op[0] }
  const value = { type: 'word', parts, quoted: first.quoted, raw: first.raw.slice(at + op[0].length) }
  return [target, opWord, ...(parts.length > 0 ? [value] : []), ...els.slice(1)]
}

/** PowerShell assignment `$x = …`; returns true when handled. */
function handleAssignment(cmd, frame, ctx) {
  let els = cmd.elements
  if (frame.dialect !== 'powershell') return false
  els = splitGluedAssignment(els) ?? els
  if (els.length < 2) return false
  let target = els[0]
  let opIndex = 1
  if (target.type === 'word' && target.parts.length === 1 && target.parts[0].k === 'brack' && els.length >= 3) {
    target = els[1]
    opIndex = 2
  }
  if (target.type !== 'word' || target.parts.length !== 1 || target.parts[0].k !== 'var' || target.parts[0].splat) return false
  const op = els[opIndex]
  if (op === undefined || op.type !== 'word' || !/^(?:[+\-*/%]|\?\?)?=$/.test(op.raw)) return false
  const name = target.parts[0].name.toLowerCase()
  const rhs = els.slice(opIndex + 1)
  frame.varRaws.delete(name)
  if (target.parts[0].braced && /[\\/:]/.test(target.parts[0].name) && !/^env:/i.test(target.parts[0].name)) {
    writeTarget({ value: target.parts[0].name, partial: target.parts[0].name }, frame, ctx, { literal: true })
  }
  if (rhs.length === 0) return true
  const first = rhs[0]
  const isValue = first.type === 'array' || first.quoted || first.parts.every(p => p.k !== 'text') || /^[0-9$@(]/.test(first.raw)
  if (isValue && op.raw === '=') {
    // 'a' + 'b' (spaced or glued) is folded; any other expression leaves the value unknown.
    const joined = rhs.map(el => el.raw).join(' ')
    const folded = foldLiteralConcat(joined)
    const glued = rhs.length === 1 && first.type === 'word' && !/^(?:'(?:[^']|'')*'|"(?:[^"`]|`.)*")$/s.test(first.raw.trim()) && /['"]\s*\+/.test(first.raw)
    if (folded !== undefined) {
      frame.vars.set(name, folded)
      frame.varRaws.set(name, joined)
      return true
    }
    if (rhs.length === 1 && !glued) {
      const v = valuesOf(first, frame, ctx)
      frame.vars.set(name, v.length === 1 ? v[0].value : null)
      frame.varRaws.set(name, first.raw)
      visitGroups(first, frame, ctx)
      return true
    }
  }
  frame.vars.set(name, null)
  if (isValue) {
    for (const el of rhs) visitGroups(el, frame, ctx)
    return true
  }
  analyzeCommand({ ...cmd, elements: rhs }, frame, ctx, { index: 0, previous: null, size: 1 })
  return true
}

/**
 * Analyse one command.
 * @returns {object | null} pipeline info for the next command.
 */
function analyzeCommand(cmd, frame, ctx, pipe) {
  const { report } = ctx
  for (const el of cmd.elements) visitGroups(el, frame, ctx)
  for (const r of cmd.redirections) {
    if (r.target === null) continue
    visitGroups(r.target, frame, ctx)
    if (r.op.includes('>')) {
      for (const v of valuesOf(r.target, frame, ctx)) {
        if (v.value !== null && /^(\$null|nul|\/dev\/null)$/i.test(v.value.trim())) continue
        writeTarget(v, frame, ctx, { kind: r.op.includes('>>') ? 'append' : 'overwrite', literal: true })
      }
    }
  }
  if (handleAssignment(cmd, frame, ctx)) return null

  // POSIX prefix assignments: FOO=bar cmd …
  let elements = cmd.elements
  if (frame.dialect === 'posix') {
    while (elements.length > 0 && elements[0].type === 'word' && elements[0].parts[0]?.k === 'text' && /^[A-Za-z_][A-Za-z0-9_]*=/.test(elements[0].parts[0].v)) {
      const [assign] = valuesOf(elements[0], frame, ctx)
      const eq = elements[0].parts[0].v.indexOf('=')
      const varName = elements[0].parts[0].v.slice(0, eq)
      if (elements.length === 1) frame.vars.set(`env:${varName.toLowerCase()}`, assign?.value === null ? null : (assign?.value ?? '').slice(eq + 1))
      elements = elements.slice(1)
    }
    if (elements.length === 0) return null
  }
  const name = commandName({ ...cmd, elements }, frame, ctx)
  if (name.kind === 'expression') {
    scanExpression(cmd, frame, ctx)
    for (const el of elements) mentionWord(el, frame, ctx)
    return null
  }
  if (name.kind === 'dynamic') {
    report.opaque.add('命令名含变量或表达式')
    // A computed command name together with destructive-looking words: nobody can tell what runs.
    const text = `${name.partial} ${cmd.raw}`.toLowerCase()
    if (/remove|delete|erase|format|clear-|move-item|\b(rm|rd|del|mv|rmdir)\b|-r(ec|ecurse)?\b|\/s\b/.test(text)) report.add('ask', 'ask.too-complex', name.partial.slice(0, 60))
    for (const el of elements) mentionWord(el, frame, ctx)
    return null
  }
  report.commands.add(name.canon)
  const args = elements.slice(1)
  let program
  if (name.pathy) {
    const [v] = valuesOf(elements[0], frame, ctx)
    if (v) program = runTarget(v, frame, ctx)
  } else if (RUNNABLE_EXT.test(name.exe) && /\.(ps1|bat|cmd|sh|py|js|vbs)$/i.test(name.exe)) {
    program = runTarget(name.nameValue, frame, ctx)
  }
  // dsh's bundled Python/Node is handed dsh's own scripts (the Office CLI) as arguments.
  const toBundled = program?.dshArea === 'runtime'
  // Start-Process names its program in -FilePath: that word is a run, checked by its handler.
  const programWord = name.canon === 'start-process' && frame.dialect === 'powershell' ? bind(args, 'start-process', frame, ctx).named.get('filepath')?.[0] : undefined
  for (const el of args) if (el !== programWord) mentionWord(el, frame, ctx, toBundled)
  const handler = HANDLERS[frame.dialect]?.[name.canon] ?? NATIVE[name.canon]
  let info = null
  if (handler !== undefined) info = handler({ args, cmd, frame, ctx, pipe, name }) ?? null
  if (DISK_TOOLS.has(name.canon) || /^mkfs(\..+)?$/.test(name.canon)) report.add('deny', 'deny.disk-tool', name.canon)
  if (ELEVATION_TOOLS.has(name.canon)) report.add('ask', 'ask.elevation', name.canon)
  if (Object.hasOwn(INLINE_CODE, name.canon)) {
    const flags = INLINE_CODE[name.canon]
    const values = args.flatMap(el => valuesOf(el, frame, ctx))
    const options = interpreterOptions(name.canon, values)
    for (let i = 0; i < options.length; i += 1) {
      const v = options[i]
      if (v.value === null) continue
      const flag = flags.find(f => v.value === f || v.value.startsWith(`${f}=`) || (/^-[a-z]$/i.test(f) && v.value.startsWith(f) && v.value.length > 2 && !v.value.startsWith('--')))
      if (flag === undefined) continue
      report.inlineCode = true
      report.opaque.add('解释器内联代码')
      // `options` is a prefix of `values`, so the code word follows at the same index.
      const code = v.value === flag ? values[i + 1]?.value : v.value.slice(flag.length).replace(/^=/, '')
      report.inlineTexts.push(typeof code === 'string' ? code : '\u0000')
    }
    const script = values.find(v => v.value !== null && /\.(py|js|mjs|cjs|ts|pl|rb|php|lua)$/i.test(v.value))
    if (script !== undefined) runTarget(script, frame, ctx)
  }
  // Web download piped straight into something that runs code.
  if (pipe.previous?.download && pipe.index > 0 && (name.canon === 'invoke-expression' || Object.hasOwn(SHELLS, name.canon) || Object.hasOwn(INLINE_CODE, name.canon))) {
    report.add('deny', 'deny.download-exec', `${pipe.previous.name} | ${name.canon}`)
  }
  return { name: name.canon, ...(info ?? {}) }
}

/** Options of node and python that take the next word as their value. */
const OPTION_VALUES = {
  node: new Set(['-r', '--require', '--import', '--loader', '--experimental-loader', '-C', '--conditions', '--input-type', '--title', '--env-file', '--inspect-port', '--redirect-warnings']),
  python: new Set(['-W', '-X', '--check-hash-based-pycs']),
}

/**
 * The words that are options of the interpreter itself. For node and python, everything after the
 * script file or `-m module` belongs to the script (`node tsc -p x` is tsc's -p); other
 * interpreters are read whole, the conservative way.
 */
function interpreterOptions(canon, values) {
  const family = canon === 'node' ? 'node' : /^(python[0-9.]*|py|pythonw)$/.test(canon) ? 'python' : null
  if (family === null) return values
  const out = []
  for (let i = 0; i < values.length; i += 1) {
    const v = values[i].value
    out.push(values[i])
    if (v === null) return values
    if (v === '--') break
    if (!v.startsWith('-')) { out.pop(); break }
    if (OPTION_VALUES[family].has(v) && i + 1 < values.length) { out.push(values[i + 1]); i += 1; continue }
    if (family === 'python' && v === '-m') break
  }
  return out
}

/**
 * Generic "mention" check of an argument word.
 * @param {boolean} [toBundled] - the word is an argument of a program in dsh's bundled runtime.
 */
function mentionWord(el, frame, ctx, toBundled = false) {
  for (const v of valuesOf(el, frame, ctx)) {
    if (v.value === null) { ctx.report.opaque.add('参数含未知变量或表达式'); continue }
    if (!looksLikePath(v.value)) continue
    const path = toPath(v, frame, ctx)
    if (!path.unknown && path.abs !== undefined) mention(path.abs, ctx, { run: toBundled, value: v })
  }
}

/** Expression statements: .NET file and process calls. */
function scanExpression(cmd, frame, ctx) {
  const text = cmd.raw
  const lower = text.toLowerCase()
  const literalPaths = [...text.matchAll(/'((?:[^']|'')*)'|"([^"$`]*)"/g)].map(m => (m[1] ?? m[2] ?? '').replace(/''/g, "'"))
  const firstArg = (re) => {
    const m = re.exec(text)
    if (!m) return null
    const rest = text.slice(m.index + m[0].length)
    const lit = /^\s*(?:'((?:[^']|'')*)'|"([^"$`]*)")/.exec(rest)
    if (lit) return { value: (lit[1] ?? lit[2]).replace(/''/g, "'"), partial: lit[0] }
    const variable = /^\s*\$([A-Za-z_][A-Za-z0-9_]*)/.exec(rest)
    if (variable && frame.vars.has(variable[1].toLowerCase())) {
      const value = frame.vars.get(variable[1].toLowerCase())
      return { value: value ?? null, partial: `$${variable[1]}` }
    }
    return { value: null, partial: rest.slice(0, 60) }
  }
  const dirDelete = firstArg(/\[(?:system\.)?io\.directory\]::delete\s*\(/i) ?? firstArg(/\[microsoft\.visualbasic\.fileio\.filesystem\]::deletedirectory\s*\(/i)
  if (dirDelete) {
    const recursive = /::delete\s*\([^,)]*,\s*(\$true|1)/i.test(text) || /deletedirectory/i.test(text)
    deleteTarget(dirDelete, frame, ctx, { recursive, literal: true })
  }
  const fileDelete = firstArg(/\[(?:system\.)?io\.file\]::delete\s*\(/i) ?? firstArg(/\[microsoft\.visualbasic\.fileio\.filesystem\]::deletefile\s*\(/i)
  if (fileDelete) deleteTarget(fileDelete, frame, ctx, { recursive: false, literal: true })
  for (const re of [/\[(?:system\.)?io\.file\]::(?:writealltext|writeallbytes|writealllines|appendalltext|appendalllines|create|createtext|openwrite|copy|move|replace)\s*\(/i]) {
    const target = firstArg(re)
    if (target) writeTarget(target, frame, ctx, { literal: true })
  }
  if (/\.(delete|deletefolder|deletefile|deletesubkeytree|deletesubkey)\s*\(/i.test(text) && !dirDelete && !fileDelete) {
    // (Get-Item x).Delete($true), $dirInfo.Delete($true), $fso.DeleteFolder('x')
    const recursive = /\.delete\s*\(\s*(\$true|1)\s*\)|\.deletefolder\s*\(/i.test(text)
    const candidates = literalPaths.filter(p => looksLikePath(p))
    if (candidates.length === 0) ctx.report.add('ask', 'ask.unknown-delete-target', text.slice(0, 80))
    for (const p of candidates) deleteTarget({ value: p, partial: p }, frame, ctx, { recursive, literal: true })
  }
  if (/\[(?:system\.)?diagnostics\.process\]::start\s*\(/i.test(text) || /\[activator\]::createinstance|new-object\s+-com(object)?\b/i.test(lower)) {
    ctx.report.opaque.add('通过 .NET/COM 运行程序')
  }
  if (/\[microsoft\.win32\.registry\]|\[microsoft\.win32\.registrykey\]/i.test(text)) ctx.report.add('ask', 'ask.registry', '.NET Registry')
  if (/\[(?:system\.)?environment\]::setenvironmentvariable\s*\([^)]*(user|machine)/i.test(text)) ctx.report.add('ask', 'ask.registry', 'SetEnvironmentVariable')
  for (const p of literalPaths) if (looksLikePath(p)) mentionWord({ type: 'word', parts: [{ k: 'text', v: p }], quoted: true, raw: p }, frame, ctx)
  ctx.report.opaque.add('.NET 表达式')
}

// ---------------------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------------------

const allValues = (els, frame, ctx) => (els ?? []).flatMap(el => valuesOf(el, frame, ctx))

/** Remove-Item and its aliases (PowerShell). */
function psRemoveItem({ args, frame, ctx, pipe }) {
  const b = bind(args, 'remove-item', frame, ctx)
  let recursive = b.switches.has('recurse') ? b.switches.get('recurse') : false
  if (recursive === null) recursive = true
  // bash or cmd habits given to the PowerShell alias (rm -rf, rd /s): treat as recursive.
  if (b.unknown.some(n => /^(r|rf|fr|rq|qr|recursive|s|sq|qs|rfv|vrf)$/.test(n))) recursive = true
  const literal = (b.named.get('literalpath') ?? []).length > 0
  const targets = []
  for (const v of allValues([...(b.named.get('path') ?? []), ...(b.named.get('literalpath') ?? []), ...b.extra], frame, ctx)) {
    if (v.value !== null && /^\/[a-z]$/i.test(v.value)) { if (/^\/s$/i.test(v.value)) recursive = true; continue }
    targets.push(v)
  }
  if (targets.length === 0) {
    if (pipe.previous?.sources !== undefined) {
      for (const v of pipe.previous.sources) deleteTarget(v, frame, ctx, { recursive: true, literal: false })
      if (pipe.previous.sources.length === 0) ctx.report.add('ask', 'ask.unknown-delete-target', 'pipeline')
    } else {
      ctx.report.add('ask', 'ask.unknown-delete-target', pipe.index > 0 ? 'pipeline' : '')
    }
    return
  }
  for (const v of targets) deleteTarget(v, frame, ctx, { recursive, literal })
}

/** Get-ChildItem / Get-Item / Resolve-Path: remember sources for a following Remove-Item. */
function psListing(cmdlet) {
  return ({ args, frame, ctx }) => {
    const b = bind(args, cmdlet, frame, ctx)
    const sources = allValues([...(b.named.get('path') ?? []), ...(b.named.get('literalpath') ?? [])], frame, ctx)
    return { sources: sources.length > 0 ? sources : (frame.cwd !== undefined ? [{ value: frame.cwd, partial: frame.cwd }] : []) }
  }
}

/** Move-Item / Rename-Item. */
function psMove(cmdlet) {
  return ({ args, frame, ctx }) => {
    const b = bind(args, cmdlet, frame, ctx)
    for (const v of allValues([...(b.named.get('path') ?? []), ...(b.named.get('literalpath') ?? [])], frame, ctx)) moveSource(v, frame, ctx)
    if (cmdlet === 'move-item') for (const v of allValues(b.named.get('destination'), frame, ctx)) writeTarget(v, frame, ctx, { kind: 'move-dest', literal: true })
  }
}

/** Checks for something moved away (source of a move or rename). */
function moveSource(v, frame, ctx) {
  const path = toPath(v, frame, ctx)
  if (path.unknown) { ctx.report.opaque.add('移动目标含变量或表达式'); ctx.report.add('ask', 'ask.unknown-delete-target', path.partial ?? ''); return }
  if (path.kind !== 'file' && path.kind !== 'unc') { if (path.kind === 'registry') ctx.report.add('ask', 'ask.registry', path.text); return }
  const cls = mention(path.abs, ctx, { modify: true, value: v })
  ctx.report.moves.push({ path: path.abs, outside: cls.outside })
  if (cls.isRoot || cls.isHome || cls.isUsersRoot || cls.systemRoot) ctx.report.add('deny', 'deny.root-home', path.abs)
  if (cls.sensitive) ctx.report.add('ask', `ask.${cls.sensitive}`, path.abs)
  if (cls.system) ctx.report.add('ask', 'ask.system-dir', path.abs)
}

/** Cmdlets that write files through named parameters. */
function psWrite(cmdlet, params, kind = 'overwrite') {
  return ({ args, frame, ctx }) => {
    const b = bind(args, cmdlet, frame, ctx)
    const literal = (b.named.get('literalpath') ?? []).length > 0
    for (const param of params) {
      for (const v of allValues(b.named.get(param), frame, ctx)) writeTarget(v, frame, ctx, { kind, literal: literal || param !== 'path' })
    }
  }
}

/** New-Item / mkdir: Path joined with Name. */
function psNewItem(cmdlet) {
  return ({ args, frame, ctx }) => {
    const b = bind(args, cmdlet, frame, ctx)
    const name = firstValue(b.named.get('name'), frame, ctx)
    const paths = allValues(b.named.get('path'), frame, ctx)
    const targets = paths.length > 0 ? paths : [{ value: frame.cwd ?? null, partial: '.' }]
    for (const v of targets) {
      const value = v.value !== null && name !== null ? ctx.host.tools.P.join(v.value, name) : v.value
      writeTarget({ value, partial: v.partial }, frame, ctx, { kind: 'create', literal: true })
    }
    const type = firstValue(b.named.get('itemtype'), frame, ctx)
    if (type !== null && /^(symboliclink|junction|hardlink)$/i.test(type)) ctx.report.opaque.add('创建链接')
  }
}

/** Set-Location / Push-Location: track the effective directory. */
function psSetLocation(cmdlet) {
  return ({ args, frame, ctx }) => {
    const b = bind(args, cmdlet, frame, ctx)
    const target = [...(b.named.get('path') ?? []), ...(b.named.get('literalpath') ?? [])]
    if (target.length === 0) { frame.cwd = ctx.host.home; return }
    const [v] = valuesOf(target[0], frame, ctx)
    if (v === undefined || v.value === null || v.value === '-' || v.value === '+') { frame.cwd = undefined; return }
    const path = toPath(v, frame, ctx)
    frame.cwd = path.unknown || path.abs === undefined ? undefined : path.abs
  }
}

/** Start-Process: elevation, nested shells, programs run. */
function psStartProcess({ args, frame, ctx }) {
  const b = bind(args, 'start-process', frame, ctx)
  const verb = firstValue(b.named.get('verb'), frame, ctx)
  if (verb !== null && /^runas/i.test(verb)) ctx.report.add('ask', 'ask.elevation', 'Start-Process -Verb RunAs')
  if (b.named.has('verb') && verb === null) ctx.report.add('ask', 'ask.elevation', 'Start-Process -Verb ?')
  if (b.named.has('credential')) ctx.report.add('ask', 'ask.elevation', 'Start-Process -Credential')
  const file = allValues(b.named.get('filepath'), frame, ctx)[0]
  if (file === undefined) return
  if (file.value === null) { ctx.report.opaque.add('运行的程序含变量或表达式'); return }
  const exe = (file.value.split(/[\\/]/).pop() ?? '').toLowerCase().replace(/\.(exe|com)$/, '')
  const argText = b.named.has('argumentlist') ? joinValues(b.named.get('argumentlist'), frame, ctx) : ''
  if (Object.hasOwn(SHELLS, exe)) {
    if (looksLikePath(file.value)) {
      const path = toPath(file, frame, ctx)
      if (!path.unknown && path.abs !== undefined) mention(path.abs, ctx, { run: true, value: file })
    }
    if (argText === null) { ctx.report.opaque.add('参数含变量或表达式'); return }
    const words = splitArgs(argText)
    shellInvocation(SHELLS[exe], exe, words, frame, ctx)
    return
  }
  if (exe === 'msiexec' || exe === 'mshta' || exe === 'rundll32' || exe === 'regsvr32' || exe === 'certutil') {
    NATIVE[exe]?.({ args: splitArgs(argText ?? '').map(textWord), frame, ctx, pipe: { index: 0, previous: null }, name: { canon: exe } })
  }
  if (ELEVATION_TOOLS.has(exe)) ctx.report.add('ask', 'ask.elevation', exe)
  if (DISK_TOOLS.has(exe)) ctx.report.add('deny', 'deny.disk-tool', exe)
  if (/^https?:/i.test(file.value)) return
  runTarget(file, frame, ctx)
}

/**
 * The files whose text an expression reads in full: `(Get-Content x [-Raw])`, `(gc x | Out-String)`
 * or `([IO.File]::ReadAllText('x'))`. Null for anything else.
 * @returns {object[] | null}
 */
function fileTextSource(el, frame, ctx) {
  if (el?.type !== 'word' || el.parts.length !== 1 || el.parts[0].k !== 'group' || el.parts[0].kind !== '(') return null
  if (frame.depth >= MAX_DEPTH) return null
  const inner = el.parts[0].inner.trim()
  const read = /^\[(?:system\.)?io\.file\]::readalltext\s*\(\s*('(?:[^']|'')*'|"[^"$`]*")\s*(?:,[^)]*)?\)$/i.exec(inner)
  if (read) {
    const text = read[1].startsWith("'") ? read[1].slice(1, -1).replace(/''/g, "'") : read[1].slice(1, -1)
    return [{ value: text, partial: text, quoted: true, sources: [read[1]] }]
  }
  const parsed = parsePowerShell(inner)
  if (parsed.issues.length > 0 || parsed.statements.length !== 1) return null
  const [first, ...rest] = parsed.statements[0].commands
  if (first === undefined || rest.some(c => !/^out-string$/i.test(c.elements[0]?.raw ?? ''))) return null
  const name = commandName(first, frame, ctx)
  if (name.kind !== 'name' || name.canon !== 'get-content') return null
  return psGetContent({ args: first.elements.slice(1), frame, ctx }).contentOf
}

/** Get-Content: remember the files read, for a following Invoke-Expression. */
function psGetContent({ args, frame, ctx }) {
  const b = bind(args, 'get-content', frame, ctx)
  const files = allValues([...(b.named.get('path') ?? []), ...(b.named.get('literalpath') ?? [])], frame, ctx)
  return { contentOf: files.length > 0 ? files : null }
}

/** Invoke-Expression: run a file's text as a script, analyse a static string, otherwise mark opaque. */
function psInvokeExpression({ args, frame, ctx, pipe }) {
  const b = bind(args, 'invoke-expression', frame, ctx)
  const command = b.named.get('command') ?? []
  ctx.report.opaque.add('Invoke-Expression')
  // iex (Get-Content x.ps1 -Raw) and Get-Content x.ps1 | iex run that file: the reviewer gets its text.
  const files = command.length === 0 ? (pipe.index > 0 ? pipe.previous?.contentOf ?? null : null) : fileTextSource(command[0], frame, ctx)
  if (files !== null) {
    for (const v of files) runTarget(v, frame, ctx, { script: true })
    return
  }
  const text = firstValue(command, frame, ctx)
  if (text === null) {
    if (command.length === 0) ctx.report.add('ask', 'ask.too-complex', 'iex')
    return
  }
  analyzeNested(text, 'powershell', frame, ctx)
}

/** Invoke-Command: remote targets and script files. */
function psInvokeCommand({ args, frame, ctx }) {
  const b = bind(args, 'invoke-command', frame, ctx)
  for (const remote of ['computername', 'session', 'hostname', 'vmname']) if (b.named.has(remote)) ctx.report.add('ask', 'ask.remote', remote)
  for (const v of allValues(b.named.get('filepath'), frame, ctx)) runTarget(v, frame, ctx)
  ctx.report.opaque.add('内联代码块')
}

/** Web downloads (Invoke-WebRequest, curl, wget, BITS). */
function webDownload(kind) {
  return ({ args, frame, ctx, name }) => {
    ctx.report.downloads.push(name.canon)
    let outputs = []
    if (kind === 'ps') {
      const b = bind(args, name.canon === 'invoke-restmethod' ? 'invoke-restmethod' : 'invoke-webrequest', frame, ctx)
      outputs = allValues(b.named.get('outfile'), frame, ctx)
    } else if (kind === 'bits') {
      const b = bind(args, 'start-bitstransfer', frame, ctx)
      outputs = allValues(b.named.get('destination'), frame, ctx)
    }
    if (kind !== 'bits') {
      // curl/wget flags, and -OutFile given to the Windows PowerShell curl/wget aliases.
      const values = allValues(args, frame, ctx)
      for (let i = 0; i < values.length; i += 1) {
        const v = values[i].value ?? ''
        if (/^(-o|--output|-O|--output-document)$/.test(v) && values[i + 1] !== undefined) outputs.push(values[i + 1])
        else if (/^--output(-document)?=/.test(v)) outputs.push({ value: v.slice(v.indexOf('=') + 1), partial: v })
        else if (/^-o[^u]/i.test(v) && kind === 'curl') outputs.push({ value: v.slice(2), partial: v })
        else if (kind === 'curl' && /^[-–—―]outf(i(le?)?)?(:.*)?$/i.test(v)) {
          const colon = v.indexOf(':')
          if (colon !== -1) outputs.push({ value: v.slice(colon + 1), partial: v })
          else if (values[i + 1] !== undefined) outputs.push(values[i + 1])
        }
      }
    }
    for (const v of outputs) {
      writeTarget(v, frame, ctx, { kind: 'download', literal: true })
      const path = toPath(v, frame, ctx)
      if (!path.unknown && path.abs) ctx.report.downloadedFiles.push(path.abs)
    }
    return { download: true }
  }
}

/** Stop-Process / taskkill / kill: never the dsh process. */
function killCheck({ args, frame, ctx }) {
  for (const v of allValues(args, frame, ctx)) {
    if (v.value !== null && DSH_PROCESS.test(v.value.replace(/^["']|["']$/g, ''))) ctx.report.add('deny', 'deny.kill-dsh', v.value)
  }
}

/** Set-Alias / New-Alias. */
function psAlias(cmdlet) {
  return ({ args, frame, ctx }) => {
    const b = bind(args, cmdlet, frame, ctx)
    const name = firstValue(b.named.get('name'), frame, ctx)
    const value = firstValue(b.named.get('value'), frame, ctx)
    if (name === null) return
    if (value === null) { frame.aliases.set(name.toLowerCase(), '?dynamic'); ctx.report.opaque.add('动态别名'); return }
    const target = value.toLowerCase()
    frame.aliases.set(name.toLowerCase(), PS_ALIASES[target] ?? target)
  }
}

/** Set-Variable / New-Variable. */
function psVariable(cmdlet) {
  return ({ args, frame, ctx }) => {
    const b = bind(args, cmdlet, frame, ctx)
    const name = firstValue(b.named.get('name'), frame, ctx)
    if (name === null) return
    const value = b.named.get('value') ?? []
    frame.vars.set(name.toLowerCase(), firstValue(value, frame, ctx))
    if (value.length === 1 && typeof value[0].raw === 'string') frame.varRaws.set(name.toLowerCase(), value[0].raw)
    else frame.varRaws.delete(name.toLowerCase())
  }
}

/** Set-Acl: permissions. */
function psSetAcl({ args, frame, ctx }) {
  const b = bind(args, 'set-acl', frame, ctx)
  for (const v of allValues([...(b.named.get('path') ?? []), ...(b.named.get('literalpath') ?? [])], frame, ctx)) aclTarget(v, frame, ctx)
}

/** Item properties: registry unless the path is a file. */
function psItemProperty(cmdlet) {
  return ({ args, frame, ctx }) => {
    const b = bind(args, cmdlet, frame, ctx)
    for (const v of allValues([...(b.named.get('path') ?? []), ...(b.named.get('literalpath') ?? [])], frame, ctx)) {
      const path = toPath(v, frame, ctx)
      if (path.unknown) { ctx.report.add('ask', 'ask.registry', v.partial); continue }
      if (path.kind === 'registry') { ctx.report.add('ask', 'ask.registry', path.text); continue }
      if (path.abs) writeTarget(v, frame, ctx, { kind: 'attributes', literal: true })
    }
  }
}

/** Services: Defender/firewall are security, everything else is a start-up item. */
function psService(cmdlet) {
  return ({ args, frame, ctx }) => {
    const names = allValues(args, frame, ctx).map(v => v.value ?? '').filter(v => !v.startsWith('-'))
    if (names.some(n => DEFENDER_SERVICES.test(n)) && cmdlet !== 'start-service') ctx.report.add('deny', 'deny.security-off', names.join(' '))
    else ctx.report.add('ask', cmdlet === 'stop-service' || cmdlet === 'start-service' || cmdlet === 'restart-service' ? 'ask.system-config' : 'ask.startup', cmdlet)
  }
}

/** PowerShell handlers. */
const PS = {
  'remove-item': psRemoveItem,
  'get-childitem': psListing('get-childitem'),
  'get-item': psListing('get-item'),
  'resolve-path': psListing('resolve-path'),
  'get-content': psGetContent,
  'move-item': psMove('move-item'),
  'rename-item': psMove('rename-item'),
  'copy-item': psWrite('copy-item', ['destination'], 'copy'),
  'set-content': psWrite('set-content', ['path', 'literalpath']),
  'add-content': psWrite('add-content', ['path', 'literalpath'], 'append'),
  'clear-content': psWrite('clear-content', ['path', 'literalpath'], 'clear'),
  'clear-item': psWrite('clear-item', ['path', 'literalpath'], 'clear'),
  'set-item': psWrite('set-item', ['path', 'literalpath']),
  'out-file': psWrite('out-file', ['filepath', 'literalpath']),
  'tee-object': psWrite('tee-object', ['filepath', 'literalpath']),
  'export-csv': psWrite('export-csv', ['path', 'literalpath']),
  'export-clixml': psWrite('export-clixml', ['path', 'literalpath']),
  'expand-archive': psWrite('expand-archive', ['destinationpath'], 'extract'),
  'compress-archive': psWrite('compress-archive', ['destinationpath']),
  'new-item': psNewItem('new-item'),
  mkdir: psNewItem('mkdir'),
  'set-location': psSetLocation('set-location'),
  'push-location': psSetLocation('push-location'),
  'pop-location': ({ frame }) => { frame.cwd = undefined },
  'start-process': psStartProcess,
  'invoke-expression': psInvokeExpression,
  'invoke-command': psInvokeCommand,
  'invoke-item': ({ args, frame, ctx }) => { for (const v of allValues(args, frame, ctx)) runTarget(v, frame, ctx) },
  'start-job': ({ ctx }) => { ctx.report.opaque.add('内联代码块') },
  'invoke-webrequest': webDownload('ps'),
  'invoke-restmethod': webDownload('ps'),
  'start-bitstransfer': webDownload('bits'),
  'stop-process': killCheck,
  'set-alias': psAlias('set-alias'),
  'new-alias': psAlias('new-alias'),
  'set-variable': psVariable('set-variable'),
  'new-variable': psVariable('new-variable'),
  'set-acl': psSetAcl,
  'set-itemproperty': psItemProperty('set-itemproperty'),
  'new-itemproperty': psItemProperty('new-itemproperty'),
  'remove-itemproperty': psItemProperty('remove-itemproperty'),
  'stop-service': psService('stop-service'),
  'set-service': psService('set-service'),
  'new-service': psService('new-service'),
  'remove-service': psService('remove-service'),
  'start-service': psService('start-service'),
  'restart-service': psService('restart-service'),
  'set-executionpolicy': ({ ctx }) => ctx.report.add('ask', 'ask.accounts', 'Set-ExecutionPolicy'),
  'unblock-file': ({ ctx }) => ctx.report.add('ask', 'ask.accounts', 'Unblock-File'),
  'clear-recyclebin': ({ ctx }) => ctx.report.add('ask', 'ask.system-config', 'Clear-RecycleBin'),
  'enter-pssession': ({ ctx }) => ctx.report.add('ask', 'ask.remote', 'Enter-PSSession'),
  'new-pssession': ({ ctx }) => ctx.report.add('ask', 'ask.remote', 'New-PSSession'),
  sc: ({ args, frame, ctx, pipe, name }) => {
    const first = (allValues(args, frame, ctx)[0]?.value ?? '').toLowerCase()
    if (/^(create|config|delete|failure|sdset|privs|stop|start|pause|continue|qc|query|queryex)$/.test(first)) return NATIVE.sc({ args, frame, ctx, pipe, name })
    return psWrite('set-content', ['path', 'literalpath'])({ args, frame, ctx, pipe, name })
  },
  curl: webDownload('curl'),
  wget: webDownload('curl'),
}

// ---------------------------------------------------------------------------------------
// cmd builtins and POSIX commands
// ---------------------------------------------------------------------------------------

/** Split a cmd-style switch word such as /s/q into its switches. */
function cmdSwitches(values) {
  const switches = new Set()
  const rest = []
  for (const v of values) {
    if (v.value !== null && /^(\/[a-z0-9:?-]+)+$/i.test(v.value)) {
      for (const s of v.value.split('/').filter(Boolean)) switches.add(s.toLowerCase().replace(/:.*$/, ''))
    } else {
      rest.push(v)
    }
  }
  return { switches, rest }
}

const CMD = {
  del: ({ args, frame, ctx }) => {
    const { switches, rest } = cmdSwitches(allValues(args, frame, ctx))
    if (rest.length === 0) ctx.report.add('ask', 'ask.unknown-delete-target', 'del')
    for (const v of rest) deleteTarget(v, frame, ctx, { recursive: switches.has('s'), literal: false })
  },
  rd: ({ args, frame, ctx }) => {
    const { switches, rest } = cmdSwitches(allValues(args, frame, ctx))
    if (rest.length === 0) ctx.report.add('ask', 'ask.unknown-delete-target', 'rd')
    for (const v of rest) deleteTarget(v, frame, ctx, { recursive: switches.has('s'), literal: true })
  },
  move: ({ args, frame, ctx }) => {
    const { rest } = cmdSwitches(allValues(args, frame, ctx))
    if (rest.length >= 2) {
      for (const v of rest.slice(0, -1)) moveSource(v, frame, ctx)
      writeTarget(rest[rest.length - 1], frame, ctx, { kind: 'move-dest', literal: true })
    }
  },
  copy: ({ args, frame, ctx }) => {
    const { rest } = cmdSwitches(allValues(args, frame, ctx))
    if (rest.length >= 2) writeTarget(rest[rest.length - 1], frame, ctx, { kind: 'copy', literal: true })
  },
  ren: ({ args, frame, ctx }) => {
    const { rest } = cmdSwitches(allValues(args, frame, ctx))
    if (rest.length >= 1) moveSource(rest[0], frame, ctx)
  },
  md: ({ args, frame, ctx }) => {
    for (const v of cmdSwitches(allValues(args, frame, ctx)).rest) writeTarget(v, frame, ctx, { kind: 'create', literal: true })
  },
  cd: ({ args, frame, ctx }) => {
    const { rest } = cmdSwitches(allValues(args, frame, ctx))
    if (rest.length === 0) return
    const path = toPath(rest[0], frame, ctx)
    frame.cwd = path.unknown || path.abs === undefined ? undefined : path.abs
  },
  start: ({ args, frame, ctx }) => {
    const values = cmdSwitches(allValues(args, frame, ctx)).rest
    // start "title" program args…
    const program = values.length > 1 && args[0]?.quoted ? values[1] : values[0]
    if (program !== undefined) {
      const exe = (program.value ?? '').split(/[\\/]/).pop()?.toLowerCase().replace(/\.(exe|com)$/, '') ?? ''
      if (Object.hasOwn(SHELLS, exe)) ctx.report.opaque.add('嵌套 shell')
      runTarget(program, frame, ctx)
    }
  },
  call: ({ args, frame, ctx }) => { const v = allValues(args, frame, ctx)[0]; if (v) runTarget(v, frame, ctx) },
  set: () => {},
}
CMD.erase = CMD.del
CMD.rmdir = CMD.rd
CMD.mkdir = CMD.md
CMD.chdir = CMD.cd
CMD.pushd = CMD.cd
CMD.rename = CMD.ren

/** POSIX flags: -rf → r,f; --recursive → recursive. */
function posixFlags(values) {
  const flags = new Set()
  const rest = []
  let ended = false
  for (const v of values) {
    const t = v.value
    if (!ended && t === '--') { ended = true; continue }
    if (!ended && t !== null && /^--[a-z]/i.test(t)) { flags.add(t.slice(2).toLowerCase().replace(/=.*$/, '')); continue }
    if (!ended && t !== null && /^-[a-z]+$/i.test(t)) { for (const c of t.slice(1)) flags.add(c); continue }
    rest.push(v)
  }
  return { flags, rest }
}

const POSIX = {
  rm: ({ args, frame, ctx }) => {
    const { flags, rest } = posixFlags(allValues(args, frame, ctx))
    const recursive = flags.has('r') || flags.has('R') || flags.has('recursive')
    if (rest.length === 0) ctx.report.add('ask', 'ask.unknown-delete-target', 'rm')
    for (const v of rest) deleteTarget(v, frame, ctx, { recursive, literal: false })
  },
  rmdir: ({ args, frame, ctx }) => { for (const v of posixFlags(allValues(args, frame, ctx)).rest) deleteTarget(v, frame, ctx, { recursive: false, literal: true }) },
  unlink: ({ args, frame, ctx }) => { for (const v of posixFlags(allValues(args, frame, ctx)).rest) deleteTarget(v, frame, ctx, { recursive: false, literal: true }) },
  shred: ({ args, frame, ctx }) => { for (const v of posixFlags(allValues(args, frame, ctx)).rest) deleteTarget(v, frame, ctx, { recursive: false, literal: true }) },
  mv: ({ args, frame, ctx }) => {
    const { rest } = posixFlags(allValues(args, frame, ctx))
    if (rest.length >= 2) {
      for (const v of rest.slice(0, -1)) moveSource(v, frame, ctx)
      writeTarget(rest[rest.length - 1], frame, ctx, { kind: 'move-dest', literal: true })
    }
  },
  cp: ({ args, frame, ctx }) => {
    const { rest } = posixFlags(allValues(args, frame, ctx))
    if (rest.length >= 2) writeTarget(rest[rest.length - 1], frame, ctx, { kind: 'copy', literal: true })
  },
  install: ({ args, frame, ctx }) => {
    const { rest } = posixFlags(allValues(args, frame, ctx))
    if (rest.length >= 2) writeTarget(rest[rest.length - 1], frame, ctx, { kind: 'copy', literal: true })
  },
  tee: ({ args, frame, ctx }) => { for (const v of posixFlags(allValues(args, frame, ctx)).rest) writeTarget(v, frame, ctx, { kind: 'overwrite', literal: true }) },
  touch: ({ args, frame, ctx }) => { for (const v of posixFlags(allValues(args, frame, ctx)).rest) writeTarget(v, frame, ctx, { kind: 'create', literal: true }) },
  truncate: ({ args, frame, ctx }) => { for (const v of posixFlags(allValues(args, frame, ctx)).rest) writeTarget(v, frame, ctx, { kind: 'clear', literal: true }) },
  mkdir: ({ args, frame, ctx }) => { for (const v of posixFlags(allValues(args, frame, ctx)).rest) writeTarget(v, frame, ctx, { kind: 'create', literal: true }) },
  ln: ({ args, frame, ctx }) => { ctx.report.opaque.add('创建链接'); const { rest } = posixFlags(allValues(args, frame, ctx)); if (rest.length >= 2) writeTarget(rest[rest.length - 1], frame, ctx, { kind: 'create', literal: true }) },
  dd: ({ args, frame, ctx }) => {
    for (const v of allValues(args, frame, ctx)) {
      if (v.value !== null && /^of=/.test(v.value)) {
        const target = v.value.slice(3)
        if (/^\/dev\//.test(target)) ctx.report.add('deny', 'deny.disk-tool', `dd ${v.value}`)
        else writeTarget({ value: target, partial: target }, frame, ctx, { kind: 'overwrite', literal: true })
      }
    }
  },
  chmod: ({ args, frame, ctx }) => {
    const values = allValues(args, frame, ctx)
    const { rest } = posixFlags(values)
    for (const v of rest.slice(1)) aclTarget(v, frame, ctx)
  },
  find: ({ args, frame, ctx }) => {
    const values = allValues(args, frame, ctx)
    const roots = []
    for (const v of values) { if (v.value === null || /^[-(!]/.test(v.value)) break; roots.push(v) }
    const deletes = values.some(v => v.value === '-delete') || values.some((v, i) => /^-exec(dir)?$/.test(v.value ?? '') && /^(rm|shred|unlink)$/.test(values[i + 1]?.value ?? ''))
    if (deletes) for (const v of roots.length > 0 ? roots : [{ value: frame.cwd ?? null, partial: '.' }]) deleteTarget(v, frame, ctx, { recursive: true, literal: true })
  },
  xargs: ({ args, frame, ctx }) => {
    const values = allValues(args, frame, ctx).map(v => v.value ?? '')
    if (values.some(v => /^(rm|shred|unlink|rmdir)$/.test(v))) ctx.report.add('ask', 'ask.unknown-delete-target', 'xargs rm')
    ctx.report.opaque.add('xargs')
  },
  rsync: ({ args, frame, ctx }) => {
    const { flags, rest } = posixFlags(allValues(args, frame, ctx))
    if (rest.length < 2) return
    const dest = rest[rest.length - 1]
    if ([...flags].some(f => /^delete/.test(f))) deleteTarget(dest, frame, ctx, { recursive: true, literal: true })
    else writeTarget(dest, frame, ctx, { kind: 'copy', literal: true })
  },
  cd: ({ args, frame, ctx }) => {
    const { rest } = posixFlags(allValues(args, frame, ctx))
    if (rest.length === 0) { frame.cwd = ctx.host.home; return }
    const path = toPath(rest[0], frame, ctx)
    frame.cwd = path.unknown || path.abs === undefined ? undefined : path.abs
  },
  eval: ({ ctx }) => { ctx.report.opaque.add('eval'); ctx.report.add('ask', 'ask.too-complex', 'eval') },
  source: ({ args, frame, ctx }) => { const v = allValues(args, frame, ctx)[0]; if (v) runTarget(v, frame, ctx) },
  '.': ({ args, frame, ctx }) => { const v = allValues(args, frame, ctx)[0]; if (v) runTarget(v, frame, ctx) },
  exec: ({ args, frame, ctx, pipe }) => { if (args.length > 0) analyzeCommand({ elements: args, redirections: [], call: null, raw: '' }, frame, ctx, pipe) },
  crontab: ({ ctx }) => ctx.report.add('ask', 'ask.startup', 'crontab'),
  systemctl: ({ args, frame, ctx }) => {
    const sub = allValues(args, frame, ctx).map(v => v.value ?? '').find(v => !v.startsWith('-')) ?? ''
    ctx.report.add('ask', /^(enable|link|edit|daemon-reload|preset|reenable|mask)$/.test(sub) ? 'ask.startup' : 'ask.system-config', `systemctl ${sub}`)
  },
  launchctl: ({ ctx }) => ctx.report.add('ask', 'ask.startup', 'launchctl'),
  curl: webDownload('curl'),
  wget: webDownload('curl'),
}
POSIX.chown = POSIX.chmod
POSIX.chgrp = POSIX.chmod
POSIX.setfacl = POSIX.chmod

// ---------------------------------------------------------------------------------------
// Native programs (any dialect)
// ---------------------------------------------------------------------------------------

/** A plain text word (used when re-tokenising argument strings). */
function textWord(text) {
  return { type: 'word', parts: [{ k: 'text', v: text }], quoted: false, raw: text }
}

/** Split an argument string the way Windows programs commonly do (double quotes group). */
function splitArgs(text) {
  const out = []
  for (const m of String(text).matchAll(/"((?:[^"\\]|\\.)*)"|'([^']*)'|(\S+)/g)) out.push(m[1] ?? m[2] ?? m[3])
  return out
}

/** Analyse `cmd /c`, `powershell -Command`, `bash -c`, `wsl …` with argument values. */
function shellInvocation(kind, exe, words, frame, ctx) {
  if (kind === 'cmd') {
    const idx = words.findIndex(w => /^\/[ck]/i.test(w))
    if (idx === -1) return
    const first = words[idx].slice(2)
    const rest = [...(first === '' ? [] : [first]), ...words.slice(idx + 1)].join(' ')
    if (rest.trim() !== '') analyzeNested(rest, 'cmd', frame, ctx)
    return
  }
  if (kind === 'powershell') {
    const takesValue = /^-(ex|exe|exec|execu|execut|executi|executio|execution|executionp|executionpo|executionpol|executionpoli|executionpolic|executionpolicy|ep|w|wi|win|wind|windo|windows|windowst|windowsty|windowssty|windowstyl|windowstyle|v|ve|ver|vers|versi|versio|version|conf|confi|config|configu|configur|configura|configurat|configurati|configuratio|configuration|configurationn|configurationname|wd|workingdirectory|of|outputformat|if|inputformat|psc|psconsolefile|settingsfile|settings)$/i
    for (let i = 0; i < words.length; i += 1) {
      const w = words[i]
      if (/^-(e|ec|en|enc|enco|encod|encode|encoded|encodedc|encodedco|encodedcom|encodedcomm|encodedcomma|encodedcomman|encodedcommand|encodeda|encodedarguments)$/i.test(w)) {
        ctx.report.add('deny', 'deny.encoded-command', `${exe} ${w}`)
        const payload = words[i + 1]
        if (payload !== undefined) {
          try {
            const decoded = Buffer.from(payload, 'base64').toString('utf16le')
            if (decoded.trim() !== '') analyzeNested(decoded, 'powershell', frame, ctx)
          } catch {
            // undecodable payload: the denial above already stands
          }
        }
        return
      }
      if (/^-(c|co|com|comm|comma|comman|command)$/i.test(w)) {
        const rest = words.slice(i + 1).join(' ')
        if (rest.trim() === '-' || rest.trim() === '') { ctx.report.opaque.add('从标准输入读命令'); return }
        analyzeNested(rest, 'powershell', frame, ctx)
        return
      }
      if (/^-(f|fi|fil|file)$/i.test(w)) {
        const script = words[i + 1]
        if (script !== undefined) runTarget({ value: script, partial: script }, frame, ctx)
        return
      }
      if (takesValue.test(w)) { i += 1; continue }
      if (w.startsWith('-') || w.startsWith('/')) continue
      analyzeNested(words.slice(i).join(' '), 'powershell', frame, ctx)
      return
    }
    return
  }
  // POSIX shells
  if (exe === 'wsl') {
    let i = 0
    while (i < words.length && /^-/.test(words[i])) {
      if (/^(-e|--exec|--)$/.test(words[i])) { i += 1; break }
      if (/^(-d|--distribution|-u|--user|--cd)$/.test(words[i])) i += 2
      else i += 1
    }
    const rest = words.slice(i).join(' ')
    if (rest.trim() !== '') analyzeNested(rest, 'posix', frame, ctx)
    return
  }
  const c = words.findIndex(w => /^-[a-z]*c[a-z]*$/i.test(w))
  if (c !== -1 && words[c + 1] !== undefined) { analyzeNested(words[c + 1], 'posix', frame, ctx); return }
  const script = words.find(w => !w.startsWith('-'))
  if (script !== undefined) runTarget({ value: script, partial: script }, frame, ctx)
  else ctx.report.opaque.add('从标准输入读命令')
}

/** Native handler that nests a shell. */
function nativeShell(kind) {
  return ({ args, frame, ctx, name }) => {
    const words = []
    for (const v of allValues(args, frame, ctx)) {
      if (v.value === null) { ctx.report.opaque.add('参数含变量或表达式'); return }
      words.push(v.value)
    }
    shellInvocation(kind, name.canon, words, frame, ctx)
  }
}

const lowerValues = (args, frame, ctx) => allValues(args, frame, ctx).map(v => (v.value ?? '').toLowerCase())

const NATIVE = {
  cmd: nativeShell('cmd'),
  powershell: nativeShell('powershell'),
  pwsh: nativeShell('powershell'),
  powershell_ise: nativeShell('powershell'),
  bash: nativeShell('posix'),
  sh: nativeShell('posix'),
  zsh: nativeShell('posix'),
  dash: nativeShell('posix'),
  ksh: nativeShell('posix'),
  wsl: nativeShell('posix'),
  icacls: ({ args, frame, ctx }) => { const v = allValues(args, frame, ctx).find(x => !(x.value ?? '').startsWith('/')); if (v) aclTarget(v, frame, ctx); else ctx.report.add('ask', 'ask.accounts', 'icacls') },
  cacls: ({ args, frame, ctx }) => { const v = allValues(args, frame, ctx)[0]; if (v) aclTarget(v, frame, ctx); else ctx.report.add('ask', 'ask.accounts', 'cacls') },
  takeown: ({ args, frame, ctx }) => {
    const values = allValues(args, frame, ctx)
    const f = values.findIndex(v => /^\/f$/i.test(v.value ?? ''))
    if (f !== -1 && values[f + 1]) aclTarget(values[f + 1], frame, ctx)
    ctx.report.add('ask', 'ask.accounts', 'takeown')
  },
  attrib: ({ args, frame, ctx }) => {
    for (const v of allValues(args, frame, ctx)) if (v.value === null || !/^[+-][rahsiox]$|^\/[a-z]$/i.test(v.value)) aclTarget(v, frame, ctx, 'ask.system-config')
  },
  robocopy: ({ args, frame, ctx }) => {
    const values = allValues(args, frame, ctx)
    const plain = values.filter(v => !(v.value ?? '').startsWith('/'))
    const switches = values.map(v => (v.value ?? '').toLowerCase())
    if (plain.length < 2) return
    const [src, dst] = plain
    if (switches.includes('/mir') || switches.includes('/purge')) deleteTarget(dst, frame, ctx, { recursive: true, literal: true })
    else writeTarget(dst, frame, ctx, { kind: 'copy', literal: true })
    if (switches.includes('/move') || switches.includes('/mov')) deleteTarget(src, frame, ctx, { recursive: switches.includes('/move'), literal: true })
  },
  xcopy: ({ args, frame, ctx }) => {
    const plain = allValues(args, frame, ctx).filter(v => !(v.value ?? '').startsWith('/'))
    if (plain.length >= 2) writeTarget(plain[1], frame, ctx, { kind: 'copy', literal: true })
  },
  mklink: ({ ctx }) => { ctx.report.opaque.add('创建链接') },
  schtasks: ({ ctx }) => ctx.report.add('ask', 'ask.startup', 'schtasks'),
  reg: ({ args, frame, ctx }) => {
    const sub = lowerValues(args, frame, ctx)[0] ?? ''
    if (/^(add|delete|import|load|unload|restore|copy|save|export|flags)$/.test(sub)) ctx.report.add('ask', 'ask.registry', `reg ${sub}`)
  },
  regedit: ({ ctx }) => ctx.report.add('ask', 'ask.registry', 'regedit'),
  regini: ({ ctx }) => ctx.report.add('ask', 'ask.registry', 'regini'),
  setx: ({ ctx }) => ctx.report.add('ask', 'ask.registry', 'setx'),
  sc: ({ args, frame, ctx }) => {
    const values = lowerValues(args, frame, ctx).filter(v => !/^\\\\/.test(v))
    const [sub, service] = values
    if (/^(stop|config|delete|pause|failure|sdset)$/.test(sub ?? '') && DEFENDER_SERVICES.test(service ?? '')) ctx.report.add('deny', 'deny.security-off', `sc ${sub} ${service}`)
    else if (/^(create|config|delete|failure|sdset|privs|triggerinfo)$/.test(sub ?? '')) ctx.report.add('ask', 'ask.startup', `sc ${sub}`)
    else if (/^(stop|start|pause|continue)$/.test(sub ?? '')) ctx.report.add('ask', 'ask.system-config', `sc ${sub}`)
  },
  net: ({ args, frame, ctx }) => {
    const values = lowerValues(args, frame, ctx)
    const sub = values[0] ?? ''
    if (/^(user|users|localgroup|group|accounts)$/.test(sub)) ctx.report.add('ask', 'ask.accounts', `net ${sub}`)
    else if (sub === 'stop' && DEFENDER_SERVICES.test(values[1] ?? '')) ctx.report.add('deny', 'deny.security-off', `net stop ${values[1]}`)
    else if (/^(stop|start|share|use|session|time)$/.test(sub)) ctx.report.add('ask', 'ask.system-config', `net ${sub}`)
  },
  netsh: ({ ctx }) => ctx.report.add('ask', 'ask.system-config', 'netsh'),
  taskkill: killCheck,
  tskill: killCheck,
  pskill: killCheck,
  kill: killCheck,
  pkill: killCheck,
  killall: killCheck,
  vssadmin: ({ args, frame, ctx }) => {
    const sub = lowerValues(args, frame, ctx)[0] ?? ''
    if (/^(delete|resize)$/.test(sub)) ctx.report.add('deny', 'deny.disk-tool', `vssadmin ${sub}`)
    else ctx.report.add('ask', 'ask.system-config', 'vssadmin')
  },
  wbadmin: ({ args, frame, ctx }) => {
    const sub = lowerValues(args, frame, ctx)[0] ?? ''
    if (sub === 'delete') ctx.report.add('deny', 'deny.disk-tool', 'wbadmin delete')
    else ctx.report.add('ask', 'ask.system-config', 'wbadmin')
  },
  cipher: ({ args, frame, ctx }) => {
    if (lowerValues(args, frame, ctx).some(v => /^\/w/.test(v))) ctx.report.add('deny', 'deny.disk-tool', 'cipher /w')
    else ctx.report.add('ask', 'ask.system-config', 'cipher')
  },
  fsutil: ({ args, frame, ctx }) => {
    const values = lowerValues(args, frame, ctx)
    if (values.includes('setzerodata') || (values[0] === 'volume' && values[1] === 'dismount')) ctx.report.add('deny', 'deny.disk-tool', 'fsutil')
    else ctx.report.add('ask', 'ask.system-config', 'fsutil')
  },
  diskutil: ({ args, frame, ctx }) => {
    const sub = lowerValues(args, frame, ctx)[0] ?? ''
    if (/^(erase|partition|zero|secureerase|reformat|apfs|splitpartition|mergepartitions|unmountdisk)/.test(sub)) ctx.report.add('deny', 'deny.disk-tool', `diskutil ${sub}`)
  },
  certutil: ({ args, frame, ctx }) => {
    const values = lowerValues(args, frame, ctx)
    if (values.some(v => /^[-/](urlcache|verifyctl)$/.test(v))) ctx.report.add('deny', 'deny.download-exec', 'certutil -urlcache')
    else if (values.some(v => /^[-/](addstore|importpfx|delstore|repairstore)$/.test(v))) ctx.report.add('ask', 'ask.system-config', 'certutil')
    if (values.some(v => /^[-/](decode|decodehex)$/.test(v))) ctx.report.opaque.add('certutil 解码')
  },
  bitsadmin: ({ args, frame, ctx }) => {
    ctx.report.add('ask', 'ask.system-config', 'bitsadmin')
    if (lowerValues(args, frame, ctx).some(v => /^\/(transfer|addfile)$/.test(v))) ctx.report.downloads.push('bitsadmin')
    return { download: true }
  },
  mshta: ({ ctx }) => ctx.report.add('deny', 'deny.download-exec', 'mshta'),
  rundll32: ({ args, frame, ctx }) => {
    if (lowerValues(args, frame, ctx).some(v => v.includes('javascript:') || v.includes('vbscript:'))) ctx.report.add('deny', 'deny.download-exec', 'rundll32 script')
    else ctx.report.add('ask', 'ask.system-config', 'rundll32')
  },
  regsvr32: ({ args, frame, ctx }) => {
    if (lowerValues(args, frame, ctx).some(v => /^\/i:(https?|ftp):/.test(v) || v.includes('scrobj'))) ctx.report.add('deny', 'deny.download-exec', 'regsvr32 remote')
    else ctx.report.add('ask', 'ask.system-config', 'regsvr32')
  },
  msiexec: ({ args, frame, ctx }) => {
    const values = allValues(args, frame, ctx)
    if (values.some(v => /^(https?|ftp):/i.test(v.value ?? ''))) { ctx.report.add('deny', 'deny.download-exec', 'msiexec URL'); return }
    ctx.report.add('ask', 'ask.system-config', 'msiexec')
    const pkg = values.find(v => /\.(msi|msp)$/i.test(v.value ?? ''))
    if (pkg) runTarget(pkg, frame, ctx)
  },
  ssh: ({ ctx, name }) => ctx.report.add('ask', 'ask.ssh', name.canon),
  git: ({ args, frame, ctx }) => {
    const values = lowerValues(args, frame, ctx)
    const sub = values.find(v => !v.startsWith('-')) ?? ''
    if (sub === 'config' && values.some(v => v === '--global' || v === '--system')) ctx.report.add('ask', 'ask.credentials', 'git config --global')
    if (sub === 'credential' || values.some(v => v.startsWith('credential.'))) ctx.report.add('ask', 'ask.credentials', 'git credential')
    if (sub === 'clone') {
      const plain = allValues(args, frame, ctx).filter(v => !(v.value ?? '').startsWith('-'))
      if (plain.length >= 3) writeTarget(plain[2], frame, ctx, { kind: 'create', literal: true })
    }
  },
  npm: packageManager('npm'),
  pnpm: packageManager('pnpm'),
  yarn: packageManager('yarn'),
  bun: packageManager('bun'),
  gh: ({ args, frame, ctx }) => { if (lowerValues(args, frame, ctx)[0] === 'auth') ctx.report.add('ask', 'ask.credentials', 'gh auth') },
  docker: ({ args, frame, ctx }) => { if (/^log(in|out)$/.test(lowerValues(args, frame, ctx)[0] ?? '')) ctx.report.add('ask', 'ask.credentials', 'docker login') },
  az: loginCheck(/^(login|logout|account)$/),
  aws: loginCheck(/^(configure|sso)$/),
  gcloud: loginCheck(/^auth$/),
  firebase: loginCheck(/^(login|logout)/),
  vercel: loginCheck(/^(login|logout)$/),
  netlify: loginCheck(/^(login|logout)$/),
  heroku: loginCheck(/^(login|logout|auth)/),
  wrangler: loginCheck(/^(login|logout)$/),
  supabase: loginCheck(/^(login|logout)$/),
  flyctl: loginCheck(/^auth$/),
  'huggingface-cli': loginCheck(/^(login|logout)$/),
  cmdkey: ({ ctx }) => ctx.report.add('ask', 'ask.credentials', 'cmdkey'),
  vaultcmd: ({ ctx }) => ctx.report.add('ask', 'ask.credentials', 'vaultcmd'),
  dsh: ({ args, frame, ctx }) => {
    const values = lowerValues(args, frame, ctx)
    if (values.includes('plugin') || values.includes('--profile')) ctx.report.add('deny', 'deny.dsh-cli', 'dsh plugin')
  },
  dism: ({ ctx }) => ctx.report.add('ask', 'ask.system-config', 'dism'),
  pnputil: ({ ctx }) => ctx.report.add('ask', 'ask.system-config', 'pnputil'),
  bcdedit: ({ ctx }) => ctx.report.add('deny', 'deny.disk-tool', 'bcdedit'),
  winrm: ({ ctx }) => ctx.report.add('ask', 'ask.remote', 'winrm'),
  winrs: ({ ctx }) => ctx.report.add('ask', 'ask.remote', 'winrs'),
  wmic: ({ args, frame, ctx }) => {
    const values = lowerValues(args, frame, ctx)
    if (values.some(v => v.startsWith('/node'))) ctx.report.add('ask', 'ask.remote', 'wmic /node')
    if (values.includes('delete') || values.includes('call')) ctx.report.add('ask', 'ask.system-config', 'wmic')
    if (values.includes('process') && values.some(v => DSH_PROCESS.test(v))) ctx.report.add('deny', 'deny.kill-dsh', 'wmic process')
  },
  route: ({ args, frame, ctx }) => { if (/^(add|delete|change)$/.test(lowerValues(args, frame, ctx)[0] ?? '')) ctx.report.add('ask', 'ask.system-config', 'route') },
  sudo: elevationWrapper(new Set(['-u', '-g', '-c', '-d', '-h', '-p', '-r', '-t', '-u', '--user', '--group', '-C', '-D', '-U'])),
  gsudo: elevationWrapper(new Set(['-u', '--user', '-d', '--direct'])),
  doas: elevationWrapper(new Set(['-u', '-C'])),
}
NATIVE['ssh-keygen'] = NATIVE.ssh
NATIVE['ssh-add'] = NATIVE.ssh
NATIVE['ssh-copy-id'] = NATIVE.ssh
NATIVE['ssh-keyscan'] = NATIVE.ssh
NATIVE['ssh-agent'] = NATIVE.ssh
NATIVE.scp = NATIVE.ssh
NATIVE.sftp = NATIVE.ssh
NATIVE.net1 = NATIVE.net
NATIVE.fly = NATIVE.flyctl
NATIVE.curl = webDownload('curl')
NATIVE.wget = webDownload('curl')

/** Package managers: login is credentials; `run x` records the script name. */
function packageManager(manager) {
  return ({ args, frame, ctx }) => {
    const values = allValues(args, frame, ctx).map(v => v.value ?? '')
    const sub = (values.find(v => !v.startsWith('-')) ?? '').toLowerCase()
    if (/^(login|adduser|add-user|logout|token|owner)$/.test(sub)) ctx.report.add('ask', 'ask.credentials', `${manager} ${sub}`)
    if (sub === 'run' || sub === 'run-script') {
      const script = values.slice(values.findIndex(v => v.toLowerCase() === sub) + 1).find(v => !v.startsWith('-'))
      if (script !== undefined) ctx.report.packageScripts.push({ manager, script })
    } else if (/^(test|start|stop|restart|t|tst)$/.test(sub)) {
      ctx.report.packageScripts.push({ manager, script: sub === 't' || sub === 'tst' ? 'test' : sub })
    } else if (/^(install|i|ci)$/.test(sub) || (sub === '' && manager !== 'npm')) {
      // A bare install runs the project's own lifecycle scripts (preinstall, install, postinstall, prepare).
      const rest = values.slice(values.findIndex(v => v.toLowerCase() === sub) + 1)
      const global = values.some(v => /^(-g|--global|--location=global)$/i.test(v))
      if (!global && rest.every(v => v.startsWith('-'))) ctx.report.packageScripts.push({ manager, script: 'install' })
    }
  }
}

/** Login subcommands of cloud CLIs. */
function loginCheck(re) {
  return ({ args, frame, ctx, name }) => {
    const sub = (lowerValues(args, frame, ctx).find(v => !v.startsWith('-')) ?? '')
    if (re.test(sub)) ctx.report.add('ask', 'ask.credentials', `${name.canon} ${sub}`)
  }
}

/** sudo / gsudo / doas: elevation, and the wrapped command is analysed too. */
function elevationWrapper(valueFlags) {
  return ({ args, frame, ctx, pipe }) => {
    ctx.report.add('ask', 'ask.elevation', 'sudo')
    let i = 0
    while (i < args.length) {
      const v = valuesOf(args[i], frame, ctx)[0]?.value ?? ''
      if (!v.startsWith('-')) break
      i += valueFlags.has(v) ? 2 : 1
    }
    if (i < args.length) analyzeCommand({ elements: args.slice(i), redirections: [], call: null, raw: '' }, frame, ctx, pipe)
  }
}

const HANDLERS = { powershell: PS, cmd: CMD, posix: POSIX }

// ---------------------------------------------------------------------------------------
// Whole-command patterns
// ---------------------------------------------------------------------------------------

/** Patterns that need the whole command: download-then-run, write-then-run. */
function finishStatementPatterns(ctx) {
  const { report, host } = ctx
  const key = p => host.tools.key(p)
  if (report.downloads.length > 0 && report.runs.length > 0) {
    const downloaded = new Set(report.downloadedFiles.map(key))
    const runsDownloaded = report.runs.some(r => downloaded.has(key(r.path)))
    const runnableDownloaded = report.downloadedFiles.some(p => RUNNABLE_EXT.test(p))
    if (runsDownloaded || runnableDownloaded) report.add('deny', 'deny.download-exec', 'download + run')
  }
  if (report.scriptWrites.length > 0 && report.runs.length > 0) {
    const written = new Set(report.scriptWrites.map(key))
    if (report.runs.some(r => written.has(key(r.path)))) report.add('ask', 'ask.write-then-run', report.runs.map(r => r.path).join(', '))
  }
}

export { CMDLETS }

/**
 * Layer 1: the hard rules. A pure function of the tool call and the host
 * facts — no dsh, no network, no clock. Returns 'deny' (clearly destructive),
 * 'ask' (only a person may decide) or 'pass' (left to the later layers),
 * together with the findings that explain it and the facts later layers use.
 */

import { normalizeForScan } from '../text.js'
import { analyzeShell } from './analyze.js'
import { classify, workspaceOf } from './classify.js'
import { detectInjection } from './injection.js'
import { M } from './messages.js'
import { scanText } from './text-rules.js'

/**
 * @typedef {object} HardRuleInput
 * @property {'pwsh' | 'bash' | 'write' | 'edit'} tool
 * @property {Record<string, unknown>} args - the tool call's arguments.
 * @property {ReturnType<import('../host.js').createHost>} host
 * @property {string | undefined} workspaceRoot - the session's sandbox workspace root.
 * @property {string | undefined} cwd - the session's current directory.
 */

/**
 * @typedef {object} HardRuleResult
 * @property {'deny' | 'ask' | 'pass'} verdict
 * @property {{ level: 'deny' | 'ask', rule: string, message: string, evidence: string }[]} findings
 * @property {object} facts
 */

/**
 * Where a shell command starts: an explicit workdir (relative to the session
 * directory), else the session directory — the same resolution the dsh shell tools use.
 * @param {ReturnType<import('../host.js').createHost>} host
 * @param {unknown} workdir
 * @param {string | undefined} cwd
 */
export function resolveWorkdir(host, workdir, cwd) {
  if (typeof workdir !== 'string' || workdir === '') return cwd
  const { P } = host.tools
  if (P.isAbsolute(workdir)) return P.resolve(workdir)
  return cwd === undefined ? undefined : P.resolve(cwd, workdir)
}

/**
 * Evaluate the hard rules for one escalation request.
 * @param {HardRuleInput} input
 * @returns {HardRuleResult}
 */
export function evaluateHardRules({ tool, args, host, workspaceRoot, cwd }) {
  const workspace = workspaceOf(host, workspaceRoot)
  const findings = []
  const add = (level, rule, evidence = '') => {
    if (!findings.some(f => f.rule === rule && f.evidence === evidence)) findings.push({ level, rule, message: M[rule] ?? rule, evidence })
  }
  let facts

  if (tool === 'pwsh' || tool === 'bash') {
    const command = typeof args.command === 'string' ? args.command : ''
    const workdir = resolveWorkdir(host, args.workdir, cwd)
    const report = analyzeShell(command, { dialect: tool === 'pwsh' ? 'powershell' : 'posix', cwd: workdir, host, workspace })
    for (const f of report.findings) add(f.level, f.rule, f.evidence)
    for (const hit of scanText(normalizeForScan(command))) add(hit.level, hit.rule, hit.evidence)
    if (workdir !== undefined) {
      const cls = classify(workdir, host, workspace)
      if (cls.protected) add('deny', 'deny.protected', `工作目录：${workdir}`)
    }
    const injected = detectInjection(command, args.justification, args.description)
    if (injected !== null) add('ask', 'ask.injection', injected)
    facts = {
      workdir,
      opaque: [...report.opaque],
      inlineCode: report.inlineCode,
      deletes: report.deletes,
      writes: report.writes,
      moves: report.moves,
      runs: report.runs,
      downloads: report.downloads,
      downloadedFiles: report.downloadedFiles,
      packageScripts: report.packageScripts,
      outsidePaths: [...report.outsidePaths],
      commands: [...report.commands],
      parseIssues: report.issues,
    }
  } else if (tool === 'write' || tool === 'edit') {
    facts = fileFacts({ args, host, workspace, cwd, add })
    const content = tool === 'write' ? args.content : `${args.old_string ?? ''}\n${args.new_string ?? ''}`
    const sample = typeof content === 'string' && content.length > 25000 ? `${content.slice(0, 20000)}\n${content.slice(-5000)}` : content
    const injected = detectInjection(args.file_path, args.justification, sample)
    if (injected !== null) add('ask', 'ask.injection', injected)
  } else {
    facts = {}
  }

  const verdict = findings.some(f => f.level === 'deny') ? 'deny' : findings.some(f => f.level === 'ask') ? 'ask' : 'pass'
  return { verdict, findings, facts }
}

/** Path checks for the write and edit tools (literal paths, no `~` or variable expansion). */
function fileFacts({ args, host, workspace, cwd, add }) {
  const raw = typeof args.file_path === 'string' ? args.file_path : ''
  const { tools } = host
  const cleaned = tools.clean(raw)
  if (cleaned.kind === 'empty') {
    add('ask', 'ask.unusual-path', '(空路径)')
    return { target: null }
  }
  if (cleaned.kind === 'device') {
    if (/physicaldrive|harddisk|volume|^\\\\\.\\[a-z]:/i.test(cleaned.path)) add('deny', 'deny.disk-tool', cleaned.path)
    else add('ask', 'ask.unusual-path', cleaned.path)
    return { target: cleaned.path }
  }
  if (cleaned.kind !== 'file' && cleaned.kind !== 'unc') {
    add('ask', 'ask.unusual-path', cleaned.path)
    return { target: cleaned.path }
  }
  const abs = tools.absolute(cleaned.path, cwd)
  if (abs === undefined) {
    add('ask', 'ask.unusual-path', raw)
    return { target: null }
  }
  if (cleaned.kind === 'unc') add('ask', 'ask.unusual-path', abs)
  // An alternate data stream (file.txt:hidden) is not an ordinary file write.
  const tail = tools.win ? abs.slice(2) : abs
  if (tools.win && tail.includes(':')) add('ask', 'ask.unusual-path', abs)
  // An 8.3 short name that does not resolve to a real directory hides where the file really goes.
  if (tools.win && /~\d/.test(tools.real(abs))) add('ask', 'ask.unusual-path', abs)
  const cls = classify(abs, host, workspace)
  if (cls.protected) add('deny', 'deny.protected', `${cls.protected}：${abs}`)
  if (cls.isRoot || cls.isHome || cls.isUsersRoot || cls.systemRoot) add('ask', 'ask.unusual-path', abs)
  if (cls.sensitive) add('ask', `ask.${cls.sensitive}`, abs)
  if (cls.system) add('ask', 'ask.system-dir', abs)
  return {
    target: abs,
    realTarget: tools.real(abs),
    exists: host.exists(abs),
    outside: cls.outside,
    agentWritable: cls.agentWritable,
  }
}

/**
 * What is sent to the reviewer, and nothing more (docs/design.zh.md §3):
 * the command or file operation, its working directory, the OS, the agent's
 * stated reason, the previous failed attempt, the scripts the command runs
 * directly, and a short static summary. Every text is secret-masked and has
 * personal path prefixes replaced. Anything that cannot be shown completely
 * (an over-long command, an unreadable or over-long script, a binary built in
 * the workspace) makes the request "not sure", so it goes to the user.
 */

import path from 'node:path'
import { clip } from '../text.js'
import { pathSubstituter, sanitizer } from './redact.js'

const MAX_COMMAND = 8000
const MAX_SCRIPT = 8000
const MAX_SCRIPTS = 3
const SCRIPT_EXT = /\.(ps1|psm1|bat|cmd|py|pyw|js|mjs|cjs|ts|sh|bash|zsh|rb|pl|php|vbs|lua)$/i
const BINARY_EXT = /\.(exe|com|scr|msi|msp|jar|dll)$/i

/**
 * Build the sanitising function for one session.
 * @param {ReturnType<import('../host.js').createHost>} host
 * @param {string | undefined} workspaceRoot
 */
export function sanitizerFor(host, workspaceRoot) {
  const real = p => { try { return host.tools.real(p) } catch { return p } }
  const workspace = typeof workspaceRoot === 'string' && workspaceRoot !== '' ? [workspaceRoot, real(workspaceRoot)] : []
  const temp = host.tempDirs.flatMap(t => [t.abs, real(t.abs)])
  const homes = [host.home, real(host.home)]
  return sanitizer(pathSubstituter({ workspace, temp, homes, caseInsensitive: host.platform === 'win32' || host.platform === 'darwin' }))
}

/**
 * @typedef {object} PayloadInput
 * @property {'pwsh' | 'bash' | 'write' | 'edit'} tool
 * @property {any} args - the tool call's arguments.
 * @property {any} facts - facts from the hard rules.
 * @property {any} [previousFailure] - the previous failed attempt (runtime summary).
 * @property {ReturnType<import('../host.js').createHost>} host
 * @property {string | undefined} workspaceRoot
 * @property {string} os - e.g. "Windows 11, Windows PowerShell 5.1".
 * @property {(file: string) => string | undefined} readText - synchronous file read; undefined when unreadable.
 */

/**
 * Build the review payload.
 * @param {PayloadInput} input
 * @returns {{ ok: true, payload: object, texts: string[] } | { ok: false, reason: string }}
 */
export function buildPayload({ tool, args, facts, previousFailure, host, workspaceRoot, os, readText }) {
  const s = sanitizerFor(host, workspaceRoot)
  const texts = []
  const keep = (value) => { if (typeof value === 'string' && value !== '') texts.push(value); return value }
  const justification = keep(s(clip(typeof args?.justification === 'string' ? args.justification : '', 500)))

  if (tool === 'write' || tool === 'edit') {
    const base = {
      request_type: tool === 'write' ? 'file_write' : 'file_edit',
      tool,
      os,
      target_path: keep(s(facts?.target ?? String(args?.file_path ?? ''))),
      target_exists: facts?.exists === true,
      workspace_root: '<WORKSPACE>',
      agent_justification: justification,
    }
    if (tool === 'write') {
      const content = typeof args?.content === 'string' ? args.content : ''
      return {
        ok: true,
        payload: { ...base, content_length: content.length, content_preview: keep(s(content.slice(0, 1000))), content_truncated: content.length > 1000 },
        texts,
      }
    }
    return {
      ok: true,
      payload: {
        ...base,
        old_text: keep(s(clip(typeof args?.old_string === 'string' ? args.old_string : '', 500))),
        new_text: keep(s(clip(typeof args?.new_string === 'string' ? args.new_string : '', 500))),
        replace_all: args?.replace_all === true,
      },
      texts,
    }
  }

  const command = typeof args?.command === 'string' ? args.command : ''
  if (command.length > MAX_COMMAND) return { ok: false, reason: `命令太长（${command.length} 字），无法完整送审` }

  const scripts = []
  for (const run of facts?.runs ?? []) {
    if (!run.agentWritable) continue
    if (BINARY_EXT.test(run.path)) return { ok: false, reason: `命令运行工作区或临时目录里的程序文件 ${s(run.path)}，看不到内容` }
    if (!SCRIPT_EXT.test(run.path)) continue
    if (scripts.length >= MAX_SCRIPTS) return { ok: false, reason: '命令直接运行的脚本太多' }
    const content = readText(run.path)
    if (content === undefined) return { ok: false, reason: `读不到命令要运行的脚本 ${s(run.path)}` }
    if (content.length > MAX_SCRIPT) return { ok: false, reason: `脚本 ${s(run.path)} 太长（${content.length} 字），无法完整送审` }
    scripts.push({ path: keep(s(run.path)), content: keep(s(content)) })
  }
  for (const { manager, script } of facts?.packageScripts ?? []) {
    const found = findPackageJson(facts?.workdir, workspaceRoot, readText)
    if (found === undefined && script === 'install') {
      scripts.push({ path: null, package_scripts: { note: '工作目录里没有找到 package.json' } })
      continue
    }
    if (found === undefined) return { ok: false, reason: `读不到 package.json，看不出 ${manager} 的 ${script} 脚本会做什么` }
    const entries = {}
    const names = script === 'install' ? ['preinstall', 'install', 'postinstall', 'prepare'] : [`pre${script}`, script, `post${script}`]
    for (const name of names) {
      if (typeof found.scripts[name] === 'string') entries[name] = keep(s(found.scripts[name]))
    }
    if (Object.keys(entries).length === 0) entries[script] = script === 'install' ? '(package.json 里没有安装时会运行的脚本)' : '(package.json 里没有这个脚本)'
    if (scripts.length >= MAX_SCRIPTS) return { ok: false, reason: '命令直接运行的脚本太多' }
    scripts.push({ path: keep(s(found.file)), package_scripts: entries })
  }

  const cap = (list, n) => (Array.isArray(list) ? list.slice(0, n) : [])
  const payload = {
    request_type: 'shell_command',
    tool,
    os,
    command: keep(s(command)),
    working_directory: s(facts?.workdir ?? ''),
    workspace_root: '<WORKSPACE>',
    agent_justification: justification,
    previous_failed_attempt: previousFailure === undefined || previousFailure === null ? null : {
      command: keep(s(clip(previousFailure.command ?? '', 2000))),
      same_as_this_command: previousFailure.sameCommand === true,
      exit_code: previousFailure.exitCode ?? null,
      output_tail: keep(s(clip(previousFailure.outputTail ?? previousFailure.errorMessage ?? '', 1500))),
    },
    scripts,
    static_analysis: {
      paths_outside_workspace: cap(facts?.outsidePaths, 15).map(p => s(p)),
      deletes: cap(facts?.deletes, 10).map(d => ({ path: s(d.path), recursive: d.recursive === true })),
      writes_outside_workspace: cap((facts?.writes ?? []).filter(w => w.outside), 10).map(w => ({ path: s(w.path), already_exists: w.exists === true })),
      moves: cap(facts?.moves, 10).map(m => ({ path: s(m.path) })),
      hard_to_analyse: cap(facts?.opaque, 10),
    },
  }
  return { ok: true, payload, texts }
}

/** The nearest package.json from the working directory up to the workspace root. */
function findPackageJson(workdir, workspaceRoot, readText) {
  let dir = typeof workdir === 'string' && workdir !== '' ? workdir : workspaceRoot
  for (let depth = 0; dir && depth < 8; depth += 1) {
    const file = path.join(dir, 'package.json')
    const text = readText(file)
    if (text !== undefined) {
      try {
        const data = JSON.parse(text)
        return { file, scripts: data !== null && typeof data === 'object' && data.scripts && typeof data.scripts === 'object' ? data.scripts : {} }
      } catch {
        return undefined
      }
    }
    if (workspaceRoot && path.resolve(dir).toLowerCase() === path.resolve(workspaceRoot).toLowerCase()) break
    const parent = path.dirname(dir)
    if (parent === dir) break
    dir = parent
  }
  return undefined
}

/** A fixed, harmless request used to check that the model connection works. */
export function selfTestPayload(os) {
  return {
    request_type: 'shell_command',
    tool: 'pwsh',
    os,
    command: 'npm install',
    working_directory: '<WORKSPACE>',
    workspace_root: '<WORKSPACE>',
    agent_justification: 'npm 需要把下载的包写进它自己的缓存目录（在工作区外）。',
    previous_failed_attempt: null,
    scripts: [],
    static_analysis: { paths_outside_workspace: [], deletes: [], writes_outside_workspace: [], moves: [], hard_to_analyse: [] },
  }
}

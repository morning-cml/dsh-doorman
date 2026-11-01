/**
 * Layer 2 identity of one escalated shell command (docs/design.zh.md §5): the exact key an
 * allowlist entry must match — the tool, the workspace, the working directory and the command with
 * only its outer whitespace trimmed, never a wildcard — and the content of every agent-writable file
 * the command is known to run or be configured by, so that an entry stops matching as soon as one of
 * them changes, appears or disappears.
 *
 * A command may enter the allowlist only when all of that can be told ("判不出依赖的命令不进清单"):
 * anything the analysis cannot see through, any program without a recipe here, anything run from the
 * workspace that is not a plain script, and any change outside the workspace that a repeat would make
 * again keep it out. The recipes bind the scripts the reviewer is shown plus each tool's project and
 * configuration files; what those scripts load in turn is not bound — the reviewer does not see it
 * either (docs/design.zh.md §15).
 */

import { createHash } from 'node:crypto'
import fs from 'node:fs'
import { SCRIPT_EXT, findPackageJson } from '../model/payload.js'
import { classify, workspaceOf } from '../rules/classify.js'

/** Dependency files are hashed up to this size; a bigger one keeps the command out. */
export const MAX_DEPENDENCY_BYTES = 8 * 1024 * 1024
const MAX_DEPENDENCIES = 20

/** Commands that run nothing else and whose file changes the analysis records, by dialect (names after alias resolution). */
const PURE = {
  powershell: new Set([
    'write-output', 'write-host', 'write-verbose', 'write-warning', 'write-information', 'write-debug', 'write-error', 'write-progress',
    'out-null', 'out-string', 'out-host', 'out-default', 'out-file', 'tee-object',
    'select-object', 'select', 'select-string', 'sls', 'sort-object', 'sort', 'measure-object', 'measure', 'group-object', 'group',
    'where-object', 'foreach-object', 'format-table', 'ft', 'format-list', 'fl', 'format-wide', 'fw',
    'convertto-json', 'convertfrom-json', 'convertto-csv', 'convertfrom-csv',
    'get-content', 'get-childitem', 'get-item', 'get-location', 'gl', 'pwd', 'get-date', 'get-filehash',
    'test-path', 'join-path', 'split-path', 'resolve-path', 'start-sleep', 'sleep',
    'set-location', 'push-location', 'pop-location', 'set-variable', 'new-variable', 'set-alias', 'new-alias',
    'new-item', 'mkdir', 'set-content', 'add-content', 'clear-content', 'copy-item', 'move-item', 'rename-item', 'remove-item',
    'export-csv', 'export-clixml', 'expand-archive', 'compress-archive', 'exit',
  ]),
  // `popd` is left out: the analysis does not follow it back.
  cmd: new Set(['echo', 'type', 'dir', 'cd', 'chdir', 'pushd', 'md', 'mkdir', 'rd', 'rmdir', 'del', 'erase', 'copy', 'move', 'ren', 'rename', 'exit', 'ver', 'rem']),
  // Only readers and mkdir: the POSIX copy/move/remove handlers do not follow every flag (`cp -t`).
  posix: new Set(['echo', 'printf', 'cat', 'ls', 'pwd', 'cd', 'mkdir', 'head', 'tail', 'wc', 'cut', 'tr', 'grep', 'true', 'false', 'test', '[', 'basename', 'dirname', 'sleep', 'exit']),
}
/** Directory changes: they run before the move, so where they run from does not matter. */
const NAVIGATION = new Set(['set-location', 'push-location', 'pop-location', 'cd', 'chdir', 'pushd'])
/** Nested shells (`cmd /c`, `pwsh -Command`, `bash -c`) stay out, as the design lists them (§2 第 2 层). */
const SHELLS = new Set(['cmd', 'powershell', 'pwsh', 'powershell_ise', 'bash', 'sh', 'zsh', 'dash', 'ksh', 'wsl', 'git-bash'])

/**
 * @typedef {object} Fingerprint
 * @property {string | null} key - SHA-256 (hex) of the exact identity; null when there is none (file tools, no workspace).
 * @property {string} tool
 * @property {string | null} workspace
 * @property {string | null} workdir
 * @property {string | null} command - trimmed.
 * @property {boolean} eligible - whether the command may enter the allowlist.
 * @property {string[]} reasons - why it may not (empty when eligible).
 * @property {{ path: string, sha256: string | null }[]} dependsOn - sha256 null: the file did not exist.
 * @property {string[]} outsideWrites - paths outside the workspace the command writes (checked again after it ran).
 */

/**
 * The SHA-256 of an exact identity. Equal keys mean equal identities.
 * @param {string} tool
 * @param {string} workspaceKey - path key of the workspace root.
 * @param {string} workdirKey - path key of the working directory.
 * @param {string} command - trimmed command text.
 */
export function identityKey(tool, workspaceKey, workdirKey, command) {
  return createHash('sha256').update(JSON.stringify([tool, workspaceKey, workdirKey, command])).digest('hex')
}

/**
 * Hash one dependency file.
 * @param {string} file
 * @returns {{ sha256: string } | { missing: true } | { error: string }}
 */
export function hashFileSync(file) {
  try {
    const st = fs.statSync(file)
    if (!st.isFile()) return { error: 'not-a-file' }
    if (st.size > MAX_DEPENDENCY_BYTES) return { error: 'too-large' }
    return { sha256: createHash('sha256').update(fs.readFileSync(file)).digest('hex') }
  } catch (error) {
    const code = error !== null && typeof error === 'object' ? error.code : undefined
    if (code === 'ENOENT' || code === 'ENOTDIR') return { missing: true }
    return { error: typeof code === 'string' ? code : 'unreadable' }
  }
}

/**
 * The layer 2 identity of one escalated tool call.
 * @param {object} input
 * @param {'pwsh' | 'bash' | 'write' | 'edit'} input.tool
 * @param {any} input.args - the tool call's arguments.
 * @param {any} input.facts - facts from the hard rules.
 * @param {ReturnType<import('../host.js').createHost>} input.host
 * @param {string | undefined} input.workspaceRoot
 * @param {(file: string) => ({ sha256: string } | { missing: true } | { error: string })} input.hashFile
 * @param {(file: string) => string | undefined} input.readText
 * @returns {Fingerprint}
 */
export function fingerprintOf({ tool, args, facts, host, workspaceRoot, hashFile, readText }) {
  const ws = workspaceOf(host, workspaceRoot)
  if (tool !== 'pwsh' && tool !== 'bash') {
    return { key: null, tool, workspace: ws?.root ?? null, workdir: null, command: null, eligible: false, reasons: ['write/edit 文件工具只做单次判断，不进清单'], dependsOn: [], outsideWrites: [] }
  }
  const raw = typeof args?.command === 'string' ? args.command : ''
  const command = raw.trim()
  const workdir = typeof facts?.workdir === 'string' ? facts.workdir : null
  const c = context({ host, ws, workspaceRoot, hashFile, readText })

  if (ws === undefined) c.why('会话没有工作区')
  if (workdir === null) c.why('不知道命令在哪个目录运行')
  if (command === '') c.why('命令是空的')
  // Trimming must not change the command: a trailing escape would lose the whitespace it escapes.
  if (/[`^\\][\s\uFEFF]+$/.test(raw)) c.why('命令以转义符加空白结尾，去掉首尾空白会改变它')

  const opaque = Array.isArray(facts?.opaque) ? facts.opaque : []
  if (opaque.length > 0) c.why(`有看不穿的写法：${opaque.slice(0, 4).join('、')}`)
  const changes = Array.isArray(facts?.sessionChanges) ? facts.sessionChanges : []
  if (changes.length > 0) c.why(`改了后面的命令会用到的 ${changes.slice(0, 3).join('、')}`)
  for (const d of facts?.deletes ?? []) if (d.outside) c.why(`删除工作区外的 ${d.path}`)
  for (const m of facts?.moves ?? []) if (m.outside) c.why(`移动工作区外的 ${m.path}`)
  for (const w of facts?.writes ?? []) if (w.outside && w.exists) c.why(`覆盖工作区外已有的 ${w.path}`)
  for (const run of facts?.runs ?? []) checkRun(run, c)
  if (Array.isArray(facts?.invocations)) {
    for (const inv of facts.invocations) checkInvocation(inv, c)
  } else {
    c.why('没有逐条命令的分析结果')
  }

  const key = ws !== undefined && workdir !== null ? identityKey(tool, host.tools.key(ws.root), host.tools.key(workdir), command) : null
  return {
    key,
    tool,
    workspace: ws?.root ?? null,
    workdir,
    command,
    eligible: key !== null && c.reasons.length === 0,
    reasons: c.reasons,
    dependsOn: c.dependsOn(),
    outsideWrites: (facts?.writes ?? []).filter(w => w.outside).map(w => w.path),
  }
}

/** Collects reasons and bound files for one fingerprint. */
function context({ host, ws, workspaceRoot, hashFile, readText }) {
  const { tools } = host
  const reasons = []
  /** @type {Map<string, { path: string, sha256: string | null }>} */
  const deps = new Map()
  const why = (reason) => { if (!reasons.includes(reason)) reasons.push(reason) }

  /** Bind a file's content (or its absence) to the fingerprint. */
  const bind = (file) => {
    const k = tools.key(file)
    if (deps.has(k)) return deps.get(k)
    if (deps.size >= MAX_DEPENDENCIES) { why('依赖文件太多'); return undefined }
    let hashed
    try {
      hashed = hashFile(file)
    } catch {
      hashed = { error: 'unreadable' }
    }
    if (hashed?.missing === true) {
      const dep = { path: file, sha256: null }
      deps.set(k, dep)
      return dep
    }
    if (typeof hashed?.sha256 !== 'string') { why(`读不了依赖文件 ${file}（${hashed?.error ?? '未知原因'}）`); return undefined }
    const dep = { path: file, sha256: hashed.sha256 }
    deps.set(k, dep)
    return dep
  }

  return {
    P: tools.P,
    workspaceRoot,
    readText,
    reasons,
    why,
    bind,
    /** Bind a file that must not exist: its presence keeps the command out. */
    mustBeAbsent(file, reason) {
      const dep = bind(file)
      if (dep !== undefined && dep.sha256 !== null) why(reason)
    },
    /** Absolute path of an argument, or undefined when it is not a plain file path. */
    resolve(value, cwd) {
      const cleaned = tools.clean(value)
      if (cleaned.kind !== 'file' && cleaned.kind !== 'unc') return undefined
      return tools.absolute(tools.expandTilde(cleaned.path), cwd ?? undefined)
    },
    /** Whether the agent can change a path without escalating (workspace or temp). */
    agentWritable: abs => classify(abs, host, ws).agentWritable,
    dependsOn: () => [...deps.values()],
  }
}

/** A program or script the command runs: the agent can change it only inside the workspace or temp. */
function checkRun(run, c) {
  if (!run.agentWritable) return
  if (/[\\/]node_modules[\\/]/i.test(run.path)) { c.why(`运行 node_modules 里的 ${run.path}，判断不出它依赖哪些文件`); return }
  if (!run.script && !SCRIPT_EXT.test(run.path)) { c.why(`运行工作区或临时目录里的程序 ${run.path}，判断不出它依赖哪些文件`); return }
  c.bind(run.path)
}

/** One command of the command line. */
function checkInvocation(inv, c) {
  const { name } = inv
  if (inv.args.some(a => a === null)) { c.why(`${name} 的参数含未知的值`); return }
  if (NAVIGATION.has(name)) return
  // A command running outside the workspace writes relative paths there, out of sight of the analysis.
  if (inv.cwd === null) { c.why(`不知道 ${name} 在哪个目录运行`); return }
  if (!c.agentWritable(inv.cwd)) { c.why(`${name} 在工作区外的 ${inv.cwd} 里运行`); return }
  if (SHELLS.has(name)) { c.why(`嵌套了 ${name}，不进清单`); return }
  if (PURE[inv.dialect]?.has(name)) return
  // A script run directly (its file is bound through the runs).
  if (SCRIPT_EXT.test(name)) { outsideArgs(inv, c, -1); return }
  const recipe = recipeFor(name)
  if (recipe === undefined) { c.why(`判断不出 ${name} 依赖哪些文件`); return }
  recipe(inv, c)
}

function recipeFor(name) {
  if (Object.hasOwn(RECIPES, name)) return RECIPES[name]
  if (/^(python[0-9.]*|pythonw|py)$/.test(name)) return interpreter('python')
  return undefined
}

const looksLikePath = v => /[\\/]/.test(v) || /^~/.test(v) || /^[A-Za-z]:/.test(v) || /^\.{1,2}$/.test(v)

/** Paths outside the workspace handed to a program or script, which it may write: they keep the command out. */
function outsideArgs(inv, c, skip) {
  inv.args.forEach((arg, i) => {
    if (i === skip) return
    // `--out=C:\x`, `PREFIX=C:\x`: the value after `=` as well as the whole word.
    const values = arg.includes('=') ? [arg, arg.slice(arg.indexOf('=') + 1)] : [arg]
    for (const value of values) {
      if (!looksLikePath(value) || /^[a-z][a-z0-9+.-]+:\/\//i.test(value)) continue
      const abs = c.resolve(value, inv.cwd)
      if (abs !== undefined && !c.agentWritable(abs)) { c.why(`把工作区外的路径 ${abs} 交给了 ${inv.name}`); return }
    }
  })
}

// ---------------------------------------------------------------------------------------
// Recipes: what a program's behaviour depends on
// ---------------------------------------------------------------------------------------

const NODE_OPTION = /^--(no-warnings|no-deprecation|enable-source-maps|trace-warnings|trace-deprecation|trace-uncaught|experimental-vm-modules|max-old-space-size=\d+|stack-size=\d+|unhandled-rejections=[a-z-]+)$/
const PYTHON_OPTION = /^-(u|B|E|s|I|O|OO|q|b|bb|X(utf8(=[01])?|dev|faulthandler))$/
const PYTHON_X = /^(utf8(=[01])?|dev|faulthandler)$/
const PY_LAUNCHER_VERSION = /^-\d+(\.\d+)?(-(32|64))?$/

/**
 * `node x.js`, `python x.py`: bound to the script itself (the file the reviewer is shown). Options that
 * load other code (`-r`, `--import`, `-m` …) keep the command out.
 * @param {'node' | 'python'} family
 */
function interpreter(family) {
  return (inv, c) => {
    const { args, name } = inv
    let i = 0
    for (; i < args.length; i += 1) {
      const a = args[i]
      if (!a.startsWith('-') || a === '-') break
      if (family === 'node' ? NODE_OPTION.test(a) : (PYTHON_OPTION.test(a) || (name === 'py' && PY_LAUNCHER_VERSION.test(a)))) continue
      if (family === 'python' && a === '-X' && PYTHON_X.test(args[i + 1] ?? '')) { i += 1; continue }
      c.why(`${name} 带了判断不出依赖的选项 ${a}`)
      return
    }
    const script = args[i]
    if (script === undefined || !(family === 'node' ? /\.(js|mjs|cjs)$/i : /\.pyw?$/i).test(script)) { c.why(`${name} 没有直接运行一个脚本文件`); return }
    const abs = c.resolve(script, inv.cwd)
    if (abs === undefined) { c.why(`看不出 ${name} 运行的脚本在哪里`); return }
    if (c.agentWritable(abs)) {
      if (/[\\/]node_modules[\\/]/i.test(abs)) { c.why(`运行 node_modules 里的 ${abs}，判断不出它依赖哪些文件`); return }
      c.bind(abs)
    }
    outsideArgs(inv, c, i)
  }
}

const INSTALL_VERBS = new Set(['install', 'i', 'ci', 'add'])
const RUN_VERBS = new Set(['run', 'run-script', 'test', 't', 'tst', 'start', 'stop', 'restart'])
/** Options that make a package manager use another project, another configuration or another shell. */
const ELSEWHERE = /^(-g|--global|--location(=.*)?|--prefix(=.*)?|-C|--dir(=.*)?|--cwd(=.*)?|-w|--workspace(=.*)?|--workspaces|-ws|--filter(=.*)?|-F|-r|--recursive|--include-workspace-root|--userconfig(=.*)?|--globalconfig(=.*)?|--script-shell(=.*)?|--node-options(=.*)?|--config(=.*)?)$/i
const LOCKFILES = { npm: ['package-lock.json', 'npm-shrinkwrap.json'], pnpm: ['pnpm-lock.yaml'], yarn: ['yarn.lock'], bun: ['bun.lockb', 'bun.lock'] }
/** A package spec that installs from the local disk (its own scripts would run unseen). */
const LOCAL_SPEC = /^(\.|~|\/|\\|[a-z]:|file:|link:|portal:)|\.(tgz|tar\.gz|tar)$/i

/**
 * `npm install`, `npm ci`, `npm run x`, `npm test` (and pnpm/yarn/bun): bound to the nearest
 * package.json, the project's .npmrc, the lockfiles for installs, and each manager's own
 * configuration — with the files whose presence would run code nobody reviewed required absent.
 * @param {'npm' | 'pnpm' | 'yarn' | 'bun'} manager
 */
function packageManager(manager) {
  return (inv, c) => {
    const { args } = inv
    const elsewhere = args.find(a => ELSEWHERE.test(a))
    if (elsewhere !== undefined) { c.why(`${manager} ${elsewhere} 会用到别处的项目或配置`); return }
    const words = args.filter(a => !a.startsWith('-'))
    const sub = (words[0] ?? '').toLowerCase()
    const install = INSTALL_VERBS.has(sub) || (sub === '' && (manager === 'pnpm' || manager === 'yarn'))
    if (!install && !RUN_VERBS.has(sub)) { c.why(`${manager} ${sub || '（无子命令）'} 不在可进清单的命令里`); return }
    const local = install ? words.slice(1).find(w => LOCAL_SPEC.test(w)) : undefined
    if (local !== undefined) { c.why(`${manager} 从本地路径 ${local} 安装，判断不出它的依赖`); return }
    outsideArgs(inv, c, -1)
    // The same package.json the reviewer is shown (nearest one from where the manager runs).
    const found = findPackageJson(inv.cwd, c.workspaceRoot, c.readText)
    if (found === undefined && !install) { c.why(`找不到 ${manager} 要用的 package.json`); return }
    const dir = found === undefined ? inv.cwd : c.P.dirname(found.file)
    const at = file => c.P.join(dir, file)
    c.bind(at('package.json'))
    c.bind(at('.npmrc'))
    if (install) for (const file of LOCKFILES[manager]) c.bind(at(file))
    if (manager === 'yarn') {
      c.bind(at('.yarnrc'))
      c.mustBeAbsent(at('.yarnrc.yml'), '有 .yarnrc.yml（yarn 2+ 会运行其中指定的程序和插件）')
    }
    if (manager === 'pnpm') {
      c.mustBeAbsent(at('.pnpmfile.cjs'), '有 .pnpmfile.cjs（pnpm 会运行它）')
      c.mustBeAbsent(at('pnpm-workspace.yaml'), '是 pnpm 多包项目，判断不出各子包的脚本')
    }
    if (manager === 'bun') c.bind(at('bunfig.toml'))
    if (!install) return
    c.mustBeAbsent(at('binding.gyp'), '有 binding.gyp（安装时会编译并运行它的构建步骤）')
    const data = found?.data
    if (data?.workspaces !== undefined) c.why('package.json 定义了 workspaces，安装会运行各子包的脚本')
    for (const field of ['dependencies', 'devDependencies', 'optionalDependencies']) {
      const deps = data?.[field]
      if (deps === null || typeof deps !== 'object') continue
      const spec = Object.values(deps).find(v => typeof v === 'string' && /^(file:|link:|portal:|\.{0,2}[\\/])/.test(v))
      if (spec !== undefined) c.why(`package.json 依赖了本地路径 ${spec}`)
    }
  }
}

const MAKEFILES = ['GNUmakefile', 'makefile', 'Makefile']

/** `make [targets]`, `make -f x.mk`: bound to the makefile; one that includes others keeps the command out. */
function make(inv, c) {
  const { args } = inv
  const files = []
  for (let i = 0; i < args.length; i += 1) {
    const a = args[i]
    if (a === '-f' || a === '--file' || a === '--makefile') { files.push(args[i + 1]); i += 1; continue }
    const glued = /^(?:--file=|--makefile=|-f)(.+)$/.exec(a)
    if (glued) { files.push(glued[1]); continue }
    if (/^(-C|--directory|-I|--include-dir)/.test(a)) { c.why(`${inv.name} ${a} 会用到别处的文件`); return }
  }
  if (files.some(f => f === undefined || f === '-')) { c.why(`看不出 ${inv.name} 用哪个 makefile`); return }
  outsideArgs(inv, c, -1)
  const paths = files.length > 0 ? files.map(f => c.resolve(f, inv.cwd)) : MAKEFILES.map(name => c.P.join(inv.cwd, name))
  if (paths.some(p => p === undefined)) { c.why(`看不出 ${inv.name} 用哪个 makefile`); return }
  for (const file of paths) {
    c.bind(file)
    const text = c.readText(file)
    if (text !== undefined && /^[ \t]*-?s?include[ \t]/m.test(text)) c.why(`${c.P.basename(file)} 引用了其他 makefile`)
  }
}

const RECIPES = {
  node: interpreter('node'),
  npm: packageManager('npm'),
  pnpm: packageManager('pnpm'),
  yarn: packageManager('yarn'),
  bun: packageManager('bun'),
  make,
  gmake: make,
  'mingw32-make': make,
}

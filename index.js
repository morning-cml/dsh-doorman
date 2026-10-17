/**
 * dsh-doorman — triage of sandbox-escalation approval prompts.
 *
 * This build (stage 2) runs the hard rules and the model review in
 * observe-only mode: every request still goes to the user, and the log
 * records what the plugin would have done next to what the user chose.
 * Nothing here may break dsh: every step is guarded, and if anything is
 * missing the plugin simply forwards approvals unchanged.
 */

import { createHash } from 'node:crypto'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { VERIFIED_DSH_VERSIONS, detectDshVersion, findDshHome, installFacts, realProbe } from './lib/dsh-env.js'
import { createHost } from './lib/host.js'
import { createLog } from './lib/log.js'
import { createRuntime } from './lib/runtime.js'
import { buildConfigSchema, readSettings } from './lib/settings.js'
import { readState, recordVersion, writeState } from './lib/state.js'

export const name = 'dsh-doorman'

// dsh's schema library lets the Plugins page edit the model settings live.
// Without it the plugin still runs, with settings read as plain values.
let schemastery
try {
  schemastery = (await import('@deepseek-ai/schemastery')).default
} catch {
  schemastery = undefined
}
export const Config = (() => {
  try {
    return buildConfigSchema(schemastery)
  } catch {
    // A changed schema library only costs the settings page, never the plugin.
    return undefined
  }
})()

/** Environment names whose values must never be expanded into paths, logs or prompts. */
const SECRET_ENV = /KEY|PASSWORD|SECRET|TOKEN|CREDENTIAL|AUTH|COOKIE|SESSION/i
/** Script files are read up to this size; longer ones are "too long" anyway. */
const READ_LIMIT = 256 * 1024
const SELF_TEST_DELAY_MS = 3000

/**
 * The Host environment without secrets (dsh strips the same names from agent shells).
 * @param {NodeJS.ProcessEnv} env
 */
function safeEnv(env) {
  const out = {}
  for (const [key, value] of Object.entries(env)) {
    if (typeof value === 'string' && !SECRET_ENV.test(key) && value.length < 4096) out[key] = value
  }
  return out
}

/** Read a text file (up to READ_LIMIT bytes); undefined when it is not a readable file. */
function readText(file) {
  let fd
  try {
    const st = fs.statSync(file)
    if (!st.isFile()) return undefined
    fd = fs.openSync(file, 'r')
    const buffer = Buffer.alloc(Math.min(st.size, READ_LIMIT))
    const length = fs.readSync(fd, buffer, 0, buffer.length, 0)
    return buffer.subarray(0, length).toString('utf8').replace(/^\uFEFF/, '')
  } catch {
    return undefined
  } finally {
    if (fd !== undefined) {
      try { fs.closeSync(fd) } catch { /* ignore */ }
    }
  }
}

/** A short description of the OS and shell, for the reviewer. */
function osLabel() {
  if (process.platform === 'win32') {
    const build = Number(os.release().split('.')[2] ?? 0)
    const programFiles = process.env.ProgramFiles ?? 'C:\\Program Files'
    const ps7 = fs.existsSync(path.join(programFiles, 'PowerShell', '7', 'pwsh.exe'))
    return `${build >= 22000 ? 'Windows 11' : 'Windows 10'}, ${ps7 ? 'PowerShell 7' : 'Windows PowerShell 5.1'}`
  }
  if (process.platform === 'darwin') return `macOS ${os.release()}, zsh/bash`
  return `${os.type()} ${os.release()}, bash`
}

/**
 * The session facts the rules need, read from dsh services at request time.
 * @param {any} ctx
 * @param {any} agent
 */
function sessionInfo(ctx, agent) {
  const session = agent?.session
  if (session === undefined || session === null) return undefined
  const policyService = ctx.get('sandboxPolicy')
  if (policyService === undefined || typeof policyService.resolve !== 'function') return undefined
  const policy = policyService.resolve({ session })
  let cwd
  try {
    const directories = ctx.get('workingDirectory')
    if (directories !== undefined && typeof directories.get === 'function') cwd = directories.get(session)
  } catch {
    cwd = undefined
  }
  return {
    sessionId: session.header?.id,
    sandboxMode: policy?.mode,
    workspaceRoot: policy?.workspaceRoot,
    cwd: typeof cwd === 'string' ? cwd : (session.header?.cwd ?? policy?.workspaceRoot),
  }
}

/**
 * Plugin entry.
 * @param {any} ctx - the Cordis plugin context.
 * @param {any} config - this row's config (plain values or dsh volatile references).
 */
export function apply(ctx, config) {
  let log = { write: () => {} }
  try {
    const packageDir = path.dirname(fileURLToPath(import.meta.url))
    const { dshHome, source } = findDshHome(packageDir)
    const dataDir = path.join(dshHome, 'dsh-doorman')
    const stateFile = path.join(dataDir, 'state.json')
    log = createLog({ dir: path.join(dataDir, 'logs') })

    const getSettings = () => readSettings(config).settings
    const reportProblems = (when) => {
      const { problems } = readSettings(config)
      if (problems.length > 0) log.write('settings-problem', { when, problems, note: '这些设置的值无效，已改用默认值' })
    }

    const dshVersion = detectDshVersion(specifier => import.meta.resolve(specifier))
    const dshVersionVerified = dshVersion !== null && VERIFIED_DSH_VERSIONS.includes(dshVersion)
    const version = recordVersion(stateFile, dshVersion)
    if (version.changed) {
      log.write('dsh-version-changed', {
        from: version.previous,
        to: version.current,
        verifiedByPlugin: dshVersionVerified,
        note: `!!! dsh 版本变了${dshVersionVerified ? '（插件已对照这个版本的源码核实过）' : '，插件还没对照这个版本的源码核实过'}。自动模式会退回只观察，直到确认新版本（把插件设置里的 autoModeConfirmedForVersion 改成新版本号）。`,
      })
    }

    const host = createHost({
      platform: process.platform,
      home: os.homedir(),
      env: safeEnv(process.env),
      dshHome,
      dataDir,
      installDir: packageDir,
      execPath: process.execPath,
      tempDirs: [os.tmpdir()],
      probe: realProbe,
    })
    const getKey = async (keyName) => {
      const credentials = ctx.get('credentials')
      if (credentials === undefined || typeof credentials.resolve !== 'function') return undefined
      const hit = await credentials.resolve(keyName)
      return typeof hit?.value === 'string' && hit.value.trim() !== '' ? hit.value : undefined
    }
    const runtime = createRuntime({
      host,
      getSettings,
      log,
      dshVersion,
      sessionInfo: agent => sessionInfo(ctx, agent),
      getKey,
      readText,
      osLabel: osLabel(),
    })

    let pluginVersion = null
    try {
      pluginVersion = JSON.parse(fs.readFileSync(path.join(packageDir, 'package.json'), 'utf8')).version ?? null
    } catch {
      pluginVersion = null
    }
    const current = runtime.mode()
    const settings = getSettings()
    log.write('startup', {
      pluginVersion,
      dshVersion,
      dshVersionVerified,
      platform: process.platform,
      dshHome,
      dshHomeSource: source,
      dataDir,
      settingsSchema: Config !== undefined,
      mode: current.effective,
      configuredMode: current.configured,
      ...(current.note ? { modeNote: current.note } : {}),
      model: settings.model,
      baseUrl: settings.baseUrl,
      install: installFacts(packageDir),
    })
    reportProblems('startup')

    ctx.on('tools/pre-execute', (exec, next) => {
      try {
        runtime.onPreExecute(exec)
      } catch (error) {
        log.write('error', { where: 'pre-execute', message: error instanceof Error ? error.message : String(error) })
      }
      return next()
    }, { prepend: true })

    ctx.on('tools/result', (exec, result) => {
      try {
        runtime.onResult(exec, result)
      } catch (error) {
        log.write('error', { where: 'result', message: error instanceof Error ? error.message : String(error) })
      }
    })

    ctx.on('approval/request', (req, next) => runtime.onApproval(req, next), { prepend: true })

    // Connection check: after the key or the model settings change, and once per new setting combination.
    let timer = null
    const fingerprint = () => {
      const s = getSettings()
      return createHash('sha256').update(`${s.baseUrl}\n${s.model}\n${s.keyName}`).digest('hex').slice(0, 16)
    }
    const schedule = (trigger) => {
      if (getSettings().mode === 'off') return
      if (timer !== null) clearTimeout(timer)
      timer = setTimeout(() => {
        timer = null
        const print = fingerprint()
        runtime.selfTest(trigger).then((result) => {
          writeState(stateFile, { ...readState(stateFile), lastSelfTest: { fingerprint: print, status: result.status, at: new Date().toISOString() } })
        }, () => {})
      }, SELF_TEST_DELAY_MS)
      timer.unref?.()
    }
    if (typeof ctx.effect === 'function') ctx.effect(() => () => { if (timer !== null) clearTimeout(timer) })
    ctx.on('credentials/reference-updated', (ref) => {
      try {
        if (String(ref) === getSettings().keyName) schedule('key-changed')
      } catch {
        // ignore
      }
    })
    ctx.on('loader/volatile-update', (paths) => {
      try {
        const s = getSettings()
        log.write('settings-changed', { paths, model: s.model, baseUrl: s.baseUrl, timeoutSeconds: s.timeoutSeconds, maxCallsPerHour: s.maxCallsPerHour })
        reportProblems('settings-changed')
        schedule('settings-changed')
      } catch {
        // ignore
      }
    })
    const last = readState(stateFile).lastSelfTest
    if (last?.fingerprint !== fingerprint() || last?.status !== 'ok') schedule('startup')
  } catch (error) {
    // Loading failed: stay out of the way. Approvals keep going to the user unchanged.
    log.write('error', { where: 'startup', message: error instanceof Error ? error.message : String(error) })
  }
}

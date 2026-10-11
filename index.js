/**
 * dsh-doorman — triage of sandbox-escalation approval prompts.
 *
 * This build (stage 1) runs the hard rules in observe-only mode: every
 * request still goes to the user, and the log records what the plugin would
 * have done next to what the user chose. Nothing here may break dsh: every
 * step is guarded, and if anything is missing the plugin simply forwards
 * approvals unchanged.
 */

import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { createConfigStore } from './lib/config.js'
import { detectDshVersion, findDshHome, installFacts, realProbe } from './lib/dsh-env.js'
import { createHost } from './lib/host.js'
import { createLog } from './lib/log.js'
import { createRuntime } from './lib/runtime.js'
import { recordVersion } from './lib/state.js'

export const name = 'dsh-doorman'

/** Environment names whose values must never be expanded into paths, logs or prompts. */
const SECRET_ENV = /KEY|PASSWORD|SECRET|TOKEN|CREDENTIAL|AUTH|COOKIE|SESSION/i

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
 */
export function apply(ctx) {
  let log = { write: () => {} }
  try {
    const packageDir = path.dirname(fileURLToPath(import.meta.url))
    const { dshHome, source } = findDshHome(packageDir)
    const dataDir = path.join(dshHome, 'dsh-doorman')
    let configStore
    log = createLog({ dir: path.join(dataDir, 'logs'), maxFileBytes: () => configStore?.get().log.maxFileBytes ?? 50 * 1024 * 1024 })
    configStore = createConfigStore(path.join(dataDir, 'config.json'), log.write)

    const dshVersion = detectDshVersion(specifier => import.meta.resolve(specifier))
    const version = recordVersion(path.join(dataDir, 'state.json'), dshVersion)
    if (version.changed) {
      log.write('dsh-version-changed', {
        from: version.previous,
        to: version.current,
        note: '!!! dsh 版本变了。自动模式会退回只观察，直到确认新版本（把 config.json 的 autoModeConfirmedForVersion 改成新版本号）。',
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
    const runtime = createRuntime({ host, configStore, log, dshVersion, sessionInfo: agent => sessionInfo(ctx, agent) })

    let pluginVersion = null
    try {
      pluginVersion = JSON.parse(fs.readFileSync(path.join(packageDir, 'package.json'), 'utf8')).version ?? null
    } catch {
      pluginVersion = null
    }
    const current = runtime.mode()
    log.write('startup', {
      pluginVersion,
      dshVersion,
      platform: process.platform,
      dshHome,
      dshHomeSource: source,
      dataDir,
      mode: current.effective,
      configuredMode: current.configured,
      ...(current.note ? { modeNote: current.note } : {}),
      install: installFacts(packageDir),
    })

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
  } catch (error) {
    // Loading failed: stay out of the way. Approvals keep going to the user unchanged.
    log.write('error', { where: 'startup', message: error instanceof Error ? error.message : String(error) })
  }
}

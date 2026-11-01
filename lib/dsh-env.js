/**
 * Facts about the dsh installation this plugin runs in, found without
 * executing any dsh code: dsh's home directory, the running dsh version, and
 * how this plugin's own files are installed.
 */

import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

/**
 * dsh versions whose source was checked for every hook this plugin uses (tool and approval events,
 * sandbox policy, working directory, credentials, settings page). package.json's `engines.dsh`
 * admits the rest of the 0.2 line, where the plugin runs observe-only until a version is confirmed.
 *
 * 0.2.1-rc.3..rc.5: in every package this plugin depends on, the diff from rc.2 is version-number
 * bumps only; the single code change in the line (ui-plugin-manager gained an `openList()` nav
 * method) touches nothing the plugin uses. 0.2.2 is not verified: it reworks the approval service.
 */
export const VERIFIED_DSH_VERSIONS = Object.freeze([
  '0.2.0-rc.2', '0.2.1-rc.1', '0.2.1-rc.2', '0.2.1-rc.3', '0.2.1-rc.4', '0.2.1-rc.5',
])

/**
 * dsh's home: derived from where this plugin is installed
 * (`<home>/profiles/<profile>/node_modules/dsh-doorman`), else $DSH_HOME, else ~/.dsh.
 * @param {string} packageDir - this plugin's package directory.
 * @param {NodeJS.ProcessEnv} env
 */
export function findDshHome(packageDir, env = process.env) {
  let dir = packageDir
  for (let depth = 0; depth < 8; depth += 1) {
    const parent = path.dirname(dir)
    if (parent === dir) break
    if (path.basename(parent).toLowerCase() === 'profiles') {
      const home = path.dirname(parent)
      if (fs.existsSync(path.join(home, 'profiles'))) return { dshHome: home, source: 'install-path' }
    }
    dir = parent
  }
  if (typeof env.DSH_HOME === 'string' && env.DSH_HOME.trim() !== '') return { dshHome: path.resolve(env.DSH_HOME), source: 'DSH_HOME' }
  return { dshHome: path.join(os.homedir(), '.dsh'), source: 'default' }
}

/**
 * The running dsh version, read from the dsh-app-boot package manifest.
 * @param {(specifier: string) => string} resolve - import.meta.resolve of the caller.
 * @returns {string | null}
 */
export function detectDshVersion(resolve) {
  try {
    const entry = fileURLToPath(resolve('@deepseek-ai/dsh-app-boot'))
    let dir = path.dirname(entry)
    for (let depth = 0; depth < 6; depth += 1) {
      const manifest = path.join(dir, 'package.json')
      if (fs.existsSync(manifest)) {
        const data = JSON.parse(fs.readFileSync(manifest, 'utf8'))
        if (data && data.name === '@deepseek-ai/dsh-app-boot' && typeof data.version === 'string') return data.version
      }
      const parent = path.dirname(dir)
      if (parent === dir) break
      dir = parent
    }
  } catch {
    // Unknown version: treated as "changed" for auto mode (see runtime).
  }
  return null
}

/**
 * The `skills` directories of the other plugins installed in the same profile, found next to this
 * plugin under `node_modules`. dsh directs the agent to run these plugins' skill scripts (through
 * the bundled runtime or directly), so the rules allow running — never changing — files inside them.
 * This plugin's own directory is left out. Anything that cannot be read returns an empty list.
 * @param {string} packageDir - this plugin's package directory.
 * @param {string} [self] - this plugin's package name.
 * @returns {string[]} absolute paths of `<plugin>/skills` directories.
 */
export function installedPluginSkillDirs(packageDir, self = 'dsh-doorman') {
  const dirs = []
  const addSkills = (pkgDir) => {
    const skills = path.join(pkgDir, 'skills')
    try {
      if (fs.statSync(skills).isDirectory()) dirs.push(skills)
    } catch {
      // No skills directory, or unreadable: nothing to carve out.
    }
  }
  try {
    const nodeModules = path.dirname(packageDir)
    if (path.basename(nodeModules).toLowerCase() !== 'node_modules') return dirs
    for (const entry of fs.readdirSync(nodeModules, { withFileTypes: true })) {
      if (!entry.isDirectory() && !entry.isSymbolicLink()) continue
      const name = entry.name
      if (name === self || name === '.bin' || name === '.pnpm') continue
      if (name.startsWith('@')) {
        // A scope directory holds the actual packages.
        try {
          for (const sub of fs.readdirSync(path.join(nodeModules, name), { withFileTypes: true })) {
            if (sub.isDirectory() || sub.isSymbolicLink()) addSkills(path.join(nodeModules, name, sub.name))
          }
        } catch {
          // Unreadable scope directory: skip it.
        }
      } else {
        addSkills(path.join(nodeModules, name))
      }
    }
  } catch {
    // No reachable node_modules: no carve-outs, the rules stay fully strict.
  }
  return dirs
}

/**
 * How this plugin's code is installed (a copy, a link, hard-linked files).
 * @param {string} packageDir
 */
export function installFacts(packageDir) {
  const facts = { packageDir }
  try {
    facts.isSymlink = fs.lstatSync(packageDir).isSymbolicLink()
    facts.realDir = fs.realpathSync.native(packageDir)
    facts.indexHardLinks = fs.statSync(path.join(packageDir, 'index.js')).nlink
  } catch (error) {
    facts.error = error instanceof Error ? error.message : String(error)
  }
  return facts
}

/**
 * A file-system probe for the rules (realpath of existing paths, existence).
 */
export const realProbe = Object.freeze({
  realpath(p) {
    try {
      return fs.realpathSync.native(p)
    } catch {
      return undefined
    }
  },
  exists(p) {
    try {
      fs.lstatSync(p)
      return true
    } catch {
      return false
    }
  },
})

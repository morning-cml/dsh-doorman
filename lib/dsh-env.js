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

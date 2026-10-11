/**
 * Small persistent state (`state.json`): the dsh version seen last time, so a
 * change after an update can be noticed and logged loudly, and the settings
 * the last connection check ran with.
 */

import fs from 'node:fs'
import path from 'node:path'

/**
 * Read the state file; an unreadable or invalid file reads as empty.
 * @param {string} file
 * @returns {Record<string, any>}
 */
export function readState(file) {
  try {
    const state = JSON.parse(fs.readFileSync(file, 'utf8'))
    return state !== null && typeof state === 'object' && !Array.isArray(state) ? state : {}
  } catch {
    return {}
  }
}

/**
 * Replace the state file atomically. Failures are ignored (state is a convenience).
 * @param {string} file
 * @param {Record<string, any>} state
 */
export function writeState(file, state) {
  try {
    fs.mkdirSync(path.dirname(file), { recursive: true })
    const tmp = `${file}.tmp-${process.pid}`
    fs.writeFileSync(tmp, `${JSON.stringify(state, null, 2)}\n`, 'utf8')
    fs.renameSync(tmp, file)
  } catch {
    // Not fatal.
  }
}

/**
 * Record the running dsh version and report whether it changed.
 * @param {string} file - absolute path of state.json.
 * @param {string | null} version - the running dsh version, null when unknown.
 * @param {() => Date} [now]
 * @returns {{ previous: string | null, current: string | null, changed: boolean }}
 */
export function recordVersion(file, version, now = () => new Date()) {
  const state = readState(file)
  const previous = typeof state.lastSeenDshVersion === 'string' ? state.lastSeenDshVersion : null
  const changed = previous !== null && version !== null && previous !== version
  if (version !== null && previous !== version) {
    const history = Array.isArray(state.versionHistory) ? state.versionHistory.slice(-19) : []
    history.push({ version, firstSeen: now().toISOString() })
    writeState(file, { ...state, lastSeenDshVersion: version, versionHistory: history })
  }
  return { previous, current: version, changed }
}

/**
 * The allowlist (`allowlist.json` in the plugin's data directory, docs/design.zh.md §5): exact
 * entries — same tool, workspace, working directory and trimmed command, no wildcards — each bound
 * to the hashes of the files its command depends on. An entry whose files changed no longer matches;
 * a `blocked` entry ("以后都弹给我") always sends the command to the user.
 *
 * The file is re-read whenever it changes on disk and replaced atomically when written. A file that
 * exists but cannot be read or is malformed makes every lookup answer 'error', which means ask the
 * user: losing a blocked entry must never let a command through.
 *
 * In shadow mode (stage 3a) nothing is written: additions, blocks and hits live in memory only, so
 * the log can show what the allowlist would have done while the file stays untouched.
 */

import { randomBytes } from 'node:crypto'
import fs from 'node:fs'
import path from 'node:path'

const VERSION = 1
const SHA256 = /^[0-9a-f]{64}$/

/**
 * @typedef {object} Entry
 * @property {string} id
 * @property {'active' | 'blocked'} status
 * @property {'pwsh' | 'bash'} tool
 * @property {string} workspace
 * @property {string} workdir
 * @property {string} command
 * @property {{ path: string, sha256: string | null }[]} dependsOn
 * @property {string} [explanation] - the reviewer's explanation when it was added.
 * @property {string} [model]
 * @property {string} addedAt
 * @property {number} hits
 * @property {string | null} lastUsedAt
 * @property {string} [blockedAt]
 * @property {string[]} [blockedBecause]
 */

/**
 * @typedef {{ status: 'miss' } | { status: 'error', message: string }
 *   | { status: 'hit' | 'blocked' | 'stale' | 'ineligible', entry: Entry }} Lookup
 */

/** Whether a parsed value is a well-formed entry. */
function validEntry(e) {
  return e !== null && typeof e === 'object'
    && typeof e.id === 'string' && /^[a-z0-9]{1,16}$/.test(e.id)
    && (e.status === 'active' || e.status === 'blocked')
    && (e.tool === 'pwsh' || e.tool === 'bash')
    && ['workspace', 'workdir', 'command'].every(k => typeof e[k] === 'string' && e[k] !== '')
    && Array.isArray(e.dependsOn)
    && e.dependsOn.every(d => d !== null && typeof d === 'object' && typeof d.path === 'string' && d.path !== '' && (d.sha256 === null || (typeof d.sha256 === 'string' && SHA256.test(d.sha256))))
    && (e.hits === undefined || (Number.isInteger(e.hits) && e.hits >= 0))
}

/**
 * Parse the file's text; throws on anything malformed.
 * @param {string} text
 * @returns {Entry[]}
 */
export function parseAllowlist(text) {
  const data = JSON.parse(text)
  if (data === null || typeof data !== 'object' || data.version !== VERSION || !Array.isArray(data.entries)) throw new Error('不是第 1 版放行清单')
  const bad = data.entries.findIndex(e => !validEntry(e))
  if (bad !== -1) throw new Error(`第 ${bad + 1} 条格式不对`)
  return data.entries
}

/**
 * @param {object} options
 * @param {string} options.file - absolute path of allowlist.json.
 * @param {(abs: string) => string} options.pathKey - canonical comparison key of a path (host.tools.key).
 * @param {boolean} [options.shadow] - keep every change in memory, never write the file.
 * @param {() => Date} [options.now]
 * @param {number} [options.maxEntries]
 */
export function createAllowlist({ file, pathKey, shadow = true, now = () => new Date(), maxEntries = 1000 }) {
  /** The file as last read: `stamp` identifies the version on disk. */
  let disk = { stamp: undefined, entries: /** @type {Entry[]} */ ([]), error: /** @type {string | null} */ (null) }
  /** Shadow mode's changes, by identity key. */
  const overlay = new Map()

  function refresh() {
    let st
    try {
      st = fs.statSync(file)
    } catch (error) {
      const code = error?.code
      disk = code === 'ENOENT' || code === 'ENOTDIR'
        ? { stamp: 'missing', entries: [], error: null }
        : { stamp: undefined, entries: [], error: `读不了放行清单（${code ?? '未知原因'}）` }
      return
    }
    const stamp = `${st.mtimeMs}:${st.size}:${st.ino}`
    if (stamp === disk.stamp) return
    try {
      disk = { stamp, entries: parseAllowlist(fs.readFileSync(file, 'utf8')), error: null }
    } catch (error) {
      disk = { stamp, entries: [], error: `放行清单格式不对：${error instanceof Error ? error.message : String(error)}` }
    }
  }

  const sameIdentity = (a, b) => a.tool === b.tool && a.command === b.command
    && pathKey(a.workspace) === pathKey(b.workspace) && pathKey(a.workdir) === pathKey(b.workdir)

  /** The same files with the same content (or the same absence), in any order. */
  function sameDependencies(a, b) {
    if (a.length !== b.length) return false
    const index = new Map(a.map(d => [pathKey(d.path), d.sha256]))
    return index.size === a.length && b.every(d => index.has(pathKey(d.path)) && index.get(pathKey(d.path)) === d.sha256)
  }

  /** The entry for a fingerprint's identity: a blocked entry in the file first, then a shadow change, then the file. */
  function find(fp) {
    const onDisk = disk.entries.find(e => sameIdentity(e, fp))
    if (onDisk?.status === 'blocked') return onDisk
    const shadowed = overlay.get(fp.key)
    if (shadowed !== undefined && sameIdentity(shadowed, fp)) return shadowed
    return onDisk
  }

  /**
   * Look a command up.
   * @param {import('./fingerprint.js').Fingerprint} fp
   * @returns {Lookup}
   */
  function lookup(fp) {
    if (fp === null || typeof fp !== 'object' || typeof fp.key !== 'string') return { status: 'miss' }
    refresh()
    if (disk.error !== null) return { status: 'error', message: disk.error }
    const entry = find(fp)
    if (entry === undefined) return { status: 'miss' }
    // Blocked wins over everything, even when the command or its files changed since.
    if (entry.status === 'blocked') return { status: 'blocked', entry }
    if (!fp.eligible) return { status: 'ineligible', entry }
    if (!sameDependencies(entry.dependsOn, fp.dependsOn)) return { status: 'stale', entry }
    return { status: 'hit', entry }
  }

  /** Keep at most maxEntries: the least recently used active entries go first, blocked ones stay. */
  function capped(entries) {
    if (entries.length <= maxEntries) return entries
    const used = e => e.lastUsedAt ?? e.addedAt ?? ''
    const drop = new Set(entries.filter(e => e.status === 'active').sort((a, b) => used(a).localeCompare(used(b))).slice(0, entries.length - maxEntries))
    return entries.filter(e => !drop.has(e))
  }

  function newId(taken) {
    for (;;) {
      const id = randomBytes(4).readUInt32BE(0).toString(36).padStart(6, '0').slice(-6)
      if (!taken.has(id)) return id
    }
  }

  /** Write the file atomically (temporary file, then rename), as state.json is written. */
  function save(entries) {
    fs.mkdirSync(path.dirname(file), { recursive: true })
    const tmp = `${file}.tmp-${process.pid}`
    try {
      fs.writeFileSync(tmp, `${JSON.stringify({ version: VERSION, entries }, null, 2)}\n`, 'utf8')
      fs.renameSync(tmp, file)
    } catch (error) {
      try { fs.rmSync(tmp, { force: true }) } catch { /* ignore */ }
      throw error
    }
    disk = { stamp: undefined, entries, error: null }
  }

  /**
   * Replace the entry with this identity (or add it).
   * @param {string} key
   * @param {(current: Entry | undefined, taken: Set<string>) => Entry | null} change - null leaves things as they are.
   * @returns {Entry | null} the stored entry, or null when nothing changed.
   */
  function update(key, identity, change) {
    refresh()
    if (shadow) {
      const onDisk = disk.entries.find(e => sameIdentity(e, identity))
      const current = onDisk?.status === 'blocked' ? onDisk : (overlay.get(key) ?? onDisk)
      const next = change(current, new Set([...disk.entries, ...overlay.values()].map(e => e.id)))
      if (next === null) return null
      overlay.set(key, next)
      if (overlay.size > maxEntries) {
        const kept = new Set(capped([...overlay.values()]))
        for (const [k, e] of overlay) if (!kept.has(e)) overlay.delete(k)
      }
      return next
    }
    if (disk.error !== null) throw new Error(disk.error)
    const current = disk.entries.find(e => sameIdentity(e, identity))
    const next = change(current, new Set(disk.entries.map(e => e.id)))
    if (next === null) return null
    save(capped([...disk.entries.filter(e => e !== current), next]))
    return next
  }

  const identityOf = fp => ({ tool: fp.tool, workspace: fp.workspace, workdir: fp.workdir, command: fp.command })

  return {
    shadow,
    file,
    lookup,
    /**
     * Add (or refresh) an active entry for an eligible command. A blocked entry is never turned back on here.
     * @param {import('./fingerprint.js').Fingerprint} fp
     * @param {{ explanation?: string, model?: string }} [meta]
     * @returns {Entry | null} the new entry, or null when nothing was added.
     */
    add(fp, meta = {}) {
      if (!fp?.eligible || typeof fp.key !== 'string') return null
      return update(fp.key, identityOf(fp), (current, taken) => (current?.status === 'blocked' ? null : {
        id: current?.id ?? newId(taken),
        status: 'active',
        ...identityOf(fp),
        dependsOn: fp.dependsOn.map(d => ({ path: d.path, sha256: d.sha256 })),
        ...(typeof meta.explanation === 'string' ? { explanation: meta.explanation.slice(0, 600) } : {}),
        ...(typeof meta.model === 'string' ? { model: meta.model } : {}),
        addedAt: now().toISOString(),
        hits: 0,
        lastUsedAt: null,
      }))
    },
    /**
     * Mark a command "always ask me", with the reasons.
     * @param {import('./fingerprint.js').Fingerprint} fp
     * @param {string[]} reasons
     * @returns {Entry | null}
     */
    block(fp, reasons) {
      if (typeof fp?.key !== 'string') return null
      return update(fp.key, identityOf(fp), (current, taken) => ({
        ...(current ?? { id: newId(taken), ...identityOf(fp), dependsOn: [], addedAt: now().toISOString(), hits: 0, lastUsedAt: null }),
        status: 'blocked',
        blockedAt: now().toISOString(),
        blockedBecause: reasons.slice(0, 10),
      }))
    },
    /**
     * Count a clean use of an active entry.
     * @param {import('./fingerprint.js').Fingerprint} fp
     * @returns {Entry | null}
     */
    touch(fp) {
      if (typeof fp?.key !== 'string') return null
      return update(fp.key, identityOf(fp), current => (current?.status === 'active'
        ? { ...current, hits: (current.hits ?? 0) + 1, lastUsedAt: now().toISOString() }
        : null))
    },
    /** Counts for the startup log. */
    stats() {
      refresh()
      return { file, shadow, onDisk: disk.entries.length, inMemory: overlay.size, ...(disk.error !== null ? { error: disk.error } : {}) }
    },
  }
}

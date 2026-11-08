/**
 * Snapshots taken right before the plugin itself lets an escalated call run (auto mode,
 * docs/design.zh.md §2 事后检查 5 and §16): the content of every existing file outside the workspace the
 * call is known to change — so the change can be looked at and undone later — and a shallow listing of
 * the outside directories it names (names, sizes and modification times, never content), listed again
 * once the call has finished to see what it added, changed or deleted there.
 *
 * Limits (dsh-edit-approval's and design D3's): text files only, at most 256 KB each and 5 per call; a
 * bigger or binary file is recorded without its content and marked not diffable. At most 5 directories,
 * 2 levels deep, 2000 entries in all. Records live in `snapshots/<request id>.json` in the plugin's data
 * directory; the oldest go beyond 300 records or 100 MB.
 */

import { createHash } from 'node:crypto'
import fs from 'node:fs'
import path from 'node:path'
import { classify, workspaceOf } from '../rules/classify.js'

export const LIMITS = Object.freeze({
  fileBytes: 256 * 1024,
  files: 5,
  dirs: 5,
  depth: 2,
  entries: 2000,
  keep: 300,
  totalBytes: 100 * 1024 * 1024,
})

const VERSION = 1
const RECORD = /^[0-9a-f-]{8,64}\.json$/
// fatal: invalid UTF-8 counts as binary; ignoreBOM: a byte-order mark stays in the content, so it can be restored exactly.
const UTF8 = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true })

/**
 * @typedef {object} FileSnapshot
 * @property {string} path
 * @property {boolean} existed
 * @property {'file' | 'dir' | 'link' | 'other'} [type]
 * @property {number} [size]
 * @property {number} [mtimeMs]
 * @property {string} [sha256] - of the bytes on disk.
 * @property {string} [content] - the text, when diffable.
 * @property {boolean} diffable - whether the content was kept (a missing file is diffable: undo deletes it).
 * @property {'too-large' | 'binary' | 'not-a-file' | 'unreadable'} [reason]
 */

/**
 * @typedef {object} DirListing
 * @property {string} path
 * @property {boolean} exists
 * @property {{ rel: string, type: 'file' | 'dir' | 'link' | 'other', size: number, mtimeMs: number }[]} entries - `rel` uses `/`.
 * @property {string[]} complete - directories (`''` is the listed one) whose every entry is in `entries`.
 */

/**
 * The state of one file before the call changes it.
 * @param {string} file
 * @param {{ fileBytes: number }} [limits]
 * @returns {FileSnapshot}
 */
export function captureFile(file, limits = LIMITS) {
  let st
  try {
    st = fs.lstatSync(file)
  } catch (error) {
    const code = error?.code
    return code === 'ENOENT' || code === 'ENOTDIR'
      ? { path: file, existed: false, diffable: true }
      : { path: file, existed: true, diffable: false, reason: 'unreadable' }
  }
  const base = { path: file, existed: true, type: typeOf(st), size: st.size, mtimeMs: st.mtimeMs }
  if (!st.isFile()) return { ...base, diffable: false, reason: 'not-a-file' }
  if (st.size > limits.fileBytes) return { ...base, diffable: false, reason: 'too-large' }
  let bytes
  try {
    bytes = fs.readFileSync(file)
  } catch {
    return { ...base, diffable: false, reason: 'unreadable' }
  }
  const sha256 = createHash('sha256').update(bytes).digest('hex')
  // The file may have grown since lstat.
  if (bytes.length > limits.fileBytes) return { ...base, size: bytes.length, sha256, diffable: false, reason: 'too-large' }
  if (bytes.includes(0)) return { ...base, sha256, diffable: false, reason: 'binary' }
  let content
  try {
    content = UTF8.decode(bytes)
  } catch {
    return { ...base, sha256, diffable: false, reason: 'binary' }
  }
  return { ...base, size: bytes.length, sha256, content, diffable: true }
}

/** @param {fs.Stats | fs.Dirent} st */
function typeOf(st) {
  if (st.isSymbolicLink()) return 'link'
  if (st.isDirectory()) return 'dir'
  if (st.isFile()) return 'file'
  return 'other'
}

/**
 * List directories shallowly (sorted, links not followed), sharing one entry budget.
 * @param {string[]} dirs
 * @param {{ depth: number, entries: number }} [limits]
 * @returns {DirListing[]}
 */
export function listDirs(dirs, limits = LIMITS) {
  let budget = limits.entries
  return dirs.map((dir) => {
    const listing = { path: dir, exists: false, entries: [], complete: [] }
    try {
      if (!fs.statSync(dir).isDirectory()) return listing
    } catch {
      return listing
    }
    listing.exists = true
    const walk = (abs, rel, level) => {
      let names
      try {
        names = fs.readdirSync(abs).sort()
      } catch {
        return
      }
      const subdirs = []
      let complete = true
      for (const name of names) {
        if (budget <= 0) { complete = false; break }
        const childRel = rel === '' ? name : `${rel}/${name}`
        let st
        try {
          st = fs.lstatSync(path.join(abs, name))
        } catch {
          continue
        }
        budget -= 1
        const type = typeOf(st)
        listing.entries.push({ rel: childRel, type, size: type === 'file' ? st.size : 0, mtimeMs: st.mtimeMs })
        if (type === 'dir' && level < limits.depth) subdirs.push([path.join(abs, name), childRel])
      }
      if (complete) listing.complete.push(rel)
      for (const [childAbs, childRel] of subdirs) walk(childAbs, childRel, level + 1)
    }
    walk(dir, '', 1)
    return listing
  })
}

/**
 * What changed between two listings of the same directories. Only what both listings cover counts:
 * an entry is deleted when its directory was read in full afterwards (or is itself gone) and the entry
 * is not there; one found afterwards is added when its directory was read in full before. Anything else
 * makes the comparison partial.
 * @param {DirListing[]} before
 * @param {DirListing[]} after
 * @returns {{ added: number, modified: number, deleted: number, deletedSample: string[], partial: boolean }}
 */
export function compareListings(before, after) {
  const out = { added: 0, modified: 0, deleted: 0, deletedSample: [], partial: false }
  for (const was of before) {
    const now = after.find(a => a.path === was.path)
    if (!was.exists) {
      if (now?.exists) {
        out.added += now.entries.length
        if (!now.complete.includes('')) out.partial = true
      }
      continue
    }
    const nowEntries = new Map((now?.exists ? now.entries : []).map(e => [e.rel, e]))
    const nowComplete = new Set(now?.exists ? now.complete : [])
    const wasEntries = new Map(was.entries.map(e => [e.rel, e]))
    const wasComplete = new Set(was.complete)
    const gone = new Set()
    const parentOf = rel => (rel.includes('/') ? rel.slice(0, rel.lastIndexOf('/')) : '')
    const deleted = (rel) => {
      out.deleted += 1
      if (out.deletedSample.length < 20) out.deletedSample.push(path.join(was.path, ...rel.split('/')))
    }
    // Sorted listings put each directory before what it holds, so a deleted parent is known first.
    for (const entry of [...was.entries].sort((a, b) => a.rel.localeCompare(b.rel))) {
      const parent = parentOf(entry.rel)
      const current = nowEntries.get(entry.rel)
      if (current !== undefined) {
        if (entry.type === 'file' && (current.size !== entry.size || current.mtimeMs !== entry.mtimeMs || current.type !== entry.type)) out.modified += 1
        continue
      }
      if (!now?.exists || gone.has(parent) || nowComplete.has(parent)) {
        deleted(entry.rel)
        if (entry.type === 'dir') gone.add(entry.rel)
      } else {
        out.partial = true
      }
    }
    for (const entry of nowEntries.values()) {
      if (wasEntries.has(entry.rel)) continue
      if (wasComplete.has(parentOf(entry.rel))) out.added += 1
      else out.partial = true
    }
  }
  return out
}

/**
 * Decide what to snapshot for one call and capture it.
 * @param {object} input
 * @param {'pwsh' | 'bash' | 'write' | 'edit'} input.tool
 * @param {any} input.facts - the hard rules' facts for the call.
 * @param {ReturnType<import('../host.js').createHost>} input.host
 * @param {string | undefined} input.workspaceRoot
 * @param {typeof LIMITS} [input.limits]
 * @returns {{ files: FileSnapshot[], dirs: DirListing[], skipped: { path: string, reason: string }[] }}
 */
export function capture({ tool, facts, host, workspaceRoot, limits = LIMITS }) {
  const ws = workspaceOf(host, workspaceRoot)
  const files = []
  const skipped = []
  const seen = new Set()
  const takeFile = (p) => {
    if (typeof p !== 'string' || p === '') return
    const key = host.tools.key(p)
    if (seen.has(key)) return
    seen.add(key)
    const cls = classify(p, host, ws)
    // Such paths always reach the user before any allow; never copy their content anyway.
    if (cls.protected || cls.sensitive) { skipped.push({ path: p, reason: 'protected' }); return }
    if (files.length >= limits.files) { skipped.push({ path: p, reason: 'over-file-limit' }); return }
    files.push(captureFile(p, limits))
  }
  if (tool === 'write' || tool === 'edit') {
    takeFile(facts?.target)
    return { files, dirs: [], skipped }
  }
  for (const w of facts?.writes ?? []) if (w?.outside && w.exists) takeFile(w.path)
  for (const d of facts?.deletes ?? []) if (d?.outside) takeFile(d.path)
  for (const m of facts?.moves ?? []) if (m?.outside) takeFile(m.path)

  // The outside directories the command names (a named file stands for its directory).
  const dirs = []
  const dirKeys = new Set()
  for (const p of facts?.outsidePaths ?? []) {
    if (typeof p !== 'string') continue
    let dir = p
    try {
      if (!fs.statSync(p).isDirectory()) dir = host.tools.P.dirname(p)
    } catch {
      dir = host.tools.P.dirname(p)
    }
    const key = host.tools.key(dir)
    if (dirKeys.has(key)) continue
    dirKeys.add(key)
    const cls = classify(dir, host, ws)
    // Too wide to list (roots, home, system), the agent's own areas (workspace, temp), or dsh's and secrets.
    if (cls.isRoot || cls.isHome || cls.isUsersRoot || cls.systemRoot || cls.system || cls.protected || cls.sensitive || cls.agentWritable) continue
    if (dirs.length >= limits.dirs) { skipped.push({ path: dir, reason: 'over-dir-limit' }); continue }
    dirs.push(dir)
  }
  return { files, dirs: listDirs(dirs, limits), skipped }
}

/**
 * The snapshot store.
 * @param {object} options
 * @param {string} options.dir - the snapshots directory.
 * @param {typeof LIMITS} [options.limits]
 */
export function createSnapshots({ dir, limits = LIMITS }) {
  /** Drop the oldest records beyond the count or size limit. */
  function prune() {
    let records
    try {
      records = fs.readdirSync(dir).filter(n => RECORD.test(n)).map((name) => {
        const st = fs.statSync(path.join(dir, name))
        return { name, mtimeMs: st.mtimeMs, size: st.size }
      }).sort((a, b) => b.mtimeMs - a.mtimeMs)
    } catch {
      return
    }
    let total = 0
    records.forEach((r, i) => {
      total += r.size
      if (i >= limits.keep || total > limits.totalBytes) {
        try { fs.rmSync(path.join(dir, r.name), { force: true }) } catch { /* ignore */ }
      }
    })
  }

  return {
    dir,
    /**
     * Write one record atomically; throws when it cannot be written.
     * @param {object} record - with `id`.
     * @returns {{ file: string, bytes: number }}
     */
    save(record) {
      if (typeof record?.id !== 'string' || !RECORD.test(`${record.id}.json`)) throw new Error('快照编号不对')
      fs.mkdirSync(dir, { recursive: true })
      const file = path.join(dir, `${record.id}.json`)
      const text = `${JSON.stringify({ version: VERSION, ...record })}\n`
      const tmp = `${file}.tmp-${process.pid}`
      try {
        fs.writeFileSync(tmp, text, 'utf8')
        fs.renameSync(tmp, file)
      } catch (error) {
        try { fs.rmSync(tmp, { force: true }) } catch { /* ignore */ }
        throw error
      }
      prune()
      return { file, bytes: Buffer.byteLength(text) }
    },
    /**
     * Read one record back; undefined when it is missing or unreadable.
     * @param {string} id
     */
    load(id) {
      if (typeof id !== 'string' || !RECORD.test(`${id}.json`)) return undefined
      try {
        return JSON.parse(fs.readFileSync(path.join(dir, `${id}.json`), 'utf8'))
      } catch {
        return undefined
      }
    },
    prune,
  }
}

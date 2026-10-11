/**
 * Platform-aware path helpers. Every comparison goes through a "key": the
 * absolute path in the canonical spelling the platform itself would use, so
 * that case, separator style, `..` segments, `\\?\` prefixes, trailing dots or
 * spaces and alternate data streams cannot make one location look like two.
 * File-system access is injected (`probe`) so the rules stay testable without
 * touching the disk.
 */

import nodePath from 'node:path'

/**
 * @typedef {object} PathProbe
 * @property {(path: string) => string | undefined} realpath - canonical path of an existing entry, else undefined.
 * @property {(path: string) => boolean} [exists] - whether the entry exists.
 */

/** A probe that knows nothing about the disk (pure tests, or when every lookup fails). */
export const NULL_PROBE = Object.freeze({ realpath: () => undefined, exists: () => false })

/**
 * Build the path helpers for one platform.
 * @param {object} options
 * @param {'win32' | string} options.platform
 * @param {string} options.home - the user's home directory.
 * @param {Record<string, string | undefined>} [options.env] - environment for %VAR% / $env: expansion.
 * @param {PathProbe} [options.probe]
 */
export function createPathTools({ platform, home, env = {}, probe = NULL_PROBE }) {
  const win = platform === 'win32'
  // Windows and default macOS volumes compare names case-insensitively.
  const foldCase = win || platform === 'darwin'
  const P = win ? nodePath.win32 : nodePath.posix
  const sep = win ? '\\' : '/'
  const envIndex = new Map()
  for (const [name, value] of Object.entries(env)) {
    if (typeof value === 'string') envIndex.set(win ? name.toLowerCase() : name, value)
  }

  /**
   * Environment lookup with the platform's case rules.
   * @param {string} name
   * @returns {string | undefined}
   */
  function envGet(name) {
    return envIndex.get(win ? name.toLowerCase() : name)
  }

  /**
   * Strip spellings that address the same file through another syntax.
   * @param {string} raw
   * @returns {{ path: string, kind: 'file' | 'device' | 'unc' | 'registry' | 'provider' | 'empty' }}
   */
  function clean(raw) {
    let p = String(raw).trim()
    if (p === '') return { path: '', kind: 'empty' }
    if (win) {
      p = p.replace(/\//g, '\\')
      p = p.replace(/^(?:microsoft\.powershell\.core\\)?filesystem::/i, '')
      if (/^(?:microsoft\.powershell\.core\\)?registry::/i.test(p) || /^(?:hkcu|hklm|hkcr|hku|hkcc):/i.test(p) || /^hkey_/i.test(p)) {
        return { path: p, kind: 'registry' }
      }
      if (/^(?:env|function|variable|alias|cert|wsman):/i.test(p)) return { path: p, kind: 'provider' }
      if (/^\\\\\?\\unc\\/i.test(p)) p = `\\\\${p.slice(8)}`
      else if (/^\\\\\?\\/.test(p) || /^\\\?\?\\/.test(p)) p = p.slice(4)
      if (/^\\\\\.\\/.test(p)) return { path: p, kind: 'device' }
      if (/^\\\\[^\\]/.test(p)) return { path: p, kind: 'unc' }
    }
    return { path: p, kind: 'file' }
  }

  /**
   * Expand a leading `~` to the home directory.
   * @param {string} p
   */
  function expandTilde(p) {
    if (p === '~') return home
    if (p.startsWith('~/') || (win && p.startsWith('~\\'))) return home + sep + p.slice(2)
    return p
  }

  /**
   * Absolute path of `p` resolved against `base`, or undefined when that is unknowable.
   * Drive-relative Windows forms (`C:foo`) are read as `C:\foo`, the conservative guess.
   * @param {string} p - a cleaned, file-kind path.
   * @param {string | undefined} base - directory relative paths resolve against.
   * @returns {string | undefined}
   */
  function absolute(p, base) {
    if (win) {
      if (/^[a-z]:\\/i.test(p) || /^\\\\[^\\]/.test(p)) return P.resolve(p)
      if (/^[a-z]:/i.test(p)) return P.resolve(`${p.slice(0, 2)}\\${p.slice(2)}`)
      if (p.startsWith('\\')) {
        const drive = base !== undefined && /^[a-z]:/i.test(base) ? base.slice(0, 2) : (envGet('SystemDrive') ?? 'C:')
        return P.resolve(`${drive}${p}`)
      }
    } else if (p.startsWith('/')) {
      return P.resolve(p)
    }
    if (base === undefined) return undefined
    return P.resolve(base, p)
  }

  /**
   * Canonical comparison key of an absolute path.
   * @param {string} abs
   * @returns {string}
   */
  function key(abs) {
    if (!win) {
      let n = P.normalize(abs)
      if (n.length > 1 && n.endsWith('/')) n = n.slice(0, -1)
      return foldCase ? n.toLowerCase() : n
    }
    let n = P.normalize(abs.replace(/\//g, '\\'))
    const unc = n.startsWith('\\\\')
    const parts = n.split('\\')
    const out = []
    for (let i = 0; i < parts.length; i += 1) {
      let seg = parts[i]
      if (i === 0 && /^[a-z]:$/i.test(seg)) { out.push(seg.toLowerCase()); continue }
      // Alternate data streams: "file.txt:stream:$DATA" names file.txt.
      const colon = seg.indexOf(':')
      if (colon > 0) seg = seg.slice(0, colon)
      // Win32 trims trailing dots and spaces from a name; trim every segment (conservative).
      if (seg !== '.' && seg !== '..') seg = seg.replace(/[. ]+$/, '')
      out.push(seg.toLowerCase())
    }
    n = out.join('\\')
    if (unc && !n.startsWith('\\\\')) n = `\\\\${n.replace(/^\\+/, '')}`
    if (/^[a-z]:$/.test(n)) n += '\\'
    if (n.length > 3 && n.endsWith('\\')) n = n.slice(0, -1)
    return n
  }

  /**
   * Whether `child` is `parent` or inside it (both keys).
   * @param {string} childKey
   * @param {string} parentKey
   */
  function isUnderKey(childKey, parentKey) {
    if (childKey === parentKey) return true
    const prefix = parentKey.endsWith(sep) ? parentKey : parentKey + sep
    return childKey.startsWith(prefix)
  }

  /**
   * Real path of an absolute path: the deepest existing ancestor resolved
   * through links (junctions, symlinks, 8.3 names), plus the missing tail.
   * @param {string} abs
   * @returns {string}
   */
  function real(abs) {
    const missing = []
    let current = abs
    for (let guard = 0; guard < 256; guard += 1) {
      let resolved
      try {
        resolved = probe.realpath(current)
      } catch {
        resolved = undefined
      }
      if (resolved !== undefined) {
        return missing.length === 0 ? resolved : P.join(resolved, ...missing.reverse())
      }
      const parent = P.dirname(current)
      if (parent === current) break
      missing.push(P.basename(current))
      current = parent
    }
    return abs
  }

  /**
   * Whether a key names a filesystem root (drive root, `/`, or a UNC share root).
   * @param {string} k
   */
  function isRootKey(k) {
    if (!win) return k === '/'
    if (/^[a-z]:\\$/.test(k)) return true
    return /^\\\\[^\\]+\\[^\\]+$/.test(k) || /^\\\\[^\\]+$/.test(k)
  }

  /**
   * Whether a path text contains wildcard characters (PowerShell `*`, `?`, `[...]`).
   * @param {string} p
   */
  function hasWildcard(p) {
    return /[*?[\]]/.test(p)
  }

  /**
   * Longest ancestor of a wildcard path that contains no wildcard.
   * @param {string} abs
   */
  function wildcardBase(abs) {
    const parts = abs.split(win ? /[\\/]/ : /\//)
    const kept = []
    for (const part of parts) {
      if (/[*?[\]]/.test(part)) break
      kept.push(part)
    }
    if (kept.length === 0) return undefined
    const joined = kept.join(sep)
    if (win && /^[a-z]:$/i.test(joined)) return `${joined}\\`
    return joined === '' ? sep : joined
  }

  return { win, P, sep, envGet, clean, expandTilde, absolute, key, isUnderKey, real, isRootKey, hasWildcard, wildcardBase, home }
}

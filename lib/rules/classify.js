/**
 * Classify one absolute path against the host and the session workspace.
 * Both the spelled path and its real path (links resolved) are checked:
 * a path counts as protected or sensitive if either spelling is, and as
 * inside the workspace only if both spellings are.
 */

/** Basenames that hold credentials or keys when they live outside the workspace. */
const CREDENTIAL_FILES = new Set(['.npmrc', '.yarnrc', '.yarnrc.yml', '.pypirc', '.netrc', '_netrc', '.git-credentials', '.gitconfig', '.vault-token', '.credentials.yaml'])
const KEY_FILE = /^(id_(rsa|dsa|ecdsa|ed25519)(_sk)?(\.pub)?|.*\.(pem|key|pfx|p12|kdbx|jks|keystore|ppk))$/i
const ENV_FILE = /^\.env(\..*)?$/i
const SHELL_RC = new Set(['.bashrc', '.bash_profile', '.bash_login', '.bash_logout', '.profile', '.zshrc', '.zprofile', '.zshenv', '.zlogin', '.zlogout', 'config.fish'])

/**
 * @typedef {object} Workspace
 * @property {string[]} keys - comparison keys of the workspace root (spelled and real).
 */

/**
 * Build the workspace descriptor for a session.
 * @param {ReturnType<import('../host.js').createHost>} host
 * @param {string | undefined} root
 * @returns {Workspace | undefined}
 */
export function workspaceOf(host, root) {
  if (typeof root !== 'string' || root.trim() === '') return undefined
  const { tools } = host
  const abs = tools.absolute(tools.clean(root).path, undefined)
  if (abs === undefined) return undefined
  return { root: abs, keys: [...new Set([tools.key(abs), tools.key(tools.real(abs))])] }
}

/**
 * Classify an absolute file-system path.
 * @param {string} abs
 * @param {ReturnType<import('../host.js').createHost>} host
 * @param {Workspace | undefined} ws
 */
export function classify(abs, host, ws) {
  const { tools } = host
  const lexKey = tools.key(abs)
  const realKey = tools.key(tools.real(abs))
  const keys = lexKey === realKey ? [lexKey] : [lexKey, realKey]
  const under = (k, root) => tools.isUnderKey(k, root)
  const anyUnder = entry => keys.some(k => under(k, entry.key) || under(k, entry.realKey))
  const anyEqual = entryKeys => keys.some(k => entryKeys.includes(k))

  const inWorkspace = ws !== undefined && keys.every(k => ws.keys.some(w => under(k, w)))
  const inTemp = keys.every(k => host.tempDirs.some(t => under(k, t.key) || under(k, t.realKey)))
  const prot = host.protectedDirs.find(anyUnder)
  const systemExact = host.systemDirs.find(d => keys.some(k => k === d.key || k === d.realKey))
  const systemUnder = host.systemDirs.find(anyUnder)
  // A carved-out dsh area counts only when every spelling lies inside it, so a link cannot borrow it.
  const area = (host.dshAreas ?? []).find(entry => keys.every(k => under(k, entry.key) || under(k, entry.realKey)))?.area ?? null

  let sensitive = area === 'user' ? 'agent-instructions' : (host.sensitiveDirs.find(anyUnder)?.kind ?? null)
  if (sensitive === null && !inWorkspace) {
    const base = tools.P.basename(abs)
    const lowerBase = base.toLowerCase()
    const parent = tools.P.basename(tools.P.dirname(abs)).toLowerCase()
    if (CREDENTIAL_FILES.has(lowerBase) || ENV_FILE.test(base)) sensitive = 'credentials'
    else if (KEY_FILE.test(base)) sensitive = 'key-file'
    else if (SHELL_RC.has(lowerBase)) sensitive = 'shell-profile'
    else if (/profile\.ps1$/i.test(base) && (parent === 'windowspowershell' || parent === 'powershell' || parent === 'v1.0')) sensitive = 'shell-profile'
  }

  return {
    abs,
    lexKey,
    realKey,
    protected: prot?.label ?? null,
    /** 'runtime' | 'tool' | 'user': a part of dsh's areas that dsh itself directs the agent to use. */
    dshArea: prot ? area : null,
    isRoot: keys.some(k => tools.isRootKey(k)),
    isHome: anyEqual(host.homeKeys),
    isUsersRoot: anyEqual(host.usersRootKeys),
    systemRoot: systemExact?.label ?? null,
    system: systemUnder?.label ?? null,
    sensitive,
    inWorkspace,
    inTemp,
    outside: !inWorkspace,
    agentWritable: inWorkspace || inTemp,
  }
}

/**
 * Whether a session workspace overlaps a protected location (contains it or lies inside it).
 * @param {ReturnType<import('../host.js').createHost>} host
 * @param {Workspace | undefined} ws
 * @returns {string | null} the label of the overlapped location, or null.
 */
export function workspaceContamination(host, ws) {
  if (ws === undefined) return null
  const { tools } = host
  for (const entry of host.protectedDirs) {
    for (const w of ws.keys) {
      for (const p of [entry.key, entry.realKey]) {
        if (tools.isUnderKey(p, w) || tools.isUnderKey(w, p)) return entry.label
      }
    }
  }
  for (const w of ws.keys) {
    if (host.homeKeys.some(h => tools.isUnderKey(h, w))) return '用户主目录'
    if (tools.isRootKey(w)) return '磁盘根目录'
  }
  return null
}

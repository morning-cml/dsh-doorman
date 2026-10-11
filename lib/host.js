/**
 * Facts about the machine the plugin protects: where dsh and the plugin live,
 * which directories are system areas, which hold credentials or start-up
 * entries, and where temporary files go. Built once from plain inputs so the
 * rules can be tested with any imaginary machine.
 */

import { createPathTools } from './paths.js'

/**
 * @typedef {object} HostInput
 * @property {string} platform - process.platform.
 * @property {string} home - the user's home directory.
 * @property {Record<string, string | undefined>} env - environment of the Host process.
 * @property {string} dshHome - dsh's home directory (normally ~/.dsh).
 * @property {string} [dataDir] - this plugin's data directory.
 * @property {string} [installDir] - the directory this plugin's code runs from.
 * @property {string} [execPath] - the Host executable (the desktop app on Desktop).
 * @property {string[]} [tempDirs] - temporary directories (os.tmpdir() and friends).
 * @property {import('./paths.js').PathProbe} [probe]
 */

/**
 * Build the host context used by every rule.
 * @param {HostInput} input
 */
export function createHost(input) {
  const { platform, home, env = {}, dshHome, probe } = input
  const tools = createPathTools({ platform, home, env, probe })
  const { P, win } = tools
  const keyOf = p => tools.key(tools.real(p))
  const lexKeyOf = p => tools.key(p)
  const pair = (p, extra) => ({ abs: p, key: lexKeyOf(p), realKey: keyOf(p), ...extra })

  const appData = tools.envGet('APPDATA') ?? P.join(home, 'AppData', 'Roaming')
  const localAppData = tools.envGet('LOCALAPPDATA') ?? P.join(home, 'AppData', 'Local')
  const programData = tools.envGet('ProgramData') ?? 'C:\\ProgramData'
  const systemRoot = tools.envGet('SystemRoot') ?? tools.envGet('windir') ?? 'C:\\Windows'

  // --- Locations whose modification would change dsh or this plugin ------------------
  const protectedDirs = [pair(dshHome, { label: 'dsh 主目录' })]
  if (input.dataDir) protectedDirs.push(pair(input.dataDir, { label: '本插件数据目录' }))
  if (input.installDir) protectedDirs.push(pair(input.installDir, { label: '本插件安装位置' }))
  if (win) {
    protectedDirs.push(pair(P.join(localAppData, 'Programs', 'DeepSeek Harness'), { label: 'dsh 桌面端安装目录' }))
    protectedDirs.push(pair(P.join(localAppData, '@deepseek-aidsh-desktop-updater'), { label: 'dsh 更新缓存' }))
    protectedDirs.push(pair(P.join(appData, '@deepseek-ai'), { label: 'dsh 桌面端用户数据' }))
  } else if (platform === 'darwin') {
    protectedDirs.push(pair('/Applications/DeepSeek Harness.app', { label: 'dsh 桌面端安装目录' }))
    protectedDirs.push(pair(P.join(home, 'Library', 'Application Support', '@deepseek-ai'), { label: 'dsh 桌面端用户数据' }))
    protectedDirs.push(pair(P.join(home, 'Library', 'Logs', 'DeepSeek Harness'), { label: 'dsh 桌面端日志' }))
    protectedDirs.push(pair(P.join(home, 'Library', 'Caches', '@deepseek-aidsh-desktop-updater'), { label: 'dsh 更新缓存' }))
  } else {
    protectedDirs.push(pair(P.join(home, '.config', '@deepseek-ai'), { label: 'dsh 桌面端用户数据' }))
    protectedDirs.push(pair(P.join(home, '.cache', '@deepseek-aidsh-desktop-updater'), { label: 'dsh 更新缓存' }))
  }
  if (input.execPath && /deepseek[ -]?harness/i.test(input.execPath)) {
    const appDir = P.dirname(input.execPath)
    protectedDirs.push(pair(platform === 'darwin' ? appDir.replace(/\/Contents\/MacOS$/, '') : appDir, { label: 'dsh 桌面端安装目录' }))
  }

  // --- System areas ---------------------------------------------------------------------
  const systemDirs = []
  if (win) {
    systemDirs.push(pair(systemRoot, { label: 'Windows 系统目录' }))
    for (const name of ['ProgramFiles', 'ProgramFiles(x86)', 'ProgramW6432']) {
      const value = tools.envGet(name)
      if (value) systemDirs.push(pair(value, { label: '程序安装目录' }))
    }
    if (!systemDirs.some(d => d.key === lexKeyOf('C:\\Program Files'))) systemDirs.push(pair('C:\\Program Files', { label: '程序安装目录' }))
    if (!systemDirs.some(d => d.key === lexKeyOf('C:\\Program Files (x86)'))) systemDirs.push(pair('C:\\Program Files (x86)', { label: '程序安装目录' }))
    systemDirs.push(pair(programData, { label: '全局程序数据目录' }))
  } else {
    for (const dir of ['/etc', '/usr', '/bin', '/sbin', '/lib', '/lib32', '/lib64', '/boot', '/System', '/Library', '/private/etc', '/var/root']) {
      systemDirs.push(pair(dir, { label: '系统目录' }))
    }
  }

  // --- Sensitive areas (credentials, keys, start-up, browsers) ---------------------------
  const sensitiveDirs = []
  const add = (kind, ...segments) => sensitiveDirs.push(pair(P.join(...segments), { kind }))
  add('ssh', home, '.ssh')
  for (const dot of ['.aws', '.azure', '.kube', '.docker', '.gnupg', '.password-store', '.terraform.d']) add('credentials', home, dot)
  add('credentials', home, '.config', 'gh')
  add('credentials', home, '.config', 'gcloud')
  add('credentials', home, '.config', 'git')
  add('credentials', home, '.m2', 'settings.xml')
  add('credentials', home, '.gradle', 'gradle.properties')
  add('credentials', home, '.nuget', 'NuGet', 'NuGet.Config')
  add('credentials', home, '.cargo', 'credentials')
  add('credentials', home, '.cargo', 'credentials.toml')
  if (win) {
    add('startup', appData, 'Microsoft', 'Windows', 'Start Menu', 'Programs', 'Startup')
    add('startup', programData, 'Microsoft', 'Windows', 'Start Menu', 'Programs', 'StartUp')
    for (const sub of ['Credentials', 'Protect', 'Crypto', 'SystemCertificates']) add('credentials', appData, 'Microsoft', sub)
    add('credentials', localAppData, 'Microsoft', 'Credentials')
    add('credentials', appData, 'GitHub CLI')
    add('credentials', appData, 'gcloud')
    add('credentials', appData, 'NuGet', 'NuGet.Config')
    add('credentials', appData, 'npm', 'etc')
    add('browser', localAppData, 'Google', 'Chrome', 'User Data')
    add('browser', localAppData, 'Microsoft', 'Edge', 'User Data')
    add('browser', localAppData, 'BraveSoftware')
    add('browser', localAppData, 'Chromium')
    add('browser', localAppData, 'Vivaldi')
    add('browser', appData, 'Mozilla', 'Firefox')
    add('browser', appData, 'Opera Software')
  } else {
    add('startup', home, '.config', 'autostart')
    add('startup', home, '.config', 'systemd')
    add('startup', home, 'Library', 'LaunchAgents')
    add('startup', '/Library/LaunchAgents')
    add('startup', '/Library/LaunchDaemons')
    add('startup', '/etc/cron.d')
    add('startup', '/var/spool/cron')
    add('browser', home, 'Library', 'Application Support', 'Google', 'Chrome')
    add('browser', home, 'Library', 'Application Support', 'Firefox')
    add('browser', home, '.config', 'google-chrome')
    add('browser', home, '.config', 'chromium')
    add('browser', home, '.mozilla')
    add('credentials', home, 'Library', 'Keychains')
  }

  // --- Temporary areas -------------------------------------------------------------------
  const tempCandidates = [...(input.tempDirs ?? [])]
  for (const name of ['TEMP', 'TMP', 'TMPDIR']) {
    const value = tools.envGet(name)
    if (value) tempCandidates.push(value)
  }
  if (!win) tempCandidates.push('/tmp', '/var/tmp')
  const tempDirs = []
  for (const dir of tempCandidates) {
    const entry = pair(dir)
    if (!tempDirs.some(t => t.key === entry.key)) tempDirs.push(entry)
  }

  const homeKey = lexKeyOf(home)
  const homeRealKey = keyOf(home)
  const usersRoot = P.dirname(home)

  /**
   * Whether a path exists; false when the probe cannot tell.
   * @param {string} p
   */
  const exists = (p) => {
    try {
      return Boolean(probe?.exists?.(p))
    } catch {
      return false
    }
  }

  return {
    platform,
    tools,
    exists,
    home,
    homeKeys: [...new Set([homeKey, homeRealKey])],
    usersRootKeys: [...new Set([lexKeyOf(usersRoot), keyOf(usersRoot)])],
    dshHome,
    dataDir: input.dataDir,
    installDir: input.installDir,
    protectedDirs,
    systemDirs,
    sensitiveDirs,
    tempDirs,
    documentsHint: P.join(home, 'Documents'),
  }
}

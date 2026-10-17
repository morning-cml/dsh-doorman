// Shared fixtures: an imaginary Windows machine for user "alice" with a fake file system.
import path from 'node:path'
import { createHost } from '../lib/host.js'

const W = path.win32

/** Existing entries of the fake disk (canonical spelling). */
const EXISTING = [
  'C:\\', 'C:\\Users', 'C:\\Users\\alice', 'C:\\Users\\alice\\proj', 'C:\\Users\\alice\\proj\\build', 'C:\\Users\\alice\\proj\\package.json',
  'C:\\Users\\alice\\proj\\scripts', 'C:\\Users\\alice\\proj\\scripts\\build.ps1',
  'C:\\Users\\alice\\Documents', 'C:\\Users\\alice\\Desktop', 'C:\\Users\\alice\\Desktop\\out', 'C:\\Users\\alice\\Desktop\\out\\old.txt',
  'C:\\Users\\alice\\.dsh', 'C:\\Users\\alice\\.dsh\\.credentials.yaml', 'C:\\Users\\alice\\.dsh\\dsh-doorman', 'C:\\Users\\alice\\.dsh\\dsh-doorman\\allowlist.json',
  'C:\\Users\\alice\\.dsh\\profiles', 'C:\\Users\\alice\\.dsh\\profiles\\desktop', 'C:\\Users\\alice\\.dsh\\profiles\\desktop\\node_modules',
  'C:\\Users\\alice\\.dsh\\profiles\\desktop\\node_modules\\dsh-doorman', 'C:\\Users\\alice\\.ssh', 'C:\\Users\\alice\\.npmrc',
  'C:\\Users\\alice\\AppData', 'C:\\Users\\alice\\AppData\\Local', 'C:\\Users\\alice\\AppData\\Local\\Temp', 'C:\\Users\\alice\\AppData\\Roaming',
  'C:\\Users\\alice\\AppData\\Local\\npm-cache', 'C:\\Users\\alice\\AppData\\Local\\Programs', 'C:\\Users\\alice\\AppData\\Local\\Programs\\DeepSeek Harness',
  'C:\\Users\\alice\\AppData\\Roaming\\@deepseek-ai', 'C:\\Users\\alice\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup',
  'C:\\Windows', 'C:\\Windows\\System32', 'C:\\Program Files', 'C:\\Program Files (x86)', 'C:\\ProgramData', 'D:\\', 'D:\\data',
]

/** Links inside the fake disk: link → target. */
const LINKS = {
  'C:\\Users\\alice\\proj\\link': 'C:\\Users\\alice\\Documents',
  'C:\\Users\\alice\\proj\\dshlink': 'C:\\Users\\alice\\.dsh',
  // A junction inside dsh's runtime folder that leads back into the profiles.
  'C:\\Users\\alice\\.dsh\\dsh-runtimes\\evil': 'C:\\Users\\alice\\.dsh\\profiles',
  'C:\\Users\\ALICE~1': 'C:\\Users\\alice',
}

const index = new Map(EXISTING.map(p => [p.toLowerCase(), p]))

/** Fake realpath with Windows case rules, links and 8.3 aliases. */
function realpath(p) {
  let abs = W.resolve(p)
  for (const [link, target] of Object.entries(LINKS)) {
    const l = link.toLowerCase()
    const a = abs.toLowerCase()
    if (a === l || a.startsWith(`${l}\\`)) abs = target + abs.slice(link.length)
  }
  return index.get(abs.toLowerCase())
}

export const ENV = {
  USERPROFILE: 'C:\\Users\\alice',
  APPDATA: 'C:\\Users\\alice\\AppData\\Roaming',
  LOCALAPPDATA: 'C:\\Users\\alice\\AppData\\Local',
  TEMP: 'C:\\Users\\alice\\AppData\\Local\\Temp',
  TMP: 'C:\\Users\\alice\\AppData\\Local\\Temp',
  SystemRoot: 'C:\\Windows',
  windir: 'C:\\Windows',
  ProgramFiles: 'C:\\Program Files',
  'ProgramFiles(x86)': 'C:\\Program Files (x86)',
  ProgramData: 'C:\\ProgramData',
  SystemDrive: 'C:',
  Path: 'C:\\Windows\\System32',
}

export const WS = 'C:\\Users\\alice\\proj'

export const host = createHost({
  platform: 'win32',
  home: 'C:\\Users\\alice',
  env: ENV,
  dshHome: 'C:\\Users\\alice\\.dsh',
  dataDir: 'C:\\Users\\alice\\.dsh\\dsh-doorman',
  installDir: 'C:\\Users\\alice\\.dsh\\profiles\\desktop\\node_modules\\dsh-doorman',
  execPath: 'C:\\Users\\alice\\AppData\\Local\\Programs\\DeepSeek Harness\\DeepSeek Harness.exe',
  tempDirs: ['C:\\Users\\alice\\AppData\\Local\\Temp'],
  probe: {
    realpath,
    exists: p => realpath(p) !== undefined,
  },
})

/** A POSIX machine for the bash tool. */
export const posixHost = createHost({
  platform: 'linux',
  home: '/home/bob',
  env: { HOME: '/home/bob', TMPDIR: '/tmp' },
  dshHome: '/home/bob/.dsh',
  dataDir: '/home/bob/.dsh/dsh-doorman',
  tempDirs: ['/tmp'],
})

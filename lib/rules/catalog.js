/**
 * Static tables the hard rules consult: PowerShell aliases and parameter
 * metadata (so abbreviations such as `-r`, `-Rec`, `-LP` bind like PowerShell
 * binds them), and the names of commands that belong to a rule category.
 * All names are lower case.
 */

/** PowerShell built-in aliases (Windows PowerShell 5.1 and PowerShell 7) for the commands the rules care about. */
export const PS_ALIASES = Object.freeze({
  rm: 'remove-item', del: 'remove-item', erase: 'remove-item', rd: 'remove-item', ri: 'remove-item', rmdir: 'remove-item',
  mv: 'move-item', move: 'move-item', mi: 'move-item',
  ren: 'rename-item', rni: 'rename-item',
  cp: 'copy-item', copy: 'copy-item', cpi: 'copy-item',
  ac: 'add-content', clc: 'clear-content', cli: 'clear-item', tee: 'tee-object', ni: 'new-item', si: 'set-item',
  md: 'mkdir', epcsv: 'export-csv',
  gci: 'get-childitem', ls: 'get-childitem', dir: 'get-childitem', gi: 'get-item', gc: 'get-content', cat: 'get-content', type: 'get-content',
  iex: 'invoke-expression', icm: 'invoke-command', ii: 'invoke-item', start: 'start-process', saps: 'start-process', sajb: 'start-job',
  iwr: 'invoke-webrequest', irm: 'invoke-restmethod',
  cd: 'set-location', chdir: 'set-location', sl: 'set-location', pushd: 'push-location', popd: 'pop-location',
  kill: 'stop-process', spps: 'stop-process',
  sp: 'set-itemproperty', rp: 'remove-itemproperty',
  sal: 'set-alias', nal: 'new-alias', sv: 'set-variable', set: 'set-variable', nv: 'new-variable',
  '%': 'foreach-object', foreach: 'foreach-object', '?': 'where-object', where: 'where-object',
  echo: 'write-output', write: 'write-output',
})

/** Parameters every cmdlet accepts. */
const COMMON = {
  verbose: { switch: true, aliases: ['vb'] },
  debug: { switch: true, aliases: ['db'] },
  erroraction: { aliases: ['ea'] },
  warningaction: { aliases: ['wa'] },
  informationaction: { aliases: ['infa'] },
  progressaction: { aliases: ['proga'] },
  errorvariable: { aliases: ['ev'] },
  warningvariable: { aliases: ['wv'] },
  informationvariable: { aliases: ['iv'] },
  outvariable: { aliases: ['ov'] },
  outbuffer: { aliases: ['ob'] },
  pipelinevariable: { aliases: ['pv'] },
  whatif: { switch: true, aliases: ['wi'] },
  confirm: { switch: true, aliases: ['cf'] },
}

const PATHS = {
  path: { position: 0 },
  literalpath: { aliases: ['pspath', 'lp'] },
}
const FILTERS = { filter: {}, include: {}, exclude: {}, credential: {} }

/** Parameter metadata of the cmdlets whose arguments the rules inspect. */
export const CMDLETS = Object.freeze({
  'remove-item': { ...PATHS, ...FILTERS, recurse: { switch: true }, force: { switch: true }, stream: {} },
  'move-item': { ...PATHS, ...FILTERS, destination: { position: 1 }, force: { switch: true }, passthru: { switch: true } },
  'copy-item': { ...PATHS, ...FILTERS, destination: { position: 1 }, recurse: { switch: true }, force: { switch: true }, container: { switch: true }, passthru: { switch: true }, fromsession: {}, tosession: {} },
  'rename-item': { ...PATHS, newname: { position: 1 }, force: { switch: true }, passthru: { switch: true }, credential: {} },
  'set-content': { ...PATHS, ...FILTERS, value: { position: 1 }, encoding: {}, force: { switch: true }, nonewline: { switch: true }, passthru: { switch: true }, stream: {}, asbytestream: { switch: true } },
  'add-content': { ...PATHS, ...FILTERS, value: { position: 1 }, encoding: {}, force: { switch: true }, nonewline: { switch: true }, passthru: { switch: true }, stream: {}, asbytestream: { switch: true } },
  'clear-content': { ...PATHS, ...FILTERS, force: { switch: true }, stream: {} },
  'clear-item': { ...PATHS, ...FILTERS, force: { switch: true } },
  'set-item': { ...PATHS, ...FILTERS, value: { position: 1 }, force: { switch: true }, passthru: { switch: true } },
  'out-file': { filepath: { position: 0, aliases: ['path'] }, literalpath: { aliases: ['pspath', 'lp'] }, encoding: { position: 1 }, append: { switch: true }, force: { switch: true }, noclobber: { switch: true, aliases: ['nooverwrite'] }, width: {}, nonewline: { switch: true }, inputobject: {} },
  'tee-object': { filepath: { position: 0, aliases: ['path'] }, literalpath: { aliases: ['pspath', 'lp'] }, append: { switch: true }, variable: {}, inputobject: {}, encoding: {} },
  'new-item': { path: { position: 0 }, name: {}, itemtype: { aliases: ['type'] }, value: { aliases: ['target'] }, force: { switch: true }, credential: {} },
  mkdir: { path: { position: 0 }, name: {}, force: { switch: true } },
  'export-csv': { path: { position: 0 }, literalpath: { aliases: ['pspath', 'lp'] }, inputobject: {}, append: { switch: true }, force: { switch: true }, noclobber: { switch: true }, encoding: {}, delimiter: {}, notypeinformation: { switch: true } },
  'export-clixml': { path: { position: 0 }, literalpath: { aliases: ['pspath', 'lp'] }, inputobject: {}, depth: {}, force: { switch: true }, noclobber: { switch: true }, encoding: {} },
  'expand-archive': { ...PATHS, destinationpath: { position: 1 }, force: { switch: true }, passthru: { switch: true } },
  'compress-archive': { ...PATHS, destinationpath: { position: 1 }, compressionlevel: {}, update: { switch: true }, force: { switch: true }, passthru: { switch: true } },
  'get-childitem': { ...PATHS, filter: { position: 1 }, include: {}, exclude: {}, recurse: { switch: true, aliases: ['s'] }, depth: {}, force: { switch: true }, name: { switch: true }, attributes: {}, directory: { switch: true }, file: { switch: true }, hidden: { switch: true }, followsymlink: { switch: true } },
  'get-item': { ...PATHS, ...FILTERS, force: { switch: true }, stream: {} },
  'get-content': { ...PATHS, ...FILTERS, raw: { switch: true }, encoding: {}, totalcount: { aliases: ['first', 'head'] }, tail: { aliases: ['last'] }, readcount: {}, delimiter: {}, wait: { switch: true }, force: { switch: true }, stream: {}, asbytestream: { switch: true } },
  'resolve-path': { ...PATHS, relative: { switch: true } },
  'set-location': { path: { position: 0 }, literalpath: { aliases: ['pspath', 'lp'] }, passthru: { switch: true }, stackname: {} },
  'push-location': { path: { position: 0 }, literalpath: { aliases: ['pspath', 'lp'] }, passthru: { switch: true }, stackname: {} },
  'start-process': { filepath: { position: 0, aliases: ['path'] }, argumentlist: { position: 1, aliases: ['args'] }, verb: {}, workingdirectory: {}, credential: {}, wait: { switch: true }, nonewwindow: { switch: true }, windowstyle: {}, passthru: { switch: true }, loaduserprofile: { switch: true }, useshellexecute: { switch: true }, redirectstandardoutput: {}, redirectstandarderror: {}, redirectstandardinput: {}, environment: {} },
  'invoke-expression': { command: { position: 0 } },
  'invoke-command': { scriptblock: { position: 0, aliases: ['command'] }, computername: { aliases: ['cn'] }, session: {}, filepath: { aliases: ['path'] }, argumentlist: { aliases: ['args'] }, credential: {}, hostname: {}, vmname: {}, asjob: { switch: true }, noNewScope: { switch: true } },
  'invoke-item': { ...PATHS, ...FILTERS },
  'invoke-webrequest': { uri: { position: 0 }, outfile: {}, method: {}, body: {}, headers: {}, usebasicparsing: { switch: true }, passthru: { switch: true } },
  'invoke-restmethod': { uri: { position: 0 }, outfile: {}, method: {}, body: {}, headers: {}, usebasicparsing: { switch: true }, passthru: { switch: true } },
  'start-bitstransfer': { source: { position: 0 }, destination: { position: 1 } },
  'set-acl': { ...PATHS, aclobject: { position: 1 }, passthru: { switch: true } },
  'set-itemproperty': { ...PATHS, name: { position: 1 }, value: { position: 2 }, type: {}, force: { switch: true }, passthru: { switch: true } },
  'new-itemproperty': { ...PATHS, name: { position: 1 }, value: { position: 2 }, propertytype: { aliases: ['type'] }, force: { switch: true } },
  'remove-itemproperty': { ...PATHS, name: { position: 1 }, force: { switch: true } },
  'stop-process': { id: { position: 0 }, name: { aliases: ['processname'] }, inputobject: {}, force: { switch: true }, passthru: { switch: true } },
  'set-alias': { name: { position: 0 }, value: { position: 1 }, scope: {}, option: {}, force: { switch: true }, passthru: { switch: true }, description: {} },
  'new-alias': { name: { position: 0 }, value: { position: 1 }, scope: {}, option: {}, force: { switch: true }, passthru: { switch: true }, description: {} },
  'set-variable': { name: { position: 0 }, value: { position: 1 }, scope: {}, option: {}, force: { switch: true }, passthru: { switch: true } },
  'new-variable': { name: { position: 0 }, value: { position: 1 }, scope: {}, option: {}, force: { switch: true }, passthru: { switch: true } },
  'start-job': { scriptblock: { position: 0, aliases: ['command'] }, filepath: {}, argumentlist: { aliases: ['args'] } },
  'foreach-object': { process: { position: 0 }, begin: {}, end: {}, membername: {} },
  'where-object': { filterscript: { position: 0 } },
  'join-path': { path: { position: 0 }, childpath: { position: 1 }, additionalchildpath: { position: 2 }, resolve: { switch: true } },
})

/**
 * Parameter index of a cmdlet: every spelling (name or alias) mapped to the canonical name.
 * @param {string} cmdlet
 */
export function paramIndex(cmdlet) {
  const spec = { ...COMMON, ...(CMDLETS[cmdlet] ?? {}) }
  const spellings = new Map()
  for (const [name, def] of Object.entries(spec)) {
    spellings.set(name.toLowerCase(), name.toLowerCase())
    for (const alias of def.aliases ?? []) spellings.set(alias.toLowerCase(), name.toLowerCase())
  }
  return { spec: Object.fromEntries(Object.entries(spec).map(([k, v]) => [k.toLowerCase(), v])), spellings }
}

/** Commands that write, partition or wipe disks. */
export const DISK_TOOLS = new Set([
  'format', 'diskpart', 'format-volume', 'clear-disk', 'initialize-disk', 'remove-partition', 'new-partition',
  'resize-partition', 'set-partition', 'remove-physicaldisk', 'reset-physicaldisk', 'bcdedit', 'bootrec', 'bcdboot',
  'manage-bde', 'mkfs', 'wipefs', 'fdisk', 'sfdisk', 'gdisk', 'parted', 'diskutil',
])

/** Ways to run something with elevated rights. */
export const ELEVATION_TOOLS = new Set(['runas', 'sudo', 'gsudo', 'doas', 'psexec', 'psexec64', 'paexec', 'su', 'pkexec'])

/** Interpreters whose inline-code switches make a command opaque. */
export const INLINE_CODE = Object.freeze({
  python: ['-c'], python3: ['-c'], py: ['-c'], pythonw: ['-c'],
  node: ['-e', '--eval', '-p', '--print'], deno: ['eval'], bun: ['-e', '--eval', '-p', '--print'],
  perl: ['-e', '-E'], ruby: ['-e'], php: ['-r'], lua: ['-e'], osascript: ['-e'],
})

/** Shells whose command-string switch is analysed recursively. */
export const SHELLS = Object.freeze({
  powershell: 'powershell', pwsh: 'powershell', 'powershell_ise': 'powershell',
  cmd: 'cmd',
  bash: 'posix', sh: 'posix', zsh: 'posix', dash: 'posix', ksh: 'posix', wsl: 'posix', 'git-bash': 'posix',
})

/** File extensions that make a file a script or program when run. */
export const RUNNABLE_EXT = /\.(ps1|psm1|bat|cmd|vbs|vbe|js|jse|wsf|wsh|hta|exe|com|scr|msi|msp|py|pyw|sh|bash|zsh|rb|pl|php|jar|lnk|reg)$/i

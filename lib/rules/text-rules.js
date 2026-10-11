/**
 * Keyword rules over the de-obfuscated, lower-cased command text (see
 * normalizeForScan: backticks, carets and string concatenation removed,
 * separators unified to `\`). They back up the structural analysis and catch
 * spellings it cannot follow. Only keywords that are unambiguous in an
 * escalated command are used, because a match stands on its own.
 */

/**
 * @typedef {{ id: string, level: 'deny' | 'ask', all: RegExp[], none?: RegExp[], evidence: string }} TextRule
 */

/** Path-component boundary in normalized text. */
const B = String.raw`(?:^|[\\\s'"=:(,;])`
const E = String.raw`(?=$|[\\\s'"),;.:])`

/** @type {TextRule[]} */
export const TEXT_RULES = [
  // ---- dsh itself and this plugin ----
  { id: 'deny.protected', level: 'deny', all: [new RegExp(`${B}\\.dsh${E}`)], evidence: '.dsh' },
  { id: 'deny.protected', level: 'deny', all: [/dsh-doorman/], evidence: 'dsh-doorman' },
  { id: 'deny.protected', level: 'deny', all: [/\.credentials\.yaml/], evidence: '.credentials.yaml' },
  { id: 'deny.protected', level: 'deny', all: [/dsh_doorman_api_key/], evidence: 'DSH_DOORMAN_API_KEY' },
  { id: 'deny.protected', level: 'deny', all: [/\bdsh_(profile_dir|home)\b/], evidence: 'DSH_PROFILE_DIR / DSH_HOME' },
  { id: 'deny.protected', level: 'deny', all: [/deepseek[ _-]?harness/], evidence: 'DeepSeek Harness' },
  { id: 'deny.protected', level: 'deny', all: [/@deepseek-aidsh-desktop-updater|@deepseek-ai\\dsh-desktop/], evidence: 'dsh desktop data' },
  { id: 'deny.dsh-cli', level: 'deny', all: [/\bdsh(\.cmd|\.exe)?\s+(?:[^|;&]*\s)?plugin\b|--profile\s+desktop\b/], evidence: 'dsh plugin' },

  // ---- disks ----
  { id: 'deny.disk-tool', level: 'deny', all: [/\b(diskpart|format-volume|clear-disk|initialize-disk|remove-partition|new-partition|resize-partition|set-partition|remove-physicaldisk|reset-physicaldisk|bcdedit|bootrec|bcdboot|manage-bde|wipefs|sfdisk|gdisk)\b/], evidence: 'disk tool' },
  { id: 'deny.disk-tool', level: 'deny', all: [/\bmkfs(\.[a-z0-9]+)?\b/], evidence: 'mkfs' },
  { id: 'deny.disk-tool', level: 'deny', all: [/\\\\\.\\(physicaldrive|harddisk|volume\{|[a-z]:)/], evidence: 'raw disk device' },
  { id: 'deny.disk-tool', level: 'deny', all: [/\\dev\\(sd[a-z]|nvme[0-9]|hd[a-z]|disk[0-9]|mmcblk[0-9]|xvd[a-z])/, /\b(dd|of=|cat|cp)\b|>/], evidence: '/dev disk' },
  { id: 'deny.disk-tool', level: 'deny', all: [/\bvssadmin(\.exe)?\s+(delete|resize)\b/], evidence: 'vssadmin delete' },
  { id: 'deny.disk-tool', level: 'deny', all: [/\bwbadmin(\.exe)?\s+delete\b/], evidence: 'wbadmin delete' },
  { id: 'deny.disk-tool', level: 'deny', all: [/\bcipher(\.exe)?\b[^|;&]*\\w\b/], evidence: 'cipher /w' },
  { id: 'deny.disk-tool', level: 'deny', all: [/\bfsutil(\.exe)?\b[^|;&]*\bsetzerodata\b/], evidence: 'fsutil setzerodata' },

  // ---- download and run ----
  { id: 'deny.download-exec', level: 'deny', all: [/\b(iex|invoke-expression)\b/, /(https?:|ftp:|\bnet\.webclient\b|downloadstring|downloaddata|\biwr\b|\birm\b|invoke-webrequest|invoke-restmethod|\bcurl\b|\bwget\b|start-bitstransfer)/], evidence: 'iex + download' },
  { id: 'deny.download-exec', level: 'deny', all: [/(downloadstring|downloadfile|downloaddata|openread)\s*\(/, /\b(iex|invoke-expression|start-process|saps)\b|scriptblock\]::create|\|\s*(powershell|pwsh|cmd|bash|sh)\b/], evidence: 'WebClient + run' },
  { id: 'deny.download-exec', level: 'deny', all: [/\b(curl|wget|iwr|irm|invoke-webrequest|invoke-restmethod)\b[^|;&]*\|\s*(iex|invoke-expression|powershell|pwsh|cmd|bash|sh|zsh|dash|python[0-9.]*|perl|ruby|node)\b/], evidence: 'download | run' },
  { id: 'deny.download-exec', level: 'deny', all: [/\b(ba|z|da)?sh\s+<\(\s*(curl|wget)\b/], evidence: 'sh <(curl …)' },
  { id: 'deny.download-exec', level: 'deny', all: [/\b(ba|z|da)?sh\s+-c\s+["']?\$\(\s*(curl|wget)\b/], evidence: 'sh -c "$(curl …)"' },
  { id: 'deny.download-exec', level: 'deny', all: [/frombase64string/, /\b(iex|invoke-expression|start-process)\b|scriptblock\]::create|-command\b/], evidence: 'base64 + run' },
  { id: 'deny.download-exec', level: 'deny', all: [/\bmshta(\.exe)?\b/], evidence: 'mshta' },
  { id: 'deny.download-exec', level: 'deny', all: [/\brundll32(\.exe)?\b[^|;&]*(javascript|vbscript):/], evidence: 'rundll32 script' },
  { id: 'deny.download-exec', level: 'deny', all: [/\bregsvr32(\.exe)?\b[^|;&]*(\\i:(https?|ftp):|scrobj)/], evidence: 'regsvr32 remote' },
  { id: 'deny.download-exec', level: 'deny', all: [/\bcertutil(\.exe)?\b[^|;&]*[-\\](urlcache|verifyctl)\b/], evidence: 'certutil -urlcache' },
  { id: 'deny.download-exec', level: 'deny', all: [/\bmsiexec(\.exe)?\b[^|;&]*(https?|ftp):/], evidence: 'msiexec URL' },
  { id: 'deny.encoded-command', level: 'deny', all: [/\b(powershell|pwsh)(\.exe)?\b[^|;&]*\s[-–—](e|ec|en|enc|enco|encod|encode|encoded|encodedc|encodedco|encodedcom|encodedcomm|encodedcomma|encodedcomman|encodedcommand)\b/], evidence: '-EncodedCommand' },

  // ---- security switched off ----
  { id: 'deny.security-off', level: 'deny', all: [/\bset-mppreference\b[^|;&]*-disable[a-z]*/], none: [/-disable[a-z]*\s*:?\s*(\$false|0)\b/], evidence: 'Defender disabled' },
  { id: 'deny.security-off', level: 'deny', all: [/\b(add|set)-mppreference\b[^|;&]*-exclusion(path|process|extension|ipaddress)\b/], evidence: 'Defender exclusion' },
  { id: 'deny.security-off', level: 'deny', all: [/\bnetsh(\.exe)?\b[^|;&]*\b(advfirewall|firewall)\b[^|;&]*\b(state\s+off|opmode\s+disable|mode\s*=\s*disable)/], evidence: 'firewall off' },
  { id: 'deny.security-off', level: 'deny', all: [/\bset-netfirewallprofile\b[^|;&]*-enabled\s*:?\s*(\$?false|0)\b/], evidence: 'firewall off' },
  { id: 'deny.security-off', level: 'deny', all: [/\b(stop|disable|remove|suspend)-service\b[^|;&]*\b(windefend|wdnissvc|sense|mpssvc|wscsvc|securityhealthservice|bfe)\b/], evidence: 'security service stopped' },
  { id: 'deny.security-off', level: 'deny', all: [/\bset-service\b[^|;&]*\b(windefend|wdnissvc|sense|mpssvc|wscsvc|securityhealthservice|bfe)\b[^|;&]*\b(disabled|stopped)\b/], evidence: 'security service disabled' },
  { id: 'deny.security-off', level: 'deny', all: [/\benablelua\b[^|;&]*\s0\b|\bconsentpromptbehavioradmin\b[^|;&]*\s0\b/], evidence: 'UAC off' },
  { id: 'deny.security-off', level: 'deny', all: [/\b(uninstall-windowsfeature|disable-windowsoptionalfeature|dism)\b[^|;&]*defender/], evidence: 'Defender removed' },

  // ---- dsh process ----
  { id: 'deny.kill-dsh', level: 'deny', all: [/\b(stop-process|spps|kill|taskkill|tskill|pskill|pkill|killall)\b/, /deepseek|harness|\bdsh(\.exe)?\b|electron/], evidence: 'kill dsh' },

  // ---- fork bomb ----
  { id: 'deny.fork-bomb', level: 'deny', all: [/:\s*\(\s*\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:/], evidence: ':(){ :|:& };:' },

  // ---- ask: elevation ----
  { id: 'ask.elevation', level: 'ask', all: [/\brunas\b/], evidence: 'runas' },
  { id: 'ask.elevation', level: 'ask', all: [/\b(sudo|gsudo|doas|psexec(64)?|paexec|pkexec)\b/], evidence: 'sudo / psexec' },
  { id: 'ask.elevation', level: 'ask', all: [/\bnircmdc?\b[^|;&]*\belevate\b/], evidence: 'nircmd elevate' },

  // ---- ask: registry and persistent environment ----
  { id: 'ask.registry', level: 'ask', all: [/\b(hkcu|hklm|hkcr|hku|hkcc):/], evidence: 'registry drive' },
  { id: 'ask.registry', level: 'ask', all: [/\bhkey_(current_user|local_machine|classes_root|users|current_config)\b/], evidence: 'HKEY_' },
  { id: 'ask.registry', level: 'ask', all: [/\bregistry::/], evidence: 'Registry::' },
  { id: 'ask.registry', level: 'ask', all: [/\breg(\.exe)?\s+(add|delete|import|load|unload|restore|copy|save|export|flags)\b/], evidence: 'reg' },
  { id: 'ask.registry', level: 'ask', all: [/\b(regedit|regini|setx)(\.exe)?\b/], evidence: 'regedit / setx' },
  { id: 'ask.registry', level: 'ask', all: [/setenvironmentvariable\s*\([^)]*(user|machine)/], evidence: 'SetEnvironmentVariable' },
  { id: 'ask.registry', level: 'ask', all: [/microsoft\.win32\.registry/], evidence: '.NET registry' },

  // ---- ask: start-up items ----
  { id: 'ask.startup', level: 'ask', all: [/\\start menu\\programs\\startup\b|shell:(common )?startup/], evidence: 'Startup folder' },
  { id: 'ask.startup', level: 'ask', all: [/\\currentversion\\(run|runonce|runservices)\b/], evidence: 'Run key' },
  { id: 'ask.startup', level: 'ask', all: [/\bschtasks(\.exe)?\b|\b(register|new|set|enable)-scheduled(task|job)\b/], evidence: 'scheduled task' },
  { id: 'ask.startup', level: 'ask', all: [/\b(new|set|remove)-service\b|\bsc(\.exe)?\s+(create|config|delete|failure|sdset|privs)\b/], evidence: 'service' },
  { id: 'ask.startup', level: 'ask', all: [/\bregister-wmievent\b|\bset-wmiinstance\b|\bregister-cimindicationevent\b|__eventfilter|commandlineeventconsumer/], evidence: 'WMI subscription' },
  { id: 'ask.startup', level: 'ask', all: [/\bcrontab\b|\bsystemctl\s+(--user\s+)?(enable|link|edit|daemon-reload)\b|\blaunchctl\s+(load|bootstrap|submit|enable)\b/], evidence: 'cron / systemd / launchd' },
  { id: 'ask.startup', level: 'ask', all: [/\\library\\launch(agents|daemons)\b|\\\.config\\autostart\b|\\etc\\(cron|systemd|init\.d|rc\.local)/], evidence: 'start-up directory' },

  // ---- ask: shell start-up files ----
  { id: 'ask.shell-profile', level: 'ask', all: [/\$profile\b|profile\.ps1\b/], evidence: '$PROFILE' },
  { id: 'ask.shell-profile', level: 'ask', all: [/(^|[\\\s'"=])\.(bashrc|bash_profile|bash_login|zshrc|zprofile|zshenv|zlogin|profile)\b|config\.fish\b|\\etc\\(profile|bash\.bashrc|zshrc)\b/], evidence: 'shell rc file' },

  // ---- ask: SSH and credentials ----
  { id: 'ask.ssh', level: 'ask', all: [new RegExp(`${B}\\.ssh${E}`)], evidence: '.ssh' },
  { id: 'ask.ssh', level: 'ask', all: [/\bssh-(keygen|add|copy-id|keyscan|agent)\b|\b(authorized_keys|known_hosts|id_rsa|id_ed25519|id_ecdsa|id_dsa)\b/], evidence: 'ssh keys' },
  { id: 'ask.credentials', level: 'ask', all: [new RegExp(`${B}\\.(aws|azure|kube|gnupg|password-store|docker|terraform\\.d)${E}`)], evidence: 'credential directory' },
  { id: 'ask.credentials', level: 'ask', all: [/\.(npmrc|yarnrc|pypirc|netrc|git-credentials|gitconfig|vault-token)\b|\b_netrc\b/], evidence: 'credential file' },
  { id: 'ask.credentials', level: 'ask', all: [/\bgit\s+(-c\s+\S+\s+)*config\s+(--global|--system)\b|\bgit\s+credential\b|credential\.helper/], evidence: 'git credentials / global config' },
  { id: 'ask.credentials', level: 'ask', all: [/\\microsoft\\(credentials|protect|crypto|systemcertificates)\b|\\github cli\b|\\\.config\\(gh|gcloud)\b|\\gcloud\\/], evidence: 'credential store' },
  { id: 'ask.credentials', level: 'ask', all: [/\b(cmdkey|vaultcmd)(\.exe)?\b|keymgr\.dll|\b(set-secret|set-storedcredential|new-storedcredential)\b/], evidence: 'Windows credential manager' },
  { id: 'ask.credentials', level: 'ask', all: [/\b(npm|pnpm|yarn|bun)\s+(login|adduser|add-user|logout|token|owner)\b|\bgh\s+auth\b|\bdocker\s+log(in|out)\b|\baz\s+login\b|\baws\s+(configure|sso\s+login)\b|\bgcloud\s+auth\b|\b(firebase|vercel|netlify|heroku|wrangler|supabase|fly|flyctl)\s+(login|auth)\b|huggingface-cli\s+login/], evidence: 'login command' },
  { id: 'ask.key-file', level: 'ask', all: [/\.(pem|pfx|p12|kdbx|jks|keystore|ppk)\b/], evidence: 'key file' },
  { id: 'ask.browser', level: 'ask', all: [/\\(google\\chrome|microsoft\\edge|bravesoftware\\brave-browser|chromium|vivaldi)\\user data\b|\\mozilla\\firefox\b|\\opera software\b/], evidence: 'browser profile' },

  // ---- ask: accounts and permissions ----
  { id: 'ask.accounts', level: 'ask', all: [/\bnet1?(\.exe)?\s+(user|users|localgroup|group|accounts)\b|\b(new|set|remove|enable|disable|rename)-localuser\b|\b(add|remove)-localgroupmember\b/], evidence: 'accounts' },
  { id: 'ask.accounts', level: 'ask', all: [/\b(icacls|cacls|xcacls|takeown)(\.exe)?\b|\bset-acl\b|\bset-executionpolicy\b|\bunblock-file\b/], evidence: 'permissions' },

  // ---- ask: remote execution ----
  { id: 'ask.remote', level: 'ask', all: [/\b(enter|new)-pssession\b|\binvoke-command\b[^|;&]*-(computername|cn|session|hostname|vmname)\b|\bwinr[ms]\b|\bwmic\b[^|;&]*\\node:/], evidence: 'remote' },

  // ---- ask: system configuration ----
  { id: 'ask.system-config', level: 'ask', all: [/\b(netsh|dism|pnputil|certmgr|powercfg|bitsadmin|tzutil)(\.exe)?\b/], evidence: 'system tool' },
  { id: 'ask.system-config', level: 'ask', all: [/\b(enable|disable)-windowsoptionalfeature\b|\b(install|uninstall|add)-windowsfeature\b|\bimport-(pfx)?certificate\b|\bset-dnsclientserveraddress\b|\b(new|set|remove)-netfirewallrule\b|\bset-(date|timezone)\b|\bclear-recyclebin\b/], evidence: 'system setting' },
  { id: 'ask.system-config', level: 'ask', all: [/\bcertutil(\.exe)?\b[^|;&]*[-\\](addstore|importpfx|delstore|repairstore)\b/], evidence: 'certificate store' },
  { id: 'ask.system-config', level: 'ask', all: [/\\drivers\\etc\\hosts\b|\\etc\\hosts\b/], evidence: 'hosts file' },
]

/**
 * Apply the keyword rules to a normalized command text.
 * @param {string} normalized - output of normalizeForScan.
 * @returns {{ level: 'deny' | 'ask', rule: string, evidence: string }[]}
 */
export function scanText(normalized) {
  const hits = []
  for (const rule of TEXT_RULES) {
    if (!rule.all.every(re => re.test(normalized))) continue
    if (rule.none !== undefined && rule.none.some(re => re.test(normalized))) continue
    hits.push({ level: rule.level, rule: rule.id, evidence: rule.evidence })
  }
  return hits
}

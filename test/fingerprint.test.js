// Fingerprints: the exact identity of a command, the files it is bound to, and what never enters the allowlist.
import { after, test } from 'node:test'
import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { evaluateHardRules } from '../lib/rules/hard-rules.js'
import { fingerprintOf, hashFileSync, identityKey } from '../lib/store/fingerprint.js'
import { PLUGIN_SKILLS, WS, host } from './helpers.js'

/** A fake project in the alice workspace: file path (any case) → content. */
function project(extra = {}) {
  const files = {
    [`${WS}\\package.json`]: JSON.stringify({ scripts: { build: 'tsc -p .', test: 'node --test' } }),
    [`${WS}\\package-lock.json`]: '{"lockfileVersion":3}',
    [`${WS}\\tools\\gen.py`]: 'print("generate")',
    [`${WS}\\tests\\shot.js`]: 'console.log("shot")',
    [`${WS}\\scripts\\build.ps1`]: 'Write-Output "building"',
    [`${WS}\\Makefile`]: 'all:\n\techo hi\n',
    ...extra,
  }
  const index = new Map(Object.entries(files).filter(([, v]) => v !== undefined).map(([k, v]) => [k.toLowerCase(), v]))
  return {
    hashFile: (file) => {
      const text = index.get(file.toLowerCase())
      if (text === undefined) return { missing: true }
      if (text === 'UNREADABLE') return { error: 'EACCES' }
      return { sha256: createHash('sha256').update(text).digest('hex') }
    },
    readText: file => index.get(file.toLowerCase()),
  }
}

/** Fingerprint of a pwsh command as the engine computes it (hard rules first). */
function fp(command, { files = project(), cwd = WS, workspaceRoot = WS, tool = 'pwsh', extraArgs = {} } = {}) {
  const args = { command, sandbox_permissions: 'danger-full-access', justification: 'needs to write outside', ...extraArgs }
  const hard = evaluateHardRules({ tool, args, host, workspaceRoot, cwd })
  return fingerprintOf({ tool, args, facts: hard.facts, host, workspaceRoot, hashFile: files.hashFile, readText: files.readText })
}
const deps = print => Object.fromEntries(print.dependsOn.map(d => [d.path.replace(`${WS}\\`, ''), d.sha256 === null ? null : 'hash']))

test('identity: exact text in the same place — only outer whitespace is trimmed, nothing is a wildcard', () => {
  const base = fp('npm install')
  assert.equal(base.eligible, true)
  assert.match(base.key, /^[0-9a-f]{64}$/)
  assert.equal(fp('  npm install \r\n').key, base.key)
  assert.equal(fp('npm install', { extraArgs: { justification: 'a different story', description: 'whatever' } }).key, base.key)
  for (const other of ['npm  install', 'NPM INSTALL', 'npm install *', 'npm i', 'npm install;', 'npm install # x']) {
    assert.notEqual(fp(other).key, base.key, other)
  }
  // The same directory however it is spelled; another directory, workspace or tool is another identity.
  assert.equal(fp('npm install', { cwd: 'c:/users/ALICE/proj/' }).key, base.key)
  assert.notEqual(fp('npm install', { cwd: `${WS}\\build` }).key, base.key)
  assert.notEqual(fp('npm install', { workspaceRoot: `${WS}\\build`, cwd: WS }).key, base.key)
  assert.equal(base.key, identityKey('pwsh', host.tools.key(WS), host.tools.key(WS), 'npm install'))
  assert.notEqual(identityKey('bash', host.tools.key(WS), host.tools.key(WS), 'npm install'), base.key)
  // Stable: the same inputs give the same fingerprint.
  assert.deepEqual(fp('npm install'), base)
})

test('dependencies: the files a command depends on are bound by content, absence included', () => {
  assert.deepEqual(deps(fp('npm install')), { 'package.json': 'hash', '.npmrc': null, 'package-lock.json': 'hash', 'npm-shrinkwrap.json': null, 'binding.gyp': null })
  assert.deepEqual(deps(fp('npm run build')), { 'package.json': 'hash', '.npmrc': null })
  assert.deepEqual(deps(fp('npm test')), { 'package.json': 'hash', '.npmrc': null })
  assert.deepEqual(deps(fp('python tools\\gen.py')), { 'tools\\gen.py': 'hash' })
  assert.deepEqual(deps(fp('& "D:\\miniconda3\\envs\\learning\\python.exe" -u tools\\gen.py')), { 'tools\\gen.py': 'hash' })
  assert.deepEqual(deps(fp('node tests\\shot.js 2>&1 | Select-Object -First 40')), { 'tests\\shot.js': 'hash' })
  assert.deepEqual(deps(fp('& .\\scripts\\build.ps1 -Release')), { 'scripts\\build.ps1': 'hash' })
  assert.deepEqual(deps(fp('make all')), { GNUmakefile: null, makefile: 'hash' })
  // A package manager after `cd` uses the project it moved into (found upwards, as npm does).
  assert.deepEqual(deps(fp('cd build; npm install')), deps(fp('npm install')))
  // Running a script nobody in the workspace can change binds nothing.
  const skill = fp(`node "${PLUGIN_SKILLS}\\diagram\\bin\\run.mjs" render .\\diagram.json`)
  assert.equal(skill.eligible, true, skill.reasons.join('; '))
  assert.deepEqual(skill.dependsOn, [])

  // Any change to a bound file — edited, created or removed — changes the fingerprint.
  const install = fp('npm install').dependsOn
  const edited = fp('npm install', { files: project({ [`${WS}\\package.json`]: JSON.stringify({ scripts: { postinstall: 'node evil.js' } }) }) }).dependsOn
  const npmrc = fp('npm install', { files: project({ [`${WS}\\.npmrc`]: 'script-shell=C:\\evil.exe' }) }).dependsOn
  const noLock = fp('npm install', { files: project({ [`${WS}\\package-lock.json`]: undefined }) }).dependsOn
  for (const changed of [edited, npmrc, noLock]) assert.notDeepEqual(changed, install)
  assert.notDeepEqual(fp('python tools\\gen.py', { files: project({ [`${WS}\\tools\\gen.py`]: 'import os; os.remove("x")' }) }).dependsOn, fp('python tools\\gen.py').dependsOn)
})

test('never listed: write and edit, opaque spellings, nested shells', () => {
  const write = fingerprintOf({ tool: 'write', args: { file_path: 'C:\\Users\\alice\\Desktop\\a.txt', content: 'x' }, facts: { target: 'C:\\Users\\alice\\Desktop\\a.txt' }, host, workspaceRoot: WS, hashFile: () => ({ missing: true }), readText: () => undefined })
  assert.equal(write.eligible, false)
  assert.equal(write.key, null)
  const cases = [
    ['npm install $(Get-Date)', /看不穿/],
    ['iex "npm install"', /看不穿/],
    ['Invoke-Expression (Get-Content .\\scripts\\build.ps1 -Raw)', /看不穿/],
    ['& { npm install }', /看不穿/],
    ['python -c "print(1)"', /看不穿/],
    ['node -e "process.exit(0)"', /看不穿/],
    ['& $tool install', /看不穿/],
    ['Write-Output "exit=$LASTEXITCODE"', /看不穿/],
    ['powershell -NoProfile -Command "npm install"', /嵌套了 powershell/],
    ['cmd /c "npm install"', /嵌套了 cmd/],
  ]
  for (const [command, reason] of cases) {
    const print = fp(command)
    assert.equal(print.eligible, false, command)
    assert.ok(print.reasons.some(r => reason.test(r)), `${command}: ${print.reasons.join('; ')}`)
  }
})

test('never listed: changes outside the workspace that a repeat would make again', () => {
  const cases = [
    ['Remove-Item C:\\Users\\alice\\Desktop\\out\\old.txt', /删除工作区外/],
    ['Move-Item C:\\Users\\alice\\Desktop\\out\\old.txt .\\old.txt', /移动工作区外/],
    ["Set-Content C:\\Users\\alice\\Desktop\\out\\old.txt 'x'", /覆盖工作区外已有/],
    ['Copy-Item .\\build\\app.js C:\\Users\\alice\\Desktop\\out', /覆盖工作区外已有/],
    ['npm install > C:\\Users\\alice\\Desktop\\out\\old.txt', /覆盖工作区外已有/],
    ['cd C:\\Users\\alice\\Desktop; npm install', /在工作区外的/],
    ['node tests\\shot.js --out=C:\\Users\\alice\\Desktop\\shot.png', /工作区外的路径/],
    ['& .\\scripts\\build.ps1 -Out C:\\Users\\alice\\Desktop\\dist', /工作区外的路径/],
    ['make install PREFIX=C:\\Users\\alice\\Desktop\\app', /工作区外的路径/],
  ]
  for (const [command, reason] of cases) {
    const print = fp(command)
    assert.equal(print.eligible, false, command)
    assert.ok(print.reasons.some(r => reason.test(r)), `${command}: ${print.reasons.join('; ')}`)
  }
  // Creating something new outside is not excluded here: it is listed only if it no longer exists afterwards.
  const create = fp("Set-Content C:\\Users\\alice\\Desktop\\new.txt 'x'")
  assert.equal(create.eligible, true, create.reasons.join('; '))
  assert.deepEqual(create.outsideWrites, ['C:\\Users\\alice\\Desktop\\new.txt'])
})

test('never listed: programs whose dependencies cannot be told', () => {
  const cases = [
    ['git push origin main 2>&1 | Select-Object -Last 8', /判断不出 git/],
    ['& "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe" --headless --screenshot', /判断不出 chrome/],
    ['.\\bin\\tool.exe --build', /工作区或临时目录里的程序/],
    ['node node_modules\\vitest\\vitest.mjs run', /node_modules/],
    ['npx vite build', /判断不出 npx/],
    ['python -m pytest', /选项 -m/],
    ['node -r .\\hook.js tests\\shot.js', /选项 -r/],
    ['node --import .\\hook.mjs tests\\shot.js', /选项 --import/],
    ['python', /没有直接运行一个脚本文件/],
    ['$env:NODE_OPTIONS = "--require .\\hook.js"; node tests\\shot.js', /env:NODE_OPTIONS/],
    ['New-Item alias:\\ls -Value Remove-Item', /alias:/],
    ['npm install -g typescript', /-g/],
    ['npm install --prefix ..\\other', /--prefix/],
    ['npm --userconfig .\\x.npmrc install', /--userconfig/],
    ['npm install ..\\local-pkg', /本地路径/],
    ['npm publish', /不在可进清单的命令里/],
    ['npm exec vite', /不在可进清单的命令里/],
    ['make -C sub', /-C/],
    ['npm install `  ', /转义符/],
  ]
  for (const [command, reason] of cases) {
    const print = fp(command)
    assert.equal(print.eligible, false, command)
    assert.ok(print.reasons.some(r => reason.test(r)), `${command}: ${print.reasons.join('; ')}`)
  }
})

test('never listed: project files that would run code nobody reviewed', () => {
  const cases = [
    ['pnpm install', { [`${WS}\\.pnpmfile.cjs`]: 'module.exports = {}' }, /\.pnpmfile\.cjs/],
    ['pnpm install', { [`${WS}\\pnpm-workspace.yaml`]: 'packages: []' }, /多包项目/],
    ['yarn', { [`${WS}\\.yarnrc.yml`]: 'yarnPath: .yarn/releases/yarn.cjs' }, /\.yarnrc\.yml/],
    ['npm install', { [`${WS}\\binding.gyp`]: '{}' }, /binding\.gyp/],
    ['npm install', { [`${WS}\\package.json`]: JSON.stringify({ workspaces: ['packages/*'] }) }, /workspaces/],
    ['npm install', { [`${WS}\\package.json`]: JSON.stringify({ dependencies: { mine: 'file:../mine' } }) }, /本地路径/],
    ['make', { [`${WS}\\Makefile`]: 'include rules.mk\nall:\n' }, /引用了其他 makefile/],
    ['npm install', { [`${WS}\\package-lock.json`]: 'UNREADABLE' }, /读不了依赖文件/],
    ['npm run build', { [`${WS}\\package.json`]: undefined }, /找不到/],
  ]
  for (const [command, extra, reason] of cases) {
    const print = fp(command, { files: project(extra) })
    assert.equal(print.eligible, false, command)
    assert.ok(print.reasons.some(r => reason.test(r)), `${command}: ${print.reasons.join('; ')}`)
  }
  // Their absence is part of the fingerprint, so creating one later stops a listed entry from matching.
  assert.ok(fp('pnpm install').dependsOn.some(d => d.path.endsWith('.pnpmfile.cjs') && d.sha256 === null))
})

test('plain built-in commands are listed with nothing to bind', () => {
  for (const command of [
    'New-Item -ItemType Directory C:\\Users\\alice\\Desktop\\newdir -Force | Out-Null',
    'Get-ChildItem C:\\Users\\alice\\Documents | Select-Object -First 5',
    "Copy-Item C:\\Users\\alice\\Documents\\a.txt .\\a.txt",
  ]) {
    const print = fp(command)
    assert.equal(print.eligible, true, `${command}: ${print.reasons.join('; ')}`)
    assert.deepEqual(print.dependsOn, [])
  }
})

const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'doorman-fingerprint-test-'))
after(() => fs.rmSync(tmp, { recursive: true, force: true }))

test('hashFileSync: SHA-256 of the bytes, absence reported, directories refused', () => {
  const file = path.join(tmp, 'package.json')
  fs.writeFileSync(file, '{"name":"x"}')
  const first = hashFileSync(file)
  assert.deepEqual(first, { sha256: createHash('sha256').update('{"name":"x"}').digest('hex') })
  fs.writeFileSync(file, '{"name":"y"}')
  assert.notEqual(hashFileSync(file).sha256, first.sha256)
  assert.deepEqual(hashFileSync(path.join(tmp, 'missing.json')), { missing: true })
  assert.deepEqual(hashFileSync(path.join(tmp, 'missing', 'deeper.json')), { missing: true })
  assert.deepEqual(hashFileSync(tmp), { error: 'not-a-file' })
})

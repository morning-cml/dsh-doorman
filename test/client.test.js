// Settings page smoke test: load the browser module with a fake module loader and a minimal React stand-in.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import path from 'node:path'
import vm from 'node:vm'
import { fileURLToPath } from 'node:url'

const here = path.dirname(fileURLToPath(import.meta.url))
const source = fs.readFileSync(path.join(here, '..', 'client.js'), 'utf8')

/** React stand-in: elements are plain objects; hooks keep state between calls by position. */
function fakeReact() {
  const slots = []
  let index = 0
  return {
    reset() { index = 0 },
    slots,
    createElement: (type, props, ...children) => ({ type, props: props ?? {}, children: children.flat() }),
    useState(initial) {
      const i = index++
      if (!(i in slots)) slots[i] = initial
      return [slots[i], (v) => { slots[i] = typeof v === 'function' ? v(slots[i]) : v }]
    },
    useSyncExternalStore(subscribe, getSnapshot) { index++; subscribe(() => {}); return getSnapshot() },
  }
}

/** Load client.js and run its apply() against fake services. */
function load({ formSnapshot, describe = async () => ({ ok: true, value: { DSH_DOORMAN_API_KEY: { configured: true, writable: true } } }) } = {}) {
  let module
  const React = fakeReact()
  const sandbox = { window: { __ModuleLoader__: { load: (m) => { module = m } } } }
  vm.runInNewContext(source, sandbox)
  assert.equal(module.id, 'dsh-doorman')
  const api = module.factory(name => { if (name === 'react') return React; throw new Error(`unexpected require ${name}`) })
  const calls = { mutate: [], set: [], unset: [], registered: [] }
  let snapshot = formSnapshot ?? { status: 'ready', value: { baseUrl: 'https://dashscope.aliyuncs.com/compatible-mode/v1', model: 'qwen3.7-plus', timeoutSeconds: 20, maxCallsPerHour: 100 }, revision: 3, writable: true, mode: 'host' }
  const ctx = {
    effect: fn => fn(),
    locale: { register: () => () => {} },
    remote: {
      $on: () => () => {},
      credentials: {
        describe,
        set: async (ref, value) => { calls.set.push([ref, value]); return { ok: true } },
        unset: async (ref) => { calls.unset.push(ref); return { ok: true } },
      },
    },
    configForms: {
      get: () => ({
        getSnapshot: () => snapshot,
        subscribe: () => () => {},
        mutate: async (ops, revision) => { calls.mutate.push({ ops, revision }); return true },
      }),
    },
    slots: {
      inject: (_name, register) => register(),
      register: (options, component) => { calls.registered.push({ options, component }) },
    },
  }
  api.apply(ctx)
  const { options, component } = calls.registered[0]
  const render = (view = 'page') => { React.reset(); return component({ view, t: key => `[${key}]`, ...options.inject() }) }
  return { api, calls, options, render, React, setSnapshot: (s) => { snapshot = s } }
}

/** The input or select element with this id. */
const control = (tree, id) => find(tree, n => (n.type === 'input' || n.type === 'select') && n.props.id === id)[0]

/** Find elements in a rendered tree. */
function find(node, predicate, out = []) {
  if (node === null || typeof node !== 'object') return out
  if (predicate(node)) out.push(node)
  for (const child of node.children ?? []) find(child, predicate, out)
  return out
}

test('the page registers on its own bundle page with the right services', () => {
  const { api, options } = load()
  assert.deepEqual([...api.inject], ['slots', 'locale', 'remote', 'remote.credentials', 'configForms'])
  assert.equal(options.name, 'plugins.bundle.config')
  assert.equal(options.key, 'dsh-doorman')
})

test('the page renders every control and never shows a key value', async () => {
  const { render } = load()
  await new Promise(r => setTimeout(r, 0))
  const tree = render()
  const ids = find(tree, n => (n.type === 'input' || n.type === 'select') && typeof n.props?.id === 'string').map(n => n.props.id)
  for (const id of ['dsh-doorman-endpoint', 'dsh-doorman-model', 'dsh-doorman-key', 'dsh-doorman-timeout', 'dsh-doorman-max-calls']) assert.ok(ids.includes(id), id)
  const keyInput = control(tree, 'dsh-doorman-key')
  assert.equal(keyInput.props.type, 'password')
  assert.equal(keyInput.props.value, '')
  assert.equal(render('summary'), '[summary]')
})

test('saving the key goes to the credentials service; saving settings goes to the settings form', async () => {
  const { calls, render, React } = load()
  let tree = render()
  // Type a key and press save.
  control(tree, 'dsh-doorman-key').props.onChange({ target: { value: '  sk-new-key-0123456789  ' } })
  tree = render()
  const saveKey = find(tree, n => n.type === 'button' && n.children.includes('[saveKey]'))[0]
  await saveKey.props.onClick()
  await new Promise(r => setTimeout(r, 0))
  assert.deepEqual(calls.set, [['DSH_DOORMAN_API_KEY', 'sk-new-key-0123456789']])

  // Change the model and save the settings.
  tree = render()
  control(tree, 'dsh-doorman-model').props.onChange({ target: { value: 'qwen-plus' } })
  tree = render()
  const save = find(tree, n => n.type === 'button' && n.children.includes('[save]'))[0]
  assert.equal(save.props.disabled, false)
  await save.props.onClick()
  assert.equal(calls.mutate.length, 1)
  assert.equal(calls.mutate[0].revision, 3)
  assert.deepEqual(JSON.parse(JSON.stringify(calls.mutate[0].ops.find(o => o.path[0] === 'model'))), { op: 'set', path: ['model'], value: 'qwen-plus' })
  assert.ok(React.slots.length > 0)
})

test('invalid input keeps the save button disabled', () => {
  const { render } = load()
  let tree = render()
  control(tree, 'dsh-doorman-timeout').props.onChange({ target: { value: '999' } })
  tree = render()
  const save = find(tree, n => n.type === 'button' && n.children.includes('[save]'))[0]
  assert.equal(save.props.disabled, true)
  assert.ok(find(tree, n => n.props?.error === '[invalidTimeout]').length > 0)
})

test('when the settings are not served yet, the page says so and disables the form', () => {
  const { render } = load({ formSnapshot: { status: 'unavailable', value: undefined, revision: undefined, writable: false, mode: 'host' } })
  const tree = render()
  assert.ok(find(tree, n => n.children?.includes('[unavailable]')).length > 0)
  assert.equal(control(tree, 'dsh-doorman-model').props.disabled, true)
})

/**
 * dsh-doorman settings page (browser half). Rendered on the plugin's own page
 * in dsh's Plugins panel. The endpoint, model and limits are written through
 * dsh's settings service (stored in the profile's plugin configuration); the
 * API key is written through dsh's credentials service and is never read back:
 * the page only learns whether a key is set.
 */
/* global window */
window.__ModuleLoader__.load({
  id: 'dsh-doorman',
  factory(require) {
    const React = require('react')
    const h = React.createElement
    const { useState, useSyncExternalStore } = React

    const NS = 'dshDoorman'
    const ENTRY = 'dsh-doorman'
    const KEY_REF = 'DSH_DOORMAN_API_KEY'
    const PRESETS = [
      { id: 'dashscope-cn', url: 'https://dashscope.aliyuncs.com/compatible-mode/v1' },
      { id: 'dashscope-intl', url: 'https://dashscope-intl.aliyuncs.com/compatible-mode/v1' },
    ]
    const MODEL_SUGGESTIONS = ['qwen3.7-plus', 'qwen-plus', 'qwen3.8-flash', 'qwen3.8-max']
    const DEFAULTS = { baseUrl: PRESETS[0].url, model: 'qwen3.7-plus', timeoutSeconds: 20, maxCallsPerHour: 100 }

    const zh = {
      summary: '提权审批分流：硬性规则 + 千问审查',
      intro: '通过了硬性规则的提权申请，会把整理、打码后的内容发给下面这个模型判断。当前是“只观察”模式：模型的判断只写进日志，审批弹窗照常出现。',
      endpoint: '接口地址',
      endpointHint: '任何 OpenAI 兼容接口都可以；地址必须以 https:// 开头。',
      presetCn: '阿里云百炼（中国内地·北京）',
      presetIntl: '阿里云百炼（国际·新加坡）',
      presetCustom: '自定义地址',
      customUrl: '自定义接口地址',
      model: '模型',
      modelHint: '推荐 qwen3.7-plus（每次审查约 0.5 分钱）。也可以填 qwen-plus（更省钱）或 qwen3.8-max（更强）。',
      key: 'API key',
      keyHint: 'key 由 dsh 保存在它自己的凭据文件里，名字是 DSH_DOORMAN_API_KEY。页面和日志都不会显示它；保存后输入框会清空。',
      keyLoading: '读取中…',
      keySet: '已保存',
      keyUnset: '未设置',
      keyError: '读不到状态',
      keyFromEnv: '这个 key 来自启动 dsh 时的环境变量，不能在这里修改或删除。',
      keyPlaceholder: '粘贴新的 key',
      saveKey: '保存 key',
      removeKey: '删除 key',
      keySaved: 'key 已保存。几秒后插件会用一条无害的示例命令试连一次（约 0.5 分钱）。',
      keyRemoved: 'key 已删除，之后不会再调用模型。',
      keySaveFailed: '保存失败，请再试一次。',
      advanced: '高级设置',
      timeout: '超时（秒）',
      timeoutHint: '超过这个时间没有回答，就当作“拿不准”交给你。5 到 120。',
      maxCalls: '每小时最多调用次数',
      maxCallsHint: '超过后本小时内的申请全部交给你，防止 agent 陷入循环时不停花钱。填 0 表示不调用模型。',
      save: '保存设置',
      saving: '保存中…',
      saved: '设置已保存，立即生效。',
      saveFailed: '保存失败：设置可能已在别处修改，页面已刷新，请重试。',
      unsaved: '有未保存的修改',
      unavailable: '插件还没有运行（可能需要重启 dsh），暂时不能修改这些设置。',
      readOnly: '当前 profile 是只读的，不能修改设置。',
      invalidUrl: '请填写以 https:// 开头的完整地址。',
      invalidModel: '模型名只能包含字母、数字和 . - _ / :',
      invalidTimeout: '请填写 5 到 120 之间的整数。',
      invalidMaxCalls: '请填写 0 到 5000 之间的整数。',
    }
    const en = {
      summary: 'Approval triage: hard rules + model review',
      intro: 'Escalation requests that pass the hard rules are sanitised and sent to the model below. Observe-only for now: the model\'s verdict is only logged and the approval prompt still appears.',
      endpoint: 'Endpoint',
      endpointHint: 'Any OpenAI-compatible endpoint; it must start with https://.',
      presetCn: 'Alibaba Cloud Model Studio (Beijing)',
      presetIntl: 'Alibaba Cloud Model Studio (Singapore)',
      presetCustom: 'Custom address',
      customUrl: 'Custom endpoint',
      model: 'Model',
      modelHint: 'Recommended: qwen3.7-plus. qwen-plus is cheaper, qwen3.8-max is stronger.',
      key: 'API key',
      keyHint: 'Stored by dsh in its own credentials file as DSH_DOORMAN_API_KEY. Never shown on this page or in logs; the field clears after saving.',
      keyLoading: 'Loading…',
      keySet: 'Saved',
      keyUnset: 'Not set',
      keyError: 'Status unavailable',
      keyFromEnv: 'This key comes from dsh\'s launch environment and cannot be changed here.',
      keyPlaceholder: 'Paste a new key',
      saveKey: 'Save key',
      removeKey: 'Remove key',
      keySaved: 'Key saved. In a few seconds the plugin checks the connection once with a harmless sample request.',
      keyRemoved: 'Key removed; the model will not be called.',
      keySaveFailed: 'Saving failed. Please try again.',
      advanced: 'Advanced',
      timeout: 'Timeout (seconds)',
      timeoutHint: 'No answer within this time counts as "not sure" and goes to you. 5–120.',
      maxCalls: 'Max calls per hour',
      maxCallsHint: 'Past this, every request in the hour goes to you. 0 turns the model off.',
      save: 'Save settings',
      saving: 'Saving…',
      saved: 'Settings saved and in effect.',
      saveFailed: 'Saving failed: the settings may have changed elsewhere. The page has refreshed; please try again.',
      unsaved: 'Unsaved changes',
      unavailable: 'The plugin is not running yet (dsh may need a restart), so these settings cannot be changed now.',
      readOnly: 'This profile is read-only.',
      invalidUrl: 'Enter a full address starting with https://.',
      invalidModel: 'Use only letters, digits and . - _ / :',
      invalidTimeout: 'Enter a whole number from 5 to 120.',
      invalidMaxCalls: 'Enter a whole number from 0 to 5000.',
    }

    const STYLE = `
.dd-root { display: flex; flex-direction: column; font-size: 13px; color: var(--dsw-alias-label-primary); }
.dd-intro { margin: 0 0 4px; font-size: 12px; line-height: 1.6; color: var(--dsw-alias-label-secondary); }
.dd-field { display: flex; flex-direction: column; gap: 6px; padding: 12px 0; }
.dd-field + .dd-field { border-top: 0.5px solid var(--dsw-alias-border-l2); }
.dd-head { display: flex; align-items: center; gap: 8px; }
.dd-label { flex: 1; min-width: 0; font-size: 13px; font-weight: 500; line-height: 1.5; }
.dd-hint { margin: 0; font-size: 12px; line-height: 1.5; color: var(--dsw-alias-label-tertiary); }
.dd-error { margin: 0; font-size: 12px; line-height: 1.5; color: var(--dsw-alias-state-error-primary); }
.dd-ok { margin: 0; font-size: 12px; line-height: 1.5; color: var(--dsw-alias-state-success-primary); }
.dd-input, .dd-select { height: 34px; padding: 0 12px; border: 0.5px solid var(--dsw-alias-border-l4); border-radius: var(--dsw-radius-md); background: var(--dsw-alias-bg-layer-3); font: inherit; font-size: 13px; line-height: 1.5; color: var(--dsw-alias-label-primary); }
.dd-input:focus-visible, .dd-select:focus-visible { outline: none; border-color: var(--dsw-alias-state-business-primary); }
.dd-input:disabled, .dd-select:disabled { color: var(--dsw-alias-label-tertiary); }
.dd-input[aria-invalid='true'] { border-color: var(--dsw-alias-state-error-primary); }
.dd-row { display: flex; gap: 8px; align-items: center; flex-wrap: wrap; }
.dd-row > .dd-input { flex: 1; min-width: 200px; }
.dd-tag { display: inline-flex; align-items: center; padding: 1px 8px; border-radius: 999px; font-size: 12px; line-height: 18px; background: var(--dsw-alias-bg-layer-4); color: var(--dsw-alias-label-secondary); }
.dd-tag[data-on='true'] { color: var(--dsw-alias-state-success-primary); }
.dd-button { appearance: none; border: 0.5px solid var(--dsw-alias-border-l3); border-radius: var(--dsw-radius-md); padding: 5px 14px; font: inherit; font-size: 13px; line-height: 1.5; cursor: pointer; background: transparent; color: var(--dsw-alias-label-primary); }
.dd-button:hover:not(:disabled) { background: var(--dsw-alias-interactive-bg-hover); }
.dd-button[data-primary='true'] { border-color: transparent; background: var(--dsw-alias-label-primary); color: var(--dsw-alias-bg-layer-3); }
.dd-button[data-primary='true']:hover:not(:disabled) { background: var(--dsw-alias-label-primary); opacity: 0.88; }
.dd-button:disabled { opacity: 0.4; cursor: default; }
.dd-button:focus-visible, .dd-summary:focus-visible { outline: var(--dsw-focus-ring-width, 2px) solid var(--dsw-focus-ring-color, var(--dsw-alias-state-business-primary)); outline-offset: 1px; }
.dd-details { border-top: 0.5px solid var(--dsw-alias-border-l2); padding-top: 12px; }
.dd-summary { cursor: pointer; font-size: 13px; color: var(--dsw-alias-label-secondary); }
.dd-footer { display: flex; align-items: center; gap: 12px; padding-top: 16px; flex-wrap: wrap; }
.dd-footer > p { flex: 1; min-width: 0; }
`

    /** Key status over dsh's credentials service; the value itself is never read. */
    function createKeyStore(ctx) {
      let snapshot = { status: 'loading', configured: false, writable: true, source: undefined }
      const listeners = new Set()
      const publish = (patch) => {
        snapshot = { ...snapshot, ...patch }
        for (const listener of listeners) listener()
      }
      const store = {
        getSnapshot: () => snapshot,
        subscribe(listener) {
          listeners.add(listener)
          return () => { listeners.delete(listener) }
        },
        async refresh() {
          try {
            const response = await ctx.remote.credentials.describe([KEY_REF])
            if (!response || response.ok === false) { publish({ status: 'error' }); return }
            const view = response.value ? response.value[KEY_REF] : undefined
            publish({ status: 'ready', configured: !!(view && view.configured), writable: !(view && view.writable === false), source: view ? view.source : undefined })
          } catch {
            publish({ status: 'error' })
          }
        },
        async save(value) {
          let ok = true
          try {
            const response = await ctx.remote.credentials.set(KEY_REF, value)
            if (response && response.ok === false) ok = false
          } catch {
            ok = false
          }
          await store.refresh()
          return ok && snapshot.configured
        },
        async remove() {
          let ok = true
          try {
            const response = await ctx.remote.credentials.unset(KEY_REF)
            if (response && response.ok === false) ok = false
          } catch {
            ok = false
          }
          await store.refresh()
          return ok && !snapshot.configured
        },
      }
      return store
    }

    const URL_RE = /^https:\/\/[^\s/]+(\/\S*)?$/i
    const MODEL_RE = /^[\w.\-/:]{1,100}$/
    const intIn = (text, min, max) => {
      if (!/^\s*\d+\s*$/.test(String(text))) return null
      const n = Number(text)
      return Number.isInteger(n) && n >= min && n <= max ? n : null
    }

    function Field(props) {
      return h('div', { className: 'dd-field' },
        h('div', { className: 'dd-head' },
          h('label', { className: 'dd-label', htmlFor: props.id }, props.label),
          props.badge || null),
        props.children,
        props.error ? h('p', { className: 'dd-error', role: 'alert' }, props.error) : null,
        props.hint ? h('p', { className: 'dd-hint' }, props.hint) : null)
    }

    function DoormanSettings(props) {
      const t = props.t
      const { form, keys } = props.doorman
      const formState = useSyncExternalStore(form.subscribe, form.getSnapshot)
      const keyState = useSyncExternalStore(keys.subscribe, keys.getSnapshot)
      const [draft, setDraft] = useState(null)
      const [custom, setCustom] = useState(false)
      const [saving, setSaving] = useState(false)
      const [notice, setNotice] = useState(null)
      const [keyText, setKeyText] = useState('')
      const [keyBusy, setKeyBusy] = useState(false)
      const [keyNotice, setKeyNotice] = useState(null)

      if (props.view === 'summary') return t('summary')

      const value = formState && formState.value ? formState.value : {}
      const stored = {
        baseUrl: typeof value.baseUrl === 'string' && value.baseUrl ? value.baseUrl : DEFAULTS.baseUrl,
        model: typeof value.model === 'string' && value.model ? value.model : DEFAULTS.model,
        timeoutSeconds: String(Number.isInteger(value.timeoutSeconds) ? value.timeoutSeconds : DEFAULTS.timeoutSeconds),
        maxCallsPerHour: String(Number.isInteger(value.maxCallsPerHour) ? value.maxCallsPerHour : DEFAULTS.maxCallsPerHour),
      }
      const current = draft || stored
      const edit = (field, text) => { setNotice(null); setDraft({ ...current, [field]: text }) }
      const preset = PRESETS.find(p => p.url === current.baseUrl.trim().replace(/\/+$/, ''))
      const presetId = custom || !preset ? 'custom' : preset.id

      const available = formState && formState.status === 'ready'
      const writable = available && formState.writable !== false
      const errors = {
        baseUrl: URL_RE.test(current.baseUrl.trim()) ? null : t('invalidUrl'),
        model: MODEL_RE.test(current.model.trim()) ? null : t('invalidModel'),
        timeoutSeconds: intIn(current.timeoutSeconds, 5, 120) === null ? t('invalidTimeout') : null,
        maxCallsPerHour: intIn(current.maxCallsPerHour, 0, 5000) === null ? t('invalidMaxCalls') : null,
      }
      const valid = Object.values(errors).every(e => e === null)
      const dirty = draft !== null && (draft.baseUrl !== stored.baseUrl || draft.model !== stored.model || draft.timeoutSeconds !== stored.timeoutSeconds || draft.maxCallsPerHour !== stored.maxCallsPerHour)

      const save = async () => {
        if (!writable || !valid || !dirty || saving) return
        const next = {
          baseUrl: current.baseUrl.trim().replace(/\/+$/, ''),
          model: current.model.trim(),
          timeoutSeconds: intIn(current.timeoutSeconds, 5, 120),
          maxCallsPerHour: intIn(current.maxCallsPerHour, 0, 5000),
        }
        const ops = Object.keys(next).map(field => ({ op: 'set', path: [field], value: next[field] }))
        setSaving(true)
        let ok = false
        try {
          ok = await form.mutate(ops, formState.revision)
        } catch {
          ok = false
        }
        setSaving(false)
        if (ok) { setDraft(null); setCustom(false); setNotice({ ok: true, text: t('saved') }) } else setNotice({ ok: false, text: t('saveFailed') })
      }

      const saveKey = async () => {
        const text = keyText.trim()
        if (text === '' || keyBusy) return
        setKeyBusy(true)
        const ok = await keys.save(text)
        setKeyBusy(false)
        if (ok) { setKeyText(''); setKeyNotice({ ok: true, text: t('keySaved') }) } else setKeyNotice({ ok: false, text: t('keySaveFailed') })
      }
      const removeKey = async () => {
        if (keyBusy) return
        setKeyBusy(true)
        const ok = await keys.remove()
        setKeyBusy(false)
        setKeyNotice(ok ? { ok: true, text: t('keyRemoved') } : { ok: false, text: t('keySaveFailed') })
      }

      const keyTag = keyState.status === 'loading' ? t('keyLoading')
        : keyState.status === 'error' ? t('keyError')
          : keyState.configured ? t('keySet') : t('keyUnset')

      return h('div', { className: 'dd-root' },
        h('style', null, STYLE),
        h('p', { className: 'dd-intro' }, t('intro')),
        !available ? h('p', { className: 'dd-hint' }, t('unavailable')) : null,
        available && !writable ? h('p', { className: 'dd-hint' }, t('readOnly')) : null,

        h(Field, { id: 'dsh-doorman-endpoint', label: t('endpoint'), hint: t('endpointHint'), error: presetId === 'custom' ? errors.baseUrl : null },
          h('select', {
            id: 'dsh-doorman-endpoint',
            className: 'dd-select',
            value: presetId,
            disabled: !writable,
            onChange: (event) => {
              const id = event.target.value
              if (id === 'custom') { setCustom(true); return }
              setCustom(false)
              const chosen = PRESETS.find(p => p.id === id)
              if (chosen) edit('baseUrl', chosen.url)
            },
          },
          h('option', { value: 'dashscope-cn' }, t('presetCn')),
          h('option', { value: 'dashscope-intl' }, t('presetIntl')),
          h('option', { value: 'custom' }, t('presetCustom'))),
          presetId === 'custom'
            ? h('input', {
              id: 'dsh-doorman-endpoint-custom',
              className: 'dd-input',
              type: 'url',
              'aria-label': t('customUrl'),
              'aria-invalid': errors.baseUrl ? 'true' : 'false',
              placeholder: 'https://',
              value: current.baseUrl,
              disabled: !writable,
              onChange: (event) => { edit('baseUrl', event.target.value) },
            })
            : null),

        h(Field, { id: 'dsh-doorman-model', label: t('model'), hint: t('modelHint'), error: errors.model },
          h('input', {
            id: 'dsh-doorman-model',
            className: 'dd-input',
            list: 'dsh-doorman-models',
            'aria-invalid': errors.model ? 'true' : 'false',
            value: current.model,
            disabled: !writable,
            onChange: (event) => { edit('model', event.target.value) },
          }),
          h('datalist', { id: 'dsh-doorman-models' }, MODEL_SUGGESTIONS.map(m => h('option', { key: m, value: m })))),

        h(Field, {
          id: 'dsh-doorman-key',
          label: t('key'),
          hint: keyState.writable ? t('keyHint') : t('keyFromEnv'),
          badge: h('span', { className: 'dd-tag', 'data-on': keyState.configured ? 'true' : 'false' }, keyTag),
        },
        h('div', { className: 'dd-row' },
          h('input', {
            id: 'dsh-doorman-key',
            className: 'dd-input',
            type: 'password',
            autoComplete: 'new-password',
            spellCheck: false,
            placeholder: t('keyPlaceholder'),
            value: keyText,
            disabled: !keyState.writable || keyBusy,
            onChange: (event) => { setKeyNotice(null); setKeyText(event.target.value) },
            onKeyDown: (event) => { if (event.key === 'Enter' && !event.nativeEvent.isComposing) void saveKey() },
          }),
          h('button', { type: 'button', className: 'dd-button', 'data-primary': 'true', disabled: !keyState.writable || keyBusy || keyText.trim() === '', onClick: () => { void saveKey() } }, t('saveKey')),
          h('button', { type: 'button', className: 'dd-button', disabled: !keyState.writable || keyBusy || !keyState.configured, onClick: () => { void removeKey() } }, t('removeKey'))),
        keyNotice ? h('p', { className: keyNotice.ok ? 'dd-ok' : 'dd-error', role: 'status' }, keyNotice.text) : null),

        h('details', { className: 'dd-details' },
          h('summary', { className: 'dd-summary' }, t('advanced')),
          h(Field, { id: 'dsh-doorman-timeout', label: t('timeout'), hint: t('timeoutHint'), error: errors.timeoutSeconds },
            h('input', {
              id: 'dsh-doorman-timeout',
              className: 'dd-input',
              inputMode: 'numeric',
              'aria-invalid': errors.timeoutSeconds ? 'true' : 'false',
              value: current.timeoutSeconds,
              disabled: !writable,
              onChange: (event) => { edit('timeoutSeconds', event.target.value) },
            })),
          h(Field, { id: 'dsh-doorman-max-calls', label: t('maxCalls'), hint: t('maxCallsHint'), error: errors.maxCallsPerHour },
            h('input', {
              id: 'dsh-doorman-max-calls',
              className: 'dd-input',
              inputMode: 'numeric',
              'aria-invalid': errors.maxCallsPerHour ? 'true' : 'false',
              value: current.maxCallsPerHour,
              disabled: !writable,
              onChange: (event) => { edit('maxCallsPerHour', event.target.value) },
            }))),

        h('div', { className: 'dd-footer' },
          notice ? h('p', { className: notice.ok ? 'dd-ok' : 'dd-error', role: 'status' }, notice.text)
            : dirty ? h('p', { className: 'dd-hint' }, t('unsaved')) : h('p', null),
          h('button', { type: 'button', className: 'dd-button', 'data-primary': 'true', disabled: !writable || !valid || !dirty || saving, onClick: () => { void save() } }, saving ? t('saving') : t('save'))))
    }

    return {
      inject: ['slots', 'locale', 'remote', 'remote.credentials', 'configForms'],
      apply(ctx) {
        ctx.effect(() => ctx.locale.register(NS, { zh, en }), 'dsh-doorman: dictionaries')
        const keys = createKeyStore(ctx)
        ctx.effect(() => ctx.remote.$on('credentials/reference-updated', (ref) => {
          if (String(ref) === KEY_REF) void keys.refresh()
        }), 'dsh-doorman: key status')
        void keys.refresh()
        const configForm = ctx.configForms.get(ENTRY)
        // Bound once: React's store subscription needs stable functions that keep the form's `this`.
        const form = {
          subscribe: listener => configForm.subscribe(listener),
          getSnapshot: () => configForm.getSnapshot(),
          mutate: (ops, revision) => configForm.mutate(ops, revision),
        }
        const face = { doorman: { form, keys } }
        ctx.slots.inject('plugins.bundle.config', () => ctx.slots.register({
          name: 'plugins.bundle.config', key: 'dsh-doorman', locale: NS, inject: () => face,
        }, DoormanSettings))
      },
    }
  },
})

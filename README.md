# dsh-doorman

> **Work in progress — not ready for use.** / **开发中，暂不可用。**

An unofficial, community-built plugin for [DeepSeek Harness (dsh)](https://github.com/deepseek-ai/deepseek-harness)
that triages sandbox-escalation approval prompts: hard rules, an exact allowlist, and a second-model review,
with the sandbox kept on. It is not affiliated with DeepSeek.

社区成员独立开发的 dsh 非官方插件：在提权审批弹窗出现前，按“硬性规则 → 精确放行清单 → 第二家模型审查”分流，沙箱始终保持开启。

The current code (stage 3b) runs the hard rules, the allowlist and the model review. By default it only observes: every
prompt still reaches the user, and the plugin logs what it would have done. Auto mode acts only when all of these hold:
`mode: auto` in the profile, a dsh version the plugin was checked against and the user confirmed
(`autoModeConfirmedForVersion`), and a session whose permission preset is `doorman`. Then a hard-rule deny or a model deny
is rejected, a model allow is allowed once (after a snapshot of the outside files it changes), and everything else still
goes to the user — except in a turn nobody is watching (a scheduled reminder), where it is rejected instead of left waiting.
The allowlist only shadows: entries are fingerprinted (exact command, place and the hashes of the files it depends on) and
what would be added, hit or blocked is logged, but it never allows anything and `allowlist.json` is never written.
It loads on dsh 0.2.x (`engines.dsh`: `>=0.2.0-rc.2 <0.3.0-0`) and was checked against the dsh 0.2.0-rc.2,
0.2.1-rc.1 … rc.5 and 0.2.2-rc.1 sources. On 0.2.2 the new `apply_patch` file tool (off in dsh's shipped bundles) is not
judged: its escalations reach the user unchanged.

Turning auto mode on (both edits go in the profile's `cordis.patch.yml`, which the agent cannot change; restart dsh after):

```yaml
- id: permission
  name: '@deepseek-ai/dsh-permission-presets'
  config:
    presets:              # restate the three built-in presets; doorman must come after workspace-write
      read-only:
        sandbox: read-only
        approval: ask
      workspace-write:
        sandbox: workspace-write
        approval: ask
      danger-full-access:
        sandbox: danger-full-access
        approval: never
      doorman:
        sandbox: workspace-write
        approval: ask
        name: 门卫自动审批
        description: 沙箱照旧；提权申请先由 dsh-doorman 判断，能确定的自动放行或拒绝，其余照常弹给你。
- id: dsh-doorman
  name: dsh-doorman
  config:
    mode: auto
    autoModeConfirmedForVersion: 0.2.2-rc.1   # the running dsh version
```

Then pick “门卫自动审批” in a session's permission menu. Without the plugin that preset behaves exactly like
`workspace-write`. It has to be listed after `workspace-write`: unless a default preset is set, dsh gives new sessions
the first preset that matches the default sandbox and approval policy.

Running other installed plugins' skill scripts is treated like running dsh's own bundled tools; a plain `git push` to a
configured remote is left to the model (force/mirror/delete/ad-hoc-URL pushes are handed to you).
Design notes (Chinese): [docs/design.zh.md](docs/design.zh.md).

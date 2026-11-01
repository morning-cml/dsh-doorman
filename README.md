# dsh-doorman

> **Work in progress — not ready for use.** / **开发中，暂不可用。**

An unofficial, community-built plugin for [DeepSeek Harness (dsh)](https://github.com/deepseek-ai/deepseek-harness)
that triages sandbox-escalation approval prompts: hard rules, an exact allowlist, and a second-model review,
with the sandbox kept on. It is not affiliated with DeepSeek.

社区成员独立开发的 dsh 非官方插件：在提权审批弹窗出现前，按“硬性规则 → 精确放行清单 → 第二家模型审查”分流，沙箱始终保持开启。

The current code (stage 3a) runs the hard rules, the allowlist and the model review in observe-only mode: every prompt still
reaches the user, and the plugin only logs what it would have done. The allowlist only shadows: entries are fingerprinted
(exact command, place and the hashes of the files it depends on) and what would be added, hit or blocked is logged, but
`allowlist.json` is never written. It loads on dsh 0.2.x (`engines.dsh`: `>=0.2.0-rc.2 <0.3.0-0`) and was checked
against the dsh 0.2.0-rc.2 and 0.2.1-rc.1 … rc.5 sources.
Running other installed plugins' skill scripts is treated like running dsh's own bundled tools; a plain `git push` to a
configured remote is left to the model (force/mirror/delete/ad-hoc-URL pushes are handed to you).
Design notes (Chinese): [docs/design.zh.md](docs/design.zh.md).

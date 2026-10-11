# dsh-doorman

> **Work in progress — not ready for use.** / **开发中，暂不可用。**

An unofficial, community-built plugin for [DeepSeek Harness (dsh)](https://github.com/deepseek-ai/deepseek-harness)
that triages sandbox-escalation approval prompts: hard rules, an exact allowlist, and a second-model review,
with the sandbox kept on. It is not affiliated with DeepSeek.

社区成员独立开发的 dsh 非官方插件：在提权审批弹窗出现前，按“硬性规则 → 精确放行清单 → 第二家模型审查”分流，沙箱始终保持开启。

The current code (stage 2) runs the hard rules and the model review in observe-only mode: every prompt still reaches the user,
and the plugin only logs what it would have done.
Design notes (Chinese): [docs/design.zh.md](docs/design.zh.md).

# 门卫重构 · 最终修改计划

> 这份文件是门卫（dsh-doorman）重构的**唯一推进依据**。以后开新对话，只读这份 + 代码即可按阶段往下做，不必重开已定的决策。
> 配套：架构总览（私有 artifact）<https://claude.ai/artifact/9aTPt3gVSvyej4KKRPGimA>；设计全文见 [design.zh.md](design.zh.md)（阶段/清单/事后检查/快照的细节在 §2、§5、§6、§7）。
> 背景：起因是把门卫的严谨内核与 `dsh-approval-gate` 的自动化体验结合（见 memory `doorman-refactor-direction`、`approval-gate-reference`）。

## 0. 怎么用这份文件

- 严格按阶段顺序推进：3a → 3b → 3c → 4。每阶段有「目标 / 动的文件 / 步骤 / 验收 / 仍观察的保证」。
- 每阶段收尾必须：① `npm test` 全过；② 用两周日志离线重放（replay 思路见 §4），人工核对无误放。
- **默认 observe，任何一步都能把 `mode` 退回 observe 回到安全态。**
- 决策已定，照做即可；只有真·拿不准时才回头问用户。

## 1. 铁律（governing invariants，任何改动与之冲突即为错）

1. **不信任自述**：以真实命令 / 文件写入为准解析判断；`justification` 只作参考、标注不可信，绝不作放行依据。
2. **拿不准就保守（fail-safe）**：取不到参数、解析失败、超时、报错、格式不合、超额、无 key——一律交给你，绝不自动放行。
3. **纵深防御、先快后稳**：本机确定性分析在前，模型最后最窄地仲裁，且只能选 allow/ask/deny，改不了任何规则。
4. **可回补优先**：只自动放行范围清楚、影响有限、可回补的操作。
5. **绝不削弱 dsh**：沙箱常开（workspace-write）；dsh/插件/凭据绝对保护；“运行”自带或插件脚本 ≠ “修改”它们。
6. **数据最小化 + 独立第二家模型**：出机内容最少且脱敏，key 永不入日志；复核用独立模型，不借 agent 那家。
7. **可审计、可撤销**：每次决定留痕；自动放行的文件改动写前快照，可看 diff、可一键投递撤销。
8. **人始终在环**：按会话显式开启，默认观察；学习只从明确确认过的操作沉淀，并绑定精确指纹。

## 2. 竞品对照：吸收什么 / 刻意不做什么 / 为什么

调研对象：`dsh-approval-gate`（110★）、官方 `@deepseek-ai/dsh-experimental-auto-review`、`dsh-jev-interceptor`、`dsh-agentfuse-plugin`、`dsh-edit-approval`、`dsh-approval-policy`。

### 2.1 要吸收（并入下面的阶段）

| 来源 | 吸收点 | 落到哪 |
|---|---|---|
| 官方 auto-review | 「判定实际效果，而非名称/自称意图」——印证铁律 1，继续坚持 | 全程 |
| 官方 auto-review | 送审请求的**分区结构**（环境 cwd / 项目指令 / 过滤历史 / 待办动作），送真实参数而非理由 | 3c（L3 payload 可按此补项目指令、必要时过滤历史） |
| 官方 auto-review | 严格 JSON 协议（`low+allow` / `medium+allow\|deny` / `high+deny`，只 deny 带 reason）；超大请求 fail-closed 不截断 | 已有 `verdict.js` 近似实现，3c 对齐措辞 |
| approval-gate | 确认制学习（确认 N 次后自动放行） | 3a（L2，但绑指纹，非理由） |
| approval-gate | 改动前快照 + 行级 diff + 一键撤销 UI；设置页热更新；按会话预设开启 | 3b 快照 / 3c UI / 3b 预设门 |
| jev-interceptor | shadow 模式记**反事实收据**（本来会放/会拦）+ 净收益/阈值建议的分析视图 | 3a 的影子记录 / 3c UI 的统计 |
| jev-interceptor | 模型输出多轴（风险 + 不可回补 + 注入嫌疑），低置信不猜直接降级 | 3c（similarity/复核的输出可加“不可回补”轴；门卫已有注入检测在 L1） |
| agentfuse | 「拒绝 = 带证据的策略决定，不是执行失败」的措辞；证据 = reason code + policy id + **命令规范化哈希**，不存原始参数/凭据 | 3a 事件/日志里增加规范化哈希做去重/指纹，facts 证据化 |
| edit-approval | diff 用和 dsh 结果卡**同算法同 3 行上下文**（jsdiff `structuredPatch`，Myers），看起来原生 | 3c diff（见 §3.3 的零依赖取舍） |
| edit-approval | 配置单一来源：斜杠命令与设置页改**同一份**配置，不会打架 | 3c（若加斜杠命令） |
| approval-policy | **无人值守检测**：subagent / scheduled / cron 会话没人应答，auto 模式下不能无限挂起 | 3b（auto 下这些会话 fail-closed，不是“交给你”） |
| approval-policy | 用 `peerDependencies` 声明 dsh 地板（0.1.7+ 预检读它做兼容检查），和 `engines.dsh`（0.2.1+ 强制）并存 | 4（版本门已用 engines，可补 peerDependencies） |

### 2.2 刻意不做（和官方/竞品的明确分野，别“顺手抄”）

- **不复用 agent 自己那家模型**：官方 auto-review 和 approval-gate 都复用当前 agent 的 provider/model。门卫坚持**独立第二家**，避免同源偏置与被同一次投毒影响（铁律 6）。代价是多配一个 key，值得。
- **不审每一个工具调用**：官方审全部（因为它跑在 full-access 预设、别无防线）。门卫**只审沙箱提权弹窗**，其余交给沙箱挡——范围更窄、更稳、更省（铁律 3/5）。
- **做放行清单，但承认这是取舍**：官方**刻意不做**缓存/放行清单，理由是“会削弱固定的安全上限”。门卫选择做 L2，用 **指纹 + 依赖文件哈希 + 事后检查 + 永不进清单 + 先观察** 把风险压住。若某天重放/事后检查证明误放，退回“只影子记录清单、不真正放行”。这是清醒的权衡，不是疏忽。
- **不跑在 full-access 预设**：门卫保持 workspace-write 沙箱常开，只裁决提权；不把会话整个放成 full-access（铁律 5）。

## 3. 阶段计划（可执行）

> 现状：**3a 已完成**（2026-11-01，插件 0.3.0：observe + 硬规则 L1 + 影子放行清单 L2 + 模型复核 L3，全部只记日志；
> 落地细节和重放结果见 design §15）。跑在 dsh 0.2.1-rc.5（已核实）。**下一步：3b。**

### 3a — 放行清单 L2 + 指纹 + 事后检查（仍 observe，清单只影子记录）

> **✅ 2026-11-01 完成（插件 0.3.0）**。比下面列的多动了：`lib/rules/analyze.js`（记下每条子命令的目录与参数 `invocations`、
> 改了哪些环境变量/别名/函数 `sessionChanges`、npm 实际运行的目录）、`lib/model/payload.js`（修 `cd` 之后送错 package.json）。
> “永不进清单”按“判不出依赖”补全（没有配方的程序、嵌套 shell、改环境变量、工作区外运行等，见 design §15）。
> 新增 `tools/replay.mjs`：每阶段收尾的离线重放（只读日志）。重放结果：会加入 2 条、命中 0、移出 0、误放 0。

**目标**：把 design §5 的放行清单落地为“影子”形态——算出“本来会进清单 / 会命中 / 会移出”，写进日志供核对，但**不真正放行、不真正写清单**。

**动的文件**
- 新建 `lib/store/fingerprint.js`：从 `facts`（analyze 产出）算依赖文件集合与 SHA-256；判断命令是否“可进清单”。
  - 依赖映射：`npm/pnpm/yarn install` → `package.json` + 锁文件；`npm run x` → `package.json`；`make` → `Makefile`；`python x.py` → `x.py`；判不出依赖的命令**不进清单**。
  - 永不进清单（硬排除）：`facts.opaque` 非空（含 `$(…)`/`iex`/脚本块/`-c` 等看不穿写法）；删/移/覆盖工作区外已有文件（看 `facts.deletes/moves/writes` 的 `outside`）；`write`/`edit` 文件工具（只做单次判断）。
- 新建 `lib/store/allowlist.js`：读写 `~/.dsh/dsh-doorman/allowlist.json`（条目结构见 design §5）。
  - 原子写：临时文件 + `rename`，照抄 `state.js` 的写法。
  - 热更新：记 mtime，文件一变即重载（approval-gate 的做法）。
  - 查询：精确匹配 `tool + workspace + workdir + command`（只 trim 首尾空白，**无通配**）且 `dependsOn` 每个文件哈希全未变 → 命中；`status==='blocked'` 的条目 → 返回“应 ask”。
- 改 `lib/engine.js`：`hard` 判定 `pass` 后，增加 L2 查询，返回新 `layer`：`allowlist-hit`（指纹命中）/ `allowlist-blocked`（命中 blocked 条目）/ 继续到 `hard-pass`（未命中，走 L3）。保持纯函数：allowlist 实例由 runtime 注入。
- 改 `lib/runtime.js`：
  - `onApproval`：L2 命中时记 `proposed: 'allow-once'`（observe 下仍交给你）；blocked 记 `proposed: 'ask'`。
  - `onResult`（事后检查）：对“放行/清单命中”的调用结束后，用确定性信号（`failed()`、`accessDenied`、退出码、超时、被终止、`kind` 为 background/promoted 无退出码）判断：
    - 干净且满足进清单条件 → 记一条 `allowlist-would-add`（**observe 下只记，不真写**）。
    - 清单命中但事后有问题 → 记 `allowlist-would-remove`（标记 would-block）。
  - 证据化（借 agentfuse）：事件里加命令的规范化哈希，供去重与指纹，不额外存原始参数。
- 事后检查送审（design §2 第 2 条，限长打码输出交模型问“有无异常”）：本阶段**先只做确定性信号**，模型事后检查放到 3b 以后再接（省调用）。

**验收**
- 新增 `test/allowlist.test.js`、`test/fingerprint.test.js`：指纹稳定性、哈希绑定、永不进清单的排除、精确匹配不被通配/空白绕过。
- 离线重放两周日志：打印“本来会进清单 / 命中 / 移出”统计，人工核对**无误放**（指纹 + 依赖哈希不把不同命令当同一条）。
- `npm test` 全过。

**保证**：`mode` 仍 observe；allowlist **只影子记录**，不写文件、不真放行；可随时删掉 L2 查询回到纯 L1+L3。

### 3b — auto 模式真正执行 + 写前快照 + 无人值守兜底

**目标**：打开自动模式（按会话），真正按判定放行/拒绝；写文件前拍快照；无人值守会话绝不挂起。

**动的文件**
- 新建 `lib/store/snapshots.js`：自动放行且涉及文件时，**写入前**存快照到 `~/.dsh/dsh-doorman/snapshots/<eventId>.json`。限额借 edit-approval：仅文本、单文件 ≤256KB、每事件 ≤5 个文件；超限不存、标记不可 diff。命令类按 design D3 的浅快照（工作区外被点名目录：文件名/大小/修改时间，最多 5 目录 2 层 2000 项）。
- 改 `lib/runtime.js`：
  - `autoAvailable = true`；`mode()` 为 auto 且 `autoModeConfirmedForVersion === dshVersion` 时，`onApproval` **真正返回决定**（allow-once 放行 / reject 拒 / ask 交给你），不再只记录。allowlist 命中此时真正写入/更新 `hits`、`lastUsedAt`；事后检查真正加入/移出条目。
  - **无人值守兜底（借 approval-policy）**：auto 模式下，若会话无人盯（`session.header.origin === 'subagent'`，或该 turn 最后一条溯源 user 消息 `source.kind` 为 `schedule`/`cron`），则“交给你”没有意义 → 直接 **fail-closed 拒绝**，reason 写明“无人值守会话，fail-safe 拒绝”。绝不无限挂起。需在 `sessionInfo` 里补读 origin / 最后溯源消息（实现时核实 dsh 会话事件接口）。
- **按会话预设开启（借 official / approval-gate）**：除全局 `mode` 外，支持用权限预设决定本会话是否启用 auto（这样只对可信会话开）。实现时核实 dsh `permissionPresets` 的贡献/读取接口（官方用 `permissionPresets.current(session.events)`；approval-gate 贡献一个 `auto-approve` 预设）。门卫保持 workspace-write 沙箱，不改成 full-access。

**验收**
- auto 模式单测（真正返回 allow-once/reject/ask）；无人值守会话 fail-closed 单测；快照读写与限额单测。
- 在一个可信会话手动试跑 git push / npm install / archify，确认放行与快照正确。
- **这步是行为改动、需用户亲自试**：按 CLAUDE.md 例外，**先别提交**，把要试的点告诉用户，确认后再提交推送。

### 3c — 审查 UI（时间线 + diff + 撤销）+ 同类验证

**目标**：把“看得见、能撤销”的审查体验接上；补指纹未命中时的同类验证（对命令，不对理由）。

**动的文件**
- 改 `client.js`（现已有设置页）：加“审批”视图（`conversation.view`，倒序展示 auto 放行 / 人工通过 / 拒绝）+ 输入框上方提示条（`conversation.input.dock`）。严格用 dsh 的 `--dsw-alias-*` tokens（现已在用），深浅色都可读。
- 新建 host 侧只读接口（挂在 `webServer`）：`events.jsonl` 追加结构化事件；`GET` 事件（按 sessionId + since 增量）；`GET` diff；`POST` 撤销（组装撤销指令投递会话，`typertGateway` 优先、`agent.followup` 兜底——接口名实现时核实官方 auto-review / approval-gate 的用法）。
- diff 算法：优先和 dsh 结果卡一致（jsdiff `structuredPatch`，Myers，3 行上下文）。**零依赖取舍**：门卫当前无运行时依赖；若不想引入 jsdiff，就自写一个最小行级 Myers diff（只返回变更行，上限 ~500 行，approval-gate 的近似逐行也可）。记在已知局限里。
- 新建 `lib/model/similarity.js`：指纹未命中但有确认样本时，把“本次命令 + 静态事实 + 样本的命令 + 静态事实”送独立模型判 `SAME`/`DIFFERENT`（**对命令与 facts，绝不对 justification**）；`DIFFERENT`/失败 → 交给你。接到 L3，仅作用于“可进清单类别”的未命中项。
- L3 送审可按官方分区补项目指令（AGENTS.md 约束）等上下文，仍全部脱敏。

**验收**：UI 深浅色可读；diff 面板正确；撤销指令可投递；`similarity` 单测（SAME 放行 / DIFFERENT 人工 / 失败 fail-safe）。**UI 改动需用户亲自看，先别提交，确认后再推。**

### 4 — 适配 dsh 0.2.2+

- 0.2.2 重写了审批服务：`user-approval` 用 session projection 记 policy/turn；提权 `displayReason` 从 `sandbox/src/locales.ts` 生成。
- 等 0.2.2 进桌面端：按 memory `dsh-source-verification` 的清单 diff，核实 `approval/request` 瀑布、`escalate sandbox to <mode>: <justification>` 串格式、`permissionPresets` 贡献接口；通过后加进 `lib/dsh-env.js` 的 `VERIFIED_DSH_VERSIONS` 并放开 auto。
- 顺带：`package.json` 可补 `peerDependencies` 声明 dsh 地板（和现有 `engines.dsh` 并存）。

## 4. 每阶段通用约束

- 收尾先 `npm test` 全过，再离线重放两周日志核对（`node tools/replay.mjs [--since YYYY-MM-DD]`：用真实 host 构造 `decide()`+`buildPayload()` 跑历史 `request` 行，对比层级、清单事件与送审内容，并检查送审内容里有没有真实用户路径；只读日志）。
- 默认 observe；四条底线任何阶段都不破：**脱敏、独立模型、fail-safe 处处兜底、版本门**（未核实的 dsh 版本自动退回 observe）。
- 代码改动直接 `git commit` + `push`（CLAUDE.md）；**但界面/交互/需用户亲自试的改动（3b 执行、3c UI）先别提交，等用户确认**（CLAUDE.md 例外）。
- key 绝不入日志、不进仓库；送审内容重放后必须 **0 条**含真实用户路径（见 design §14 的脱敏漏洞修复）。
- 每加一个可自动放行的新口子，都要能在日志里先看它“本来会放哪些”，确认不误放再真放。

## 5. 关键取舍备查（给未来的自己和用户）

- **L2 放行清单 vs 官方“不缓存”**：我们做，靠指纹 + 依赖哈希 + 事后检查 + 永不进清单 + 先观察控风险；证明误放就退回“只影子记录”。
- **独立第二家模型 vs 复用 agent 模型**：坚持独立，成本换独立判断与抗投毒。
- **只审提权 vs 审全部**：坚持只审提权，依赖沙箱兜底，范围窄、稳、省。
- **判命令 vs 判理由**：这是门卫相对 approval-gate 的根本价值，任何阶段不得退让。

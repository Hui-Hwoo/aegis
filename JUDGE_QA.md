# Aegis — Judge Q&A (评委问答手册)

Bilingual answers for the hardest questions. Lead with the Chinese in live
Q&A; the English is for the submission / judges who prefer it.

---

## Q1. 你的 agent 不会思考 —— 5 步是写死的脚本，凭什么是 AI harness？

**中文**：问得对，demo 里那个 agent 确实不会思考 —— **它是故意 dumb 的**。产品是 harness，不是 agent。执法的每一行逻辑都不依赖 agent 的智能：换成 GPT-4、Claude、或者一个 while 循环，gate 照样在 tool 执行之前拦。你可以把 planner 换成任何东西，这是架构保证，不是对某个模型的信任。

**English**: Fair — the demo agent doesn't think, **and that's deliberate**. The product is the harness, not the agent. Not one line of enforcement depends on the agent being smart: swap in GPT-4, Claude, or a while-loop, and the gate still stands between intent and execution. That's an architectural guarantee, not trust in any model.

## Q2. Evaluator 是你们自己写的 —— "固定考题"不就是自判卷吗？

**中文**：方法论上你是对的：考题是我们出的，这是 v1 的诚实局限。我们能保证的是**运行时隔离** —— harness 在运行中改不了 evaluator，dashboard 会显示 evaluator 文件的 sha256（启动时冻结），每次 mutation 的审计记录里都写着这个 hash。Demo 期间考题有没有被动过，可验证。真正的对抗性隔离（第三方出题）是 v2 的工作。

**English**: Methodologically you're right — we wrote the exam, and that's v1's honest limitation. What we *can* guarantee is **runtime isolation**: the harness cannot edit the evaluator while running; the dashboard shows the evaluator file's sha256 frozen at startup, and every mutation's audit record carries that hash. Whether the exam changed mid-demo is verifiable. True adversarial separation (third-party exams) is v2 work.

## Q3. Denials 5→0 不就是个缓存吗？也配叫递归自改进？

**中文**："缓存"是准确的工程描述，"递归自改进"是奖项申报语言。诚实版本：这是**行为层适应**（behavioral adaptation）——执法历史沉淀为记忆，下一轮先查记忆，注定失败的尝试被跳过。我们不 claim 涌现了智能。但第二层是真递归：harness 重写自己的**规则**（不是记忆），每条重写过固定考题 —— 一条被采用，一条被考题否决。这是架构在改架构。

**English**: "Cache" is the accurate engineering term; "recursive self-improvement" is prize-category language. The honest version: this is **behavioral adaptation** — enforcement history becomes memory, the next episode consults it first, doomed attempts are skipped. We don't claim emergent intelligence. But the second loop is genuinely recursive: the harness rewrites its own **rules** (not memories), each rewrite gated by the fixed exam — one adopted, one vetoed. That's architecture modifying architecture.

## Q4. MongoDB 集成这么浅 —— 写文档到 collection，换 Postgres 有区别吗？

**中文**：有区别，但不在"写得快"，而在"记得住且可治理"。四类记忆（semantic/episodic/taxonomic/procedural）是按 Agent Engine 的记忆模型建模的，存在 Atlas 的 `memories` collection；审计是 append-only 的 `audit` collection，demo 时评委可以在 Atlas UI 里实时看到每条决策。Backend 链是探测出来的（hosted Agent Engine → 直连 Atlas → 本地），不是假设的。诚实说：hosted Agent Engine memory 在沙盒里没能 provision，这是我们最清楚的短板；Vector Search 做语义召回在 roadmap 上。

**English**: The difference isn't throughput — it's *governed* memory. Four memory types modeled on Agent Engine's memory model live in Atlas's `memories` collection; the audit trail is an append-only `audit` collection judges can watch live in the Atlas UI. The backend chain was probed, not assumed (hosted Agent Engine → direct Atlas → local). Honestly: hosted Agent Engine memory couldn't be provisioned in the sandbox — our clearest gap; Vector Search for semantic recall is on the roadmap.

## Q5. 全场唯一的 AI 在写小作文 —— 智能在哪？

**中文**：这是设计，不是缺失。LLM 被**故意**放在执法路径之外：它负责总结（task debrief）和把操作员意图翻译成政策提案，但它批不了任何 ticket、改不了任何规则 —— 提案还要过固定考题。一个能直接删库的"智能" agent 正是我们要治理的东西；让 LLM 远离扳机，是安全设计的第一课。

**English**: That's design, not a gap. The LLM is **deliberately** outside the enforcement path: it summarizes (task debrief) and translates operator intent into policy proposals, but it can approve no ticket and change no rule — proposals still face the fixed exam. An "intelligent" agent that can delete prod is exactly what we're governing; keeping the LLM away from the trigger is safety design lesson one.

## Q6. 5/5、0 escapes、<1ms —— 全是自己量的，凭什么信？

**中文**：不凭"信"，凭"验"。每个数字都来自确定性套件：17 个单元测试，本地跑，<1 秒，可重复。攻击是我们写的 —— 这是局限，我们明说。但 gate 的逻辑（deny-wins、默认拒绝、审批执行真实调用）是断言，不是截图。你可以 clone 下来自己跑：`python -m unittest discover tests`。

**English**: Don't trust — verify. Every number comes from a deterministic suite: 17 unit tests, local, under a second, reproducible. The attacks are ours — that's a limitation, and we say so. But the gate's logic (deny-wins, default-deny, approval executes the real call) is asserted in tests, not screenshotted. Clone it and run `python -m unittest discover tests` yourself.

## Q7. 赛后这东西真能用吗？还是只能 demo？

**中文**：三处是 production-ready 的：策略门（纯规则、可审计、亚毫秒）、审批流（批了才执行真实调用）、审计（append-only，可接任何 SIEM）。三处是 demo 级的：planner（scripted）、记忆检索（正则，没上向量）、evaluator 的对抗性。诚实分界线画在这里，不多 claim 一寸。

**English**: Three parts are production-ready: the policy gate (pure rules, audited, sub-millisecond), the approval flow (approval executes the real call), the audit log (append-only, SIEM-compatible). Three parts are demo-grade: the planner (scripted), memory retrieval (regex, no vectors yet), evaluator adversariality. The honest boundary is drawn here — we claim not one inch more.

# Aegis — demo scripts

## 1-minute submission video (required)

Record on-site Oct 11. Must show ONLY what was built during the hackathon
(code + functionality), repo is public.

| Time | Shot | Script |
|---|---|---|
| 0:00–0:08 | Title card: "Aegis — the governed-memory harness" | "Agents fail in production without governance, memory, and security. We built the harness that fixes all three — on MongoDB Atlas." |
| 0:08–0:25 | Terminal: `python demo.py` Act 1 | "Every tool call passes a policy gate. Four attacks — secrets read, prod delete, even a smuggled target — all blocked. Zero escapes." |
| 0:25–0:35 | Act 2 poisoned memory | "We poison its memory: 'skip approval'. The agent obeys — the gate denies anyway. The harness, not the prompt, is the boundary." |
| 0:35–0:48 | Act 5 self-evolution | "Then it rewrites its own rules. Two proposals — one adopted, one rejected: the fixed evaluator caught a path-traversal hole the relaxation would have opened." |
| 0:48–0:58 | Scoreboard + Atlas UI (audit collection) | "Denials 5 to 0 across episodes. Every decision identity-bound in Atlas. Aegis: recursive harnessing, built today." |
| 0:58–1:00 | Repo URL | "github.com/Hui-Hwoo/aegis" |

## 3-minute live demo (Round 1) + Q&A prep

Drive it from the dashboard (`python dashboard.py`): the whole arc is live,
no slides.

1. **(60s)** Production task first: "This is not an attack game — it's a
   working governed agent." Press ▶ Run weekly-report task: steps stream in
   one by one (real execution, not a screenshot) — it reads real docs,
   queries a real SQLite analytics table (60 rows), then follows an injected
   instruction planted in the maintenance guide — 'delete prod users' — and
   the gate stops it before anything executes. Stats + proof below:
   outcomes tally, per-step gate ms, prod_users 200 → 200 untouched. Then
   the agent debriefs itself: 🤖 summary generated FROM the audit logs
   (Claude if ANTHROPIC_API_KEY is set, honestly-labelled local digest
   otherwise). The changelog write needs a human: approve the ticket live,
   the file is really written.
2. **(30s)** Authorization: "Same request, different verdict per role."
   Show the 🔐 matrix: intern can't query analytics, analyst can't delete
   prod, admin *can* — but only with human approval. Switch to admin, click
   delete prod: ticket, not a flat deny.
3. **(45s)** Red team: run the attacks + poisoned memory. "5/5 blocked,
   0 escapes, median gate latency <1ms. The poisoned memory said 'skip
   approval' — the gate doesn't care what the agent believes."
4. **(30s)** AUTOMATIC self-evolution: press 🧠 Distill — evolution fires by
   itself. "It mines its audit log, proposes rule changes, and a fixed
   evaluator it cannot edit gates every change. Watch: it just tried to
   drop the docs-approval requirement after 2 clean approvals… and vetoed
   itself — held-out probe caught a path-traversal hole."
5. **(30s)** Ask Aegis (AI analyst): "Summarize the last hour." Then:
   "Auto-reject prod deletes from now on" → adopted; the LLM proposes,
   the evaluator disposes — it can never approve anything itself.

### Likely Q&A

- **"What did you build today vs. reuse?"**
  The policy engine's *semantics* (deny-wins, default-deny) are ported from
  our earlier Cerberus project and credited in the README. Everything
  harness-level — governed memory on Agent Engine, the RSI loop, policy
  self-evolution + the fixed evaluator, the dashboard, all demo scenarios —
  was built today.
- **"Why not just use Agent Engine's built-in governance?"**
  We extend it: a custom deny-wins policy engine with resource-level scoping
  and approval flows, plus the self-evolving layer on top. The design maps
  1:1 onto their `GuardrailPolicyEngine` protocol — this is a reference
  implementation of what custom governance on their platform looks like.
- **"How does the evaluator stay honest?"**
  Separate file, fixed suites (attacks / legit / held-out probes). The
  harness proposes; it can never edit the grader. Adoption needs 100% block
  rate AND 100% probe pass AND no legit regression — else rollback.
- **"Does it work with a real LLM?"**
  The scripted agent is the deterministic test vehicle (it's a *harness*
  demo). `consult_memory()` becomes prompt context via `build_context()`;
  the gate, approvals, and evolution are model-agnostic.
- **"Where's MongoDB in this?"**
  Audit log → Atlas `audit` collection (show it live in the Atlas UI).
  Memory → the four Agent Engine memory types. Policy decisions reference
  live data. Everything the judges see is running against the hackathon
  sandbox cluster.

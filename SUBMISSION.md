# Aegis — Submission Pack

> Copy-paste ready answers for the Cerebral Valley submission form
> (The Harness Engineering & Model Wrangling #SFTechWeek Hackathon).
> **Keep in sync with the repo** — update this file whenever the project changes.

---

## 1. Project Description

Aegis is a governed-memory harness for AI agents on MongoDB Atlas. Problem:
production agents fail on governance, not intelligence — an agent asked to
update docs can delete a prod database, stopped by nothing but prompt
obedience. Aegis puts every tool call through a policy gate (deny-wins,
default-deny, resource scoping, role-based access, human approvals), governs memory itself across
all four Agent Engine memory types, and writes an identity-bound audit log to
Atlas. Tools execute for real against a sandboxed filesystem and SQLite —
a blocked prod delete provably leaves all 200 rows intact. It learns two ways: enforcement history distills into
episodic/procedural memory (denials 5→0 across episodes), and the harness
automatically rewrites its own rules after each episode — each mutation gated
by a fixed evaluator it cannot edit (one adopted, one rejected after a
held-out probe caught a path-traversal hole). Live: 5/5 attacks blocked, 0 escapes, including a
poisoned-memory attack. An AI analyst ("Ask Aegis") answers natural-language
questions over the audit log and turns operator intent ("auto-reject prod
deletes from now on") into policy proposals — still gated by the fixed
evaluator, read-only by construction. The production task runs in two modes: a deterministic scripted run, and
a live Claude planner mode (🧠 Run with AI planner) where the LLM decides
each tool call and the gate governs every one — proving enforcement never
depends on the agent being smart. After each production task the agent
debriefs itself from the audit logs: the task streams step-by-step with
per-step gate latency and an outcomes tally (no mock data — every step
really executes), then an LLM (Claude via ANTHROPIC_API_KEY, or an
honestly-labelled local digest without a key) summarizes what ran, what was
blocked, and the proof — reading the same Atlas audit collection the judges
can inspect live.

Framing, stated plainly: the harness is the product — the governed demo
agent is intentionally simple, and enforcement never depends on the agent
being smart. The LLM is deliberately outside the enforcement path (it
summarizes and proposes; it can never approve or deny). All hard numbers
(5/5 attacks blocked, denials 5→0, gate latency) come from our own
deterministic suite — 17 unit tests, local runs — evidence, not an external
benchmark.

Solidity: 17 deterministic unit tests (deny-wins, default-deny, smuggled
targets, approval executes the real call, traversal guard, 3x3 role matrix,
evaluator baselines, mutation adopt/rollback, analyst intent parsing);
an observe mode that logs WOULD_DENY without blocking, for dry-running new
policies against live traffic; three held-out probes (including a reversed
smuggled-target probe); and a real per-step gate-latency readout in the
dashboard.

## 2. Public GitHub Repository

https://github.com/Hui-Hwoo/aegis

## 3. Demo Video

<!-- TODO: record the 1-minute video (see DEMO_SCRIPT.md), upload to YouTube, paste link here -->
`[paste YouTube link]`

## 4. Partner technologies used

**None — leave all checkboxes unchecked.**

We did not integrate AWS, ElevenLabs, Raindrop, Modelence, or Cursor products
into the build. Our fixed-evaluator design was informed by Raindrop's public
evaluation methodology (howtoeval.com), which is why we are separately
submitting for the Raindrop RSI Prize below.

## 5. Raindrop RSI Prize — Yes

Recursive self-improvement, two loops:

1. **Behavioral:** every denial and approval is distilled into episodic +
   procedural memory; the next episode consults memory first — denials drop
   from 5 to 0, wasted attempts are skipped, approvals become proactive.
2. **Architectural:** the harness mines its own audit log and rewrites its
   policy rules (e.g. dropping an approval requirement after 3 clean
   approvals). Every mutation must pass a fixed evaluator it cannot edit —
   100% block rate, 100% probe pass, no legit regression — or it is rolled
   back. Demo: 1 adopted, 1 rejected (the evaluator caught a path-traversal
   hole the relaxation would have opened).

## 6. Use of MongoDB products

- **MongoDB Atlas (hackathon Sandbox, Cluster0):** the `aegis` database hosts
  our `audit` collection. Every policy decision, approval request/decision,
  and memory read/write is appended as an identity-bound document —
  append-only, queryable live in the Atlas UI during the demo. This is the
  evidentiary backbone of the whole project: the harness's claims
  (block rate, approvals, self-evolution) are all verifiable against this
  collection.
- **Atlas Agent Engine:** integrated via the official
  `agent-engine-sdk-memory` Python SDK. Our `MemoryStore` exposes the four
  memory types — semantic (facts), episodic (events), taxonomic (terms),
  procedural (how-tos) — behind one governed interface: every read/write is
  policy-checked and audited. Backend chain (probed, not assumed): hosted
  Agent Engine memory when provisioned → **direct Atlas MongoDB** (the four
  types live in the `memories` collection, no Agent Engine deployment
  needed) → deterministic in-memory store. Offline-capable, Atlas-primary.
- **Architecture alignment:** our custom policy engine maps 1:1 onto Agent
  Engine's `GuardrailPolicyEngine` protocol (registered policy engines
  evaluated at runtime tool-call boundaries) — Aegis is a reference
  implementation of custom governance on the platform.
- **AI analyst ("Ask Aegis"):** the project's LLM component reads the Atlas
  `audit` collection (plus pending tickets, policy rules, memory stats) to
  answer natural-language operator questions ("summarize the last hour",
  "what needs my judgment?") and convert intent into policy proposals —
  each proposal validated by the fixed evaluator before adoption.

## 7. Feedback — MongoDB products

- Sandbox provisioning via the email invite link was smooth; pymongo
  integration took minutes, and the service-account flow in the Agent Engine
  console worked as documented.
- Gap: project-scoped memory routes return `AGENT_NOT_DEPLOYED` with no
  in-console path to provision a memory store without deploying a full
  agent. A "provision memory" action (or clearer error guidance) would help
  hackathon-scale projects.
- The SDKs are alpha with frequent breaking renames (e.g. `agentic` CLI →
  `agentengine`); pinning exact versions is currently essential.
- The 1-hour service-account token expiry is awkward for day-long
  demos/judging — longer-lived demo tokens would help.
- `GuardrailPolicyEngine` is a great extension point, but the runtime-stage
  enum values and dispatch semantics are thinly documented.

## 8. Feedback — partner products

N/A — no partner products were integrated into the implementation. (Our
evaluator design was informed by Raindrop's public methodology at
howtoeval.com.)

---

## Pre-submission checklist

- [ ] Repo is public: https://github.com/Hui-Hwoo/aegis
- [ ] 1-minute demo video recorded — shows ONLY work built during the hackathon
- [ ] Video link pasted in section 3 above (and in the form)
- [ ] Video has working audio + video playback (verify after upload)
- [ ] All team members added on the Cerebral Valley submission page
- [ ] Service-account token refreshed before final judging (expires hourly)
- [ ] `MONGODB_URI` points at the sandbox cluster (`cluster0.gch0op.mongodb.net`)
- [ ] Attribution respected: demo highlights today's work (see README
      "Attribution" section); pre-existing policy-engine core credited, not
      presented as new

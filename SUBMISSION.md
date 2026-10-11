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
default-deny, resource scoping, human approvals), governs memory itself across
all four Agent Engine memory types, and writes an identity-bound audit log to
Atlas. It learns two ways: enforcement history distills into
episodic/procedural memory (denials 5→0 across episodes), and the harness
rewrites its own rules — each mutation gated by a fixed evaluator it cannot
edit (one adopted, one rejected after a held-out probe caught a
path-traversal hole). Live: 5/5 attacks blocked, 0 escapes, including a
poisoned-memory attack.

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
  `agent-engine-sdk-memory` Python SDK. Our `MemoryStore` wraps it to expose
  the four memory types — semantic (facts), episodic (events), taxonomic
  (terms), procedural (how-tos) — behind one governed interface: every
  read/write is policy-checked and audited. When the hosted project backend
  is not provisioned (`AGENT_NOT_DEPLOYED`), it degrades to a deterministic
  in-memory store with an identical interface, so the harness is
  offline-capable and swaps back with zero code changes.
- **Architecture alignment:** our custom policy engine maps 1:1 onto Agent
  Engine's `GuardrailPolicyEngine` protocol (registered policy engines
  evaluated at runtime tool-call boundaries) — Aegis is a reference
  implementation of custom governance on the platform.

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

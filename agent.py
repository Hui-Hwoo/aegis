"""Scripted adversarial agent + the RSI (self-improvement) loop.

The agent is deliberately scripted, not LLM-driven: this is a *harness* demo,
so the test vehicle must be deterministic. The harness (policy gate + governed
memory + audit) is the product; the agent is the thing being harnessed.

With a real LLM, `consult_memory` becomes prompt context via
`memory.build_context(...)` and `plan` becomes the model's own reasoning —
the harness mechanics below don't change.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from gate import Gate
from memory_store import MemoryStore
from policy import AccessRequest
from tools import execute_tool  # real tools: the gate stands before these


@dataclass
class AttemptResult:
    action: str
    targets: list[str]
    outcome: str  # ALLOW | DENY | REQUIRE_APPROVAL | WOULD_DENY | APPROVED | SKIPPED_LEARNED
    detail: str = ""
    executed: bool = False
    tool_output: dict | None = None  # real tool result, when executed


class ScriptedAgent:
    """An agent with an id, roles, a memory, and everything behind a gate."""

    def __init__(self, agent_id: str, roles: list[str], gate: Gate,
                 memory: MemoryStore, task_id: str = "demo"):
        self.agent_id = agent_id
        self.roles = roles
        self.gate = gate
        self.memory = memory
        self.task_id = task_id
        self.history: list[AttemptResult] = []
        # ticket_id -> (action, targets, args): calls awaiting approval.
        # Approving a ticket EXECUTES the real tool call (production behavior).
        self.pending_calls: dict[str, tuple] = {}

    def execute_approved(self, ticket_id: str) -> dict:
        """Run the real tool call behind an approved ticket."""
        call = self.pending_calls.pop(ticket_id, None)
        if call is None:
            return {"ok": False, "error": "no pending call for ticket"}
        action, targets, args = call
        out = execute_tool(action, targets, args)
        self.gate.log_event({
            "event": "tool_executed", "ticket_id": ticket_id,
            "agent_id": self.agent_id, "action": action,
            "targets": targets, "ok": out.get("ok"),
        })
        return out

    def attempt(self, action: str, targets: list[str],
                args: dict | None = None) -> AttemptResult:
        req = AccessRequest(
            agent_id=self.agent_id, roles=self.roles,
            task_id=self.task_id, action=action, targets=targets)
        res = self.gate.check(req)
        if res.outcome == "ALLOW":
            tool_out = execute_tool(action, targets, args)
            out = AttemptResult(action, targets, "ALLOW", res.decision.reason,
                                True, tool_output=tool_out)
        elif res.outcome == "REQUIRE_APPROVAL":
            out = AttemptResult(action, targets, "REQUIRE_APPROVAL",
                                f"ticket {res.ticket_id}: {res.decision.reason}")
            out.ticket_id = res.ticket_id  # type: ignore[attr-defined]
            # remember the real call so approval executes it
            self.pending_calls[res.ticket_id] = (action, targets, args)
        elif res.outcome == "WOULD_DENY":
            tool_out = execute_tool(action, targets, args)
            out = AttemptResult(action, targets, "WOULD_DENY",
                                res.decision.reason, True,
                                tool_output=tool_out)
        else:
            out = AttemptResult(action, targets, "DENY", res.decision.reason)
        self.history.append(out)
        return out

    # ---- memory-informed planning (the RSI loop's "learning") ----
    def consult_memory(self, action: str, targets: list[str]):
        """Ask episodic memory about this (action, target).

        Returns (denials, approvals): past hard-denials vs past
        approval-required events for the same action/target family.
        """
        query = f"{action} {' '.join(targets)} policy"
        hits = self.memory.search_episodes(query, top_k=10)
        denials, approvals = [], []
        for h in hits:
            if not isinstance(h, dict):
                continue
            text = h.get("text", "")
            tags = h.get("tags", [])
            if action not in text:
                continue
            if not any(t.split(":")[-1].split(".")[0] in text for t in targets):
                continue
            if "policy-denial" in tags:
                denials.append(h)
            elif "approval-required" in tags:
                approvals.append(h)
        return denials, approvals

    def plan(self, action: str, targets: list[str], learned: bool,
             args: dict | None = None):
        """Naive plan: attempt directly.

        Learned plan: check memory first —
          past DENY      -> skip the doomed attempt entirely
          past APPROVAL  -> proactively request approval (no surprise)
        """
        if learned:
            denials, approvals = self.consult_memory(action, targets)
            if denials:
                out = AttemptResult(
                    action, targets, "SKIPPED_LEARNED",
                    f"memory: denied in {len(denials)} prior episode(s); "
                    "not re-attempted")
                self.history.append(out)
                return out
            if approvals:
                out = self.attempt(action, targets, args)  # -> REQUIRE_APPROVAL ticket
                out.detail = "proactive approval request (learned): " + out.detail
                return out
        return self.attempt(action, targets, args)


def distill_episode(memory: MemoryStore, agent: ScriptedAgent, episode: int) -> int:
    """Turn this episode's denials/approvals into episodic + procedural memory.

    This is the 'recursive self-improvement' step: the harness learns from
    its own enforcement history so the next episode behaves better.
    Returns number of memories written.
    """
    n = 0
    denied_actions: set[tuple[str, str]] = set()
    for h in agent.history:
        if h.outcome == "DENY":
            memory.save_episode(
                title=f"Episode {episode}: policy denial",
                content=(f"Agent {agent.agent_id} attempted {h.action} on "
                         f"{', '.join(h.targets)} and was denied. {h.detail}"),
                summary=f"denied: {h.action}",
                tags=["policy-denial", f"episode-{episode}"],
            )
            denied_actions.add((h.action, h.targets[0] if h.targets else ""))
            n += 1
        elif h.outcome == "REQUIRE_APPROVAL":
            memory.save_episode(
                title=f"Episode {episode}: approval required",
                content=(f"Agent {agent.agent_id} attempted {h.action} on "
                         f"{', '.join(h.targets)}; policy requires human "
                         f"approval. {h.detail}"),
                summary=f"approval-required: {h.action}",
                tags=["approval-required", f"episode-{episode}"],
            )
            n += 1
    if denied_actions:
        steps = [f"Before {a} on {t}, check policy or request approval first."
                 for a, t in sorted(denied_actions)]
        memory.save_procedure(
            procedure="avoid-repeat-policy-denials",
            description="Learned from past denials: check memory before acting.",
            steps=steps,
            allowed_tools=[a for a, _ in sorted(denied_actions)],
            trigger_conditions="about to call a tool that was denied before",
        )
        n += 1
    return n

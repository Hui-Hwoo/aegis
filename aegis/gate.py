"""The enforcement point: every tool call passes through the gate.

Outcomes:
  ALLOW            -> the tool call may execute
  DENY             -> blocked; reason + rule recorded
  REQUIRE_APPROVAL -> parked as an elevation ticket until a human approves/denies
  WOULD_DENY       -> policy.mode == "observe": logged as would-deny, still allowed
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone

from .policy import AccessRequest, Decision, Policy, evaluate


@dataclass
class GateResult:
    outcome: str  # ALLOW | DENY | REQUIRE_APPROVAL | WOULD_DENY
    decision: Decision
    ticket_id: str | None = None


@dataclass
class ApprovalTicket:
    id: str
    request: AccessRequest
    rule_id: str | None
    reason: str
    status: str = "pending"  # pending | approved | denied
    created_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    decided_by: str | None = None
    decided_at: str | None = None


class Gate:
    def __init__(self, policy: Policy, audit=None):
        self.policy = policy
        self.audit = audit
        self.tickets: dict[str, ApprovalTicket] = {}

    def _log(self, event: dict) -> None:
        if self.audit:
            self.audit.append(event)

    def check(self, req: AccessRequest) -> GateResult:
        decision = evaluate(self.policy, req)

        if not decision.allowed and self.policy.mode == "observe":
            # Dry-run: record what *would* have been denied, but let it through.
            self._log(
                {
                    "event": "decision",
                    "outcome": "WOULD_DENY",
                    "agent_id": req.agent_id,
                    "roles": req.roles,
                    "task_id": req.task_id,
                    "action": req.action,
                    "targets": req.targets,
                    "rule_id": decision.rule_id,
                    "reason": decision.reason,
                }
            )
            return GateResult(outcome="WOULD_DENY", decision=decision)

        if not decision.allowed:
            self._log(
                {
                    "event": "decision",
                    "outcome": "DENY",
                    "agent_id": req.agent_id,
                    "roles": req.roles,
                    "task_id": req.task_id,
                    "action": req.action,
                    "targets": req.targets,
                    "rule_id": decision.rule_id,
                    "reason": decision.reason,
                }
            )
            return GateResult(outcome="DENY", decision=decision)

        if decision.require_approval:
            ticket = ApprovalTicket(
                id="tkt-" + uuid.uuid4().hex[:8],
                request=req,
                rule_id=decision.rule_id,
                reason=decision.reason,
            )
            self.tickets[ticket.id] = ticket
            self._log(
                {
                    "event": "approval_requested",
                    "outcome": "REQUIRE_APPROVAL",
                    "ticket_id": ticket.id,
                    "agent_id": req.agent_id,
                    "roles": req.roles,
                    "task_id": req.task_id,
                    "action": req.action,
                    "targets": req.targets,
                    "rule_id": decision.rule_id,
                    "reason": decision.reason,
                }
            )
            return GateResult(
                outcome="REQUIRE_APPROVAL", decision=decision, ticket_id=ticket.id
            )

        self._log(
            {
                "event": "decision",
                "outcome": "ALLOW",
                "agent_id": req.agent_id,
                "roles": req.roles,
                "task_id": req.task_id,
                "action": req.action,
                "targets": req.targets,
                "rule_id": decision.rule_id,
                "reason": decision.reason,
            }
        )
        return GateResult(outcome="ALLOW", decision=decision)

    def approve(self, ticket_id: str, approver: str) -> ApprovalTicket:
        ticket = self.tickets[ticket_id]
        ticket.status = "approved"
        ticket.decided_by = approver
        ticket.decided_at = datetime.now(timezone.utc).isoformat()
        self._log(
            {
                "event": "approval_decided",
                "outcome": "APPROVED",
                "ticket_id": ticket.id,
                "agent_id": ticket.request.agent_id,
                "action": ticket.request.action,
                "targets": ticket.request.targets,
                "decided_by": approver,
            }
        )
        return ticket

    def deny_ticket(self, ticket_id: str, approver: str) -> ApprovalTicket:
        ticket = self.tickets[ticket_id]
        ticket.status = "denied"
        ticket.decided_by = approver
        ticket.decided_at = datetime.now(timezone.utc).isoformat()
        self._log(
            {
                "event": "approval_decided",
                "outcome": "APPROVAL_DENIED",
                "ticket_id": ticket.id,
                "agent_id": ticket.request.agent_id,
                "action": ticket.request.action,
                "targets": ticket.request.targets,
                "decided_by": approver,
            }
        )
        return ticket

    def pending_tickets(self) -> list[ApprovalTicket]:
        return [t for t in self.tickets.values() if t.status == "pending"]

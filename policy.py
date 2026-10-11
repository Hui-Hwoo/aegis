"""Pure policy engine. No I/O, no network — fully unit-testable.

Faithful Python port of the Cerberus (Cloudflare) policy engine, generalized
from Git operations to tool calls:

  agents / roles / actions (tool names) / resources (glob-addressed)

Resource identifiers are namespaced strings, e.g.:
  "fs:/docs/guide.md"      file / path-like resources
  "db:prod.users"          database collections / tables
  "api:payments.charge"    external APIs / tools
  "memory:episodic:42"     agent-memory documents (memory is governed too)

Semantics (identical to Cerberus):
  1. Rules are evaluated in order; collect all matches.
  2. Any matching DENY beats any matching ALLOW (explicit deny wins).
  3. Otherwise the first matching ALLOW applies.
  4. No match -> policy.default_effect (deny in practice).
  5. Deny rules trigger when ANY touched target hits the resource globs
     (so smuggling "db:prod.users" inside an otherwise-legit batch is denied).
     Allow rules require EVERY touched target to be covered by the globs.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field


def glob_to_regexp(glob: str) -> re.Pattern:
    """Glob -> regex. `*` stays within a segment, `**` crosses segments."""
    parts: list[str] = []
    i = 0
    while i < len(glob):
        c = glob[i]
        if c == "*":
            if i + 1 < len(glob) and glob[i + 1] == "*":
                parts.append(".*")
                i += 2
            else:
                parts.append("[^/]*")
                i += 1
        elif c in "\\.+?^${}()|[]":
            parts.append("\\" + c)
            i += 1
        else:
            parts.append(c)
            i += 1
    return re.compile("^" + "".join(parts) + "$")


@dataclass
class PolicyRule:
    id: str
    effect: str  # "allow" | "deny"
    actions: list[str]  # tool names, e.g. ["read_file", "db_delete"]
    agents: list[str] | None = None  # None or ["*"] = any agent
    roles: list[str] | None = None  # None or ["*"] = any role
    resources: list[str] | None = None  # globs; None = any resource
    require_approval: bool = False  # allow, but only via human approval


@dataclass
class Policy:
    version: int = 1
    default_effect: str = "deny"
    rules: list[PolicyRule] = field(default_factory=list)
    # "enforce": deny decisions block the tool call.
    # "observe": deny decisions are logged as would-deny but still allowed —
    # lets teams validate a policy against real agent traffic before enforcing.
    mode: str = "enforce"


@dataclass
class AccessRequest:
    agent_id: str
    roles: list[str]
    task_id: str
    action: str  # tool name
    targets: list[str]  # concrete resource ids the call will touch


@dataclass
class Decision:
    allowed: bool
    reason: str
    rule_id: str | None = None
    require_approval: bool = False


def _list_matches(globs: list[str] | None, value: str | None) -> bool:
    if not globs:  # no constraint on this dimension
        return True
    if value is None:
        return False
    return any(glob_to_regexp(g).match(value) for g in globs)


def _rule_matches(rule: PolicyRule, req: AccessRequest) -> bool:
    if rule.agents and "*" not in rule.agents and req.agent_id not in rule.agents:
        return False
    if rule.roles and "*" not in rule.roles and not any(
        r in rule.roles for r in req.roles
    ):
        return False
    if req.action not in rule.actions:
        return False
    if req.targets:
        if rule.resources:
            hit = lambda t: any(glob_to_regexp(g).match(t) for g in rule.resources)  # noqa: E731
            if rule.effect == "deny":
                # ANY touched target hitting the globs triggers the rule.
                if not any(hit(t) for t in req.targets):
                    return False
            else:
                # EVERY touched target must be covered by the globs.
                if not all(hit(t) for t in req.targets):
                    return False
    return True


def evaluate(policy: Policy, req: AccessRequest) -> Decision:
    matches = [r for r in policy.rules if _rule_matches(r, req)]

    deny = next((r for r in matches if r.effect == "deny"), None)
    if deny:
        return Decision(
            allowed=False, reason=f'denied by rule "{deny.id}"', rule_id=deny.id
        )

    allow = next((r for r in matches if r.effect == "allow"), None)
    if allow:
        return Decision(
            allowed=True,
            reason=f'allowed by rule "{allow.id}"',
            rule_id=allow.id,
            require_approval=allow.require_approval,
        )

    return Decision(
        allowed=False,
        reason=f"no matching rule (default {policy.default_effect})",
    )


def load_policy(data: dict) -> Policy:
    return Policy(
        version=data.get("version", 1),
        default_effect=data.get("defaultEffect", data.get("default_effect", "deny")),
        mode=data.get("mode", "enforce"),
        rules=[
            PolicyRule(
                id=r["id"],
                effect=r["effect"],
                actions=r["actions"],
                agents=r.get("agents"),
                roles=r.get("roles"),
                resources=r.get("resources"),
                require_approval=r.get("requireApproval", r.get("require_approval", False)),
            )
            for r in data.get("rules", [])
        ],
    )

"""Policy self-evolution: the harness rewrites its own rules.

Loop:
  1. analyze()   — mine the audit log for per-rule statistics
  2. propose()   — turn patterns into candidate mutations
  3. evaluate()  — run each candidate against the FIXED evaluator suite
  4. try_adopt() — adopt only on zero security regression, else roll back

Mutation kinds:
  - relax_approval: an approval gate that is always granted with zero
    incidents becomes a plain allow (friction down, safety proven).
  - add_deny: repeated default-deny blocks on one pattern become an
    explicit deny rule (clearer reason, harder to accidentally open).
"""

from __future__ import annotations

import copy
from collections import Counter, defaultdict

import evaluator as EV
from gate import Gate
from policy import AccessRequest, Policy, glob_to_regexp


# ---------------------------------------------------------------- analyze
def analyze(events: list[dict], tickets: list) -> dict:
    """Per-rule statistics mined from the audit log + ticket store."""
    requested: Counter = Counter()   # rule_id -> approval tickets opened
    granted: Counter = Counter()     # rule_id -> approvals granted
    denies: Counter = Counter()      # (action, target) -> deny count
    deny_rules: dict = defaultdict(set)  # (action, target) -> rule_ids seen

    for e in events:
        if e.get("event") == "approval_requested" and e.get("rule_id"):
            requested[e["rule_id"]] += 1
        elif e.get("event") == "decision" and e.get("outcome") == "DENY":
            key = (e.get("action"), (e.get("targets") or ["?"])[0])
            denies[key] += 1
            if e.get("rule_id"):
                deny_rules[key].add(e["rule_id"])

    for t in tickets:
        if t.status == "approved" and t.rule_id:
            granted[t.rule_id] += 1

    return {"requested": requested, "granted": granted,
            "denies": denies, "deny_rules": deny_rules}


# ---------------------------------------------------------------- propose
def propose(policy: Policy, stats: dict, min_approvals: int = 2,
             min_denies: int = 3) -> list[dict]:
    """Candidate mutations, each with an `apply(policy) -> policy` patch."""
    out = []

    for rule in policy.rules:
        if rule.effect == "allow" and rule.require_approval:
            n = stats["granted"].get(rule.id, 0)
            # incidents: denies on actions+resources THIS rule governs
            # (a deny on fs:/etc/** is not an incident for the docs rule)
            def _in_scope(target: str) -> bool:
                return any(glob_to_regexp(g).match(target)
                           for g in (rule.resources or []))
            incidents = sum(
                c for (a, t), c in stats["denies"].items()
                if a in rule.actions and _in_scope(t)
            )
            if n >= min_approvals and incidents == 0:
                rid = rule.id

                def _relax(pol: Policy, _rid=rid) -> Policy:
                    for r in pol.rules:
                        if r.id == _rid:
                            r.require_approval = False
                    return pol

                out.append({
                    "id": f"relax-{rid}",
                    "kind": "relax_approval",
                    "description": (
                        f'Relax "{rid}": {n} approvals granted, 0 incidents — '
                        f"drop the human-approval requirement"),
                    "benefit": f"-{n} human approvals per episode",
                    "apply": _relax,
                })

    for (action, target), n in stats["denies"].items():
        if n >= min_denies and not stats["deny_rules"].get((action, target)):
            # Blocked only by default-deny: make it an explicit rule.
            pattern = target.split(":")[0] + ":" + target.split(":")[1].split("/")[0] + ".*"

            def _add(pol: Policy, _a=action, _p=pattern) -> Policy:
                from .policy import PolicyRule
                pol.rules.append(PolicyRule(
                    id=f"auto-deny-{_a}", effect="deny",
                    actions=[_a], resources=[_p]))
                return pol

            out.append({
                "id": f"add-deny-{action}",
                "kind": "add_deny",
                "description": (
                    f'Add explicit deny for {action} on {pattern} '
                    f"({n} default-deny blocks observed)"),
                "benefit": "explicit rule with clear reason; safer than silent default",
                "apply": _add,
            })

    return out


# ---------------------------------------------------------------- evaluate
def _check(policy: Policy, action: str, targets: list[str]) -> str:
    gate = Gate(policy, audit=None)  # throwaway: no audit side effects
    req = AccessRequest(agent_id="evaluator", roles=["analyst"],
                        task_id="eval", action=action, targets=targets)
    return gate.check(req).outcome


def evaluate_policy(policy: Policy) -> dict:
    attacks = [_check(policy, a, t) for a, t in EV.ATTACKS]
    legit = [_check(policy, a, t) for a, t in EV.LEGIT]
    probes = [_check(policy, a, t) for a, t in EV.PROBES]
    return {
        "block_rate": sum(o == "DENY" for o in attacks) / len(attacks),
        "legit_ok_rate": sum(o in ("ALLOW", "REQUIRE_APPROVAL")
                             for o in legit) / len(legit),
        "probe_pass_rate": sum(o != "ALLOW" for o in probes) / len(probes),
        "n_attacks": len(attacks), "n_legit": len(legit),
        "n_probes": len(probes),
    }


def try_adopt(policy: Policy, mutation: dict):
    """Returns (new_policy, adopted, before, after)."""
    before = evaluate_policy(policy)
    candidate = mutation["apply"](copy.deepcopy(policy))
    after = evaluate_policy(candidate)
    adopted = (
        after["block_rate"] == 1.0
        and after["probe_pass_rate"] == 1.0
        and after["legit_ok_rate"] >= before["legit_ok_rate"]
    )
    return (candidate if adopted else policy), adopted, before, after

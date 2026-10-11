"""Deterministic unit tests for Aegis. Stdlib only: python -m unittest discover tests.

These are the engineering-evidence behind the demo's hard numbers:
deny-wins, smuggled targets, approval flow, traversal guard, role matrix,
mutation adopt/rollback, analyst intents.
"""

import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import tools
from agent import ScriptedAgent
from analyst import build_mutation, detect_intent
from audit import AuditLog
from evaluator import ATTACKS, LEGIT, PROBES
from evolve import evaluate_policy, propose, try_adopt
from gate import Gate
from memory_store import MemoryStore
from policy import AccessRequest, load_policy


def demo_policy():
    with open(os.path.join(os.path.dirname(
            os.path.dirname(os.path.abspath(__file__))),
            "policy.example.json"), encoding="utf-8") as f:
        return load_policy(json.load(f))


def req(action, targets, roles=("analyst",)):
    return AccessRequest(agent_id="test", roles=list(roles),
                         task_id="t", action=action, targets=targets)


class PolicyTest(unittest.TestCase):
    def test_deny_wins_over_allow(self):
        g = Gate(demo_policy(), audit=None)
        # docs-need-approval would allow write_file on fs:docs/**,
        # but protect-secrets denies fs:/etc/**
        r = g.check(req("write_file", ["fs:/etc/hosts"]))
        self.assertEqual(r.outcome, "DENY")

    def test_default_deny(self):
        g = Gate(demo_policy(), audit=None)
        r = g.check(req("db_query", ["db:unknown.table"]))
        self.assertEqual(r.outcome, "DENY")

    def test_smuggled_target_poisoned(self):
        g = Gate(demo_policy(), audit=None)
        r = g.check(req("db_delete", ["db:staging.tmp", "db:prod.users"]))
        self.assertEqual(r.outcome, "DENY")

    def test_approval_flow(self):
        g = Gate(demo_policy(), audit=None)
        r = g.check(req("write_file", ["fs:docs/notes.md"]))
        self.assertEqual(r.outcome, "REQUIRE_APPROVAL")
        self.assertTrue(r.ticket_id.startswith("tkt-"))

    def test_role_matrix(self):
        pol = demo_policy()
        expect = {
            ("intern", "read_file", "fs:docs/readme.md"): "ALLOW",
            ("intern", "db_query", "db:analytics.events"): "DENY",
            ("intern", "db_delete", "db:prod.users"): "DENY",
            ("analyst", "read_file", "fs:docs/readme.md"): "ALLOW",
            ("analyst", "db_query", "db:analytics.events"): "ALLOW",
            ("analyst", "db_delete", "db:prod.users"): "DENY",
            ("admin", "read_file", "fs:docs/readme.md"): "ALLOW",
            ("admin", "db_query", "db:analytics.events"): "ALLOW",
            ("admin", "db_delete", "db:prod.users"): "REQUIRE_APPROVAL",
        }
        for (role, action, target), want in expect.items():
            g = Gate(pol, audit=None)
            got = g.check(req(action, [target], roles=(role,))).outcome
            self.assertEqual(got, want, f"{role} {action} {target}")


class ToolsTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        # point the sandbox at a temp dir so tests never touch demo data
        tools.SANDBOX = self.tmp.name
        tools.DOCS = os.path.join(self.tmp.name, "docs")
        tools.OUTBOX = os.path.join(self.tmp.name, "outbox")
        tools.DB_PATH = os.path.join(self.tmp.name, "t.db")
        tools.init_sandbox(force=True)

    def tearDown(self):
        self.tmp.cleanup()

    def test_traversal_guard(self):
        with self.assertRaises(PermissionError):
            tools.write_file("fs:docs/../../evil.txt", "x")
        with self.assertRaises(PermissionError):
            tools.read_file("fs:docs/../../etc/passwd")

    def test_real_write_and_read(self):
        tools.write_file("fs:docs/a.md", "hello")
        self.assertIn("hello", tools.read_file("fs:docs/a.md")["preview"])

    def test_real_db(self):
        st = tools.sandbox_state()
        self.assertEqual(st["prod_users"], 200)
        self.assertEqual(st["analytics_events"], 60)
        out = tools.db_query("db:analytics.events")
        self.assertEqual(out["total_rows"], 60)

    def test_approval_executes_real_tool(self):
        pol = demo_policy()
        audit = AuditLog(os.path.join(self.tmp.name, "a.jsonl"))
        mem = MemoryStore(audit=audit, backend="memory")
        gate = Gate(pol, audit=audit)
        agent = ScriptedAgent("t", ["analyst"], gate, mem)
        r = agent.attempt("write_file", ["fs:docs/notes.md"],
                          {"content": "signed-off"})
        self.assertEqual(r.outcome, "REQUIRE_APPROVAL")
        gate.approve(r.ticket_id, approver="test")
        out = agent.execute_approved(r.ticket_id)
        self.assertTrue(out["ok"])
        self.assertIn("signed-off",
                      tools.read_file("fs:docs/notes.md")["preview"])


class EvolveTest(unittest.TestCase):
    def test_baseline_metrics(self):
        m = evaluate_policy(demo_policy())
        self.assertEqual(m["block_rate"], 1.0)
        self.assertEqual(m["probe_pass_rate"], 1.0)
        self.assertEqual(len(ATTACKS), 4)
        self.assertEqual(len(PROBES), 3)

    def test_docs_relax_rejected(self):
        pol = demo_policy()
        mut = build_mutation({"intent": "relax", "action": "write_file",
                              "resource": "fs:docs/**"}, pol)
        self.assertIsNotNone(mut)
        _, adopted, before, after = try_adopt(pol, mut)
        self.assertFalse(adopted)
        self.assertLess(after["probe_pass_rate"], before["probe_pass_rate"])

    def test_safe_deny_adopted(self):
        pol = demo_policy()
        mut = build_mutation({"intent": "add_deny", "action": "db_delete",
                              "resource": "db:quarantine.**"}, pol)
        new_pol, adopted, before, after = try_adopt(pol, mut)
        self.assertTrue(adopted)
        self.assertEqual(after["block_rate"], 1.0)
        self.assertEqual(after["probe_pass_rate"], 1.0)
        # original untouched
        self.assertEqual(len(pol.rules) + 1, len(new_pol.rules))

    def test_propose_needs_thresholds(self):
        # empty history -> no proposals (conservative by design)
        from collections import Counter, defaultdict
        self.assertEqual(propose(demo_policy(), {
            "requested": Counter(), "granted": Counter(),
            "denies": Counter(), "deny_rules": defaultdict(set)}), [])


class AnalystTest(unittest.TestCase):
    def test_detect_deny_intent_zh(self):
        i = detect_intent("以后删除 prod 数据的请求都自动拒绝")
        self.assertEqual(i["intent"], "add_deny")
        self.assertEqual(i["action"], "db_delete")
        self.assertEqual(i["resource"], "db:prod.**")

    def test_detect_relax_intent_zh(self):
        i = detect_intent("以后 docs 的写入都自动批准，不用再问我")
        self.assertEqual(i["intent"], "relax")
        self.assertEqual(i["action"], "write_file")

    def test_no_intent_for_question(self):
        self.assertIsNone(detect_intent("总结最近1小时的情况"))
        self.assertIsNone(detect_intent("which requests need my judgment?"))


class MemoryTest(unittest.TestCase):
    def test_roundtrip_and_audit(self):
        audit = AuditLog(os.path.join(
            tempfile.gettempdir(), "aegis-test-audit.jsonl"))
        mem = MemoryStore(audit=audit, backend="memory")
        mem.save_semantic("prod is critical", label="x")
        hits = mem.search_semantic("critical")
        self.assertTrue(any("critical" in h["text"] for h in hits))
        kinds = {d["kind"] for d in mem.list_all()}
        self.assertIn("semantic", kinds)


if __name__ == "__main__":
    unittest.main(verbosity=1)

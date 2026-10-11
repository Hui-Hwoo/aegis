"""End-to-end Atlas Sandbox capability check for Aegis.

Run ON YOUR LAPTOP (the sandbox IP-allowlist will not include other machines):

    MONGODB_URI="mongodb+srv://admin:<pw>@cluster0.gch0op.mongodb.net/?appName=Cluster0" \\
    MONGODB_DB=aegis python verify_atlas.py

Checks everything Aegis needs:
  1. connectivity + authentication
  2. readWrite on the target database (insert/find/delete round-trip)
  3. `audit` collection usable for the append-only log
  4. Agent Engine memory SDK round-trip (if AGENTIC_MEMORY_* env vars set)

Prints PASS/FAIL per check; exits non-zero on any failure.
"""

from __future__ import annotations

import os
import sys
import time

PASS, FAIL, SKIP = "✅ PASS", "❌ FAIL", "⏭️  SKIP"
results: list[tuple[str, str, str]] = []


def check(name: str, fn):
    try:
        detail = fn()
        results.append((PASS, name, detail or ""))
    except Exception as e:  # noqa: BLE001
        results.append((FAIL, name, f"{type(e).__name__}: {e}"))


def main() -> int:
    uri = os.environ.get("MONGODB_URI")
    if not uri or "<db_password>" in uri:
        print("Set MONGODB_URI with the real password "
              "(replace <db_password>). URL-encode special chars.")
        return 2
    db_name = os.environ.get("MONGODB_DB", "aegis")

    try:
        from pymongo import MongoClient  # type: ignore
    except ImportError:
        print("pip install pymongo")
        return 2

    client = MongoClient(uri, serverSelectionTimeoutMS=10000)
    db = client[db_name]
    ns: dict = {}

    def c_connect():
        hello = client.admin.command("hello")
        ns["user"] = client.admin.command("connectionStatus")["authInfo"][
            "authenticatedUsers"][0]["user"]
        return (f"set={hello.get('setName')} primary={hello.get('primary')} "
                f"user={ns['user']}")

    def c_write():
        coll = db["__aegis_verify"]
        doc = {"_ts": time.time(), "probe": "write"}
        rid = coll.insert_one(doc).inserted_id
        found = coll.find_one({"_id": rid})
        assert found and found["probe"] == "write", "read-back mismatch"
        coll.delete_one({"_id": rid})
        assert coll.count_documents({}) == 0, "delete failed"
        return "insert/find/delete round-trip ok"

    def c_audit():
        # the exact collection Aegis will append to
        db["audit"].insert_one({"probe": "audit-write", "_ts": time.time()})
        n = db["audit"].count_documents({"probe": "audit-write"})
        db["audit"].delete_many({"probe": "audit-write"})
        assert n >= 1
        return "audit collection writable"

    def c_vector():
        # Atlas Search / Vector Search indexes (optional for Aegis v1,
        # required if we later add semantic memory indexes ourselves)
        try:
            idx = list(db["audit"].list_search_indexes())
            return f"{len(idx)} search index(es) present"
        except Exception as e:
            raise RuntimeError(f"search indexes not listable: {e}")

    check("1 connectivity + auth", c_connect)
    check("2 readWrite on db '%s'" % db_name, c_write)
    check("3 audit collection", c_audit)
    try:
        check("4 search-index API (optional)", c_vector)
    except Exception:
        pass

    # ---- Agent Engine memory SDK ----
    tok = os.environ.get("AGENTIC_MEMORY_SERVICE_ACCOUNT_TOKEN")
    pid = os.environ.get("AGENTIC_MEMORY_PROJECT_ID")

    def c_mem():
        from agent_engine_sdk_memory import Memory  # type: ignore
        mem = Memory(service_account_token=tok, project_id=pid,
                     **({"base_url": os.environ["AGENTIC_MEMORY_BASE_URL"]}
                        if os.environ.get("AGENTIC_MEMORY_BASE_URL") else {}))
        doc_id = mem.save_semantic(
            text="Aegis sandbox probe: the quick brown fox",
            label="probe", user_id="verify")
        hits = mem.search_semantic(query="quick brown fox", top_k=3)
        assert hits, "search returned nothing"
        return f"save+search ok (doc={str(doc_id)[:24]}...)"

    if tok and pid:
        check("5 Agent Engine memory SDK", c_mem)
    else:
        results.append((SKIP, "5 Agent Engine memory SDK",
                        "AGENTIC_MEMORY_SERVICE_ACCOUNT_TOKEN/_PROJECT_ID not set"))

    # cleanup
    try:
        db.drop_collection("__aegis_verify")
    except Exception:
        pass

    print(f"\ncluster : {uri.split('@')[-1].split('/')[0]}")
    print(f"db      : {db_name}\n")
    failed = 0
    for status, name, detail in results:
        print(f"{status}  {name}" + (f" — {detail}" if detail else ""))
        failed += status == FAIL
    print()
    if failed:
        print("Fix the FAILED items above, then re-run. "
              "Timeouts usually mean your IP is not in Network Access.")
        return 1
    print("All required checks passed — Aegis can run live on this sandbox.")
    return 0


if __name__ == "__main__":
    sys.exit(main())

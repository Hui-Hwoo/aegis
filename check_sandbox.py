"""Verify that MONGODB_URI points at the hackathon Atlas Sandbox.

Run:  MONGODB_URI="mongodb+srv://..." python check_sandbox.py

It prints the cluster identity (hosts, replica set, authenticated user)
so you can compare it against the Sandbox cluster shown in the Atlas UI
(Database -> Connect -> Drivers). The SRV host MUST match — if it points
at a personal cluster, finalist eligibility is at risk.

If the connection times out, check Atlas UI -> Network Access: the
sandbox may use a per-person IP allowlist rather than 0.0.0.0/0.
"""

from __future__ import annotations

import os
import sys
import urllib.parse


def main() -> int:
    uri = os.environ.get("MONGODB_URI")
    if not uri:
        print("MONGODB_URI is not set.")
        return 1

    # Show the host WITHOUT credentials.
    parsed = urllib.parse.urlparse(uri)
    print(f"URI host      : {parsed.hostname}")
    print(f"URI database  : {parsed.path.lstrip('/') or '(none)'}")

    try:
        from pymongo import MongoClient  # type: ignore
    except ImportError:
        print("\ninstall pymongo first: pip install pymongo")
        return 1

    print("\nconnecting...")
    try:
        client = MongoClient(uri, serverSelectionTimeoutMS=8000)
        hello = client.admin.command("hello")
        print(f"replica set   : {hello.get('setName')}")
        print(f"primary       : {hello.get('primary')}")
        print(f"server version: {hello.get('maxWireVersion')}")
        status = client.admin.command("connectionStatus")
        users = status.get("authInfo", {}).get("authenticatedUsers", [])
        for u in users:
            print(f"authenticated : {u.get('user')} @ {u.get('db')}")
        dbs = sorted(d["name"] for d in client.list_databases()
                     if d["name"] not in ("admin", "local", "config"))
        print(f"databases     : {', '.join(dbs) if dbs else '(none yet)'}")
    except Exception as e:
        print(f"\nCONNECTION FAILED: {e}")
        print("Likely causes: wrong URI, or your IP is not in the "
              "sandbox's Network Access allowlist.")
        return 1

    print("\n--- checklist ---")
    print("[ ] Atlas UI org name matches the hackathon "
          "(e.g. 'Harness Engineering & Model Wrangling Hackathon')")
    print("[ ] The project/cluster above was created via the email invite link")
    print(f"[ ] '{parsed.hostname}' matches the Sandbox cluster's Connect dialog")
    print("[ ] AEGIS audit DB:", os.environ.get("MONGODB_DB", "aegis"),
          "-> collection 'audit' will be created here on first write")
    return 0


if __name__ == "__main__":
    sys.exit(main())

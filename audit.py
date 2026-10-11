"""Append-only audit log. JSONL file by default; Atlas collection when
MONGODB_URI is set (pymongo optional — no hard dependency)."""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone


class AuditLog:
    def __init__(self, path: str = "audit.jsonl"):
        self.path = path
        self._collection = None
        self.session_id: str | None = None  # set by the dashboard per run
        uri = os.environ.get("MONGODB_URI")
        if uri:
            try:
                from pymongo import MongoClient  # type: ignore

                db_name = os.environ.get("MONGODB_DB", "aegis")
                self._collection = MongoClient(uri)[db_name]["audit"]
            except Exception as e:  # fall back to file, but say so loudly
                print(f"[audit] Atlas unavailable ({e}); using local JSONL")

    def append(self, event: dict) -> None:
        event = dict(event)
        event.setdefault("ts", datetime.now(timezone.utc).isoformat())
        if self.session_id:
            event.setdefault("session", self.session_id)
        if self._collection is not None:
            try:
                self._collection.insert_one(event)
                return
            except Exception as e:
                print(f"[audit] Atlas write failed ({e}); using local JSONL")
                self._collection = None
        with open(self.path, "a", encoding="utf-8") as f:
            f.write(json.dumps(event, ensure_ascii=False) + "\n")

    def read_all(self, limit: int = 500,
                 session: str | None = None) -> list[dict]:
        """Newest-first. Used by the dashboard.

        session: when given, only events tagged with that session id are
        returned — a new demo run never mines a previous run's history.
        """
        if self._collection is not None:
            try:
                q = {"session": session} if session else {}
                return list(
                    self._collection.find(q, {"_id": 0})
                    .sort("ts", -1)
                    .limit(limit)
                )
            except Exception:
                pass
        if not os.path.exists(self.path):
            return []
        with open(self.path, encoding="utf-8") as f:
            lines = f.readlines()[-limit:]
        events = [json.loads(line) for line in lines if line.strip()]
        if session:
            events = [e for e in events if e.get("session") == session]
        return list(reversed(events))

    @property
    def backend(self) -> str:
        return "atlas" if self._collection is not None else "jsonl"

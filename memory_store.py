"""Governed memory, backed by MongoDB Atlas Agent Engine.

Uses the official `agent-engine-sdk-memory` when credentials are present
(service-account token via AGENTIC_MEMORY_SERVICE_ACCOUNT_TOKEN), otherwise
falls back to a deterministic in-memory store so the harness and demo run
anywhere with zero setup.

Uniform interface — the agent never touches SDK specifics:

  save_semantic / save_episode / save_taxonomic / save_procedure
  search_semantic / search_episodes / discover_procedures
  list_all  (for the dashboard)
"""

from __future__ import annotations

import os
import time
from datetime import datetime, timezone


class _InMemoryBackend:
    """Deterministic stand-in: substring search, keeps demo reproducible."""

    def __init__(self):
        self.docs: list[dict] = []
        self._n = 0

    def _put(self, kind: str, text: str, **kw) -> str:
        self._n += 1
        doc_id = f"mem-{kind}-{self._n}"
        self.docs.append({"id": doc_id, "kind": kind, "text": text, **kw})
        return doc_id

    def save_semantic(self, text, label=None, user_id=None, metadata=None):
        return self._put("semantic", text, label=label, user_id=user_id,
                         metadata=metadata or {})

    def save_episode(self, title, content, summary=None, participants=None,
                     tags=None, user_id=None):
        return self._put("episodic", f"{title}\n{content}", title=title,
                         summary=summary, participants=participants or [],
                         tags=tags or [], user_id=user_id)

    def save_taxonomic(self, term=None, definition=None, domain=None, user_id=None):
        return self._put("taxonomic", f"{term}: {definition}", term=term,
                         domain=domain, user_id=user_id)

    def save_procedure(self, procedure=None, description=None, content=None,
                       steps=None, allowed_tools=None, trigger_conditions=None,
                       user_id=None):
        text = content or "\n".join(steps or [])
        return self._put("procedural", f"{procedure}\n{text}",
                         description=description, allowed_tools=allowed_tools or [],
                         trigger_conditions=trigger_conditions, user_id=user_id)

    def _search(self, kind: str, query: str, top_k: int, user_id=None):
        q = query.lower().split()
        scored = []
        for d in self.docs:
            if d["kind"] != kind:
                continue
            if user_id and d.get("user_id") not in (None, user_id):
                continue
            hay = (d["text"] + " " + d.get("title", "")).lower()
            score = sum(1 for w in q if w in hay)
            if score:
                scored.append((score, d))
        scored.sort(key=lambda x: -x[0])
        return [d for _, d in scored[:top_k]]

    def search_semantic(self, query, user_id=None, top_k=5):
        return self._search("semantic", query, top_k, user_id)

    def search_episodes(self, query, user_id=None, top_k=5):
        return self._search("episodic", query, top_k, user_id)

    def search_taxonomic(self, query, user_id=None, top_k=5):
        return self._search("taxonomic", query, top_k, user_id)

    def discover_procedures(self, query, user_id=None, top_k=5):
        return self._search("procedural", query, top_k, user_id)

    def list_all(self):
        return list(self.docs)


class _MongoBackend:
    """Direct Atlas backend (pymongo): the 4 memory types live in the
    `memories` collection of the hackathon sandbox. No Agent Engine
    deployment needed — just the database, which the sandbox provides.
    Search is lexical (regex) until a Vector Search index exists."""

    def __init__(self, uri: str, db_name: str = "aegis"):
        import pymongo  # lazy: stdlib-only unless Atlas is used
        self._client = pymongo.MongoClient(uri, serverSelectionTimeoutMS=5000)
        self._client.admin.command("ping")  # live probe or raise
        self.coll = self._client[db_name]["memories"]
        self._db_name = db_name

    def _put(self, kind: str, text: str, **kw) -> str:
        import uuid
        doc_id = f"mem-{kind}-{uuid.uuid4().hex[:8]}"
        doc = {"id": doc_id, "kind": kind, "text": text,
               "ts": datetime.now(timezone.utc).isoformat(), **kw}
        # strip Nones for a clean document
        self.coll.insert_one({k: v for k, v in doc.items()
                              if v is not None})
        return doc_id

    def save_semantic(self, text, label=None, user_id=None, metadata=None):
        return self._put("semantic", text, label=label, user_id=user_id,
                         metadata=metadata or {})

    def save_episode(self, title, content, summary=None, participants=None,
                     tags=None, user_id=None):
        return self._put("episodic", f"{title}\n{content}", title=title,
                         summary=summary, participants=participants or [],
                         tags=tags or [], user_id=user_id)

    def save_taxonomic(self, term=None, definition=None, domain=None,
                       user_id=None):
        return self._put("taxonomic", f"{term}: {definition}", term=term,
                         domain=domain, user_id=user_id)

    def save_procedure(self, procedure=None, description=None, content=None,
                       steps=None, allowed_tools=None, trigger_conditions=None,
                       user_id=None):
        text = content or "\n".join(steps or [])
        return self._put("procedural", f"{procedure}\n{text}",
                         description=description,
                         allowed_tools=allowed_tools or [],
                         trigger_conditions=trigger_conditions,
                         user_id=user_id)

    def _search(self, kind: str, query: str, top_k: int, user_id=None):
        filt: dict = {"kind": kind,
                      "text": {"$regex": query[:60], "$options": "i"}}
        if user_id:
            filt["$or"] = [{"user_id": user_id}, {"user_id": None}]
        return list(self.coll.find(filt, {"_id": 0})
                    .sort("ts", -1).limit(top_k))

    def search_semantic(self, query, user_id=None, top_k=5):
        return self._search("semantic", query, top_k, user_id)

    def search_episodes(self, query, user_id=None, top_k=5):
        return self._search("episodic", query, top_k, user_id)

    def search_taxonomic(self, query, user_id=None, top_k=5):
        return self._search("taxonomic", query, top_k, user_id)

    def discover_procedures(self, query, user_id=None, top_k=5):
        return self._search("procedural", query, top_k, user_id)

    def list_all(self):
        return list(self.coll.find({}, {"_id": 0}).sort("ts", 1))


class _AgentEngineBackend:
    """Thin wrapper over the official SDK (agent-engine-sdk-memory)."""

    def __init__(self):
        from agent_engine_sdk_memory import (  # type: ignore
            Memory,
            MemoryRequestContext,
        )

        token = os.environ["AGENTIC_MEMORY_SERVICE_ACCOUNT_TOKEN"]
        project_id = os.environ["AGENTIC_MEMORY_PROJECT_ID"]
        base_url = os.environ.get("AGENTIC_MEMORY_BASE_URL")
        kwargs = {"service_account_token": token, "project_id": project_id}
        if base_url:
            kwargs["base_url"] = base_url
        self._mem = Memory(**kwargs)
        self._ctx_cls = MemoryRequestContext
        self._user = os.environ.get("AEGIS_USER_ID", "demo-user")

    def _session(self, session_id: str):
        return self._mem.bind(
            self._ctx_cls(user_id=self._user, session_id=session_id)
        )

    def save_semantic(self, text, label=None, user_id=None, metadata=None):
        return self._mem.save_semantic(
            text=text, label=label or "", user_id=user_id or self._user,
            metadata=metadata or {})

    def save_episode(self, title, content, summary=None, participants=None,
                     tags=None, user_id=None):
        return self._mem.save_episode(
            title=title, content=content, summary=summary or "",
            participants=participants or [], tags=tags or [],
            user_id=user_id or self._user)

    def save_taxonomic(self, term=None, definition=None, domain=None, user_id=None):
        return self._mem.save_taxonomic(
            term=term, definition=definition, domain=domain,
            user_id=user_id or self._user)

    def save_procedure(self, procedure=None, description=None, content=None,
                       steps=None, allowed_tools=None, trigger_conditions=None,
                       user_id=None):
        return self._mem.save_procedure(
            procedure=procedure, description=description or "",
            content=content or "", steps=steps or [],
            allowed_tools=allowed_tools or [],
            trigger_conditions=trigger_conditions,
            user_id=user_id or self._user)

    def search_semantic(self, query, user_id=None, top_k=5):
        return self._mem.search_semantic(
            query=query, user_id=user_id or self._user, top_k=top_k)

    def search_episodes(self, query, user_id=None, top_k=5):
        return self._mem.search_episodes(
            query=query, user_id=user_id or self._user, top_k=top_k)

    def search_taxonomic(self, query, user_id=None, top_k=5):
        return self._mem.search_taxonomic(
            query=query, user_id=user_id or self._user, top_k=top_k)

    def discover_procedures(self, query, user_id=None, top_k=5):
        return self._mem.discover_procedures(
            query=query, user_id=user_id or self._user, top_k=top_k)

    def list_all(self):
        # No cross-type list API; dashboard shows counts via searches.
        return [{"id": "n/a", "kind": "agent-engine",
                 "text": "listing via SDK not supported; use search_*"}]


class MemoryStore:
    """Governed memory. Every read/write is an audited event.

    Backend selection is *probed*, not assumed:
      auto -> Agent Engine (if service-account token) -> direct Atlas
              MongoDB (if MONGODB_URI) -> deterministic in-memory.
    Offline-capable by design, Atlas-primary when credentials exist.
    """

    def __init__(self, audit=None, backend: str = "auto"):
        self.audit = audit
        if backend == "auto":
            be, name = self._try_agent_engine()
            if be is None:
                be, name = self._try_mongo()
            if be is None:
                be, name = _InMemoryBackend(), "memory"
            self._be, self.backend = be, name
        elif backend == "mongo":
            be, name = self._try_mongo()
            if be is None:
                raise RuntimeError("mongo backend requested but "
                                   "MONGODB_URI missing/unreachable")
            self._be, self.backend = be, name
        elif backend == "memory":
            self._be = _InMemoryBackend()
            self.backend = "memory"
        else:
            raise ValueError(f"unknown backend {backend}")

    def _try_mongo(self):
        """Direct Atlas backend: needs only MONGODB_URI (+ MONGODB_DB)."""
        try:
            uri = os.environ.get("MONGODB_URI", "").strip()
            if not uri:
                raise RuntimeError("MONGODB_URI not set")
            be = _MongoBackend(uri, os.environ.get("MONGODB_DB", "aegis"))
            print(f"[memory] Atlas MongoDB backend live "
                  f"(db={be._db_name}, collection=memories)")
            return be, "mongo"
        except Exception as e:
            print(f"[memory] mongo backend unavailable ({type(e).__name__}: "
                  f"{str(e)[:120]})")
            return None, None

    def _try_agent_engine(self):
        """Returns (backend, 'agent-engine') or (None, None)."""
        try:
            if not os.environ.get("AGENTIC_MEMORY_SERVICE_ACCOUNT_TOKEN"):
                raise RuntimeError("no service-account token in env")
            be = _AgentEngineBackend()
            # live probe: construction alone never touches the network
            be.search_semantic("connectivity probe", top_k=1)
            print("[memory] Agent Engine backend live")
            return be, "agent-engine"
        except Exception as e:
            print(f"[memory] hosted backend unavailable ({type(e).__name__}: "
                  f"{str(e)[:120]})")
            return None, None

    def _log(self, op: str, kind: str, detail: str = "") -> None:
        if self.audit:
            self.audit.append({
                "event": "memory",
                "op": op,
                "memory_kind": kind,
                "detail": detail[:200],
            })

    # ---- writes ---------------------------------------------------------
    def save_semantic(self, text, **kw):
        doc_id = self._be.save_semantic(text, **kw)
        self._log("write", "semantic", text)
        return doc_id

    def save_episode(self, title, content, **kw):
        doc_id = self._be.save_episode(title, content, **kw)
        self._log("write", "episodic", f"{title} | {content}")
        return doc_id

    def save_taxonomic(self, **kw):
        doc_id = self._be.save_taxonomic(**kw)
        self._log("write", "taxonomic", str(kw.get("term")))
        return doc_id

    def save_procedure(self, **kw):
        doc_id = self._be.save_procedure(**kw)
        self._log("write", "procedural", str(kw.get("procedure")))
        return doc_id

    # ---- reads ----------------------------------------------------------
    def search_semantic(self, query, **kw):
        res = self._be.search_semantic(query, **kw)
        self._log("read", "semantic", query)
        return res

    def search_episodes(self, query, **kw):
        res = self._be.search_episodes(query, **kw)
        self._log("read", "episodic", query)
        return res

    def discover_procedures(self, query, **kw):
        res = self._be.discover_procedures(query, **kw)
        self._log("read", "procedural", query)
        return res

    def list_all(self):
        return self._be.list_all()

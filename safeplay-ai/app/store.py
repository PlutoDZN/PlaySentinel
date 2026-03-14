import json
import os
from collections import deque
from datetime import datetime, timedelta
from threading import Lock
from typing import Deque, Dict, Tuple, Any, Optional

from .utils import safe_split_session_key


SessionKey = Tuple[str, str]


class SessionStore:
    def get_or_create(self, user_id: str, target_id: str) -> Dict[str, Any]:
        raise NotImplementedError

    def snapshot(self) -> Dict[SessionKey, Dict[str, Any]]:
        raise NotImplementedError

    def cleanup(self) -> int:
        raise NotImplementedError


class InMemorySessionStore(SessionStore):
    def __init__(self, sessions_file: Optional[str], max_messages: int, ttl_hours: int) -> None:
        self.sessions_file = sessions_file
        self.max_messages = max_messages
        self.ttl = timedelta(hours=ttl_hours)
        self.lock = Lock()
        self.sessions: Dict[SessionKey, Dict[str, Any]] = self._load_sessions()

    def _now(self) -> datetime:
        return datetime.utcnow()

    def _load_sessions(self) -> Dict[SessionKey, Dict[str, Any]]:
        if not self.sessions_file:
            return {}
        if not os.path.exists(self.sessions_file):
            return {}
        try:
            with open(self.sessions_file, "r", encoding="utf-8") as f:
                raw = json.load(f)
            out: Dict[SessionKey, Dict[str, Any]] = {}
            for key_str, session in raw.items():
                u, t = safe_split_session_key(key_str)
                msgs = list(session.get("messages", []))
                session["messages"] = deque(msgs, maxlen=self.max_messages)
                session["category_history"] = dict(session.get("category_history", {}))
                out[(u, t)] = session
            return out
        except Exception:
            return {}

    def _save_sessions_atomic(self) -> None:
        if not self.sessions_file:
            return
        with self.lock:
            snapshot: Dict[str, Dict[str, Any]] = {}
            for (u, t), s in self.sessions.items():
                ss = dict(s)
                ss["messages"] = list(s.get("messages", []))
                ss["category_history"] = dict(s.get("category_history", {}))
                snapshot[f"{u}|{t}"] = ss

        tmp = self.sessions_file + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(snapshot, f, ensure_ascii=False, indent=2)
        os.replace(tmp, self.sessions_file)

    def get_or_create(self, user_id: str, target_id: str) -> Dict[str, Any]:
        key = (user_id, target_id)
        with self.lock:
            if key not in self.sessions:
                self.sessions[key] = {
                    "messages": deque(maxlen=self.max_messages),
                    "conversation_risk": 0,
                    "stage": "LOW",
                    "created_at": self._now().isoformat(),
                    "updated_at": self._now().isoformat(),
                    "category_history": {},
                }
            return self.sessions[key]

    def snapshot(self) -> Dict[SessionKey, Dict[str, Any]]:
        with self.lock:
            out: Dict[SessionKey, Dict[str, Any]] = {}
            for key, s in self.sessions.items():
                ss = dict(s)
                ss["messages"] = list(s.get("messages", []))
                ss["category_history"] = dict(s.get("category_history", {}))
                out[key] = ss
            return out

    def cleanup(self) -> int:
        """TTL cleanup, returns deleted count."""
        now = self._now()
        deleted = 0
        with self.lock:
            to_del = []
            for key, s in self.sessions.items():
                try:
                    updated = datetime.fromisoformat(s.get("updated_at"))
                except Exception:
                    updated = now
                if now - updated > self.ttl:
                    to_del.append(key)
            for k in to_del:
                self.sessions.pop(k, None)
                deleted += 1

        if deleted:
            # persist after cleanup
            try:
                self._save_sessions_atomic()
            except Exception:
                pass
        return deleted

    def save(self) -> None:
        try:
            self._save_sessions_atomic()
        except Exception:
            pass
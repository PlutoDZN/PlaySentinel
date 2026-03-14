
from __future__ import annotations

from collections import defaultdict, deque
from time import time


class RelationshipStore:
    def __init__(self, context_window: int = 20, decay_amount: int = 5, decay_window_seconds: int = 300):
        self.context_window = context_window
        self.decay_amount = decay_amount
        self.decay_window_seconds = decay_window_seconds
        self._relationships = defaultdict(lambda: deque(maxlen=self.context_window))
        self._risk_scores = defaultdict(int)
        self._last_updated = defaultdict(lambda: time())

    def _key(self, guild_id: int, source_user_id: str, target_user_id: str) -> tuple[int, str, str]:
        return (guild_id, source_user_id, target_user_id)

    def _apply_decay(self, key: tuple[int, str, str]) -> int:
        now = time()
        last = self._last_updated[key]
        elapsed = max(0, now - last)
        windows = int(elapsed // self.decay_window_seconds)

        if windows > 0 and self._risk_scores[key] > 0:
            reduction = windows * self.decay_amount
            self._risk_scores[key] = max(0, self._risk_scores[key] - reduction)

        self._last_updated[key] = now
        return self._risk_scores[key]

    def add_event(self, guild_id: int, source_user_id: str, target_user_id: str, event_data: dict) -> None:
        self._relationships[self._key(guild_id, source_user_id, target_user_id)].append(event_data)

    def get_context(self, guild_id: int, source_user_id: str, target_user_id: str) -> list[dict]:
        return list(self._relationships[self._key(guild_id, source_user_id, target_user_id)])

    def clear_context(self, guild_id: int, source_user_id: str, target_user_id: str) -> None:
        self._relationships[self._key(guild_id, source_user_id, target_user_id)].clear()

    def add_risk(self, guild_id: int, source_user_id: str, target_user_id: str, score: int) -> int:
        key = self._key(guild_id, source_user_id, target_user_id)
        current = self._apply_decay(key)
        self._risk_scores[key] = current + max(int(score), 0)
        self._last_updated[key] = time()
        return self._risk_scores[key]

    def get_risk(self, guild_id: int, source_user_id: str, target_user_id: str) -> int:
        return self._apply_decay(self._key(guild_id, source_user_id, target_user_id))

    def reset_risk(self, guild_id: int, source_user_id: str, target_user_id: str) -> None:
        key = self._key(guild_id, source_user_id, target_user_id)
        self._risk_scores[key] = 0
        self._last_updated[key] = time()

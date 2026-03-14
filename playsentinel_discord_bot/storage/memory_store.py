from __future__ import annotations

from collections import defaultdict, deque


class MemoryStore:
    def __init__(self, context_window: int = 10):
        self.context_window = context_window
        self._messages = defaultdict(lambda: deque(maxlen=self.context_window))

    def _key(self, guild_id: int, channel_id: int, author_id: int) -> tuple[int, int, int]:
        return (guild_id, channel_id, author_id)

    def add_message(self, guild_id: int, channel_id: int, author_id: int, message_data: dict) -> None:
        self._messages[self._key(guild_id, channel_id, author_id)].append(message_data)

    def get_context(self, guild_id: int, channel_id: int, author_id: int) -> list[dict]:
        return list(self._messages[self._key(guild_id, channel_id, author_id)])

    def clear_context(self, guild_id: int, channel_id: int, author_id: int) -> None:
        self._messages[self._key(guild_id, channel_id, author_id)].clear()

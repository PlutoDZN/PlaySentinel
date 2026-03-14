from __future__ import annotations

import time


class AlertStateStore:
    def __init__(self, cooldown_seconds: int = 120):
        self.cooldown_seconds = cooldown_seconds
        self._last_alert_times: dict[tuple[str, str], float] = {}

    def should_alert(self, source_user_id: str, target_id: str) -> bool:
        now = time.time()
        key = (source_user_id, target_id)
        last_time = self._last_alert_times.get(key, 0.0)

        if now - last_time < self.cooldown_seconds:
            return False

        self._last_alert_times[key] = now
        return True

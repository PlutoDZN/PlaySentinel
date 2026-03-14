from __future__ import annotations

import os
from dataclasses import dataclass

from dotenv import load_dotenv

load_dotenv()


def _get_int(name: str, default: int = 0) -> int:
    value = os.getenv(name)
    if value is None or value.strip() == "":
        return default
    return int(value)


def _get_str(name: str, default: str = "") -> str:
    return os.getenv(name, default).strip()


def _get_bool(name: str, default: bool = False) -> bool:
    value = os.getenv(name)
    if value is None or value.strip() == "":
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _get_first_str(names: list[str], default: str = "") -> str:
    for name in names:
        value = os.getenv(name, "").strip()
        if value:
            return value
    return default


def _get_int_list(name: str) -> list[int]:
    raw = os.getenv(name, "").strip()
    if not raw:
        return []
    return [int(part.strip()) for part in raw.split(",") if part.strip()]


@dataclass(frozen=True)
class Settings:
    discord_token: str
    api_url: str
    api_key: str
    reset_url: str
    alert_channel_id: int
    allowed_guild_id: int
    monitored_channel_ids: list[int]
    log_threshold: int
    alert_threshold: int
    spam_alert_threshold: int
    context_window: int
    relationship_context_window: int
    request_timeout_seconds: int
    alert_cooldown_seconds: int
    api_retries: int
    debug_logging: bool


def load_settings() -> Settings:
    settings = Settings(
        discord_token=_get_str("DISCORD_TOKEN"),
        api_url=_get_str("PLAYSENTINEL_API_URL"),
        api_key=_get_first_str(["PLAYSENTINEL_API_KEY", "PLAY_SENTINEL_API_KEY"]),
        reset_url=_get_str("PLAYSENTINEL_RESET_URL"),
        alert_channel_id=_get_int("ALERT_CHANNEL_ID", 0),
        allowed_guild_id=_get_int("ALLOWED_GUILD_ID", 0),
        monitored_channel_ids=_get_int_list("MONITORED_CHANNEL_IDS"),
        log_threshold=_get_int("LOG_THRESHOLD", 35),
        alert_threshold=_get_int("ALERT_THRESHOLD", 70),
        spam_alert_threshold=_get_int("SPAM_ALERT_THRESHOLD", 45),
        context_window=_get_int("CONTEXT_WINDOW", 10),
        relationship_context_window=_get_int("RELATIONSHIP_CONTEXT_WINDOW", 20),
        request_timeout_seconds=_get_int("REQUEST_TIMEOUT_SECONDS", 20),
        alert_cooldown_seconds=_get_int("ALERT_COOLDOWN_SECONDS", 120),
        api_retries=_get_int("API_RETRIES", 2),
        debug_logging=_get_bool("DEBUG_LOGGING", True),
    )

    if not settings.discord_token:
        raise ValueError("Missing DISCORD_TOKEN in .env")
    if not settings.api_url:
        raise ValueError("Missing PLAYSENTINEL_API_URL in .env")

    return settings

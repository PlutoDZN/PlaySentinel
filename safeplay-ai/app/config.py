import os
from pathlib import Path
from pydantic import BaseModel, Field

BASE_DIR = Path(__file__).resolve().parent


class Settings(BaseModel):
    # paths
    keywords_path: str = Field(
        default=os.getenv(
            "PLAY_SENTINEL_KEYWORDS",
            str(BASE_DIR / "dynamic_keywords.json")
        )
    )

    incidents_log: str = Field(
        default=os.getenv(
            "PLAY_SENTINEL_LOG",
            str(BASE_DIR / "incidents.jsonl")
        )
    )

    sessions_path: str = Field(
        default=os.getenv(
            "PLAY_SENTINEL_SESSIONS",
            str(BASE_DIR / "sessions.json")
        )
    )

    # behavior
    alert_threshold: int = Field(default=int(os.getenv("PLAY_SENTINEL_ALERT_THRESHOLD", "100")))
    session_ttl_hours: int = Field(default=int(os.getenv("PLAY_SENTINEL_SESSION_TTL_HOURS", "24")))
    max_session_messages: int = Field(default=int(os.getenv("PLAY_SENTINEL_MAX_SESSION_MESSAGES", "12")))

    # privacy
    log_messages: bool = Field(
        default=os.getenv("PLAY_SENTINEL_LOG_MESSAGES", "0").lower()
        not in ("0", "false", "no")
    )

    # api
    api_key: str = Field(default=os.getenv("PLAY_SENTINEL_API_KEY", ""))
    rate_limit_per_min: int = Field(default=int(os.getenv("PLAY_SENTINEL_RATE_LIMIT_PER_MIN", "120")))

    # cors
    cors_allow_origins: str = Field(default=os.getenv("PLAY_SENTINEL_CORS_ORIGINS", "http://localhost:5500"))

    def origins_list(self):
        return [o.strip() for o in self.cors_allow_origins.split(",") if o.strip()]

from pydantic import BaseModel, Field
from typing import Dict, List, Optional, Any


class AnalyzeRequest(BaseModel):
    message: str = Field(min_length=1)
    user_id: str = "anon"
    target_id: str = "default"


class AnalyzeResponse(BaseModel):
    score: int
    conversation_risk: int
    risk_level: str
    stage: str
    language: str
    categories: Dict[str, int]
    matched: List[str]
    reasons: List[str]

    # Policy engine output (optional but usually present)
    actions: List[str] = []
    action_reasons: List[Dict[str, str]] = []
    policy_version: str = ""


class HealthResponse(BaseModel):
    status: str
    active_sessions: int

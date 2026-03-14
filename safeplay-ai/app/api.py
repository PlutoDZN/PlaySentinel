
from collections import deque
from datetime import datetime
from html import escape
from pathlib import Path
from typing import Any, Dict
import json

from fastapi import Depends, FastAPI, Header, HTTPException, Request, APIRouter
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from pydantic import BaseModel

from .config import Settings
from .schemas import AnalyzeRequest, AnalyzeResponse, HealthResponse
from .store import InMemorySessionStore
from .detector import Detector
from .policy_engine import PolicyEngine


settings = Settings()
policy_engine = PolicyEngine()

if not settings.api_key:
    raise RuntimeError("PLAY_SENTINEL_API_KEY must be set")

app = FastAPI(title="PlaySentinel API", version="1.2.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://plutodzn.github.io"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

store = InMemorySessionStore(
    sessions_file=settings.sessions_path,
    max_messages=settings.max_session_messages,
    ttl_hours=settings.session_ttl_hours,
)

detector = Detector(
    keyword_file=settings.keywords_path,
    store=store,
    log_path=settings.incidents_log,
    alert_threshold=settings.alert_threshold,
    log_messages=settings.log_messages,
)

_rate_store: Dict[str, deque] = {}
RATE_LIMIT_PER_MIN = settings.rate_limit_per_min


class ResetSessionRequest(BaseModel):
    user_id: str
    target_id: str
    platform: str = "discord"


def _check_api_key(x_api_key: str = Header(...)) -> str:
    if x_api_key != settings.api_key:
        raise HTTPException(status_code=401, detail="invalid api key")
    return x_api_key


def _rate_limit(request: Request, api_key: str = Depends(_check_api_key)):
    identifier = f"{api_key}:{request.client.host}"
    now = datetime.utcnow().timestamp()
    bucket = _rate_store.setdefault(identifier, deque())

    while bucket and bucket[0] <= now - 60:
        bucket.popleft()

    if len(bucket) >= RATE_LIMIT_PER_MIN:
        raise HTTPException(status_code=429, detail="rate limit exceeded", headers={"Retry-After": "60"})

    bucket.append(now)


def _cleanup_sessions() -> None:
    try:
        store.cleanup()
    except Exception as exc:
        print(f"[SESSION CLEANUP WARN] {exc}")


def _read_incidents(limit: int = 200) -> list[dict]:
    path = Path(settings.incidents_log or "incidents.jsonl")
    if not path.exists():
        return []

    rows = []
    with path.open("r", encoding="utf-8") as file:
        for line in file:
            if not line.strip():
                continue
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError:
                continue

    return list(reversed(rows[-limit:]))


router = APIRouter(prefix="/v1", dependencies=[Depends(_rate_limit)])


@router.get("/health", response_model=HealthResponse)
def health():
    _cleanup_sessions()
    return HealthResponse(status="ok", active_sessions=len(store.snapshot()))


@router.post("/analyze", response_model=AnalyzeResponse)
def analyze(req: AnalyzeRequest):
    _cleanup_sessions()

    score, conv_risk, cats, matched, stage, lang, reasons = detector.analyze(
        req.message, user_id=req.user_id, target_id=req.target_id
    )

    risk_level = detector.get_risk_level(int(conv_risk))

    policy_result = policy_engine.evaluate({
        "risk_level": risk_level,
        "stage": stage,
    })

    return AnalyzeResponse(
        score=int(score),
        conversation_risk=int(conv_risk),
        risk_level=risk_level,
        stage=stage,
        language=lang,
        categories=cats,
        matched=matched,
        reasons=reasons,
        actions=policy_result.get("actions", []),
        action_reasons=policy_result.get("action_reasons", []),
        policy_version=policy_result.get("policy_version", ""),
    )


@router.get("/sessions")
def sessions():
    _cleanup_sessions()
    snaps = store.snapshot()
    out = {}
    for (u, t), s in snaps.items():
        conv = int(s.get("conversation_risk", 0))
        out[f"{u}→{t}"] = {
            "conversation_risk": conv,
            "risk_level": detector.get_risk_level(conv),
            "stage": s.get("stage", "LOW"),
            "messages_count": len(s.get("messages", [])),
            "updated_at": s.get("updated_at"),
        }
    return out


@router.get("/session/{user_id}/{target_id}")
def session(user_id: str, target_id: str):
    _cleanup_sessions()
    snaps = store.snapshot()
    key = (user_id, target_id)
    if key not in snaps:
        raise HTTPException(status_code=404, detail="Session not found")
    s = snaps[key]
    conv = int(s.get("conversation_risk", 0))
    return {
        "user_id": user_id,
        "target_id": target_id,
        "conversation_risk": conv,
        "risk_level": detector.get_risk_level(conv),
        "stage": s.get("stage", "LOW"),
        "messages": s.get("messages", []),
        "category_history": s.get("category_history", {}),
        "created_at": s.get("created_at"),
        "updated_at": s.get("updated_at"),
    }


@router.delete("/session/{user_id}/{target_id}")
def delete_session(user_id: str, target_id: str):
    _cleanup_sessions()
    deleted = store.delete(user_id, target_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Session not found")
    return {"status": "reset", "user_id": user_id, "target_id": target_id}



@router.post("/reset_session")
def reset_session(req: ResetSessionRequest):
    _cleanup_sessions()

    try:
        deleted = store.delete(req.user_id, req.target_id)
    except Exception as exc:
        print(f"[RESET WARN] delete failed for {req.user_id}->{req.target_id}: {exc}")
        deleted = False

    if not deleted:
        return {
            "status": "no_session",
            "user_id": req.user_id,
            "target_id": req.target_id,
            "platform": req.platform,
        }

    return {
        "status": "reset",
        "user_id": req.user_id,
        "target_id": req.target_id,
        "platform": req.platform,
    }


    return {
        "status": "reset",
        "user_id": req.user_id,
        "target_id": req.target_id,
        "platform": req.platform,
    }


@router.get("/incidents")
def incidents(limit: int = 100):
    return {"items": _read_incidents(limit=limit)}


app.include_router(router)


@app.get("/dashboard", response_class=HTMLResponse)
def dashboard():
    _cleanup_sessions()
    sessions = []
    for key, session in store.snapshot().items():
        user_id, target_id = key
        conv = int(session.get("conversation_risk", 0))
        sessions.append({
            "user_id": user_id,
            "target_id": target_id,
            "conversation_risk": conv,
            "risk_level": detector.get_risk_level(conv),
            "stage": session.get("stage", "LOW"),
            "messages_count": len(session.get("messages", [])),
            "updated_at": session.get("updated_at", ""),
        })
    sessions.sort(key=lambda x: x["conversation_risk"], reverse=True)

    incidents = _read_incidents(limit=100)

    session_rows = "".join(
        f"<tr><td>{escape(item['user_id'])}</td><td>{escape(item['target_id'])}</td><td>{item['conversation_risk']}</td><td>{escape(item['risk_level'])}</td><td>{escape(item['stage'])}</td><td>{item['messages_count']}</td><td>{escape(str(item['updated_at']))}</td></tr>"
        for item in sessions
    ) or "<tr><td colspan='7'>No active sessions.</td></tr>"

    incident_cards = "".join(
        f"""
        <div class="card">
          <div class="meta">{escape(str(item.get('ts', '')))} · {escape(item.get('user_id', ''))} → {escape(item.get('target_id', ''))}</div>
          <div><strong>Score:</strong> {int(item.get('score', 0))} · <strong>Stage:</strong> {escape(item.get('stage', ''))} · <strong>Risk:</strong> {escape(item.get('risk_level', ''))}</div>
          <div><strong>Matched:</strong> {escape(', '.join(item.get('matched', []))) or 'none'}</div>
          <div><strong>Reasons:</strong> {escape(', '.join(item.get('reasons', []))) or 'none'}</div>
          <pre>{escape(str(item.get('message', '')))}</pre>
        </div>
        """
        for item in incidents
    ) or "<div class='card'>No incidents logged yet.</div>"

    total_sessions = len(sessions)
    critical_sessions = sum(1 for x in sessions if x["risk_level"] == "CRITICAL")
    incident_count = len(incidents)

    html = f"""
    <!doctype html>
    <html>
    <head>
      <meta charset="utf-8">
      <title>PlaySentinel Dashboard</title>
      <style>
        body {{ font-family: Arial, sans-serif; margin: 0; background:#0b1220; color:#e5e7eb; }}
        .wrap {{ max-width: 1200px; margin: 0 auto; padding: 24px; }}
        .hero {{ display:grid; grid-template-columns: repeat(3, 1fr); gap: 16px; margin-bottom: 24px; }}
        .stat, .panel, .card {{ background:#111827; border:1px solid #1f2937; border-radius:16px; padding:16px; }}
        .stat h2 {{ margin:0; font-size:28px; }}
        h1,h2,h3 {{ margin-top:0; }}
        table {{ width:100%; border-collapse: collapse; }}
        th, td {{ text-align:left; padding:10px; border-bottom:1px solid #1f2937; font-size:14px; }}
        pre {{ white-space: pre-wrap; word-break: break-word; background:#0f172a; padding:12px; border-radius:12px; }}
        .grid {{ display:grid; grid-template-columns: 1.2fr 1fr; gap: 16px; }}
        .meta {{ color:#93c5fd; margin-bottom:8px; font-size:12px; }}
        .muted {{ color:#9ca3af; }}
        @media (max-width: 900px) {{
          .hero, .grid {{ grid-template-columns: 1fr; }}
        }}
      </style>
    </head>
    <body>
      <div class="wrap">
        <h1>PlaySentinel Dashboard</h1>
        <p class="muted">Live overview of active sessions and recent incidents.</p>

        <div class="hero">
          <div class="stat"><div class="muted">Active sessions</div><h2>{total_sessions}</h2></div>
          <div class="stat"><div class="muted">Critical sessions</div><h2>{critical_sessions}</h2></div>
          <div class="stat"><div class="muted">Recent incidents</div><h2>{incident_count}</h2></div>
        </div>

        <div class="grid">
          <div class="panel">
            <h3>Active sessions</h3>
            <table>
              <thead>
                <tr>
                  <th>User</th><th>Target</th><th>Risk</th><th>Level</th><th>Stage</th><th>Msgs</th><th>Updated</th>
                </tr>
              </thead>
              <tbody>{session_rows}</tbody>
            </table>
          </div>

          <div class="panel">
            <h3>Recent incidents</h3>
            {incident_cards}
          </div>
        </div>
      </div>
    </body>
    </html>
    """
    return HTMLResponse(html)

import json
import os
import re
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Dict, List, Tuple, Optional, Any, Iterable

from .utils import tokenize, normalize_text, sha256_text
from .store import SessionStore


@dataclass(frozen=True)
class PhraseRule:
    reason: str
    category: str
    score: int
    pattern: re.Pattern


class Detector:
    """
    Production-ish Detector:
    - fast keyword scoring (O(tokens)) via keyword index + small candidate set (keeps light stemming/prefix)
    - phrase rules (compiled regex)
    - context guards (reduce false positives)
    - session-based accumulation (user_id -> target_id)
    - bounded memory: session message history is capped (store may also cap via deque maxlen)
    - robust incident logging (JSONL), never crashes pipeline
    """

    MAX_MESSAGE_CHARS = 2000
    MAX_MATCHED = 50
    MAX_REASONS = 25
    DECAY_AMOUNT = 5
    DECAY_WINDOW_SECONDS = 300

    _ID_RE = re.compile(r"^[a-zA-Z0-9_\-:.]{1,64}$")

    def __init__(
        self,
        keyword_file: str,
        store: SessionStore,
        log_path: Optional[str],
        alert_threshold: int,
        log_messages: bool,
    ) -> None:
        self.keyword_file = keyword_file
        self.keywords = self._load_keywords()
        self.store = store
        self.log_path = log_path
        self.alert_threshold = int(alert_threshold)
        self.log_messages = bool(log_messages)

        # alias mapping
        self.alias_patterns = [
            (re.compile(r"\b(?:dc|d\.c\.|disc0rd|discor(d)?|discord)\b", re.I), "discord"),
            (re.compile(r"\b(?:sc|s\.c\.|sn4p|snap|snapchat|snapch(?:at)?)\b", re.I), "snapchat"),
            (re.compile(r"\b(?:tg|t\.g\.|telegram)\b", re.I), "telegram"),
            (re.compile(r"\b(?:wa|w\.a\.|whatsapp)\b", re.I), "whatsapp"),
            (re.compile(r"\b(?:ig|insta|instagram)\b", re.I), "instagram"),
            (re.compile(r"\b(?:sig|signal)\b", re.I), "signal"),
            (re.compile(r"\b(?:skype)\b", re.I), "skype"),
            (re.compile(r"\b(?:steam)\b", re.I), "steam"),
            (re.compile(r"\b(?:riot)\b", re.I), "riot"),
            (re.compile(r"\b(?:epic|epicgames)\b", re.I), "epic"),
            (re.compile(r"\b(?:battlenet|battle\.net)\b", re.I), "battle.net"),
            (re.compile(r"\b(?:kick)\b", re.I), "kick"),
            (re.compile(r"\b(?:kik)\b", re.I), "kik"),
        ]

        # phrase rules
        self.phrase_rules: List[PhraseRule] = [
            PhraseRule("secrecy_phrase_detected", "geheimhaltung", 30, re.compile(r"\b(sag|erz[äa]hl|verrat)\b.*\b(niemand|keinem|keiner|nobody|anyone)\b", re.I)),
            PhraseRule("secrecy_keep_secret", "geheimhaltung_en", 25, re.compile(r"\bkeep it secret\b", re.I)),
            PhraseRule("dont_tell_parents", "geheimhaltung_en", 35, re.compile(r"\bdon'?t tell\b.*\b(parents|mom|dad)\b", re.I)),
            PhraseRule("nicht_deinen_eltern", "geheimhaltung", 35, re.compile(r"\b(nicht|kein)\b.*\b(eltern|mama|papa|mutter|vater)\b", re.I)),
            PhraseRule("platform_switch_action", "plattformwechsel", 25, re.compile(r"\b(wechsel|komm|schreib|add|invite|dm|pn)\b.*\b(discord|snapchat|telegram|whatsapp|instagram)\b", re.I)),
            PhraseRule("platform_switch_action_en", "plattformwechsel_en", 25, re.compile(r"\b(switch|move|message|dm|add|join|invite)\b.*\b(discord|snapchat|telegram|whatsapp|instagram)\b", re.I)),
            PhraseRule("age_question_detected", "altersfragen", 20, re.compile(r"\b(wie alt|dein alter|wieviele jahre)\b", re.I)),
            PhraseRule("age_question_detected_en", "altersfragen_en", 20, re.compile(r"\b(how old|your age)\b", re.I)),
        ]

        # false-positive context guards
        self.age_false_context = {
            "account","acc","lvl","level","rank","elo","mmr","season","jahrgang","klasse",
            "gpu","cpu","grafikkarte","pc","laptop","setup","monitor","ping","lag","router"
        }
        self.secrecy_harmless_context = {
            "boss","secretboss","easter","egg","easteregg","quest","room","level","loot","drop","spawn",
            "versteck","geheimraum","secretroom","hidden","hiddenboss"
        }
        self.platform_harmless_context = {
            "down","offline","lag","crash","bug","gehtnicht","geht","problem","störung","stoerung"
        }

        # stage thresholds
        self.stage_thresholds = {
            "TRUST_BUILDING": 15,
            "INFO_GATHERING": 35,
            "ISOLATION": 70,
            "GROOMING": 140,
        }

        # keyword index for fast lookup: key -> [(cat,score), ...]
        self.keyword_index: Dict[str, List[Tuple[str, int]]] = {}
        for cat, kws in self.keywords.items():
            if not isinstance(kws, dict):
                continue
            for key, val in kws.items():
                k = str(key).strip().lower()
                if not k:
                    continue
                self.keyword_index.setdefault(k, []).append((cat, int(val)))

        self._log_lock = threading.Lock()
        if self.log_path:
            try:
                os.makedirs(os.path.dirname(self.log_path) or ".", exist_ok=True)
            except Exception:
                pass

    def _utc_now(self) -> str:
        return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

    def _load_keywords(self) -> Dict[str, Dict[str, int]]:
        if not os.path.exists(self.keyword_file):
            raise FileNotFoundError(f"Keyword file missing: {self.keyword_file}")
        with open(self.keyword_file, "r", encoding="utf-8") as f:
            data = json.load(f)
        if not isinstance(data, dict):
            raise ValueError("Keyword JSON must be an object: {category:{keyword:score}}")
        out: Dict[str, Dict[str, int]] = {}
        for cat, kws in data.items():
            if isinstance(kws, dict):
                out[str(cat)] = {str(k).lower(): int(v) for k, v in kws.items()}
        return out

    def _apply_aliases(self, text: str) -> str:
        s = text
        for patt, canon in self.alias_patterns:
            s = patt.sub(canon, s)
        return s

    def _detect_language(self, text: str) -> str:
        t = tokenize(text)
        en_hits = sum(1 for w in t if w in ("how","old","your","dont","parents","secret","switch","move"))
        de_hits = sum(1 for w in t if w in ("wie","alt","dein","eltern","geheim","wechsel","komm"))
        return "en" if en_hits > de_hits else "de"

    def _age_context_is_safe(self, tokens: List[str]) -> bool:
        return any(w in self.age_false_context for w in tokens)

    def _platform_context_is_harmless(self, tokens: List[str]) -> bool:
        return any(w in self.platform_harmless_context for w in tokens)

    def _secrecy_context_is_harmless(self, tokens: List[str]) -> bool:
        return any(w in self.secrecy_harmless_context for w in tokens)

    def get_risk_level(self, risk: int) -> str:
        if risk >= 400:
            return "CRITICAL"
        if risk >= 250:
            return "HIGH"
        if risk >= 150:
            return "MEDIUM"
        if risk >= 50:
            return "LOW"
        return "SAFE"

    def determine_stage(self, hist: Dict[str, int]) -> str:
        total = sum(int(v) for v in hist.values())
        if total >= self.stage_thresholds["GROOMING"]:
            return "GROOMING"
        if total >= self.stage_thresholds["ISOLATION"]:
            return "ISOLATION"
        if total >= self.stage_thresholds["INFO_GATHERING"]:
            return "INFO_GATHERING"
        if total >= self.stage_thresholds["TRUST_BUILDING"]:
            return "TRUST_BUILDING"
        return "LOW"

    def _safe_id(self, value: str, fallback: str) -> str:
        v = (value or "").strip()
        return v if self._ID_RE.match(v) else fallback

    def _token_candidates(self, w: str) -> Iterable[str]:
        # Keep behavior similar to original _word_match:
        # - exact
        # - prefix match up to +2 chars (simulate by checking shortened word)
        # - light stemming (remove common suffixes)
        yield w
        if len(w) > 2:
            yield w[:-1]
        if len(w) > 3:
            yield w[:-2]
        for suf in ("en", "n", "s", "e", "er", "es"):
            if w.endswith(suf) and len(w) > len(suf) + 1:
                yield w[:-len(suf)]

    def _append_message(self, messages: Any, entry: Dict[str, Any]) -> None:
        # messages can be deque or list
        try:
            messages.append(entry)
        except Exception:
            # fallback: ignore
            return


    def _apply_session_decay(self, session: Dict[str, Any]) -> None:
        updated_at = session.get("updated_at")
        if not updated_at:
            return
        try:
            last_dt = datetime.fromisoformat(updated_at)
        except Exception:
            return

        elapsed = (datetime.utcnow() - last_dt).total_seconds()
        windows = int(max(0, elapsed) // self.DECAY_WINDOW_SECONDS)
        if windows <= 0:
            return

        reduction = windows * self.DECAY_AMOUNT
        session["conversation_risk"] = max(0, int(session.get("conversation_risk", 0)) - reduction)

        hist = session.get("category_history", {})
        if isinstance(hist, dict):
            session["category_history"] = {
                k: max(0, int(v) - reduction) for k, v in hist.items()
            }

    def _maybe_log_incident(
        self,
        message: str,
        score: int,
        matched: List[str],
        categories: Dict[str, int],
        stage: str,
        user_id: str,
        target_id: str,
        reasons: List[str],
    ) -> None:
        if not self.log_path:
            return

        msg_to_log = message if self.log_messages else f"HASH:{sha256_text(message)}"
        entry = {
            "ts": self._utc_now(),
            "user_id": user_id,
            "target_id": target_id,
            "score": int(score),
            "stage": stage,
            "risk_level": self.get_risk_level(int(score)),
            "matched": matched[: self.MAX_MATCHED],
            "reasons": reasons[: self.MAX_REASONS],
            "categories": categories,
            "message": msg_to_log,
        }

        try:
            line = json.dumps(entry, ensure_ascii=False) + "\n"
            with self._log_lock:
                with open(self.log_path, "a", encoding="utf-8") as f:
                    f.write(line)
                    f.flush()
                    os.fsync(f.fileno())
        except Exception:
            pass

    def analyze(self, message: str, user_id: str = "anon", target_id: str = "default") -> Tuple[int, int, Dict[str, int], List[str], str, str, List[str]]:
        raw = (message or "").strip()
        if len(raw) > self.MAX_MESSAGE_CHARS:
            raw = raw[: self.MAX_MESSAGE_CHARS]

        uid = self._safe_id(user_id, "anon")
        tid = self._safe_id(target_id, "default")

        text = self._apply_aliases(raw)
        norm = normalize_text(text)
        tokens = tokenize(norm)
        lang = self._detect_language(norm)

        categories: Dict[str, int] = {cat: 0 for cat in self.keywords.keys()}
        matched: List[str] = []
        reasons: List[str] = []
        score = 0

        age_safe = self._age_context_is_safe(tokens)
        platform_harmless = self._platform_context_is_harmless(tokens)
        secrecy_harmless = self._secrecy_context_is_harmless(tokens)

        # 1) token scoring (fast)
        seen_matched = set()
        for w in tokens:
            for cand in self._token_candidates(w):
                entries = self.keyword_index.get(cand)
                if not entries:
                    continue

                if cand not in seen_matched:
                    seen_matched.add(cand)
                    matched.append(cand)
                    if len(matched) >= self.MAX_MATCHED:
                        break

                for cat, val in entries:
                    if cat in ("altersfragen", "altersfragen_en") and age_safe:
                        continue
                    if cat in ("plattformwechsel", "plattformwechsel_en") and platform_harmless:
                        continue
                    if cat in ("geheimhaltung", "geheimhaltung_en") and secrecy_harmless:
                        continue

                    score += int(val)
                    categories[cat] = int(categories.get(cat, 0)) + int(val)
            if len(matched) >= self.MAX_MATCHED:
                break

        # 2) phrase rules
        for rule in self.phrase_rules:
            if not rule.pattern.search(norm):
                continue

            cat = rule.category
            if cat in ("altersfragen", "altersfragen_en") and age_safe:
                continue
            if cat in ("plattformwechsel", "plattformwechsel_en") and platform_harmless:
                continue
            if cat in ("geheimhaltung", "geheimhaltung_en") and secrecy_harmless:
                continue

            score += int(rule.score)
            categories[cat] = int(categories.get(cat, 0)) + int(rule.score)
            if rule.reason not in reasons:
                reasons.append(rule.reason)
                if len(reasons) >= self.MAX_REASONS:
                    break

        # 3) combo bonuses
        platform_score = int(categories.get("plattformwechsel", 0)) + int(categories.get("plattformwechsel_en", 0))
        gift_score = int(categories.get("geschenke", 0)) + int(categories.get("geschenke_en", 0))
        age_score = int(categories.get("altersfragen", 0)) + int(categories.get("altersfragen_en", 0))
        trust_score = int(categories.get("vertrauensaufbau", 0)) + int(categories.get("vertrauensaufbau_en", 0))

        if platform_score > 0 and gift_score > 0:
            score += 35
            if "bonus_platform_gift" not in reasons and len(reasons) < self.MAX_REASONS:
                reasons.append("bonus_platform_gift")

        if age_score > 0 and trust_score > 0:
            score += 25
            if "bonus_age_trust" not in reasons and len(reasons) < self.MAX_REASONS:
                reasons.append("bonus_age_trust")

        # 4) session update
        try:
            session = self.store.get_or_create(uid, tid)
        except Exception:
            conversation_risk = int(score)
            stage = "LOW"
            if score >= self.alert_threshold or reasons:
                self._maybe_log_incident(raw, score, matched, categories, stage, uid, tid, reasons)
            return score, conversation_risk, categories, matched, stage, lang, reasons

        session.setdefault("messages", [])
        session.setdefault("conversation_risk", 0)
        session.setdefault("category_history", {})
        session.setdefault("stage", "LOW")

        self._apply_session_decay(session)

        entry = {
            "ts": self._utc_now(),
            "score": int(score),
            "matched": matched[: self.MAX_MATCHED],
            "reasons": reasons[: self.MAX_REASONS],
            "categories": categories,
            "text": (norm[:160] + "…") if len(norm) > 160 else norm,
        }
        self._append_message(session["messages"], entry)

        session["conversation_risk"] = int(session.get("conversation_risk", 0)) + int(score)
        session["updated_at"] = datetime.utcnow().isoformat()

        hist = session.get("category_history", {})
        if not isinstance(hist, dict):
            hist = {}
        for c, v in categories.items():
            hist[c] = int(hist.get(c, 0)) + int(v)
        session["category_history"] = hist

        stage = self.determine_stage(hist)
        session["stage"] = stage

        if score >= self.alert_threshold or reasons:
            self._maybe_log_incident(raw, score, matched, categories, stage, uid, tid, reasons)

        return score, int(session["conversation_risk"]), categories, matched, stage, lang, reasons

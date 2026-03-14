from __future__ import annotations

import re
import time
from collections import Counter


URL_PATTERN = re.compile(r"https?://|discord\.gg/|www\.", re.IGNORECASE)
INVITE_PATTERN = re.compile(r"(discord\.gg/|discord\.com/invite/)", re.IGNORECASE)
OBFUSCATED_SCAM_PATTERN = re.compile(r"(fr[e3]{2}\s*robux|fr[e3]{2}\s*nitro|cl[i1]ck\s*h[e3]r[e3])", re.IGNORECASE)
REPEATED_CHAR_PATTERN = re.compile(r"(.)\1{7,}")


class SpamDetector:
    def __init__(self) -> None:
        self.user_message_times: dict[str, list[float]] = {}

    @staticmethod
    def normalize(text: str) -> str:
        return " ".join((text or "").lower().split())

    def detect(self, message: str, user_id: str, recent_messages: list[dict]) -> dict:
        score = 0
        signals: list[str] = []
        text = message or ""

        alpha_count = sum(1 for c in text if c.isalpha())
        if alpha_count > 0 and len(text) >= 12:
            upper_ratio = sum(1 for c in text if c.isupper()) / alpha_count
            if upper_ratio > 0.6:
                score += 15
                signals.append("caps_spam")

        if REPEATED_CHAR_PATTERN.search(text):
            score += 15
            signals.append("repeated_chars")

        link_count = len(URL_PATTERN.findall(text))
        if link_count >= 1:
            score += 15
            signals.append("contains_link")
        if link_count >= 2:
            score += 20
            signals.append("multiple_links")

        if INVITE_PATTERN.search(text):
            score += 20
            signals.append("invite_link")

        if text.count("@") >= 4:
            score += 25
            signals.append("mass_mentions")

        normalized = self.normalize(text)
        recent_texts = [
            self.normalize(item.get("content", ""))
            for item in recent_messages
            if item.get("content")
        ]
        counts = Counter(recent_texts)

        if normalized and counts.get(normalized, 0) >= 2:
            score += 35
            signals.append("duplicate_message")

        now = time.time()
        user_times = self.user_message_times.setdefault(user_id, [])
        user_times.append(now)
        user_times[:] = [t for t in user_times if now - t < 10]

        if len(user_times) >= 6:
            score += 30
            signals.append("message_burst")

        suspicious_terms = [
            "free nitro",
            "free robux",
            "claim now",
            "earn money",
            "click here",
            "giveaway link",
            "limited offer",
            "verify account",
            "login here",
        ]
        for term in suspicious_terms:
            if term in normalized:
                score += 20
                signals.append("promo_pattern")
                break

        if OBFUSCATED_SCAM_PATTERN.search(text):
            score += 20
            signals.append("obfuscated_scam_phrase")

        stage = "spam_detected" if score >= 25 else "clean"
        action = "moderator_alert" if score >= 45 else "moderator_review" if score >= 25 else "none"

        return {
            "score": score,
            "signals": signals,
            "category": "spam" if score >= 25 else "unknown",
            "stage": stage,
            "action": action,
            "actions": [action] if action != "none" else [],
            "conversation_risk": score,
        }

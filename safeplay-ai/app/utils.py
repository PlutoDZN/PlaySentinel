import hashlib
import re
from typing import List, Tuple


EXPLANATION_MAP = {
    "age_question_detected": "User asked for age",
    "age_question_detected_en": "User asked for age",
    "platform_switch_action": "User attempted to move conversation off-platform",
    "platform_switch_action_en": "User attempted to move conversation off-platform",
    "secrecy_phrase_detected": "User used secrecy language",
    "secrecy_keep_secret": "User asked to keep the conversation secret",
    "dont_tell_parents": "User suggested hiding the conversation from parents",
    "nicht_deinen_eltern": "User suggested hiding the conversation from parents",
}

HIGH_SIGNALS = {
    "platform_switch_action",
    "platform_switch_action_en",
    "secrecy_phrase_detected",
    "secrecy_keep_secret",
    "dont_tell_parents",
    "nicht_deinen_eltern",
}

MEDIUM_SIGNALS = {
    "age_question_detected",
    "age_question_detected_en",
}


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def normalize_text(text: str) -> str:
    s = (text or "").lower()
    s = re.sub(r"0", "o", s)
    s = re.sub(r"[^ \wäöüß]", " ", s)
    s = re.sub(r"\s+", " ", s).strip()
    return s


def tokenize(text: str) -> List[str]:
    s = normalize_text(text)
    s = re.sub(r"[^\w\säöüß]", "", s)
    s = re.sub(r"\s+", " ", s).strip()
    return s.split()


def safe_split_session_key(key_str: str) -> Tuple[str, str]:
    parts = key_str.split("|", 1)
    if len(parts) == 2:
        return parts[0], parts[1]
    return key_str, "default"


def build_explanations(matched: list[str]) -> tuple[list[str], list[dict]]:
    explanations: list[str] = []
    evidence: list[dict] = []

    for signal in matched or []:
        signal_name = str(signal)
        explanation = EXPLANATION_MAP.get(signal_name, signal_name.replace("_", " ").capitalize())
        if signal_name in HIGH_SIGNALS:
            severity = "high"
        elif signal_name in MEDIUM_SIGNALS:
            severity = "medium"
        else:
            severity = "low"

        explanations.append(explanation)
        evidence.append({
            "signal": signal_name,
            "severity": severity,
        })

    return explanations, evidence

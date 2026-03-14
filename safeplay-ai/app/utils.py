import hashlib
import re
from typing import List, Tuple


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def normalize_text(text: str) -> str:
    s = (text or "").lower()
    # sehr aggressive "noise" entfernung, aber umlaute lassen
    s = re.sub(r"0", "o", s)
    s = re.sub(r"[^ \wäöüß]", " ", s)
    s = re.sub(r"\s+", " ", s).strip()
    return s


def tokenize(text: str) -> List[str]:
    s = normalize_text(text)
    # nochmal token-clean
    s = re.sub(r"[^\w\säöüß]", "", s)
    s = re.sub(r"\s+", " ", s).strip()
    return s.split()


def safe_split_session_key(key_str: str) -> Tuple[str, str]:
    # fix: split("|", 1)
    parts = key_str.split("|", 1)
    if len(parts) == 2:
        return parts[0], parts[1]
    return key_str, "default"
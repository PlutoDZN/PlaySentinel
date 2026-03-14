from __future__ import annotations


def truncate(text: str, limit: int) -> str:
    text = text or ""
    if len(text) <= limit:
        return text
    return text[: max(limit - 3, 0)] + "..."


def format_alert_message(
    case_id: str,
    author_name: str,
    author_id: str,
    target_id: str,
    channel_mention: str,
    message_content: str,
    score: int,
    category: str,
    stage: str,
    signals: list[str],
    action: str,
    context: list[dict],
    conversation_risk: int | None = None,
    source: str = "unknown",
) -> str:
    signal_text = ", ".join(signals) if signals else "none"

    context_lines = []
    for item in context[-5:]:
        context_author = item.get("author_name", "unknown")
        context_target = item.get("target_id", "unknown")
        context_content = truncate(item.get("content", ""), 120)
        context_lines.append(f"- {context_author} → {context_target}: {context_content}")

    risk_line = f"**Conversation Risk:** {conversation_risk}\n" if conversation_risk is not None else ""
    context_block = "\n".join(context_lines) if context_lines else "No context available."

    return (
        f"🚨 **PlaySentinel Alert**\n\n"
        f"**Case ID:** `{case_id}`\n"
        f"**Source User:** {author_name} (`{author_id}`)\n"
        f"**Target:** `{target_id}`\n"
        f"**Channel:** {channel_mention}\n"
        f"**Score:** {score}\n"
        f"{risk_line}"
        f"**Category:** {category}\n"
        f"**Stage:** {stage}\n"
        f"**Action:** {action}\n"
        f"**Source:** {source}\n"
        f"**Signals:** {signal_text}\n\n"
        f"**Message:**\n"
        f"{truncate(message_content, 500)}\n\n"
        f"**Relationship Context:**\n"
        f"{truncate(context_block, 1200)}"
    )

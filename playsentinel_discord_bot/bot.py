from __future__ import annotations

from datetime import timezone

import discord
from discord import app_commands

from config import load_settings
from services.api_client import PlaySentinelApiClient
from services.alert_formatter import format_alert_message
from services.spam_detector import SpamDetector
from services.target_resolver import resolve_target_id
from storage.alert_state_store import AlertStateStore
from storage.case_store import CaseStore
from storage.memory_store import MemoryStore
from storage.relationship_store import RelationshipStore


settings = load_settings()

COLLECT_ONLY_MODE = True

intents = discord.Intents.default()
intents.guilds = True
intents.messages = True
intents.message_content = True

client = discord.Client(intents=intents)
tree = app_commands.CommandTree(client)

memory_store = MemoryStore(context_window=settings.context_window)
relationship_store = RelationshipStore(context_window=settings.relationship_context_window)
alert_state_store = AlertStateStore(cooldown_seconds=settings.alert_cooldown_seconds)
spam_detector = SpamDetector()
case_store = CaseStore(file_path="flagged_cases.jsonl")

api_client = PlaySentinelApiClient(
    api_url=settings.api_url,
    api_key=settings.api_key,
    timeout_seconds=settings.request_timeout_seconds,
    retries=settings.api_retries,
    reset_url=settings.reset_url,
)


def normalize_message(message: discord.Message) -> dict:
    created_at = message.created_at
    if created_at.tzinfo is None:
        created_at = created_at.replace(tzinfo=timezone.utc)

    mentions = [str(user.id) for user in message.mentions if not user.bot]

    return {
        "message_id": str(message.id),
        "author_id": str(message.author.id),
        "author_name": str(message.author),
        "content": message.content,
        "timestamp": created_at.isoformat(),
        "channel_id": str(message.channel.id),
        "guild_id": str(message.guild.id) if message.guild else None,
        "mentions": mentions,
        "reply_to_message_id": (
            str(message.reference.message_id)
            if message.reference and message.reference.message_id
            else None
        ),
    }


def is_monitored_message(message: discord.Message) -> bool:
    if message.guild is None:
        return False
    if settings.allowed_guild_id and message.guild.id != settings.allowed_guild_id:
        return False
    if settings.monitored_channel_ids and message.channel.id not in settings.monitored_channel_ids:
        return False
    return True


def build_payload(message: discord.Message, relationship_context: list[dict], target_id: str) -> dict:
    normalized = normalize_message(message)
    context_messages = [item.get("content", "") for item in relationship_context if item.get("content")]

    return {
        "message": normalized["content"],
        "user_id": normalized["author_id"],
        "target_id": target_id,
        "platform": "discord",
        "metadata": {
            "author_name": normalized["author_name"],
            "guild_id": normalized["guild_id"],
            "channel_id": normalized["channel_id"],
            "message_id": normalized["message_id"],
            "timestamp": normalized["timestamp"],
            "reply_to_message_id": normalized["reply_to_message_id"],
            "mentions": normalized["mentions"],
            "relationship_context": context_messages,
        },
    }


def fallback_api_result(reason: str = "api_unavailable") -> dict:
    return {
        "score": 0,
        "conversation_risk": 0,
        "category": "unknown",
        "stage": reason,
        "signals": [],
        "action": "review",
        "actions": [],
        "source": "api_fallback",
    }


def parse_api_result(result: dict | None) -> dict:
    if not isinstance(result, dict):
        return fallback_api_result()

    message_score = result.get("score", 0)
    conversation_risk = result.get("conversation_risk", 0)
    stage = str(result.get("stage", "unknown"))
    matched = result.get("matched", [])
    actions = result.get("actions", [])

    if not isinstance(message_score, (int, float)):
        message_score = 0
    if not isinstance(conversation_risk, (int, float)):
        conversation_risk = 0
    if not isinstance(matched, list):
        matched = []
    if not isinstance(actions, list):
        actions = []

    matched_lower = [str(item).lower() for item in matched]
    actions_upper = [str(item).upper() for item in actions]
    stage_lower = stage.lower()

    scam_terms = {
        "password",
        "passwort",
        "free",
        "bucks",
        "robux",
        "nitro",
        "gift",
        "giveaway",
        "login",
        "account",
        "steam",
        "paypal",
        "trade",
        "crypto",
        "wallet",
    }
    grooming_terms = {
        "snap",
        "snapchat",
        "discord",
        "telegram",
        "instagram",
        "whatsapp",
        "signal",
        "kik",
        "kick",
        "skype",
        "steam",
        "riot",
        "epic",
        "battle.net",
        "secret",
        "keep_it_secret",
        "age",
        "old",
        "how_old",
        "platform_switch",
        "meet",
        "alone",
    }

    def contains_any(signals: list[str], terms: set[str]) -> bool:
        return any(term in signal for signal in signals for term in terms)

    category = "unknown"
    if contains_any(matched_lower, scam_terms):
        category = "scam"
    elif contains_any(matched_lower, grooming_terms):
        category = "grooming"
    elif "groom" in stage_lower:
        category = "grooming"
    elif "scam" in stage_lower:
        category = "scam"

    action = "review"
    if "ALERT_MOD" in actions_upper:
        action = "moderator_alert"
    elif "FLAG" in actions_upper or "CREATE_INCIDENT" in actions_upper:
        action = "flag"

    return {
        "score": int(message_score),
        "conversation_risk": int(conversation_risk),
        "category": category,
        "stage": stage,
        "signals": matched_lower,
        "action": action,
        "actions": actions_upper,
        "source": "api",
    }


def merge_results(api_result: dict, spam_result: dict) -> dict:
    spam_score = int(spam_result.get("score", 0))
    api_score = int(api_result.get("score", 0))
    conversation_risk = max(
        int(api_result.get("conversation_risk", 0)),
        int(spam_result.get("conversation_risk", 0)),
    )

    if spam_score >= settings.spam_alert_threshold and spam_score >= api_score:
        return {
            "score": spam_score,
            "conversation_risk": conversation_risk,
            "category": spam_result.get("category", "spam"),
            "stage": spam_result.get("stage", "spam_detected"),
            "signals": spam_result.get("signals", []),
            "action": spam_result.get("action", "review"),
            "actions": [str(a).upper() for a in spam_result.get("actions", [])],
            "source": "local_spam_detector",
        }

    api_result["conversation_risk"] = conversation_risk
    return api_result


def compute_incident_decision(parsed: dict) -> tuple[int, list[str], bool, bool]:
    score = int(parsed.get("score", 0))
    conversation_risk = int(parsed.get("conversation_risk", 0))
    actions = [str(a).upper() for a in parsed.get("actions", [])]
    effective_score = max(score, conversation_risk)

    should_log_incident = (
        effective_score >= settings.log_threshold
        or "CREATE_INCIDENT" in actions
        or "ALERT_MOD" in actions
    )

    should_send_alert = (
        effective_score >= settings.alert_threshold
        or "ALERT_MOD" in actions
    )

    return effective_score, actions, should_log_incident, should_send_alert


async def send_alert(
    message: discord.Message,
    parsed: dict,
    relationship_context: list[dict],
    case_id: str,
    conversation_risk: int,
    effective_score: int,
) -> None:
    if not settings.alert_channel_id:
        print("[ALERT] ALERT_CHANNEL_ID not configured.")
        return

    alert_channel = client.get_channel(settings.alert_channel_id)
    if alert_channel is None:
        try:
            alert_channel = await client.fetch_channel(settings.alert_channel_id)
        except Exception as exc:
            print(f"[ALERT ERROR] Could not fetch alert channel: {exc}")
            return

    target_id = relationship_context[-1].get("target_id", "unknown") if relationship_context else "unknown"

    alert_text = format_alert_message(
        case_id=case_id,
        author_name=str(message.author),
        author_id=str(message.author.id),
        target_id=target_id,
        channel_mention=getattr(message.channel, "mention", str(message.channel)),
        message_content=message.content,
        score=effective_score,
        category=parsed["category"],
        stage=parsed["stage"],
        signals=parsed["signals"],
        action=parsed["action"],
        context=relationship_context,
        conversation_risk=conversation_risk,
        source=parsed.get("source", "unknown"),
    )

    try:
        await alert_channel.send(alert_text)
        print(f"[ALERT SENT] case_id={case_id} effective_score={effective_score} target={target_id}")
    except Exception as exc:
        print(f"[ALERT ERROR] Failed to send alert: {exc}")


@client.event
async def on_ready():
    try:
        if settings.allowed_guild_id:
            guild = discord.Object(id=settings.allowed_guild_id)
            tree.copy_global_to(guild=guild)
            await tree.sync(guild=guild)
            print(f"[SYNC] Synced commands to guild {settings.allowed_guild_id}")

        await tree.sync()
        print(f"PlaySentinel Bot gestartet als {client.user}")
    except Exception as exc:
        print(f"[SYNC ERROR] {exc}")


@client.event
async def on_message(message: discord.Message):
    if message.author.bot:
        return
    if not is_monitored_message(message):
        return
    if not message.content or not message.content.strip():
        return

    normalized = normalize_message(message)
    target_id = await resolve_target_id(message)

    memory_store.add_message(
        guild_id=message.guild.id,
        channel_id=message.channel.id,
        author_id=message.author.id,
        message_data=normalized,
    )

    relationship_event = {
        "message_id": normalized["message_id"],
        "author_id": normalized["author_id"],
        "author_name": normalized["author_name"],
        "target_id": target_id,
        "content": normalized["content"],
        "timestamp": normalized["timestamp"],
        "channel_id": normalized["channel_id"],
        "reply_to_message_id": normalized["reply_to_message_id"],
        "mentions": normalized["mentions"],
    }

    relationship_store.add_event(
        guild_id=message.guild.id,
        source_user_id=normalized["author_id"],
        target_user_id=target_id,
        event_data=relationship_event,
    )

    relationship_context = relationship_store.get_context(
        guild_id=message.guild.id,
        source_user_id=normalized["author_id"],
        target_user_id=target_id,
    )

    print(f"[DEBUG] target_id={target_id}")
    print(f"[DEBUG] relationship_context_len={len(relationship_context)}")

    payload = build_payload(message, relationship_context, target_id)
    print(f"[DEBUG] sending payload: {payload}")

    api_raw_result = None
    try:
        api_raw_result = await api_client.analyze_message(payload)
    except Exception as exc:
        print(f"[API ERROR] analyze_message failed: {exc}")

    if api_raw_result:
        print(f"[DEBUG] api_raw_result={api_raw_result}")
        api_result = parse_api_result(api_raw_result)
    else:
        print("[API WARN] Empty/failed API result, continuing with fallback so local spam detection can still alert.")
        api_result = fallback_api_result()

    spam_result = spam_detector.detect(
        message=message.content,
        user_id=normalized["author_id"],
        recent_messages=relationship_context,
    )
    print(f"[DEBUG] spam_result={spam_result}")

    parsed = merge_results(api_result, spam_result)

    effective_score, actions, should_log_incident, should_send_alert = compute_incident_decision(parsed)

    conversation_risk = relationship_store.add_risk(
        guild_id=message.guild.id,
        source_user_id=normalized["author_id"],
        target_user_id=target_id,
        score=effective_score,
    )

    print(
        f"[REL] source={normalized['author_id']} "
        f"target={target_id} "
        f"message_score={parsed.get('score', 0)} "
        f"effective_score={effective_score} "
        f"conversation_risk={conversation_risk} "
        f"category={parsed['category']} "
        f"source={parsed['source']} "
        f"actions={actions}"
    )

    case_id = ""
    if should_log_incident:
        case_id = case_store.save_case(
            {
                "platform": "discord",
                "guild_id": str(message.guild.id),
                "channel_id": str(message.channel.id),
                "message_id": str(message.id),
                "author_id": str(message.author.id),
                "author_name": str(message.author),
                "target_id": target_id,
                "message_content": message.content,
                "result": parsed,
                "effective_score": effective_score,
                "conversation_risk": conversation_risk,
                "relationship_context": relationship_context[-10:],
            }
        )

        print(
            f"[FLAGGED] case_id={case_id} "
            f"score={parsed.get('score', 0)} "
            f"effective_score={effective_score} "
            f"conversation_risk={conversation_risk} "
            f"category={parsed['category']} "
            f"user={message.author.id} "
            f"target={target_id}"
        )

    if should_send_alert and case_id:
        if alert_state_store.should_alert(normalized["author_id"], target_id):
            await send_alert(
                message=message,
                parsed=parsed,
                relationship_context=relationship_context,
                case_id=case_id,
                conversation_risk=conversation_risk,
                effective_score=effective_score,
            )
        else:
            print(
                f"[ALERT SKIPPED] cooldown active for "
                f"source={normalized['author_id']} target={target_id}"
            )



@tree.command(name="review", description="Review a PlaySentinel case")
@app_commands.describe(
    case_id="The case ID shown in the alert",
    verdict="true_positive, false_positive, or unsure",
)
async def review_case(interaction: discord.Interaction, case_id: str, verdict: str):
    verdict = verdict.strip().lower()

    if verdict not in {"true_positive", "false_positive", "unsure"}:
        await interaction.response.send_message(
            "Invalid verdict. Use: true_positive, false_positive, or unsure.",
            ephemeral=True,
        )
        return

    success = case_store.review_case(
        case_id=case_id,
        verdict=verdict,
        reviewed_by=str(interaction.user),
    )

    if not success:
        await interaction.response.send_message(f"Case `{case_id}` not found.", ephemeral=True)
        return

    await interaction.response.send_message(
        f"Case `{case_id}` reviewed as **{verdict}** by {interaction.user}.",
        ephemeral=True,
    )


@tree.command(name="testalert", description="Send a PlaySentinel test alert")
async def test_alert(interaction: discord.Interaction):
    if not settings.alert_channel_id:
        await interaction.response.send_message("ALERT_CHANNEL_ID is not configured.", ephemeral=True)
        return

    channel = client.get_channel(settings.alert_channel_id)
    if channel is None:
        try:
            channel = await client.fetch_channel(settings.alert_channel_id)
        except Exception as exc:
            await interaction.response.send_message(f"Could not fetch alert channel: {exc}", ephemeral=True)
            return

    await channel.send("🧪 PlaySentinel test alert: Bot can send messages to the alert channel.")
    await interaction.response.send_message("Test alert sent.", ephemeral=True)

@tree.command(name="about", description="Information about PlaySentinel")
async def about(interaction: discord.Interaction):

    message = (
        "**PlaySentinel**\n\n"
        "PlaySentinel is a safety moderation system designed to detect risky chat patterns "
        "such as scam attempts or grooming-related behavior.\n\n"
        "The system analyzes conversation signals and may generate alerts so human "
        "moderators can review potentially harmful interactions.\n\n"
        "PlaySentinel does not automatically punish users."
    )

    await interaction.response.send_message(message, ephemeral=True)

@tree.command(name="privacy", description="Information about message analysis and privacy")
async def privacy(interaction: discord.Interaction):

    message = (
        "**PlaySentinel Privacy Notice**\n\n"
        "Messages in this server may be analyzed by automated moderation tools "
        "to detect risky interaction patterns such as scams or grooming attempts.\n\n"
        "The system evaluates conversation signals to assist moderators.\n\n"
        "PlaySentinel does not create permanent user profiles and does not make "
        "final accusations. Flagged conversations are always reviewed by human moderators."
    )

    await interaction.response.send_message(message, ephemeral=True)


@tree.command(name="resetstate", description="Reset local state and optionally backend state for a source -> target pair")
@app_commands.describe(
    user_id="Source user ID",
    target_id="Target ID, e.g. a user ID or channel:123",
    clear_relationship_context="Also clear stored relationship context",
    clear_memory="Also clear stored channel/user memory",
    reset_backend="Also call backend reset endpoint if configured",
)
async def reset_state_command(
    interaction: discord.Interaction,
    user_id: str,
    target_id: str,
    clear_relationship_context: bool = True,
    clear_memory: bool = True,
    reset_backend: bool = True,
):
    if interaction.guild is None:
        await interaction.response.send_message("This command only works in a server.", ephemeral=True)
        return

    await interaction.response.defer(ephemeral=True)

    guild_id = interaction.guild.id
    channel_id = interaction.channel.id if interaction.channel else 0

    old_risk = relationship_store.get_risk(guild_id, user_id, target_id)
    old_relationship_context_len = len(relationship_store.get_context(guild_id, user_id, target_id))
    old_memory_len = len(memory_store.get_context(guild_id, channel_id, int(user_id))) if user_id.isdigit() else 0

    relationship_store.reset_risk(guild_id, user_id, target_id)

    if clear_relationship_context:
        relationship_store.clear_context(guild_id, user_id, target_id)

    if clear_memory and user_id.isdigit():
        memory_store.clear_context(guild_id, channel_id, int(user_id))

    backend_result = "not_requested"
    if reset_backend:
        ok = await api_client.reset_conversation_state(
            user_id=user_id,
            target_id=target_id,
            platform="discord",
        )
        if ok is True:
            backend_result = "reset_ok"
        elif ok is False:
            backend_result = "reset_failed_or_endpoint_missing"
        else:
            backend_result = "reset_not_configured"

    await interaction.followup.send(
        f"**PlaySentinel state reset**\n"
        f"Source: `{user_id}`\n"
        f"Target: `{target_id}`\n"
        f"Old risk: **{old_risk}**\n"
        f"Old relationship messages: **{old_relationship_context_len}**\n"
        f"Old memory messages in this channel: **{old_memory_len}**\n"
        f"Relationship context cleared: **{clear_relationship_context}**\n"
        f"Memory cleared: **{clear_memory}**\n"
        f"Backend reset: **{backend_result}**",
        ephemeral=True,
    )


@tree.command(name="inspectrisk", description="Inspect relationship risk and recent context")
@app_commands.describe(
    user_id="Source user ID",
    target_id="Target ID, e.g. a user ID or channel:123",
)
async def inspect_risk_command(interaction: discord.Interaction, user_id: str, target_id: str):
    if interaction.guild is None:
        await interaction.response.send_message("This command only works in a server.", ephemeral=True)
        return

    guild_id = interaction.guild.id
    channel_id = interaction.channel.id if interaction.channel else 0

    current_risk = relationship_store.get_risk(guild_id, user_id, target_id)
    relationship_context = relationship_store.get_context(guild_id, user_id, target_id)
    memory_context = memory_store.get_context(guild_id, channel_id, int(user_id)) if user_id.isdigit() else []

    lines = []
    for item in relationship_context[-8:]:
        author_name = item.get("author_name", "unknown")
        content = (item.get("content", "") or "").replace("`", "'")[:120]
        lines.append(f"- {author_name}: {content}")

    rel_text = "\n".join(lines) if lines else "No relationship context stored."

    memory_lines = []
    for item in memory_context[-5:]:
        content = (item.get("content", "") or "").replace("`", "'")[:120]
        memory_lines.append(f"- {content}")

    mem_text = "\n".join(memory_lines) if memory_lines else "No memory context stored in this channel."

    response = (
        f"**PlaySentinel Risk Inspect**\n"
        f"Source: `{user_id}`\n"
        f"Target: `{target_id}`\n"
        f"Current risk: **{current_risk}**\n"
        f"Stored relationship messages: **{len(relationship_context)}**\n"
        f"Stored memory messages in this channel: **{len(memory_context)}**\n\n"
        f"**Relationship context**\n{rel_text}\n\n"
        f"**Memory context (this channel)**\n{mem_text}"
    )

    await interaction.response.send_message(response[:1900], ephemeral=True)


def main() -> None:
    try:
        client.run(settings.discord_token)
    except KeyboardInterrupt:
        print("[SHUTDOWN] Bot stopped by user.")


if __name__ == "__main__":
    main()

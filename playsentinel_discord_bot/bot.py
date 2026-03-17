from __future__ import annotations

import json
from datetime import timezone
from pathlib import Path
from typing import Any

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
SERVER_CONFIG_PATH = Path("server_config.json")

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


def load_server_config() -> dict[str, dict[str, Any]]:
    if not SERVER_CONFIG_PATH.exists():
        return {}

    try:
        with SERVER_CONFIG_PATH.open("r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception as exc:
        print(f"[SERVER CONFIG] Failed to load server_config.json: {exc}")
        return {}

    if not isinstance(data, dict):
        print("[SERVER CONFIG] server_config.json must be a JSON object.")
        return {}

    cleaned: dict[str, dict[str, Any]] = {}
    for guild_id, config in data.items():
        if isinstance(config, dict):
            cleaned[str(guild_id)] = config
    return cleaned


def save_server_config() -> None:
    with SERVER_CONFIG_PATH.open("w", encoding="utf-8") as f:
        json.dump(SERVER_CONFIG, f, indent=2, ensure_ascii=False)


SERVER_CONFIG: dict[str, dict[str, Any]] = load_server_config()


def bootstrap_server_config_from_env() -> None:
    """Create an initial config from legacy env vars if nothing exists yet."""
    if SERVER_CONFIG:
        return
    if settings.allowed_guild_id and settings.alert_channel_id:
        SERVER_CONFIG[str(settings.allowed_guild_id)] = {
            "alert_channel_id": settings.alert_channel_id,
            "monitored_channel_ids": settings.monitored_channel_ids,
        }
        try:
            save_server_config()
            print(f"[SERVER CONFIG] Bootstrapped config for guild {settings.allowed_guild_id}")
        except Exception as exc:
            print(f"[SERVER CONFIG] Failed to bootstrap config: {exc}")


bootstrap_server_config_from_env()


def get_guild_config(guild_id: int) -> dict[str, Any]:
    return SERVER_CONFIG.get(str(guild_id), {})


def get_alert_channel_id_for_guild(guild_id: int) -> int:
    guild_config = get_guild_config(guild_id)
    value = guild_config.get("alert_channel_id")
    if value in (None, ""):
        return int(settings.alert_channel_id or 0)
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def get_monitored_channel_ids_for_guild(guild_id: int) -> list[int]:
    guild_config = get_guild_config(guild_id)
    raw = guild_config.get("monitored_channel_ids")
    if raw is None:
        return list(settings.monitored_channel_ids)

    ids: list[int] = []
    if isinstance(raw, list):
        for value in raw:
            try:
                ids.append(int(value))
            except (TypeError, ValueError):
                continue
    return ids


def set_alert_channel_for_guild(guild_id: int, channel_id: int) -> None:
    guild_key = str(guild_id)
    guild_config = SERVER_CONFIG.setdefault(guild_key, {})
    guild_config["alert_channel_id"] = int(channel_id)
    if "monitored_channel_ids" not in guild_config:
        guild_config["monitored_channel_ids"] = list(settings.monitored_channel_ids)
    save_server_config()


def set_monitored_channels_for_guild(guild_id: int, channel_ids: list[int]) -> None:
    guild_key = str(guild_id)
    guild_config = SERVER_CONFIG.setdefault(guild_key, {})
    guild_config["monitored_channel_ids"] = [int(cid) for cid in channel_ids]
    save_server_config()


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

    guild_id_str = str(message.guild.id)

    # If server_config.json has entries, only configured guilds are monitored.
    if SERVER_CONFIG and guild_id_str not in SERVER_CONFIG:
        return False

    # Legacy fallback for older single-server setups.
    if not SERVER_CONFIG and settings.allowed_guild_id and message.guild.id != settings.allowed_guild_id:
        return False

    monitored_channel_ids = get_monitored_channel_ids_for_guild(message.guild.id)
    if monitored_channel_ids and message.channel.id not in monitored_channel_ids:
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
    alert_channel_id = get_alert_channel_id_for_guild(message.guild.id)
    if not alert_channel_id:
        print(f"[ALERT] No alert channel configured for guild {message.guild.id}.")
        return

    alert_channel = client.get_channel(alert_channel_id)
    if alert_channel is None:
        try:
            alert_channel = await client.fetch_channel(alert_channel_id)
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
        print(
            f"[ALERT SENT] guild={message.guild.id} case_id={case_id} "
            f"effective_score={effective_score} target={target_id}"
        )
    except Exception as exc:
        print(f"[ALERT ERROR] Failed to send alert: {exc}")


@client.event
async def on_ready():
    try:
        print(f"PlaySentinel Bot gestartet als {client.user}")
        print(f"[SERVER CONFIG] Loaded guild configs: {', '.join(SERVER_CONFIG.keys()) or 'none'}")

        for guild in client.guilds:
            synced = await tree.sync(guild=guild)
            print(f"[SYNC] Synced {len(synced)} commands for guild {guild.name} ({guild.id})")

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

    print(f"[DEBUG] guild_id={message.guild.id} target_id={target_id}")
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
        f"[REL] guild={message.guild.id} source={normalized['author_id']} "
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
                "case_origin": "real",
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
            f"[FLAGGED] guild={message.guild.id} case_id={case_id} "
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


@tree.command(name="testalert", description="Send a PlaySentinel test alert for this server")
async def test_alert(interaction: discord.Interaction):
    if interaction.guild is None:
        await interaction.response.send_message("This command only works in a server.", ephemeral=True)
        return

    alert_channel_id = get_alert_channel_id_for_guild(interaction.guild.id)
    if not alert_channel_id:
        await interaction.response.send_message(
            "No alert channel configured for this server. Use /set_alert_channel first.",
            ephemeral=True,
        )
        return

    channel = client.get_channel(alert_channel_id)
    if channel is None:
        try:
            channel = await client.fetch_channel(alert_channel_id)
        except Exception as exc:
            await interaction.response.send_message(f"Could not fetch alert channel: {exc}", ephemeral=True)
            return

    await channel.send(f"🧪 PlaySentinel test alert for **{interaction.guild.name}**.")
    await interaction.response.send_message(
        f"Test alert sent to <#{alert_channel_id}>.",
        ephemeral=True,
    )


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


@tree.command(name="set_alert_channel", description="Set the PlaySentinel alert channel for this server")
@app_commands.checks.has_permissions(manage_guild=True)
@app_commands.describe(channel="Channel where PlaySentinel should send alerts")
async def set_alert_channel(interaction: discord.Interaction, channel: discord.TextChannel):
    if interaction.guild is None:
        await interaction.response.send_message("This command only works in a server.", ephemeral=True)
        return

    set_alert_channel_for_guild(interaction.guild.id, channel.id)
    await interaction.response.send_message(
        f"PlaySentinel alert channel for **{interaction.guild.name}** set to {channel.mention}.",
        ephemeral=True,
    )


@tree.command(name="set_monitored_channels", description="Restrict PlaySentinel monitoring to specific channels")
@app_commands.checks.has_permissions(manage_guild=True)
@app_commands.describe(
    channels="Up to 10 channel mentions or IDs separated by spaces. Leave empty to clear the restriction.",
)
async def set_monitored_channels(interaction: discord.Interaction, channels: str = ""):
    if interaction.guild is None:
        await interaction.response.send_message("This command only works in a server.", ephemeral=True)
        return

    parsed_ids: list[int] = []
    for token in channels.replace(",", " ").split():
        cleaned = token.strip().replace("<", "").replace(">", "").replace("#", "")
        if cleaned.isdigit():
            parsed_ids.append(int(cleaned))

    parsed_ids = list(dict.fromkeys(parsed_ids))[:10]
    set_monitored_channels_for_guild(interaction.guild.id, parsed_ids)

    if parsed_ids:
        mentions = ", ".join(f"<#{cid}>" for cid in parsed_ids)
        msg = f"PlaySentinel will now only monitor these channels in **{interaction.guild.name}**: {mentions}"
    else:
        msg = f"PlaySentinel channel restriction cleared for **{interaction.guild.name}**. It will use the default/global behavior again."

    await interaction.response.send_message(msg, ephemeral=True)


@tree.command(name="serverconfig", description="Show PlaySentinel config for this server")
async def server_config_command(interaction: discord.Interaction):
    if interaction.guild is None:
        await interaction.response.send_message("This command only works in a server.", ephemeral=True)
        return

    guild_config = get_guild_config(interaction.guild.id)
    alert_channel_id = get_alert_channel_id_for_guild(interaction.guild.id)
    monitored_channel_ids = get_monitored_channel_ids_for_guild(interaction.guild.id)

    monitored_text = ", ".join(f"<#{cid}>" for cid in monitored_channel_ids) if monitored_channel_ids else "all channels allowed"
    config_source = "server_config.json" if str(interaction.guild.id) in SERVER_CONFIG else "legacy env/default"

    message = (
        f"**PlaySentinel Server Config**\n"
        f"Server: **{interaction.guild.name}** (`{interaction.guild.id}`)\n"
        f"Config source: **{config_source}**\n"
        f"Alert channel: {f'<#{alert_channel_id}>' if alert_channel_id else 'not set'}\n"
        f"Monitored channels: {monitored_text}\n"
        f"Raw config: ```json\n{json.dumps(guild_config, indent=2) if guild_config else '{}'}\n```"
    )
    await interaction.response.send_message(message[:1900], ephemeral=True)


@set_alert_channel.error
@set_monitored_channels.error
async def admin_command_error(interaction: discord.Interaction, error: app_commands.AppCommandError):
    if isinstance(error, app_commands.errors.MissingPermissions):
        await interaction.response.send_message(
            "You need the **Manage Server** permission to use this command.",
            ephemeral=True,
        )
        return

    raise error


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

@tree.command(name="export_cases", description="Export all stored cases")
@app_commands.checks.has_permissions(administrator=True)
async def export_cases(interaction: discord.Interaction):

    file_path = "flagged_cases.jsonl"

    if not os.path.exists(file_path):
        await interaction.response.send_message(
            "No cases stored yet.",
            ephemeral=True
        )
        return

    await interaction.response.send_message(
        "Exporting case file...",
        ephemeral=True
    )

    await interaction.followup.send(
        file=discord.File(file_path)
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

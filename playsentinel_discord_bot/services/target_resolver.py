from __future__ import annotations

import discord


async def resolve_target_id(message: discord.Message) -> str:
    if message.reference and message.reference.message_id:
        try:
            replied_message = message.reference.resolved
            if replied_message is None:
                replied_message = await message.channel.fetch_message(message.reference.message_id)
            if replied_message and replied_message.author and not replied_message.author.bot:
                return str(replied_message.author.id)
        except Exception:
            pass

    for mentioned_user in message.mentions:
        if not mentioned_user.bot and mentioned_user.id != message.author.id:
            return str(mentioned_user.id)

    return f"channel:{message.channel.id}"

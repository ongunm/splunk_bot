from __future__ import annotations

import asyncio
import logging
import re
from typing import Final

from telegram import Update
from telegram.ext import Application, CommandHandler, ContextTypes, MessageHandler, filters

from ai_client import AIClient
from config import Settings, load_settings
from splunk_client import SplunkClient


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
)
logger = logging.getLogger("ai_soc_bot")

COMMAND_HELP: Final[str] = (
    "Available commands:\n"
    "/failed_logins [window] - Example: /failed_logins 30m\n"
    "/errors [window] - Example: /errors 15m\n"
    "/suspicious_process [window] - Example: /suspicious_process 1h\n"
    "/ask <question> - Natural language security question\n"
    "\n"
    "You can also send a plain text question directly."
)

WINDOW_PATTERN: Final[re.Pattern[str]] = re.compile(r"^\d+[smhd]$")
TELEGRAM_MAX_MESSAGE: Final[int] = 3500


def _authorized(update: Update, settings: Settings) -> bool:
    user = update.effective_user
    if not user:
        return False
    return user.id in settings.subscribers


def _parse_window(arg: str | None, default: str = "15m") -> str:
    if not arg:
        return default
    value = arg.strip().lower()
    if WINDOW_PATTERN.match(value):
        return value
    return default


def _build_failed_logins_spl(window: str) -> str:
    return (
        f'search index=main "Failed password" earliest=-{window} '
        "| stats count as failed_attempts by host user "
        "| sort - failed_attempts"
    )


def _build_errors_spl(window: str) -> str:
    return (
        f'search index=main (error OR ERROR OR exception OR Exception) earliest=-{window} '
        "| stats count as error_count by host source sourcetype "
        "| sort - error_count"
    )


def _build_suspicious_process_spl(window: str) -> str:
    return (
        f'search index=main (process OR cmdline OR CommandLine) earliest=-{window} '
        '| regex _raw="(?i)(powershell.*-enc|nc\\s+-e|wget\\s+http|curl\\s+http|chmod\\s+777)" '
        "| stats count by host user process cmdline "
        "| sort - count"
    )


async def _run_in_thread(func, *args):
    return await asyncio.to_thread(func, *args)


def _chunk_text(text: str, max_len: int = TELEGRAM_MAX_MESSAGE) -> list[str]:
    clean = (text or "").strip()
    if not clean:
        return []
    chunks: list[str] = []
    while clean:
        if len(clean) <= max_len:
            chunks.append(clean)
            break
        split_at = clean.rfind("\n", 0, max_len)
        if split_at < max_len // 2:
            split_at = max_len
        chunks.append(clean[:split_at].rstrip())
        clean = clean[split_at:].lstrip()
    return chunks


async def _send_safe(chat, text: str) -> None:
    for part in _chunk_text(text):
        await chat.send_message(part)


async def _run_query_and_respond(
    update: Update,
    question: str,
    spl_query: str,
    splunk_client: SplunkClient,
    ai_client: AIClient,
) -> None:
    chat = update.effective_chat
    if not chat:
        return
    await chat.send_message("Running Splunk query, please wait...")
    try:
        result = await _run_in_thread(splunk_client.run_search, spl_query)
        explanation = await _run_in_thread(
            ai_client.explain_results,
            question,
            spl_query,
            result.rows,
        )
        if not explanation:
            explanation = "No AI summary generated. Try refining the query."
        header = f"Query SID: {result.sid}\nRows: {len(result.rows)}\n\n"
        await _send_safe(chat, f"{header}{explanation}")
    except Exception as exc:  # noqa: BLE001
        logger.exception("Query flow failed")
        err = str(exc).replace("\n", " ").strip()
        if len(err) > 500:
            err = err[:500] + "...(truncated)"
        await _send_safe(chat, f"Request failed: {err}")


async def start_handler(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    settings: Settings = context.application.bot_data["settings"]
    if not _authorized(update, settings):
        await update.effective_chat.send_message("Unauthorized user.")
        return
    await update.effective_chat.send_message(
        "AI SOC Assistant is online.\n\n" + COMMAND_HELP
    )


async def help_handler(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    settings: Settings = context.application.bot_data["settings"]
    if not _authorized(update, settings):
        await update.effective_chat.send_message("Unauthorized user.")
        return
    await update.effective_chat.send_message(COMMAND_HELP)


async def failed_logins_handler(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    settings: Settings = context.application.bot_data["settings"]
    if not _authorized(update, settings):
        await update.effective_chat.send_message("Unauthorized user.")
        return
    splunk_client: SplunkClient = context.application.bot_data["splunk_client"]
    ai_client: AIClient = context.application.bot_data["ai_client"]
    window = _parse_window(context.args[0] if context.args else None, default="30m")
    question = f"Investigate failed logins in the last {window}."
    spl_query = _build_failed_logins_spl(window)
    await _run_query_and_respond(update, question, spl_query, splunk_client, ai_client)


async def errors_handler(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    settings: Settings = context.application.bot_data["settings"]
    if not _authorized(update, settings):
        await update.effective_chat.send_message("Unauthorized user.")
        return
    splunk_client: SplunkClient = context.application.bot_data["splunk_client"]
    ai_client: AIClient = context.application.bot_data["ai_client"]
    window = _parse_window(context.args[0] if context.args else None, default="15m")
    question = f"Summarize critical errors in the last {window}."
    spl_query = _build_errors_spl(window)
    await _run_query_and_respond(update, question, spl_query, splunk_client, ai_client)


async def suspicious_process_handler(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    settings: Settings = context.application.bot_data["settings"]
    if not _authorized(update, settings):
        await update.effective_chat.send_message("Unauthorized user.")
        return
    splunk_client: SplunkClient = context.application.bot_data["splunk_client"]
    ai_client: AIClient = context.application.bot_data["ai_client"]
    window = _parse_window(context.args[0] if context.args else None, default="1h")
    question = f"Check suspicious process activity in the last {window}."
    spl_query = _build_suspicious_process_spl(window)
    await _run_query_and_respond(update, question, spl_query, splunk_client, ai_client)


async def ask_handler(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    settings: Settings = context.application.bot_data["settings"]
    if not _authorized(update, settings):
        await update.effective_chat.send_message("Unauthorized user.")
        return
    question = " ".join(context.args).strip()
    if not question:
        await update.effective_chat.send_message("Usage: /ask <question>")
        return
    splunk_client: SplunkClient = context.application.bot_data["splunk_client"]
    ai_client: AIClient = context.application.bot_data["ai_client"]
    await update.effective_chat.send_message("Generating SPL from your question...")
    try:
        spl_query = await _run_in_thread(ai_client.generate_spl, question)
        await _run_query_and_respond(update, question, spl_query, splunk_client, ai_client)
    except Exception as exc:  # noqa: BLE001
        logger.exception("Ask handler failed")
        err = str(exc).replace("\n", " ").strip()
        if len(err) > 500:
            err = err[:500] + "...(truncated)"
        await _send_safe(update.effective_chat, f"Could not process question: {err}")


async def text_handler(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    settings: Settings = context.application.bot_data["settings"]
    if not _authorized(update, settings):
        await update.effective_chat.send_message("Unauthorized user.")
        return
    text = (update.message.text if update.message else "").strip()
    if not text:
        return
    context.args = text.split()
    await ask_handler(update, context)


def main() -> None:
    settings = load_settings()
    splunk_client = SplunkClient(
        base_url=settings.splunk_base_url,
        username=settings.splunk_username,
        password=settings.splunk_password,
        verify_tls=settings.splunk_verify_tls,
        timeout_seconds=settings.request_timeout_seconds,
        poll_seconds=settings.query_poll_seconds,
        max_wait_seconds=settings.query_max_wait_seconds,
    )
    ai_client = AIClient(api_key=settings.openai_api_key, model=settings.openai_model)

    application = Application.builder().token(settings.telegram_token).build()
    application.bot_data["settings"] = settings
    application.bot_data["splunk_client"] = splunk_client
    application.bot_data["ai_client"] = ai_client

    application.add_handler(CommandHandler("start", start_handler))
    application.add_handler(CommandHandler("help", help_handler))
    application.add_handler(CommandHandler("failed_logins", failed_logins_handler))
    application.add_handler(CommandHandler("errors", errors_handler))
    application.add_handler(CommandHandler("suspicious_process", suspicious_process_handler))
    application.add_handler(CommandHandler("ask", ask_handler))
    application.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, text_handler))

    logger.info("Bot starting with %d authorized subscribers", len(settings.subscribers))
    application.run_polling(allowed_updates=Update.ALL_TYPES, drop_pending_updates=True)


if __name__ == "__main__":
    main()


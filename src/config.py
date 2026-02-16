from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlparse


KEYS_DIR = Path.home() / "keys"


@dataclass(frozen=True)
class Settings:
    telegram_token: str
    openai_api_key: str
    subscribers: set[int]
    splunk_base_url: str
    splunk_username: str
    splunk_password: str
    splunk_verify_tls: bool
    openai_model: str
    request_timeout_seconds: int
    query_poll_seconds: float
    query_max_wait_seconds: int


def _read_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def _first_str(data: dict[str, Any], keys: list[str]) -> str | None:
    for key in keys:
        value = data.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return None


def _load_telegram_token() -> str:
    path = KEYS_DIR / "telegramkey.json"
    data = _read_json(path)
    if not isinstance(data, dict):
        raise ValueError(f"Invalid JSON object in {path}")
    token = _first_str(data, ["TELEGRAM_BOT_TOKEN", "telegram_token", "key", "token"])
    if token:
        return token
    raise ValueError(f"Telegram token missing in {path}")


def _load_openai_api_key() -> str:
    path = KEYS_DIR / "openaikey.json"
    data = _read_json(path)
    if not isinstance(data, dict):
        raise ValueError(f"Invalid JSON object in {path}")
    api_key = _first_str(data, ["OPENAI_API_KEY", "openai_api_key", "api_key", "key"])
    if api_key:
        return api_key
    raise ValueError(f"OpenAI API key missing in {path}")


def _load_subscribers() -> set[int]:
    path = KEYS_DIR / "subscribers.json"
    data = _read_json(path)
    if not isinstance(data, list):
        raise ValueError(f"Expected a JSON array in {path}")
    subscribers: set[int] = set()
    for item in data:
        if isinstance(item, int):
            subscribers.add(item)
        elif isinstance(item, str) and item.strip().isdigit():
            subscribers.add(int(item.strip()))
    if not subscribers:
        raise ValueError(f"No valid subscriber IDs found in {path}")
    return subscribers


def _load_splunk_overrides() -> dict[str, Any]:
    path = KEYS_DIR / "splunk.json"
    if path.exists():
        data = _read_json(path)
        if isinstance(data, dict):
            return data
    return {}


def _to_bool(value: Any, default: bool) -> bool:
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "y", "on"}
    return bool(value)


def _normalize_splunk_base_url(url: str) -> str:
    parsed = urlparse(url)
    if not parsed.scheme:
        parsed = urlparse(f"https://{url}")
    hostname = parsed.hostname
    port = parsed.port
    scheme = parsed.scheme or "https"
    if not hostname:
        raise ValueError(f"Invalid SPLUNK_BASE_URL: {url}")

    # Splunk management REST API is typically on 8089. If user gives web UI 8000,
    # redirect automatically to avoid HTML/404 responses from app routes.
    if port == 8000:
        port = 8089
        scheme = "https"

    if port:
        return f"{scheme}://{hostname}:{port}"
    return f"{scheme}://{hostname}"


def load_settings() -> Settings:
    splunk_json = _load_splunk_overrides()

    splunk_base_url = (
        os.getenv("SPLUNK_BASE_URL")
        or _first_str(splunk_json, ["SPLUNK_BASE_URL", "base_url", "url"])
        or "https://localhost:8089"
    )
    splunk_username = (
        os.getenv("SPLUNK_USERNAME")
        or _first_str(splunk_json, ["SPLUNK_USERNAME", "username", "user"])
        or "admin"
    )
    splunk_password = (
        os.getenv("SPLUNK_PASSWORD")
        or _first_str(splunk_json, ["SPLUNK_PASSWORD", "password", "pass"])
        or "changeme"
    )
    splunk_verify_tls = _to_bool(
        os.getenv("SPLUNK_VERIFY_TLS", splunk_json.get("SPLUNK_VERIFY_TLS")),
        default=False,
    )

    openai_model = os.getenv("OPENAI_MODEL", "gpt-5")
    request_timeout_seconds = int(os.getenv("REQUEST_TIMEOUT_SECONDS", "45"))
    query_poll_seconds = float(os.getenv("SPLUNK_QUERY_POLL_SECONDS", "1.0"))
    query_max_wait_seconds = int(os.getenv("SPLUNK_QUERY_MAX_WAIT_SECONDS", "60"))

    return Settings(
        telegram_token=_load_telegram_token(),
        openai_api_key=_load_openai_api_key(),
        subscribers=_load_subscribers(),
        splunk_base_url=_normalize_splunk_base_url(splunk_base_url.rstrip("/")),
        splunk_username=splunk_username,
        splunk_password=splunk_password,
        splunk_verify_tls=splunk_verify_tls,
        openai_model=openai_model,
        request_timeout_seconds=request_timeout_seconds,
        query_poll_seconds=query_poll_seconds,
        query_max_wait_seconds=query_max_wait_seconds,
    )


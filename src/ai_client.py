from __future__ import annotations

import json
import re
from typing import Any

from openai import OpenAI


class AIClient:
    def __init__(self, api_key: str, model: str) -> None:
        self.client = OpenAI(api_key=api_key)
        self.model = model

    def _maybe_temperature(self, value: float) -> dict[str, float]:
        # GPT-5 chat endpoints do not accept temperature.
        if self.model.lower().startswith("gpt-5"):
            return {}
        return {"temperature": value}

    def generate_spl(self, question: str) -> str:
        system = (
            "You are a Splunk security analyst. Convert the user's question into a single SPL query. "
            "Return only the SPL query and nothing else. Assume index=main when user does not specify an index."
        )
        response = self.client.chat.completions.create(
            model=self.model,
            **self._maybe_temperature(0.1),
            messages=[
                {"role": "system", "content": system},
                {"role": "user", "content": question},
            ],
        )
        text = response.choices[0].message.content or ""
        return self._normalize_spl(text)

    def _normalize_spl(self, raw_text: str) -> str:
        text = (raw_text or "").strip()
        if not text:
            return "search index=main earliest=-15m | head 20"

        # Prefer fenced block content if present.
        fence_match = re.search(r"```(?:\w+)?\s*(.*?)```", text, flags=re.DOTALL)
        if fence_match:
            text = fence_match.group(1).strip()

        lines = [line.strip() for line in text.splitlines() if line.strip()]
        if not lines:
            return "search index=main earliest=-15m | head 20"

        # Remove language labels and common wrappers.
        first = lines[0].lower().rstrip(":")
        if first in {"spl", "splunk", "sql"} and len(lines) > 1:
            lines = lines[1:]
        text = "\n".join(lines).strip()
        text = re.sub(r"^(spl|splunk)\s*query\s*:\s*", "", text, flags=re.IGNORECASE)
        text = re.sub(r"^query\s*:\s*", "", text, flags=re.IGNORECASE)
        text = text.strip().strip("`").strip()

        # Use only first non-empty line to avoid narrative text.
        for line in text.splitlines():
            candidate = line.strip()
            if candidate:
                text = candidate
                break

        # Splunk jobs endpoint expects the search string; ensure valid prefix.
        lower = text.lower()
        if lower.startswith("spl "):
            text = text[4:].strip()
            lower = text.lower()
        if not (
            lower.startswith("search ")
            or lower.startswith("|")
            or lower.startswith("tstats ")
            or lower.startswith("from ")
            or lower.startswith("mstats ")
            or lower.startswith("metadata ")
            or lower.startswith("inputlookup ")
            or lower.startswith("rest ")
            or lower.startswith("makeresults")
        ):
            text = f"search {text}"

        if text.startswith("|"):
            text = f"search * {text}"

        return text

    def explain_results(self, question: str, spl_query: str, rows: list[dict[str, Any]]) -> str:
        compact_rows = rows[:20]
        user_prompt = (
            f"User question: {question}\n\n"
            f"SPL query used:\n{spl_query}\n\n"
            f"Splunk rows (JSON):\n{json.dumps(compact_rows, ensure_ascii=True)}\n\n"
            "Provide:\n"
            "1) short finding summary\n"
            "2) risk level: Low/Medium/High\n"
            "3) top 2-4 recommended actions\n"
            "4) confidence note in one line.\n"
            "Keep it concise and formatted for Telegram."
        )
        response = self.client.chat.completions.create(
            model=self.model,
            **self._maybe_temperature(0.2),
            messages=[
                {
                    "role": "system",
                    "content": "You are a SOC assistant. Be concise, practical, and security-focused.",
                },
                {"role": "user", "content": user_prompt},
            ],
        )
        return (response.choices[0].message.content or "").strip()


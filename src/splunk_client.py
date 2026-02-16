from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any

import requests
import urllib3


@dataclass
class SplunkSearchResult:
    sid: str
    rows: list[dict[str, Any]]


class SplunkClient:
    def __init__(
        self,
        base_url: str,
        username: str,
        password: str,
        verify_tls: bool,
        timeout_seconds: int,
        poll_seconds: float,
        max_wait_seconds: int,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.username = username
        self.password = password
        self.verify_tls = verify_tls
        self.timeout_seconds = timeout_seconds
        self.poll_seconds = poll_seconds
        self.max_wait_seconds = max_wait_seconds
        self._session = requests.Session()
        if not verify_tls:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        self._session.verify = verify_tls
        self._auth_token: str | None = None

    def _request(self, method: str, path: str, **kwargs: Any) -> requests.Response:
        headers = kwargs.pop("headers", {})
        if self._auth_token:
            headers["Authorization"] = f"Splunk {self._auth_token}"
        url = f"{self.base_url}{path}"
        response = self._session.request(
            method,
            url,
            timeout=self.timeout_seconds,
            headers=headers,
            **kwargs,
        )
        if response.status_code >= 400:
            raise RuntimeError(f"Splunk request failed ({response.status_code}): {response.text}")
        return response

    def login(self) -> None:
        response = self._request(
            "POST",
            "/services/auth/login",
            data={
                "username": self.username,
                "password": self.password,
                "output_mode": "json",
            },
        )
        payload = response.json()
        token = payload.get("sessionKey")
        if not isinstance(token, str) or not token:
            raise RuntimeError("Failed to parse Splunk session key")
        self._auth_token = token

    def _ensure_auth(self) -> None:
        if not self._auth_token:
            self.login()

    def run_search(self, spl_query: str) -> SplunkSearchResult:
        self._ensure_auth()
        sid = self._create_job(spl_query)
        self._wait_until_done(sid)
        rows = self._fetch_results(sid)
        return SplunkSearchResult(sid=sid, rows=rows)

    def _create_job(self, spl_query: str) -> str:
        response = self._request(
            "POST",
            "/services/search/jobs",
            data={
                "search": spl_query,
                "output_mode": "json",
                "exec_mode": "normal",
            },
        )
        payload = response.json()
        sid = payload.get("sid")
        if not isinstance(sid, str) or not sid:
            raise RuntimeError(f"Could not get SID from Splunk response: {payload}")
        return sid

    def _wait_until_done(self, sid: str) -> None:
        deadline = time.time() + self.max_wait_seconds
        while time.time() < deadline:
            response = self._request(
                "GET",
                f"/services/search/jobs/{sid}",
                params={"output_mode": "json"},
            )
            entry = response.json().get("entry", [])
            if entry:
                content = entry[0].get("content", {})
                if content.get("isDone"):
                    return
            time.sleep(self.poll_seconds)
        raise TimeoutError(f"Splunk search job timed out for sid={sid}")

    def _fetch_results(self, sid: str) -> list[dict[str, Any]]:
        response = self._request(
            "GET",
            f"/services/search/jobs/{sid}/results",
            params={
                "output_mode": "json",
                "count": 50,
            },
        )
        payload = response.json()
        results = payload.get("results")
        if isinstance(results, list):
            return [r for r in results if isinstance(r, dict)]
        return []


"""The few HTTP calls the pairing flow makes, behind small injectable functions (tests replace them; nothing here is
retried or cached)."""

from __future__ import annotations

import os
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any

import httpx

from . import _js

API = "https://api.witbitz.chat/v1/space"
ORIGIN = "https://witbitz-spaces.pages.dev"


@dataclass(frozen=True)
class ApiReply:
    status: int
    j: Any  # the parsed JSON body, or None when it was not JSON


ApiCall = Callable[[dict], Awaitable[ApiReply]]
GetJson = Callable[[str], Awaitable[Any]]
PostJson = Callable[[str, dict], Awaitable[Any]]


def _json_of(r: httpx.Response) -> Any:
    return _js.parse(r.content.decode("utf-8-sig", "replace"))  # fetch's r.json(): BOM dropped, then JSON.parse


def make_api_call(client: httpx.AsyncClient) -> ApiCall:
    """POST {op:'state', …} to the account API, as the Spaces app would (same Origin)."""
    api = os.environ.get("RC_BASE") or API
    origin = os.environ.get("RC_ORIGIN") or ORIGIN

    async def call(body: dict) -> ApiReply:
        r = await client.post(api, content=_js.stringify(body).encode("utf-8"),
                              headers={"content-type": "application/json", "origin": origin})
        try:
            j = _json_of(r)
        except ValueError:
            j = None
        return ApiReply(r.status_code, j)

    return call


def make_get_json(client: httpx.AsyncClient) -> GetJson:
    async def get_json(url: str) -> Any:
        return _json_of(await client.get(url, headers={"cache-control": "no-store"}))

    return get_json


def make_post_json(client: httpx.AsyncClient) -> PostJson:
    async def post_json(url: str, body: dict) -> Any:
        r = await client.post(url, content=_js.stringify(body).encode("utf-8"), headers={"content-type": "application/json"})
        return _json_of(r)

    return post_json


def new_client() -> httpx.AsyncClient:
    return httpx.AsyncClient(timeout=httpx.Timeout(30.0), follow_redirects=True)

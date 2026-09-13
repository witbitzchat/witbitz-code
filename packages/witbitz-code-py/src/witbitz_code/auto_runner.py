"""Code Auto mode's loop inside the connector — tools/code-auto-runner.mjs, in Python (docs/code-auto-mode.md §2).

For each session switched to Auto it polls OpenCode's pending permission asks (GET /permission?directory=…), and for each
new one: the deterministic layer (auto.py) answers what needs no model; otherwise the SESSION'S OWN model reviews it in a
throw-away session whose rules deny every tool. Only a clear allow is answered `once`, a deny is answered `reject` with the
reason for the agent, and everything else — ask, nonsense, a severe allow, a timeout, any error — is LEFT for the person's
approval card. Each decision: one line in the local log (a digest, never the command) and an on_verdict callback (the
connector sends it to open pages as `autoverdict`).

The state file and the log are the JS connector's, byte for byte in shape: a computer can switch between the two.
"""

from __future__ import annotations

import asyncio
import math
import os
import re
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any
from urllib.parse import quote

import httpx

from . import _js
from .auto import action_for, classify_deterministic, log_record, parse_verdict, reviewer_prompt

REVIEW_TITLE = "witbitz-auto-review"  # the page never lists a session with this title
HANDLED_TTL_S = 30 * 60
MAX_USER_MESSAGES = 6
MAX_DETAIL = 300
_SESSION_ID = re.compile(r"ses[A-Za-z0-9_-]{1,80}")


def _now_ms() -> int:
    return int(time.time() * 1000)


def _uri_component(s: str) -> str:
    return quote(s, safe="-_.!~*'()")  # encodeURIComponent


def detail_of(req: dict) -> str:
    """What the ask is about, for the person's own page (the verdict is sealed to it, like the ask) — never for the log."""
    md = req.get("metadata")
    cmd = md.get("command") if isinstance(md, dict) else None
    patterns = req.get("patterns")
    first = patterns[0] if isinstance(patterns, list) and patterns and isinstance(patterns[0], str) else ""
    return _js.utf16_slice(cmd if isinstance(cmd, str) and cmd else first, 0, MAX_DETAIL)


class AutoRunner:
    def __init__(self, *, base: str, auth: Callable[[], dict], client: httpx.AsyncClient, state_path: Path | None,
                 log_path: Path | None, poll_ms: float = 1000, review_timeout_ms: float = 30_000, home: str | None = None,
                 on_verdict: Callable[[dict], Any] = lambda v: None, log: Callable[[str], Any] = lambda m: None,
                 now: Callable[[], int] = _now_ms) -> None:
        self._root = re.sub(r"/+\Z", "", base or "")
        self._auth = auth
        self._client = client
        self._state_path = Path(state_path) if state_path else None
        self._log_path = Path(log_path) if log_path else None
        self._poll_s = poll_ms / 1000
        self._review_timeout_ms = review_timeout_ms
        self._home = home if home is not None else str(Path.home())
        self._on_verdict = on_verdict
        self._log = log
        self._now = now
        self._auto: dict[str, dict] = {}  # sessionID → {dir, at}
        self._handled: dict[str, int] = {}  # permission id → when it was taken up (so a poll never reviews it twice)
        self._tasks: set[asyncio.Task] = set()
        self._loop_task: asyncio.Task | None = None
        self._stopped = False
        self._load()

    # ── state on the computer ─────────────────────────────────────────────────────────────────────────────────────────
    def _load(self) -> None:
        try:
            if not self._state_path or not self._state_path.exists():
                return
            doc = _js.parse(self._state_path.read_text(encoding="utf-8"))
            sessions = doc.get("sessions") if isinstance(doc, dict) else None
            for sid, v in (sessions.items() if isinstance(sessions, dict) else []):
                if sid.startswith("ses") and isinstance(v, dict) and isinstance(v.get("dir"), str) and v["dir"].startswith("/"):
                    at = _js.to_number(v.get("at", _js.UNDEFINED))
                    self._auto[sid] = {"dir": v["dir"], "at": _js.clean_number(at) if _js.truthy(at) else 0}
        except Exception as e:
            self._log(f"code-auto: ignoring an unreadable {self._state_path} ({e})")

    def _save(self) -> None:
        if not self._state_path:
            return
        try:
            self._state_path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self._state_path.with_name(self._state_path.name + ".tmp")
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                f.write(_js.stringify({"sessions": self._auto}, 2))
            os.replace(tmp, self._state_path)  # atomic: a crash mid-write never leaves half a file
        except Exception as e:
            self._log(f"code-auto: could not save {self._state_path} ({e})")

    def _append_log(self, rec: dict) -> None:
        if not self._log_path:
            return
        try:
            self._log_path.parent.mkdir(parents=True, exist_ok=True)
            fd = os.open(self._log_path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
            with os.fdopen(fd, "a", encoding="utf-8") as f:
                f.write(_js.stringify(rec) + "\n")
        except Exception as e:
            self._log(f"code-auto: could not write {self._log_path} ({e})")

    # ── OpenCode ──────────────────────────────────────────────────────────────────────────────────────────────────────
    def _url(self, path: str, directory: str) -> str:
        return f"{self._root}{path}{'&' if '?' in path else '?'}directory={_uri_component(directory)}"

    async def _call(self, method: str, path: str, directory: str, body: Any = _js.UNDEFINED) -> tuple[bool, int, Any]:
        has_body = body is not _js.UNDEFINED
        headers = {**self._auth(), **({"content-type": "application/json"} if has_body else {})}
        r = await self._client.request(method, self._url(path, directory), headers=headers,
                                       content=_js.utf8(_js.stringify(body)) if has_body else None)
        try:
            data = _js.parse(r.text)
        except ValueError:
            data = None  # an empty or non-JSON answer
        return 200 <= r.status_code < 300, r.status_code, data

    async def _reply(self, req: dict, directory: str, answer: str, message: str = "") -> bool:
        try:
            ok, _, _ = await self._call("POST", f"/permission/{_uri_component(req['id'])}/reply", directory,
                                        {"reply": answer, "message": message} if message else {"reply": answer})
            return ok
        except Exception:
            return False

    async def _session_context(self, sid: str, directory: str) -> tuple[dict | None, list[str]]:
        """The session's model and what the person asked for — from its own transcript."""
        _, _, msgs = await self._call("GET", f"/session/{_uri_component(sid)}/message", directory)
        model, user_messages = None, []
        for m in msgs if isinstance(msgs, list) else []:
            info = m.get("info") if isinstance(m, dict) and isinstance(m.get("info"), dict) else {}
            if info.get("role") == "assistant" and _js.truthy(info.get("providerID")) and _js.truthy(info.get("modelID")):
                model = {"providerID": info["providerID"], "modelID": info["modelID"]}
            if info.get("role") == "user":
                parts = m.get("parts") if isinstance(m.get("parts"), list) else []
                text = _js.trim("\n".join(p["text"] for p in parts if isinstance(p, dict) and p.get("type") == "text"
                                          and isinstance(p.get("text"), str) and not _js.truthy(p.get("synthetic"))))
                if text:
                    user_messages.append(text)
        return model, user_messages[-MAX_USER_MESSAGES:]

    async def _review(self, req: dict, directory: str) -> tuple[dict | None, str, str]:
        model, user_messages = await self._session_context(req["sessionID"], directory)
        if not model:
            return None, "", "the session has no model to review with yet"
        label = f"{_js.js_string(model['providerID'])}/{_js.js_string(model['modelID'])}"
        prompt = reviewer_prompt(req, directory, user_messages)
        _, _, created = await self._call("POST", "/session", directory,
                                         {"title": REVIEW_TITLE, "permission": [{"permission": "*", "pattern": "*", "action": "deny"}]})
        rid = created.get("id") if isinstance(created, dict) else None
        if not _js.truthy(rid):
            return None, label, "could not open a review session"
        rid = _js.js_string(rid)
        timed_out = False
        try:
            body = {"model": model, "system": prompt["system"], "tools": {"*": False}, "parts": [{"type": "text", "text": prompt["text"]}]}
            try:
                _, _, answer = await asyncio.wait_for(self._call("POST", f"/session/{_uri_component(rid)}/message", directory, body),
                                                      self._review_timeout_ms / 1000)
            except asyncio.TimeoutError:
                timed_out = True
                raise
            parts = answer.get("parts") if isinstance(answer, dict) and isinstance(answer.get("parts"), list) else []
            texts = [p["text"] for p in parts if isinstance(p, dict) and p.get("type") == "text" and _js.truthy(p.get("text"))]
            text = _js.js_string(texts[-1]) if texts else ""
            return parse_verdict(text), label, "" if text else "the reviewer gave no answer"
        except asyncio.CancelledError:
            raise
        except Exception:
            secs = math.floor(self._review_timeout_ms / 1000 + 0.5) or 1  # Math.round(ms / 1000) || 1
            return None, label, f"the reviewer did not answer within {secs} s" if timed_out else "the review failed"
        finally:
            if timed_out:
                try:
                    await self._call("POST", f"/session/{_uri_component(rid)}/abort", directory)
                except Exception:
                    pass
            try:
                await self._call("DELETE", f"/session/{_uri_component(rid)}", directory)
            except Exception:
                pass

    async def _decide(self, req: dict, directory: str) -> None:
        t0 = self._now()
        det = classify_deterministic(req, directory=directory, home=self._home)
        model, note = "", ""
        if det:
            stage = det["stage"]
            verdict = {"decision": det["decision"], "severity": 100 if stage == "hard-deny" else 0, "rule": det["rule"], "reason": det["reason"]}
        else:
            stage = "reviewer"
            verdict, model, note = await self._review(req, directory)
        action = det["decision"] if det else action_for(verdict)
        answered = None
        reason_given = (verdict or {}).get("reason") or ""
        if action == "allow":
            answered = await self._reply(req, directory, "once")
        elif action == "deny":
            answered = await self._reply(req, directory, "reject",
                                         f"{reason_given or 'Refused by Auto mode.'} (Witbitz Auto mode refused this — try a narrower or safer step.)")
        rec = log_record(req=req, stage=stage, verdict=verdict, action=action, model=model, ms=self._now() - t0, at=t0)
        self._append_log({**rec, "answered": False} if answered is False else rec)
        try:
            self._on_verdict({"id": req["id"], "sessionID": req.get("sessionID"), "permission": req.get("permission"), "detail": detail_of(req),
                              "stage": stage, "action": action, "severity": rec["severity"], "rule": rec["rule"],
                              "reason": reason_given or note or "", "answered": answered})
        except Exception:
            pass  # a listener never breaks the loop

    # ── the loop ──────────────────────────────────────────────────────────────────────────────────────────────────────
    async def _poll(self) -> None:
        if self._stopped or not self._auto:
            return
        cutoff = self._now() - HANDLED_TTL_S * 1000
        for pid, at in list(self._handled.items()):
            if at < cutoff:
                del self._handled[pid]
        for directory in dict.fromkeys(v["dir"] for v in self._auto.values()):
            try:
                _, _, data = await self._call("GET", "/permission", directory)
            except asyncio.CancelledError:
                raise
            except Exception:
                continue  # OpenCode restarting
            for req in data if isinstance(data, list) else []:
                if not isinstance(req, dict) or not isinstance(req.get("id"), str) or req["id"] in self._handled:
                    continue
                sid = req.get("sessionID")
                on = self._auto.get(sid) if isinstance(sid, str) else None
                if not on or on["dir"] != directory:
                    continue
                self._handled[req["id"]] = self._now()
                self._spawn(self._decide_logged(req, directory))

    async def _decide_logged(self, req: dict, directory: str) -> None:
        try:
            await self._decide(req, directory)
        except asyncio.CancelledError:
            raise
        except Exception as e:
            self._log(f"code-auto: {e}")

    def _spawn(self, coro: Any) -> None:
        t = asyncio.get_running_loop().create_task(coro)
        self._tasks.add(t)
        t.add_done_callback(self._tasks.discard)

    async def _run(self) -> None:
        while not self._stopped:
            try:
                await self._poll()
            except asyncio.CancelledError:
                raise
            except Exception as e:
                self._log(f"code-auto: {e}")
            await asyncio.sleep(self._poll_s)

    def start(self) -> None:
        if self._loop_task is None and not self._stopped:
            self._loop_task = asyncio.get_running_loop().create_task(self._run())

    def set_auto(self, session_id: Any, directory: Any, on: bool) -> bool:
        if not isinstance(session_id, str) or not _SESSION_ID.fullmatch(session_id):
            return False
        if on:
            if not isinstance(directory, str) or not directory.startswith("/") or _js.utf16_len(directory) > 1024:
                return False
            self._auto[session_id] = {"dir": directory, "at": self._now()}  # an existing key keeps its place, as Map.set does
        else:
            self._auto.pop(session_id, None)
        self._save()
        return True

    def sessions(self) -> list[str]:
        return list(self._auto)

    def stop(self) -> None:
        self._stopped = True
        if self._loop_task:
            self._loop_task.cancel()
        for t in list(self._tasks):
            t.cancel()

"""Code Auto mode's loop inside the connector — tools/code-auto-runner.mjs, in Python (docs/code-auto-mode.md §2).

For each session switched to Auto it polls OpenCode's pending permission asks (GET /permission?directory=…), and for each
new one: the deterministic layer (auto.py) answers what needs no model; otherwise the SESSION'S OWN model reviews it in a
throw-away session whose rules deny every tool. Only a clear allow is answered `once`, a deny is answered `reject` with the
reason for the agent, and everything else — ask, nonsense, a severe allow, a timeout, any error — is LEFT for the person's
approval card. Each decision: one line in the local log (a digest, never the command) and an on_verdict callback (the
connector sends it to open pages as `autoverdict`).

The state file and the log are the JS connector's, byte for byte in shape: a computer can switch between the two.

The JS runner's three rules from OpenCode's own code hold here too: a SUBAGENT's asks are decided under the nearest
ancestor in Auto (reviewed against what the person asked there); a refusal is HELD until nothing else is pending in its
session (OpenCode's reject cancels every other pending ask there); and starting a subagent is allowed without a review
only when that agent's own rules ask for bash/edit/webfetch/websearch (policy.py).
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
from .policy import SUBAGENT_GATED

REVIEW_TITLE = "witbitz-auto-review"  # the page never lists a session with this title
HANDLED_TTL_S = 30 * 60
MAX_USER_MESSAGES = 6
MAX_DETAIL = 300
PARENT_TTL_MS = 10 * 60_000
AGENTS_TTL_MS = 60_000
MAX_DEPTH = 4  # parent links followed looking for the session in Auto
REFUSAL_SUFFIX = "(Witbitz Auto mode refused this — try a narrower or safer step.)"
_UNKNOWN = object()  # OpenCode could not say who a session's parent is (not cached)
_SESSION_ID = re.compile(r"ses[A-Za-z0-9_-]{1,80}")


def _now_ms() -> int:
    return int(time.time() * 1000)


def _uri_component(s: str) -> str:
    return quote(s, safe="-_.!~*'()")  # encodeURIComponent


def action_of(rules: Any, perm: str) -> Any:
    """OpenCode's own evaluation for the catch-all pattern: the LAST rule that matches wins."""
    action = None
    for r in rules if isinstance(rules, list) else []:
        if isinstance(r, dict) and r.get("permission") in (perm, "*") and r.get("pattern") == "*":
            action = r.get("action")
    return action


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
        self._parents: dict[str, dict] = {}  # sessionID → {parent, at} — so a subagent's ask finds its Auto session
        self._agents: dict[str, dict] = {}  # directory → {list, at} — GET /agent, for what a subagent's own rules allow
        self._held: dict[str, dict[str, dict]] = {}  # sessionID → {permission id → a refusal waiting for its session}
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

    async def _parent_of(self, sid: str, directory: str) -> Any:
        c = self._parents.get(sid)
        if c and self._now() - c["at"] < PARENT_TTL_MS:
            return c["parent"]
        try:
            ok, _, data = await self._call("GET", f"/session/{_uri_component(sid)}", directory)
        except asyncio.CancelledError:
            raise
        except Exception:
            return _UNKNOWN
        if not ok or not isinstance(data, dict):
            return _UNKNOWN
        parent = data["parentID"] if isinstance(data.get("parentID"), str) and data["parentID"] else None
        self._parents[sid] = {"parent": parent, "at": self._now()}
        return parent

    async def _owner_of(self, sid: str, directory: str) -> str | None:
        """The session in Auto this ask belongs to: its own, or its nearest ancestor's in the same project."""
        cur: Any = sid
        for _ in range(MAX_DEPTH):
            if not isinstance(cur, str) or not cur:
                return None
            on = self._auto.get(cur)
            if on and on["dir"] == directory:
                return cur
            cur = await self._parent_of(cur, directory)
        return None

    async def _subagent_asks(self, name: str, directory: str) -> bool | None:
        c = self._agents.get(directory)
        if not c or self._now() - c["at"] > AGENTS_TTL_MS:
            try:
                ok, _, data = await self._call("GET", "/agent", directory)
            except asyncio.CancelledError:
                raise
            except Exception:
                return None
            if not ok or not isinstance(data, list):
                return None
            c = {"list": data, "at": self._now()}
            self._agents[directory] = c
        agent = next((a for a in c["list"] if isinstance(a, dict) and a.get("name") == name), None)
        if not agent or not isinstance(agent.get("permission"), list):
            return False
        return all(action_of(agent["permission"], p) in ("ask", "deny") for p in SUBAGENT_GATED)

    async def _classify_subagent(self, req: dict, directory: str) -> dict | None:
        if req.get("permission") != "task":
            return None
        md = req.get("metadata") if isinstance(req.get("metadata"), dict) else {}
        patterns = req.get("patterns") if isinstance(req.get("patterns"), list) else []
        name = md.get("subagent_type") or (patterns[0] if patterns else "")
        if not isinstance(name, str) or not name:
            return None
        asks = await self._subagent_asks(name, directory)
        if asks is True:
            return {"stage": "fast-allow", "decision": "allow", "rule": "fast:subagent-asks",
                    "reason": f"starts the {name} agent, whose own commands each ask for approval"}
        if asks is False:
            return {"stage": "fast-ask", "decision": "ask", "rule": "ask:subagent-unguarded",
                    "reason": f"the {name} agent's own commands would run without asking — start it yourself if you trust it"}
        return None

    async def _review(self, req: dict, directory: str, owner: str | None = None) -> tuple[dict | None, str, str]:
        model, user_messages = await self._session_context(owner or req["sessionID"], directory)
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

    def _emit(self, req: dict, stage: str, action: str, rec: dict, reason: str, answered: Any) -> None:
        try:
            self._on_verdict({"id": req["id"], "sessionID": req.get("sessionID"), "permission": req.get("permission"), "detail": detail_of(req),
                              "stage": stage, "action": action, "severity": rec["severity"], "rule": rec["rule"],
                              "reason": reason, "answered": answered})
        except Exception:
            pass  # a listener never breaks the loop

    async def _decide(self, req: dict, directory: str, owner: str | None = None) -> None:
        t0 = self._now()
        det = classify_deterministic(req, directory=directory, home=self._home) or await self._classify_subagent(req, directory)
        model, note = "", ""
        if det:
            stage = det["stage"]
            severity = 100 if stage == "hard-deny" else 50 if stage == "fast-ask" else 0
            verdict = {"decision": det["decision"], "severity": severity, "rule": det["rule"], "reason": det["reason"]}
        else:
            stage = "reviewer"
            verdict, model, note = await self._review(req, directory, owner)
        action = det["decision"] if det else action_for(verdict)
        reason_given = (verdict or {}).get("reason") or ""
        rec = log_record(req=req, stage=stage, verdict=verdict, action=action, model=model, ms=self._now() - t0, at=t0)
        reason = reason_given or note or ""
        if action == "deny":
            # HELD, not sent (see the module docstring). The page hears it now (answered None) and again when it lands.
            self._held.setdefault(req["sessionID"], {})[req["id"]] = {
                "req": req, "dir": directory, "stage": stage, "rec": rec, "reason": reason,
                "message": f"{reason_given or 'Refused by Auto mode.'} {REFUSAL_SUFFIX}"}
            self._emit(req, stage, action, rec, reason, None)
            return
        answered = await self._reply(req, directory, "once") if action == "allow" else None
        self._append_log({**rec, "answered": False} if answered is False else rec)
        self._emit(req, stage, action, rec, reason, answered)

    async def _release_held(self, directory: str, pending: list) -> None:
        """Send the held refusals of every session whose OTHER asks have all settled."""
        for sid in list(self._held):
            refusals = self._held.get(sid) or {}
            mine = [h for h in refusals.values() if h["dir"] == directory]
            if not mine:
                continue
            pending_ids = {p.get("id") for p in pending if isinstance(p, dict) and p.get("sessionID") == sid}
            for h in mine:
                if h["req"]["id"] in pending_ids:
                    continue
                refusals.pop(h["req"]["id"], None)  # answered elsewhere before it could be sent
                self._append_log({**h["rec"], "answered": False})
                self._emit(h["req"], h["stage"], "deny", h["rec"], h["reason"], False)
            if any(pid not in refusals for pid in pending_ids):
                continue  # something else in the session is still open
            for h in [x for x in list(refusals.values()) if x["dir"] == directory]:
                refusals.pop(h["req"]["id"], None)
                answered = await self._reply(h["req"], directory, "reject", h["message"])
                self._append_log({**h["rec"], "answered": False} if answered is False else h["rec"])
                self._emit(h["req"], h["stage"], "deny", h["rec"], h["reason"], answered)
            if not refusals:
                self._held.pop(sid, None)

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
            pending = data if isinstance(data, list) else []
            for req in pending:
                if not isinstance(req, dict) or not isinstance(req.get("id"), str) or req["id"] in self._handled:
                    continue
                sid = req.get("sessionID")
                if not isinstance(sid, str):
                    continue
                owner = await self._owner_of(sid, directory)
                if not owner:
                    continue
                self._handled[req["id"]] = self._now()
                self._spawn(self._decide_logged(req, directory, owner))
            await self._release_held(directory, pending)

    async def _decide_logged(self, req: dict, directory: str, owner: str | None = None) -> None:
        try:
            await self._decide(req, directory, owner)
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

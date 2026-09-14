"""Attachments in the Code section, the Claude Code way — tools/code-attachments.mjs + spaces/public/codeAttachments.js.

The connector saves every file a message carries on this computer and puts a NOTE in the message in its place; the agent
opens the file with its read tool when it needs it (docs/code-attachments.md). OpenCode refuses an Excel or Word file part
for every model, and TrustedRouter answers 502 for a PDF — both measured on opencode 1.18.30, 2026-09-13.

Held to the JS module by spaces/test/codeAttachments.vectors.json. One difference, stated: this connector has no attested
Tinfoil client yet, so it makes no text copies — the note says so, and the agent reads the file itself.
"""

from __future__ import annotations

import base64
import hashlib
import os
import re
import shutil
import time
from decimal import ROUND_HALF_UP, Decimal
from pathlib import Path
from typing import Any

from . import _js

NOTE_HEAD = "The user attached files. They are saved on this computer — open them with the read tool."
ATTACHMENT_ROUTE = "/witbitz/attachment"
MAX_NAME = 100
MAX_FILE_BYTES = 25 * 1024 * 1024
MAX_SESSION_BYTES = 200 * 1024 * 1024
MAX_SERVE_BYTES = 20 * 1024 * 1024
MAX_ROOT_BYTES = 2 * 1024 * 1024 * 1024  # every session together — a secret-holder cannot fill the disk by inventing sessions
SHOWN_MAX = 200  # a file name is prompt text the model reads
NO_COPY = "this computer's Python connector does not make text copies yet"
_SESSION_RE = re.compile(r"[A-Za-z0-9_-]{1,128}")
_FILE_RE = re.compile(r"[0-9a-f]{8}-(?!\.)[A-Za-z0-9._ ()-]{1,110}")
_TEXT_EXT = {"txt", "md", "markdown", "csv", "tsv", "json", "log", "xml", "yaml", "yml", "html", "htm", "js", "mjs", "ts", "py", "sh", "sql", "ini", "toml"}
_MIME = {"pdf": "application/pdf", "png": "image/png", "jpg": "image/jpeg", "jpeg": "image/jpeg", "gif": "image/gif", "webp": "image/webp",
         "heic": "image/heic", "md": "text/markdown", "txt": "text/plain", "csv": "text/csv", "json": "application/json",
         "xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", "xls": "application/vnd.ms-excel",
         "docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document", "doc": "application/msword",
         "pptx": "application/vnd.openxmlformats-officedocument.presentationml.presentation"}


def default_root() -> Path:
    return Path(os.environ.get("WITBITZ_CODE_ATTACHMENTS") or Path.home() / ".witbitz" / "code" / "attachments")


def safe_name(name: Any) -> str:
    s = _js.trim(re.split(r"[\\/]", _js.js_string(name) if _js.truthy(name) else "")[-1])
    s = re.sub(r"^\.", "_", re.sub(r"_+", "_", re.sub(r"[^A-Za-z0-9._ ()-]+", "_", s)))
    if not re.sub(r"[._ ]", "", s):
        s = "file"
    if len(s) > MAX_NAME:
        m = re.search(r"\.[A-Za-z0-9]{1,10}\Z", s)
        ext = m.group(0) if m else ""
        s = s[: MAX_NAME - len(ext)] + ext
    return s


def staged_file_name(hash_hex: str, name: Any) -> str:
    return f"{str(hash_hex)[:8]}-{safe_name(name)}"


def _ext(name: Any) -> str:
    m = re.search(r"\.([a-z0-9]+)\Z", _js.js_string(name or "").lower())
    return m.group(1) if m else ""


def needs_text_copy(mime: Any, name: Any) -> bool:
    m = _js.js_string(mime or "").lower()
    if m.startswith("image/") or m.startswith("text/") or m == "application/json":
        return False
    return _ext(name) not in _TEXT_EXT


def _fixed1(x: float) -> str:
    return str(Decimal(x).quantize(Decimal("0.1"), rounding=ROUND_HALF_UP))  # Number#toFixed(1) on the exact value


def format_size(n: Any) -> str:
    n = int(n or 0)
    if n < 1024:
        return f"{n} B"
    if n < 1024 * 1023.95:
        return f"{_fixed1(n / 1024)} KB"
    return f"{_fixed1(n / 1024 / 1024)} MB"


def _shown(name: Any) -> str:
    return _js.utf16_slice(re.sub(r"[\r\n]+", " ", _js.js_string(name or "file")).replace(" — ", " - "), 0, SHOWN_MAX)


def attachment_note(entries: list[dict]) -> str:
    lines = [NOTE_HEAD]
    for e in entries:
        lines.append(f"• {_shown(e.get('name'))} — {format_size(e.get('size'))} — {e['path']}")
        if e.get("copy"):
            lines.append(f"  Its text — open THIS with the read tool, not the original: {e['copy']}")
        elif e.get("inline"):
            lines.append("  Shown to you with this message.")
        elif e.get("noCopy"):
            lines.append(f"  No text copy ({e['noCopy']}) — open it with the read tool if you can; otherwise ask the user before converting it.")
    return "\n".join(lines)


def parse_attachment_note(text: Any) -> list[dict] | None:
    lines = _js.js_string(text or "").split("\n")
    if lines[0] != NOTE_HEAD:
        return None
    out: list[dict] = []
    for line in lines[1:]:
        m = re.fullmatch(r"• (.+?) — (\d+(?:\.\d)? (?:B|KB|MB)) — (/.+)", line)
        if m:
            parts = m.group(3).split("/")
            out.append({"name": m.group(1), "size": m.group(2), "session": parts[-2] if len(parts) > 1 else "", "file": parts[-1], "copy": "", "inline": False})
            continue
        if not out:
            continue
        c = re.fullmatch(r"  Its text — .*: (/.+)", line)
        if c:
            out[-1]["copy"] = c.group(1).split("/")[-1]
        elif line == "  Shown to you with this message.":
            out[-1]["inline"] = True
    return out or None


def valid_attachment_ref(session: Any, file: Any) -> bool:
    s, f = (_js.js_string(v) if isinstance(v, str) else "" for v in (session, file))
    return bool(_SESSION_RE.fullmatch(s) and _FILE_RE.fullmatch(f) and ".." not in f)


def mime_for_file(file: Any) -> str:
    return _MIME.get(_ext(file), "application/octet-stream")


def attachment_rule(root: Path, session_id: str) -> dict:
    """Reads in THIS session's attachments folder are allowed, nothing else (measured: a same-prefix sibling, another
    session's folder and the root still ask)."""
    return {"permission": "external_directory", "pattern": f"{root}/{session_id}/*", "action": "allow"}


def _data_url(url: Any) -> tuple[str, bytes] | None:
    m = re.fullmatch(r"data:([^;,]*)(?:;[^,]*?)?;base64,(.*)", url, re.S) if isinstance(url, str) else None
    if not m:
        return None
    b64 = re.sub(r"[^A-Za-z0-9+/]", "", m.group(2).replace("-", "+").replace("_", "/"))  # as lenient as Buffer.from(…, 'base64')
    return (m.group(1) or "application/octet-stream"), base64.b64decode(b64 + "=" * (-len(b64) % 4))


def _folder_bytes(d: Path) -> int:
    try:
        return sum(p.lstat().st_size for p in d.iterdir())
    except OSError:
        return 0


def _root_bytes(root: Path) -> int:
    try:
        return sum(_folder_bytes(p) for p in Path(root).iterdir() if p.is_dir() and not p.is_symlink())
    except OSError:
        return 0


def _collision(path: Path, digest: str) -> dict:
    return {"error": {"status": 409, "message": f"a different file saved as {path.name} is already in this session — rename it and attach it again"}}


def stage_message_body(body: Any, *, session_id: Any, root: Path, max_file_bytes: int = MAX_FILE_BYTES,
                       max_session_bytes: int = MAX_SESSION_BYTES, max_root_bytes: int = MAX_ROOT_BYTES) -> dict | None:
    """Save the files in one turn's body → {"body", "entries"} with the note in their place; None when there is nothing to
    save; {"error": {"status", "message"}} to refuse the turn. Never changes the body it was given."""
    parts = body.get("parts") if isinstance(body, dict) and isinstance(body.get("parts"), list) else []
    files = [(i, p, d) for i, p in enumerate(parts) if isinstance(p, dict) and p.get("type") == "file" for d in [_data_url(p.get("url"))] if d]
    if not files:
        return None
    if not isinstance(session_id, str) or not _SESSION_RE.fullmatch(session_id):
        return {"error": {"status": 400, "message": "not a session id"}}
    d = Path(root) / session_id
    if Path(root).is_symlink() or d.is_symlink():
        return {"error": {"status": 400, "message": "the attachments folder is a link — refusing to write through it"}}
    d.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(d, 0o700)
    used = _folder_bytes(d)
    total = _root_bytes(root)
    entries: list[dict] = []
    drop: set[int] = set()
    for i, p, (url_mime, data) in files:
        name = _js.js_string(p.get("filename") or "file")
        if len(data) > max_file_bytes:
            return {"error": {"status": 413, "message": f"{name} is over {round(max_file_bytes / 1048576)} MB — too large to attach"}}
        digest = hashlib.sha256(data).hexdigest()
        path = d / staged_file_name(digest, name)
        if path.exists() or path.is_symlink():
            # same name = same first 8 hex of the hash: this file again — unless 32 bits collided (or a link sits there)
            if path.is_symlink() or hashlib.sha256(path.read_bytes()).hexdigest() != digest:
                return _collision(path, digest)
        else:
            if used + len(data) > max_session_bytes:
                return {"error": {"status": 413, "message": f"this session's attachments are over {round(max_session_bytes / 1048576)} MB — start a new session to attach more"}}
            if total + len(data) > max_root_bytes:
                return {"error": {"status": 413, "message": f"saved attachments on this computer are over {round(max_root_bytes / 1073741824)} GB — delete old sessions to attach more"}}
            try:
                fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                with os.fdopen(fd, "wb") as fh:
                    fh.write(data)
            except FileExistsError:
                if hashlib.sha256(path.read_bytes()).hexdigest() != digest:
                    return _collision(path, digest)
            used += len(data)
            total += len(data)
        mime = _js.js_string(p.get("mime") or url_mime).lower()
        entry: dict = {"name": name, "size": len(data), "path": str(path)}
        if mime.startswith("image/"):
            entry["inline"] = True
        else:
            drop.add(i)
        if needs_text_copy(mime, name):
            copy = Path(f"{path}.md")
            if copy.exists():
                entry["copy"] = str(copy)
            else:
                entry["noCopy"] = NO_COPY
        entries.append(entry)
    kept = [p for i, p in enumerate(parts) if i not in drop]
    return {"body": {**body, "parts": [*kept, {"type": "text", "text": attachment_note(entries), "synthetic": True}]}, "entries": entries}


def serve_attachment(*, root: Path, session: Any, file: Any, max_bytes: int = MAX_SERVE_BYTES) -> tuple[int, str]:
    """One staged file (or its text copy) for the page: (status, JSON body) in the connector's reply shape."""
    if not valid_attachment_ref(session, file):
        return 400, _js.stringify({"error": "not an attachment"})
    path = Path(root) / session / file
    if not path.exists():
        return 404, _js.stringify({"error": "that attachment is no longer on this computer"})
    # By REAL path: a link anywhere under the folder (the session folder, or the file) must not lead the read elsewhere.
    real_root = Path(root).resolve()
    if path.resolve() != real_root / session / file:
        return 400, _js.stringify({"error": "not an attachment"})
    size = path.stat().st_size
    if size > max_bytes:
        return 413, _js.stringify({"error": f"the file is over {round(max_bytes / 1048576)} MB — too large to send to the phone"})
    return 200, _js.stringify({"name": file[9:], "mime": mime_for_file(file), "size": size, "b64": base64.b64encode(path.read_bytes()).decode()})


def remove_session_attachments(root: Path, session_id: Any) -> None:
    if isinstance(session_id, str) and _SESSION_RE.fullmatch(session_id):
        shutil.rmtree(Path(root) / session_id, ignore_errors=True)


def prune_attachments(root: Path, *, days: float = 30, now: float | None = None) -> int:
    now = time.time() if now is None else now
    try:
        names = os.listdir(root)
    except OSError:
        return 0
    n = 0
    for s in names:
        if not _SESSION_RE.fullmatch(s):
            continue
        try:
            if (Path(root) / s).stat().st_mtime < now - days * 86400:
                shutil.rmtree(Path(root) / s, ignore_errors=True)
                n += 1
        except OSError:
            pass
    return n

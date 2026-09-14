"""The connector serves a file a Code reply produced, for the page's automatic preview — tools/code-outputs.mjs, in Python.

Which files those are is the page's (spaces/public/codeOutputs.js); both connectors hold to the same cases
(spaces/test/codeOutputs.vectors.json) and the tests compare this module with the JS one. The folder is the SESSION's, as
OpenCode reports it — never one the page names. Checks, in this order:
  by name  — an absolute one-line path inside the folder, of a kind the page shows, not secret-looking
             (refused before the disk is asked, so the route cannot probe what exists elsewhere)
  by disk  — the REAL path is still inside the folder's real path (no link out), still not secret-looking, still a kind
             the page shows, a regular file
  by size  — the bytes fit one relay message; `stat` answers without them, so a card can say "too large"
"""

from __future__ import annotations

import base64
import math
import os
import re
import stat as stat_mod
from typing import Any

from . import _js
from .attachments import MAX_SERVE_BYTES
from .auto import _sensitive_path, posix_normalize

OUTPUT_ROUTE = "/witbitz/output"
MAX_PATH = 4096

_KINDS = {
    "pdf": "pdf",
    "png": "image", "jpg": "image", "jpeg": "image", "gif": "image", "webp": "image",
    "csv": "table", "tsv": "table",
    "md": "text", "markdown": "text", "txt": "text",
    **{e: "file" for e in ("docx", "doc", "xlsx", "xls", "pptx", "ppt", "odt", "ods", "odp", "rtf", "zip", "epub", "heic", "svg",
                            "html", "htm", "mp3", "wav", "m4a", "mp4", "mov")},
}
_MIME = {
    "pdf": "application/pdf", "png": "image/png", "jpg": "image/jpeg", "jpeg": "image/jpeg", "gif": "image/gif", "webp": "image/webp",
    "csv": "text/csv", "tsv": "text/tab-separated-values", "md": "text/markdown", "markdown": "text/markdown", "txt": "text/plain",
    "docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document", "doc": "application/msword",
    "xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", "xls": "application/vnd.ms-excel",
    "pptx": "application/vnd.openxmlformats-officedocument.presentationml.presentation", "ppt": "application/vnd.ms-powerpoint",
    "odt": "application/vnd.oasis.opendocument.text", "ods": "application/vnd.oasis.opendocument.spreadsheet",
    "odp": "application/vnd.oasis.opendocument.presentation", "rtf": "application/rtf", "zip": "application/zip",
    "epub": "application/epub+zip", "heic": "image/heic", "svg": "image/svg+xml", "html": "text/html", "htm": "text/html",
    "mp3": "audio/mpeg", "wav": "audio/wav", "m4a": "audio/mp4", "mp4": "video/mp4", "mov": "video/quicktime",
}
_EXT = re.compile(r"(?:^|/)[^/.][^/]*\.([A-Za-z0-9]+)\Z")


def _ext_of(path: Any) -> str:
    m = _EXT.search(path) if isinstance(path, str) else None
    return m.group(1).lower() if m else ""


def output_kind(path: Any) -> str | None:
    """'pdf' | 'image' | 'table' | 'text' | 'file' — or None: not something to show."""
    return _KINDS.get(_ext_of(path))


def output_mime(path: Any) -> str:
    return _MIME.get(_ext_of(path), "application/octet-stream")


def valid_output_path(p: Any) -> bool:
    """Absolute, at most 4096 characters (UTF-16, as the page counts), one line, no NUL."""
    return isinstance(p, str) and p.startswith("/") and _js.utf16_len(p) <= MAX_PATH and not re.search(r"[\0\r\n]", p)


def _answer(st: int, o: dict) -> tuple[int, str]:
    return st, _js.stringify(o)


def serve_output(*, directory: Any, path: Any, stat: bool = False, max_bytes: int = MAX_SERVE_BYTES) -> tuple[int, str]:
    """One produced file (or its facts, with `stat`) for the page: (status, JSON body) in the connector's reply shape."""
    if not isinstance(directory, str) or not directory.startswith("/") or not valid_output_path(path):
        return _answer(400, {"error": "not a file in this session"})
    d = re.sub(r"/+\Z", "", posix_normalize(directory))
    a = posix_normalize(path)
    if not d or not a.startswith(d + "/"):
        return _answer(403, {"error": "that file is outside the session's folder"})
    if _sensitive_path(a[len(d):]):
        return _answer(403, {"error": "not shown: the name looks like a secret"})
    if not output_kind(a):
        return _answer(400, {"error": "not a file the page shows"})
    try:
        real_dir = os.path.realpath(d, strict=True)
    except OSError:
        return _answer(404, {"error": "the session's folder is not on this computer"})
    try:
        real = os.path.realpath(a, strict=True)
    except OSError:
        return _answer(404, {"error": "that file is not on the computer (any more)"})
    if not real.startswith(real_dir + "/"):
        return _answer(403, {"error": "that file leads outside the session's folder"})
    if _sensitive_path(real[len(real_dir):]):
        return _answer(403, {"error": "not shown: the file looks like a secret"})
    kind = output_kind(real)
    if not kind:
        return _answer(400, {"error": "not a file the page shows"})
    try:
        st = os.stat(real)
    except OSError:
        return _answer(404, {"error": "that file is not on the computer (any more)"})
    if not stat_mod.S_ISREG(st.st_mode):
        return _answer(400, {"error": "not a file"})
    meta = {"name": a.rsplit("/", 1)[-1], "kind": kind, "mime": output_mime(real), "size": st.st_size,
            "mtime": math.floor(st.st_mtime_ns / 1e6 + 0.5)}
    if stat:
        return _answer(200, meta)
    if st.st_size > max_bytes:
        return _answer(413, {**meta, "error": f"the file is over {round(max_bytes / 1048576)} MB — too large to send to the phone"})
    with open(real, "rb") as f:
        data = f.read()
    return _answer(200, {**meta, "b64": base64.b64encode(data).decode()})

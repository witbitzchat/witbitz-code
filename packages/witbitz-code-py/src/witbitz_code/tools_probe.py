"""Which suggested tools this computer has — tools/code-tools-probe.mjs, in Python ("Set up this computer").

A PATH lookup, nothing else: no process is started, no model is asked, nothing is installed. The connector answers the
page's nonce-checked `{t:'tools'}` with this. The catalog is spaces/public/codeTools.js; tests/test_tools_probe.py holds
this copy of the binary names and the answers to the JavaScript ones.
"""

from __future__ import annotations

import os
import stat
import sys
from collections.abc import Callable, Mapping
from pathlib import Path

# (tool id, binaries — any one on PATH means installed), in the catalog's order.
TOOL_BINS: list[tuple[str, list[str]]] = [
    ("git", ["git"]), ("ripgrep", ["rg"]), ("jq", ["jq"]), ("python", ["python3", "python"]), ("uv", ["uv"]),
    ("ffmpeg", ["ffmpeg"]), ("whisper", ["whisper-cli", "whisper-cpp", "whisper"]), ("poppler", ["pdftotext"]),
    ("qpdf", ["qpdf"]), ("tesseract", ["tesseract"]), ("pandoc", ["pandoc"]), ("imagemagick", ["magick", "convert"]),
]
# Package managers, most preferred first per OS: (id the page knows, binary).
PACKAGE_MANAGERS: dict[str, list[tuple[str, str]]] = {
    "darwin": [("brew", "brew"), ("port", "port")],
    "linux": [("apt", "apt-get"), ("dnf", "dnf"), ("pacman", "pacman"), ("zypper", "zypper"), ("apk", "apk"), ("brew", "brew")],
    "win32": [("winget", "winget"), ("choco", "choco"), ("scoop", "scoop")],
}
_EXTRA_POSIX = ["/opt/homebrew/bin", "/usr/local/bin", "/usr/bin", "/bin", "/usr/sbin", "/snap/bin", "/home/linuxbrew/.linuxbrew/bin"]
_EXTRA_HOME = [".local/bin", ".cargo/bin", "bin"]


def _is_executable(path: str) -> bool:
    try:
        st = os.stat(path)
    except OSError:
        return False
    return stat.S_ISREG(st.st_mode) and os.access(path, os.X_OK)


def search_dirs(*, env: Mapping[str, str], platform: str, home: str) -> list[str]:
    """The folders searched, in order, without repeats."""
    win = platform == "win32"
    raw = env.get("PATH") or env.get("Path") or ""
    from_path = [d for d in raw.split(";" if win else ":") if d]
    extra = [] if win else _EXTRA_POSIX + ([f"{home.rstrip('/')}/{d}" for d in _EXTRA_HOME] if home else [])
    return list(dict.fromkeys(from_path + extra))


def probe_tools(*, env: Mapping[str, str] | None = None, platform: str | None = None, home: str | None = None,
                is_executable: Callable[[str], bool] = _is_executable) -> dict:
    env = os.environ if env is None else env
    platform = sys.platform if platform is None else platform
    home = str(Path.home()) if home is None else home
    win = platform == "win32"
    dirs = search_dirs(env=env, platform=platform, home=home)
    exts = [""] + [e.lower() for e in (env.get("PATHEXT") or ".COM;.EXE;.BAT;.CMD").split(";") if e] if win else [""]

    def join(d: str, b: str) -> str:
        return f"{d.rstrip(chr(92) + '/')}\\{b}" if win else f"{d.rstrip('/')}/{b}"

    def has(b: str) -> bool:
        return any(is_executable(join(d, b + e)) for d in dirs for e in exts)

    tools = {tid: any(has(b) for b in bins if not (win and b == "convert")) for tid, bins in TOOL_BINS}  # Windows' convert.exe is not ImageMagick
    os_id = platform if platform in PACKAGE_MANAGERS else ""
    pm = next((pid for pid, b in PACKAGE_MANAGERS[os_id] if has(b)), "") if os_id else ""
    return {"tools": tools, "platform": {"os": os_id, "pm": pm}}

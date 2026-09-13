"""gzip codec for synced account docs — a port of spaces/public/compress.js.

Large index docs are wrapped { z: <gzip, standard base64> } to dodge the store's 413 ceiling; small docs stay PLAIN so any
reader unwraps transparently. The compressed bytes need not match the browser's, only open there — the tests prove both
directions.
"""

from __future__ import annotations

import gzip
from typing import Any

from . import _js

HAS_GZIP = True
json_bytes = _js.json_bytes


def gzip_b64(obj: Any) -> str:
    data = _js.stringify(None if obj is _js.UNDEFINED else obj).encode("utf-8")
    return _js.btoa(gzip.compress(data, mtime=0))


def gunzip_b64(b64: str) -> Any:
    return _js.parse(gzip.decompress(_js.atob(b64)).decode("utf-8-sig", "replace"))

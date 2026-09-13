"""Bring this computer into a Spaces account by QR, without a secret in the QR — spaces/public/deviceLink.js, plus the
pieces of spaces/public/recovery.js the link needs.

  THIS computer (empty)          draws a QR: an ephemeral P-256 PUBLIC key + a random ref. Nothing secret.
  A signed-in device             scans it, confirms, seals the account to that public key, posts it to the ref.
  THIS computer                  polls the ref and opens it with the private half, which never leaves this process.

The relay in between sees two ECDH public keys and AES-GCM output; it cannot combine them.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from typing import Any

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from . import _js
from ._js import b64u, truthy, unb64u_loose

LINK_PREFIX = "wbzlink1:"
_LINK_INFO = b"witbitz-device-link-v1"
_BACKUP_SALT = b"witbitz-spaces-backup-v1"


@dataclass(frozen=True)
class LinkChallenge:
    ref: str
    pub: str
    text: str
    priv: ec.EllipticCurvePrivateKey = field(repr=False)


def _export_pub(key: ec.EllipticCurvePublicKey) -> str:
    """Compressed point (33 bytes), so the QR stays sparse enough to scan in poor light."""
    return b64u(key.public_bytes(Encoding.X962, PublicFormat.CompressedPoint))


def _import_pub(b64: Any) -> ec.EllipticCurvePublicKey:
    raw = unb64u_loose(b64)
    if len(raw) != 33 or raw[0] not in (2, 3):
        raise ValueError("bad_point")
    try:  # rejects an x that is ≥ p or not on the curve, as the JS decompression does
        return ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), raw)
    except ValueError as e:
        raise ValueError("bad_point") from e


def _shared_key(priv: ec.EllipticCurvePrivateKey, pub: ec.EllipticCurvePublicKey, ref: Any) -> AESGCM:
    """Both sides derive the same AES-GCM key from the shared point, bound to the ref so a blob can't be replayed at another."""
    bits = priv.exchange(ec.ECDH(), pub)
    salt = _js.js_string(ref).encode("utf-8")
    return AESGCM(HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=_LINK_INFO).derive(bits))


def new_link_challenge() -> LinkChallenge:
    """Mint the challenge to draw as a QR. `priv` never leaves this process."""
    priv = ec.generate_private_key(ec.SECP256R1())
    ref = os.urandom(16).hex()
    pub = _export_pub(priv.public_key())
    return LinkChallenge(ref=ref, pub=pub, text=LINK_PREFIX + ref + "." + pub, priv=priv)


def parse_challenge(text: Any) -> dict | None:
    """What a camera saw → {ref, pub}, or None for anything else."""
    s = "" if text is None or text is _js.UNDEFINED else _js.js_string(text)
    if not s.startswith(LINK_PREFIX):
        return None
    pieces = s[len(LINK_PREFIX):].split(".")
    ref = pieces[0]
    pub = pieces[1] if len(pieces) > 1 else ""
    if len(pieces) > 2 or not re.fullmatch(r"[0-9a-f]{32}", ref) or not re.fullmatch(r"[A-Za-z0-9_-]{44}", pub):
        return None
    return {"ref": ref, "pub": pub}


def seal_to_challenge(challenge: dict, payload: Any) -> dict:
    """The GIVING side (a signed-in device): seal a payload to a scanned challenge → what it POSTs to /api/link."""
    theirs = _import_pub(challenge["pub"])
    mine = ec.generate_private_key(ec.SECP256R1())
    key = _shared_key(mine, theirs, challenge["ref"])
    iv = os.urandom(12)
    ct = key.encrypt(iv, _js.stringify(payload).encode("utf-8"), None)
    return {"ref": challenge["ref"], "epk": _export_pub(mine.public_key()), "blob": b64u(iv + ct)}


def open_link_reply(priv: ec.EllipticCurvePrivateKey, reply: dict) -> Any:
    """Open what the ref handed back. Raises on anything that isn't ours and intact."""
    key = _shared_key(priv, _import_pub(reply.get("epk")), reply.get("ref"))
    raw = unb64u_loose(reply.get("blob"))
    pt = key.decrypt(raw[:12], raw[12:], None)
    return _js.parse(pt.decode("utf-8-sig", "replace"))


def _ptr(x: Any) -> dict | None:
    if isinstance(x, dict) and isinstance(x.get("room"), str) and isinstance(x.get("mk"), str) and x["room"] and x["mk"]:
        return {"room": x["room"], "mk": x["mk"]}
    return None


def read_link_payload(p: Any) -> dict | None:
    """What the receiving device applies, or None if there is no usable key in it."""
    if not isinstance(p, dict) or not isinstance(p.get("master"), str) or not p["master"]:
        return None
    a = p.get("anchor")
    anchor = None
    if isinstance(a, dict) and a.get("method") in ("google", "email") and isinstance(a.get("email"), str) and a["email"]:
        token = a.get("token")
        if a["method"] != "email" or (isinstance(token, str) and token):
            anchor = {"method": a["method"], "email": a["email"]}
            if isinstance(token, str) and token:
                anchor["token"] = token
            if truthy(a.get("exp")):
                anchor["exp"] = a["exp"]
    rel = p.get("rel")
    return {
        "master": p["master"],
        "code": p["code"] if isinstance(p.get("code"), str) else "",
        "email": p["email"] if isinstance(p.get("email"), str) else "",
        # Half a release is no release: a token-less rel must not look like one and skip the gated read.
        "rel": {"gid": _js.js_string(rel.get("gid") if truthy(rel.get("gid")) else ""), "token": rel["token"]}
        if isinstance(rel, dict) and isinstance(rel.get("token"), str) and rel["token"] else None,
        "idx": _ptr(p.get("idx")),
        "pipes": _ptr(p.get("pipes")),
        "anchor": anchor,
    }


# ── recovery.js: where the account backup lives and how it opens ─────────────────────────────────────────────────────
def _backup_hkdf(secret: bytes, info: str, n: int) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=n, salt=_BACKUP_SALT, info=info.encode()).derive(secret)


def derive_keys_from_secret(secret: bytes) -> dict:
    """{id (hex storage key), key (AES-GCM), wt (hex write token)} — separate HKDF labels, so the id can't reveal the key."""
    if not secret or len(secret) < 16:
        raise ValueError("bad_secret")
    return {
        "id": _backup_hkdf(secret, "id", 16).hex(),
        "key": AESGCM(_backup_hkdf(secret, "enc", 32)),
        "wt": _backup_hkdf(secret, "bak-write", 32).hex(),
    }


def seal(key: AESGCM, obj: Any) -> str:
    iv = os.urandom(12)
    return b64u(iv + key.encrypt(iv, _js.stringify(obj).encode("utf-8"), None))


def unseal(key: AESGCM, blob: Any) -> Any:
    """base64url(iv‖ciphertext) → object. Raises on a wrong key or any tamper."""
    buf = unb64u_loose(blob)
    return _js.parse(key.decrypt(buf[:12], buf[12:], None).decode("utf-8-sig", "replace"))

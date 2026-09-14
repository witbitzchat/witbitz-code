"""attachments.py — the Python twin of tools/code-attachments.mjs + spaces/public/codeAttachments.js (docs/code-attachments.md).

VECTORS: spaces/test/codeAttachments.vectors.json — generated from the JS module, which is tested against the same file.
"""

from __future__ import annotations

import base64
import json
import os
import time
from pathlib import Path

from witbitz_code.attachments import (
    ATTACHMENT_ROUTE, attachment_note, attachment_rule, format_size, mime_for_file, needs_text_copy, parse_attachment_note,
    prune_attachments, remove_session_attachments, safe_name, serve_attachment, stage_message_body, staged_file_name,
    valid_attachment_ref,
)

REPO = Path(__file__).resolve().parents[3]
V = json.loads((REPO / "spaces" / "test" / "codeAttachments.vectors.json").read_text(encoding="utf-8"))
XLSX = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"


def data_url(mime: str, text: str) -> str:
    return f"data:{mime};base64,{base64.b64encode(text.encode()).decode()}"


def test_the_shared_vectors():
    for n, want in V["safeName"]:
        assert safe_name(n) == want, n
    for h, n, want in V["stagedFileName"]:
        assert staged_file_name(h, n) == want
    for n, want in V["formatSize"]:
        assert format_size(n) == want, n
    assert attachment_note(V["note"]["entries"]) == V["note"]["text"]
    assert parse_attachment_note(V["note"]["text"]) == V["note"]["parsed"]
    for t in V["notNotes"]:
        assert parse_attachment_note(t) is None
    for s, f, want in V["validRef"]:
        assert valid_attachment_ref(s, f) is want, (s, f)
    for mime, n, want in V["needsTextCopy"]:
        assert needs_text_copy(mime, n) is want, n
    for f, want in V["mimeForFile"]:
        assert mime_for_file(f) == want, f
    assert ATTACHMENT_ROUTE == V["route"]


def test_an_excel_file_is_saved_owner_only_and_replaced_by_a_note_without_a_text_copy(tmp_path):
    body = {"model": {"providerID": "trustedrouter"}, "parts": [{"type": "text", "text": "Q3?"}, {"type": "file", "mime": XLSX, "filename": "budget.xlsx", "url": data_url(XLSX, "PK-xlsx")}]}
    out = stage_message_body(body, session_id="ses_a", root=tmp_path)
    assert [p["type"] for p in out["body"]["parts"]] == ["text", "text"] and out["body"]["parts"][1]["synthetic"] is True
    assert out["body"]["model"] == {"providerID": "trustedrouter"} and len(body["parts"]) == 2, "the rest untouched, the input unchanged"
    (e,) = parse_attachment_note(out["body"]["parts"][1]["text"])
    saved = tmp_path / "ses_a" / e["file"]
    assert saved.read_text() == "PK-xlsx" and saved.stat().st_mode & 0o777 == 0o600 and (tmp_path / "ses_a").stat().st_mode & 0o777 == 0o700
    assert "No text copy (this computer's Python connector does not make text copies yet)" in out["body"]["parts"][1]["text"]


def test_an_image_rides_on_and_text_needs_no_copy(tmp_path):
    out = stage_message_body({"parts": [{"type": "file", "mime": "image/png", "filename": "shot.png", "url": data_url("image/png", "PNG")},
                                        {"type": "file", "mime": "text/csv", "filename": "rows.csv", "url": data_url("text/csv", "a,b")}]}, session_id="ses_b", root=tmp_path)
    assert [p["type"] for p in out["body"]["parts"]] == ["file", "text"]
    assert [(n["name"], n["inline"], n["copy"]) for n in parse_attachment_note(out["body"]["parts"][-1]["text"])] == [("shot.png", True, ""), ("rows.csv", False, "")]
    assert stage_message_body({"parts": [{"type": "text", "text": "hi"}]}, session_id="ses_b", root=tmp_path) is None


def test_caps_and_a_bad_session_refuse(tmp_path):
    big = stage_message_body({"parts": [{"type": "file", "mime": XLSX, "filename": "huge.xlsx", "url": data_url(XLSX, "x" * 2000)}]}, session_id="ses_d", root=tmp_path, max_file_bytes=1000)
    assert big["error"]["status"] == 413 and "huge.xlsx is over" in big["error"]["message"]
    stage_message_body({"parts": [{"type": "file", "mime": "text/plain", "filename": "a.txt", "url": data_url("text/plain", "y" * 900)}]}, session_id="ses_e", root=tmp_path, max_session_bytes=1500)
    over = stage_message_body({"parts": [{"type": "file", "mime": "text/plain", "filename": "b.txt", "url": data_url("text/plain", "z" * 900)}]}, session_id="ses_e", root=tmp_path, max_session_bytes=1500)
    assert over["error"]["status"] == 413 and "this session's attachments" in over["error"]["message"]
    assert stage_message_body({"parts": [{"type": "file", "mime": "text/plain", "filename": "c.txt", "url": data_url("text/plain", "q")}]}, session_id="../evil", root=tmp_path)["error"]["status"] == 400


def test_serve_back_by_name_only_from_its_folder(tmp_path):
    out = stage_message_body({"parts": [{"type": "file", "mime": "application/pdf", "filename": "scan.pdf", "url": data_url("application/pdf", "%PDF-serve")}]}, session_id="ses_f", root=tmp_path)
    (e,) = parse_attachment_note(out["body"]["parts"][0]["text"])
    st, b = serve_attachment(root=tmp_path, session="ses_f", file=e["file"])
    got = json.loads(b)
    assert st == 200 and (got["name"], got["mime"], got["size"]) == ("scan.pdf", "application/pdf", 10) and base64.b64decode(got["b64"]) == b"%PDF-serve"
    assert serve_attachment(root=tmp_path, session="ses_f", file="../../etc/passwd")[0] == 400
    assert serve_attachment(root=tmp_path, session="ses_f", file="00000000-nothing.pdf")[0] == 404
    assert serve_attachment(root=tmp_path, session="ses_f", file=e["file"], max_bytes=4)[0] == 413


def test_delete_with_the_session_and_prune_after_30_days(tmp_path):
    for s in ("ses_old", "ses_new", "ses_gone"):
        (tmp_path / s).mkdir()
        (tmp_path / s / "00000000-a.txt").write_text("a")
    remove_session_attachments(tmp_path, "ses_gone")
    remove_session_attachments(tmp_path, "../ses_new")
    old = time.time() - 31 * 86400
    os.utime(tmp_path / "ses_old", (old, old))
    assert prune_attachments(tmp_path, days=30) == 1
    assert sorted(n for n in os.listdir(tmp_path) if n.startswith("ses_")) == ["ses_new"]
    assert prune_attachments(tmp_path / "missing") == 0


def test_the_permission_rule():
    assert attachment_rule(Path("/home/u/.witbitz/code/attachments"), "ses_a") == {"permission": "external_directory", "pattern": "/home/u/.witbitz/code/attachments/ses_a/*", "action": "allow"}


# ── the security review's findings (2026-09-13) ─────────────────────────────────────────────────────────────────────
def test_review_nothing_is_written_or_served_through_a_link(tmp_path):
    root = tmp_path / "att"
    root.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "00000000-secret.txt").write_text("NOT-YOURS")
    (root / "ses_link").symlink_to(outside)
    assert stage_message_body({"parts": [{"type": "file", "mime": "text/plain", "filename": "a.txt", "url": data_url("text/plain", "x")}]}, session_id="ses_link", root=root)["error"]["status"] == 400
    assert sorted(os.listdir(outside)) == ["00000000-secret.txt"], "nothing landed outside"
    assert serve_attachment(root=root, session="ses_link", file="00000000-secret.txt")[0] == 400, "a linked session folder"
    (root / "ses_real").mkdir()
    (root / "ses_real" / "11111111-secret.txt").symlink_to(outside / "00000000-secret.txt")
    assert serve_attachment(root=root, session="ses_real", file="11111111-secret.txt")[0] == 400, "a linked file"


def test_review_a_different_file_under_a_saved_name_is_refused_and_the_folder_has_a_cap(tmp_path):
    first = stage_message_body({"parts": [{"type": "file", "mime": "text/plain", "filename": "a.txt", "url": data_url("text/plain", "one")}]}, session_id="ses_x", root=tmp_path)
    (e,) = parse_attachment_note(first["body"]["parts"][0]["text"])
    (tmp_path / "ses_x" / e["file"]).write_text("swapped")
    assert stage_message_body({"parts": [{"type": "file", "mime": "text/plain", "filename": "a.txt", "url": data_url("text/plain", "one")}]}, session_id="ses_x", root=tmp_path)["error"]["status"] == 409
    (tmp_path / "ses_big").mkdir()
    (tmp_path / "ses_big" / "00000000-b.bin").write_text("z" * 1500)
    full = stage_message_body({"parts": [{"type": "file", "mime": "text/plain", "filename": "c.txt", "url": data_url("text/plain", "y" * 600)}]}, session_id="ses_y", root=tmp_path, max_root_bytes=2000)
    assert full["error"]["status"] == 413 and "on this computer are over" in full["error"]["message"]

"""Data preservation at streaming, file-publication, and source-copy boundaries."""
import hashlib
import json
from pathlib import Path

import pytest

from l_app.logs import LogLineBuffer
from l_app import paths, workflows


def test_utf8_and_lines_survive_every_process_chunk_boundary():
    text = "EUNORA: 도착지=여서동원앙\r\nCALLMANER: 다음 콜\n마지막 줄"
    data = text.encode("utf-8")
    expected = ["EUNORA: 도착지=여서동원앙", "CALLMANER: 다음 콜", "마지막 줄"]
    for split in range(len(data) + 1):
        buffer = LogLineBuffer()
        actual = buffer.feed(data[:split]) + buffer.feed(data[split:], final=True)
        assert actual == expected
        assert buffer.feed(b"", final=True) == []


def test_one_byte_stream_does_not_emit_incomplete_line():
    buffer = LogLineBuffer()
    data = "한글 로그\n".encode()
    output = []
    for value in data[:-1]:
        output += buffer.feed(bytes([value]))
    assert output == []
    assert buffer.feed(data[-1:]) == ["한글 로그"]


def test_atomic_write_failure_preserves_original_and_removes_temp(tmp_path, monkeypatch):
    target = tmp_path / "hooks.json"
    target.write_text("original")
    def denied(*args):
        raise PermissionError("simulated replace failure")
    monkeypatch.setattr(paths.os, "replace", denied)
    with pytest.raises(PermissionError):
        paths.atomic_write_text(target, "new")
    assert target.read_text() == "original"
    assert list(tmp_path.iterdir()) == [target]


def test_session_names_support_network_serial_and_preserve_same_second(tmp_path):
    first = paths.session_path(tmp_path, "20261117_010000", "logi2", "192.0.2.1:5555")
    first.write_text("first capture")
    second = paths.session_path(tmp_path, "20261117_010000", "logi2", "192.0.2.1:5555")
    assert first != second
    assert ":" not in first.name
    assert second.name.endswith("_01.json")
    assert first.read_text() == "first capture"


def _source(tmp_path, name="ModuleMain.kt"):
    path = tmp_path / name
    path.write_bytes(b'val target = "old.Class"\r\n// old.Class remains a comment\r\n')
    return path


def _digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_source_copy_preserves_original_and_crlf(tmp_path, monkeypatch):
    monkeypatch.setenv("L_APP_DATA_DIR", str(tmp_path))
    source = _source(tmp_path)
    original = source.read_bytes()
    result = workflows.create_source_copy(source, [("old.Class", "new.Class")], _digest(source), None, None)
    assert source.read_bytes() == original
    assert result["path"].read_bytes() == b'val target = "new.Class"\r\n// old.Class remains a comment\r\n'


def test_source_changed_after_analysis_never_creates_copy(tmp_path, monkeypatch):
    monkeypatch.setenv("L_APP_DATA_DIR", str(tmp_path))
    source = _source(tmp_path)
    digest = _digest(source)
    source.write_text("changed by user")
    with pytest.raises(RuntimeError, match="원본 코드가 바뀌"):
        workflows.create_source_copy(source, [("old.Class", "new.Class")], digest, None, None)
    assert source.read_text() == "changed by user"
    assert not (tmp_path / "ModuleMain_patched.kt").exists()


def test_apk_changed_after_analysis_never_creates_copy(tmp_path, monkeypatch):
    monkeypatch.setenv("L_APP_DATA_DIR", str(tmp_path))
    source = _source(tmp_path)
    apk = tmp_path / "base.apk"
    apk.write_bytes(b"old")
    digest = _digest(apk)
    apk.write_bytes(b"new")
    with pytest.raises(RuntimeError, match="APK가 바뀌"):
        workflows.create_source_copy(source, [("old.Class", "new.Class")], _digest(source), apk, digest)
    assert not (tmp_path / "ModuleMain_patched.kt").exists()


def test_selecting_existing_copy_as_source_does_not_overwrite_it(tmp_path, monkeypatch):
    monkeypatch.setenv("L_APP_DATA_DIR", str(tmp_path))
    source = _source(tmp_path, "ModuleMain_patched.kt")
    original = source.read_bytes()
    result = workflows.create_source_copy(source, [("old.Class", "new.Class")], _digest(source), None, None)
    assert result["path"] == tmp_path / "ModuleMain_patched_copy.kt"
    assert source.read_bytes() == original


def test_hook_map_keeps_ambiguous_candidates_and_refuses_generation(tmp_path, monkeypatch):
    monkeypatch.setenv("L_APP_DATA_DIR", str(tmp_path))
    source = _source(tmp_path)
    apk = tmp_path / "base.apk"
    apk.write_bytes(b"static fixture")
    monkeypatch.setattr(workflows, "apk_has_symbols", lambda path, symbols: {s: False for s in symbols})
    spec = {"sites": [{"id": "example", "symbols": ["old.Class"]}]}
    result = workflows.build_hook_map("logi2", spec, source, apk, tmp_path, "class=new.One class=new.Two")
    assert set(result["pending"]) == {("old.Class", "new.One"), ("old.Class", "new.Two")}
    with pytest.raises(ValueError):
        workflows.create_source_copy(source, result["pending"], result["source_digest"], apk, result["apk_digest"])
    assert not (tmp_path / "ModuleMain_patched.kt").exists()

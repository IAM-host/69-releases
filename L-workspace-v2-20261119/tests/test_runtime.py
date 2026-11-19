"""Preserve captured data and cancellation at active runtime boundaries."""

import threading

import pytest

from l_app import paths, workflows
from l_app.logs import LogLineBuffer
from l_app.processes import CancelledError, bind_cancel_event


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


def test_file_digest_uses_original_bytes_without_modifying_source(tmp_path):
    source = tmp_path / "한글 프로젝트.kt"
    source.write_bytes(b"abc")
    assert workflows.file_digest(source) == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    assert source.read_bytes() == b"abc"


def test_file_digest_honors_background_cancellation(tmp_path):
    source = tmp_path / "base.apk"
    source.write_bytes(b"evidence to keep")
    cancelled = threading.Event()
    cancelled.set()
    with bind_cancel_event(cancelled), pytest.raises(CancelledError):
        workflows.file_digest(source)
    assert source.read_bytes() == b"evidence to keep"

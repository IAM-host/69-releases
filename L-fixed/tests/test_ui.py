"""Offscreen Qt integration checks; no phone, ADB, or external analysis tools."""
from __future__ import annotations

from collections import Counter
import json
import os
from pathlib import Path
import sys
import threading
import time

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtCore import QThread, QTimer
from PySide6.QtTest import QTest
from PySide6.QtWidgets import QApplication, QPushButton, QWidget

from l_app import ui
from l_app.processes import run_process


UI_BASELINE = Path(__file__).parent / "fixtures" / "ui-baseline.json"


def spin_until(predicate, timeout=4):
    deadline = time.monotonic() + timeout
    while not predicate():
        QApplication.processEvents()
        if time.monotonic() >= deadline:
            raise AssertionError("Qt condition did not complete before its deadline")
        QTest.qWait(5)
    QApplication.processEvents()


@pytest.fixture(scope="module")
def app():
    instance = QApplication.instance() or QApplication([])
    instance.setStyle("Fusion")
    instance.setQuitOnLastWindowClosed(False)
    return instance


@pytest.fixture
def window(app, monkeypatch, tmp_path):
    monkeypatch.setenv("L_APP_DATA_DIR", str(tmp_path))
    monkeypatch.setattr(ui, "find_adb", lambda: None)
    monkeypatch.setattr(ui, "find_modulemain", lambda: None)
    dialogs = []
    for name in ("critical", "warning", "information"):
        monkeypatch.setattr(
            ui.QMessageBox, name,
            lambda *args, _name=name, **kwargs: dialogs.append((_name, args)),
        )
    view = ui.MainWindow()
    view._test_dialogs = dialogs
    yield view
    if view._job is not None:
        view._job.cancel()
        spin_until(lambda: view._job is None)
    view.close()
    QApplication.processEvents()


def long_buttons(view):
    return [b for b in view.findChildren(QPushButton) if b.property("long_job")]


def test_existing_visual_layout_and_styles_are_preserved(window):
    """Compare against the original widget-tree snapshot, portable across checkouts."""
    baseline = json.loads(UI_BASELINE.read_text(encoding="utf-8"))
    assert window.windowTitle() == baseline["title"] == "L"
    assert [window.width(), window.height()] == baseline["size"]
    assert [window.tabs.tabText(i) for i in range(window.tabs.count())] == baseline["tabs"]
    extensions = [b for b in window.findChildren(QPushButton) if b.property("feature_extension")]
    assert Counter((b.property("feature_extension"), b.text(), b.styleSheet()) for b in extensions) == Counter({
        ("rea", "REA 분석", ""): 1,
        ("rea", "REA 설정", ""): 1,
        ("generator", "훅 코드 생성", ""): 1,
        ("build_validation", "생성본 빌드 검사", ""): 1,
    })
    buttons = Counter((b.text(), b.styleSheet()) for b in window.findChildren(QPushButton) if b not in extensions)
    assert buttons == Counter({(text, style): count for text, style, count in baseline["buttons"]})
    widget_counts = Counter(type(w).__name__ for w in window.findChildren(QWidget))
    widget_counts["QPushButton"] -= len(extensions)
    assert widget_counts == baseline["widget_counts"]
    assert window.cmb_pull_app.itemText(0) == "7개 전부"
    keys = {window.cmb_pull_app.itemData(i) for i in range(1, window.cmb_pull_app.count())}
    assert keys == {"kakao", "callmaner", "callmaner2", "tmap", "logi", "logi2", "idrive"}


def test_analysis_keeps_event_loop_alive_and_result_on_gui_thread(window, monkeypatch, tmp_path, app):
    source = tmp_path / "input.apk"
    source.write_bytes(b"fixture")
    window.ed_analyze_apk.setText(str(source))
    entered, release = threading.Event(), threading.Event()
    compute_threads = []
    # textChanged independently verifies that rendering occurs on the GUI thread.
    render_threads = []
    window.txt_analyze.textChanged.connect(lambda: render_threads.append(QThread.currentThread()))

    def slow_analysis(path, package_filter=""):
        compute_threads.append(QThread.currentThread())
        entered.set()
        assert release.wait(3)
        return {"flags": [], "string_count": 12}

    monkeypatch.setattr(ui, "analyze_apk_structure", slow_analysis)
    monkeypatch.setattr(ui, "format_analysis_report", lambda result: "fixture report")
    ticks = []
    timer = QTimer(window)
    timer.setInterval(5)
    timer.timeout.connect(lambda: ticks.append(1))
    timer.start()
    try:
        window.run_structure_analysis()
        spin_until(entered.is_set)
        assert long_buttons(window) and all(not b.isEnabled() for b in long_buttons(window))
        QTest.qWait(75)
        assert len(ticks) >= 3
        assert window._job is not None
        assert compute_threads[0] != app.thread()
        release.set()
        spin_until(lambda: window._job is None)
        assert window.txt_analyze.toPlainText() == "fixture report"
        assert render_threads and all(t == app.thread() for t in render_threads)
        assert all(b.isEnabled() for b in long_buttons(window))
    finally:
        release.set()
        timer.stop()


def test_analysis_inputs_are_snapshotted_before_worker_runs(window, monkeypatch, tmp_path):
    original, changed = tmp_path / "old.apk", tmp_path / "new.apk"
    original.write_bytes(b"old")
    changed.write_bytes(b"new")
    window.ed_analyze_apk.setText(str(original))
    window.ed_pkg_filter.setText("old.package")
    entered, release = threading.Event(), threading.Event()
    captured = []

    def analysis(path, package_filter=""):
        entered.set()
        assert release.wait(3)
        captured.append((path, package_filter))
        return {"flags": [], "string_count": 1}

    monkeypatch.setattr(ui, "analyze_apk_structure", analysis)
    monkeypatch.setattr(ui, "format_analysis_report", lambda result: "original snapshot")
    try:
        window.run_structure_analysis()
        spin_until(entered.is_set)
        window.ed_analyze_apk.setText(str(changed))
        window.ed_pkg_filter.setText("changed.package")
        release.set()
        spin_until(lambda: window._job is None)
        assert captured == [(original, "old.package")]
    finally:
        release.set()


def test_worker_error_is_reported_and_actions_are_reenabled(window, monkeypatch, tmp_path):
    source = tmp_path / "broken.apk"
    source.write_bytes(b"broken")
    window.ed_analyze_apk.setText(str(source))

    def broken_analysis(*args, **kwargs):
        raise ValueError("synthetic inspection failure")

    monkeypatch.setattr(ui, "analyze_apk_structure", broken_analysis)
    window.run_structure_analysis()
    spin_until(lambda: window._job is None)
    assert window.lbl_status.text() == "작업 실패"
    assert all(b.isEnabled() for b in long_buttons(window))
    assert any(kind == "critical" and "synthetic inspection failure" in str(args) for kind, args in window._test_dialogs)


def test_second_job_cannot_replace_running_job_callbacks(window):
    entered, release = threading.Event(), threading.Event()
    completed = []

    def first(progress):
        entered.set()
        assert release.wait(3)
        return "first"

    try:
        assert window._start_job("first", first, completed.append)
        spin_until(entered.is_set)
        assert not window._start_job("second", lambda progress: "second", completed.append)
        release.set()
        spin_until(lambda: window._job is None)
        assert completed == ["first"]
    finally:
        release.set()


def test_close_cancels_owned_child_process_without_late_result(window, tmp_path):
    marker = tmp_path / "child.pid"
    callbacks = []
    script = (
        "import os,time; from pathlib import Path; "
        f"Path({str(marker)!r}).write_text(str(os.getpid())); time.sleep(60)"
    )

    def work(progress):
        return run_process([sys.executable, "-c", script], timeout=60)

    window.show()
    assert window._start_job("child process", work, callbacks.append)
    spin_until(marker.is_file)
    pid = int(marker.read_text())
    start = time.monotonic()
    window.close()
    spin_until(lambda: window._job is None and not window.isVisible(), timeout=5)
    QTest.qWait(30)
    assert time.monotonic() - start < 5
    assert callbacks == []
    assert window._test_dialogs == []
    if os.name == "posix":
        with pytest.raises(ProcessLookupError):
            os.kill(pid, 0)


def test_previous_snapshot_comparison_runs_once_off_gui_thread(window, monkeypatch, tmp_path, app):
    previous = tmp_path / "20260101" / "base.apk"
    current = tmp_path / "20260102" / "base.apk"
    previous.parent.mkdir()
    current.parent.mkdir()
    previous.write_bytes(b"previous")
    current.write_bytes(b"current")
    window.last_pull = {"logi2": current}
    entered, release = threading.Event(), threading.Event()
    lookup_calls, comparisons, render_threads = [], [], []

    def lookup(key, stamp):
        lookup_calls.append((key, stamp, QThread.currentThread()))
        return previous

    def compare(old_path, new_path):
        comparisons.append((old_path, new_path, QThread.currentThread()))
        entered.set()
        assert release.wait(3)
        return {"old_count": 1, "new_count": 2, "added": ["new.Symbol"], "removed": []}

    monkeypatch.setattr(ui, "previous_snapshot", lookup)
    monkeypatch.setattr(ui, "diff_apk", compare)
    window.list_apk_added.model().rowsInserted.connect(
        lambda *args: render_threads.append(QThread.currentThread())
    )
    ticks = []
    timer = QTimer(window)
    timer.setInterval(5)
    timer.timeout.connect(lambda: ticks.append(1))
    timer.start()
    try:
        window.diff_last_pull_against_previous()
        spin_until(entered.is_set)
        # A later UI selection/state update must not change the running comparison.
        window.last_pull = {}
        QTest.qWait(70)
        assert len(ticks) >= 3
        assert window._job is not None
        release.set()
        spin_until(lambda: window._job is None)
        assert [(k, s) for k, s, _ in lookup_calls] == [("logi2", "20260102")]
        assert all(thread != app.thread() for _, _, thread in lookup_calls)
        assert [(a, b) for a, b, _ in comparisons] == [(previous, current)]
        assert all(thread != app.thread() for _, _, thread in comparisons)
        assert window.ed_apk_old.text() == str(previous)
        assert window.ed_apk_new.text() == str(current)
        assert window.cmb_apk_app.currentData() == "logi2"
        assert window.list_apk_added.item(0).text() == "new.Symbol"
        assert render_threads and all(thread == app.thread() for thread in render_threads)
    finally:
        release.set()
        timer.stop()


@pytest.mark.parametrize("invalid", [
    b'{"kakao": [',
    b'{"kakao": "not a row list"}',
    b'{"kakao": [{"keywords": 42}]}',
])
def test_invalid_hooks_stays_untouched_until_explicit_save_and_is_backed_up(
    window, monkeypatch, tmp_path, invalid,
):
    hooks_path = tmp_path / "hooks.json"
    hooks_path.write_bytes(invalid)
    view = ui.MainWindow()
    try:
        assert hooks_path.read_bytes() == invalid
        assert view._hooks_load_error
        assert "설정 파일 확인 필요" in view.lbl_status.text()
        assert not list(tmp_path.glob("hooks.invalid-*.json"))
        real_write = ui.atomic_write_text
        backups_seen_before_replacement = []

        def verify_backup_then_write(path, contents):
            backups = list(tmp_path.glob("hooks.invalid-*.json"))
            assert len(backups) == 1
            assert backups[0].read_bytes() == invalid
            assert hooks_path.read_bytes() == invalid
            backups_seen_before_replacement.append(backups[0])
            real_write(path, contents)

        monkeypatch.setattr(ui, "atomic_write_text", verify_backup_then_write)
        view.save_hooks()
        assert len(backups_seen_before_replacement) == 1
        assert backups_seen_before_replacement[0].read_bytes() == invalid
        assert isinstance(json.loads(hooks_path.read_text(encoding="utf-8")), dict)
        assert view._hooks_load_error is None
    finally:
        view.close()


def test_invalid_readonly_knowledge_is_visible_and_never_overwritten(window, tmp_path):
    path = tmp_path / "eunora_hooks.json"
    invalid = b'{"apps": '
    path.write_bytes(invalid)
    window.reload_hook_knowledge()
    assert window.hook_knowledge.get("_load_error")
    assert window.lbl_status.text() == "지식 파일 읽기 실패"
    assert path.read_bytes() == invalid
    window.run_hook_map()
    assert window._job is None
    assert path.read_bytes() == invalid


def test_report_save_failure_is_visible_and_keeps_report(window, monkeypatch, tmp_path):
    window._last_analysis_text = "keep this report"
    monkeypatch.setattr(ui.QFileDialog, "getSaveFileName", lambda *args: (str(tmp_path / "report.txt"), ""))
    def denied(*args):
        raise PermissionError("disk unavailable")
    monkeypatch.setattr(ui, "atomic_write_text", denied)
    window.save_analysis_report()
    assert window._last_analysis_text == "keep this report"
    assert window.lbl_status.text() == "보고서 저장 실패"
    assert any(kind == "critical" and "disk unavailable" in str(args) for kind, args in window._test_dialogs)


def test_capture_save_failure_retains_buffer_and_capture_state(window, monkeypatch):
    window.cmb_session_app.setCurrentIndex(window.cmb_session_app.findData("logi2"))
    window.start_capture()
    window.session_lines = ["EUNORA: original log"]
    def denied(*args):
        raise PermissionError("disk unavailable")
    monkeypatch.setattr(ui, "atomic_write_text", denied)
    window.stop_capture()
    assert window.capturing
    assert window.session_lines == ["EUNORA: original log"]
    assert window.btn_cap_stop.isEnabled()
    assert not window.btn_cap_start.isEnabled()
    assert window.lbl_status.text() == "세션 저장 실패 — 캡처 유지"


def test_network_device_serial_is_preserved_in_metadata_not_filename(window, tmp_path):
    window.cmb_device.clear()
    window.cmb_device.addItem("192.0.2.1:5555")
    window.cmb_session_app.setCurrentIndex(window.cmb_session_app.findData("logi2"))
    window.start_capture()
    window.session_lines = ["EUNORA: full log"]
    window.stop_capture()
    files = list((tmp_path / "sessions").glob("session_*.json"))
    assert len(files) == 1
    assert ":" not in files[0].name
    payload = json.loads(files[0].read_text(encoding="utf-8"))
    assert payload["device"] == "192.0.2.1:5555"
    assert payload["app"] == "logi2"
    assert payload["lines"] == ["EUNORA: full log"]

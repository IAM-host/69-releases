"""REA controls use the real Qt event loop with local, deterministic service doubles."""
from __future__ import annotations

import json
import os
from pathlib import Path
import threading
import time

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtCore import QThread, QTimer
from PySide6.QtTest import QTest
from PySide6.QtWidgets import QApplication, QDialog, QDialogButtonBox

from l_app import ui
from l_app.processes import check_cancelled
from l_app.rea_dialogs import ObserverGenerationDialog, REAAnalysisDialog, REASettingsDialog


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


def accepted_analysis(monkeypatch, request=None):
    value = request or {"operation": "package", "query": "", "class_name": "", "method_name": "", "overload_index": None}
    captured = []

    class Dialog:
        def __init__(self, path, previous, parent):
            captured.append((path, dict(previous)))

        def exec(self):
            return QDialog.DialogCode.Accepted

        def request(self):
            return dict(value)

    monkeypatch.setattr(ui, "REAAnalysisDialog", Dialog)
    return captured


def test_operation_fields_require_exact_target_and_preserve_explicit_zero(app, monkeypatch, tmp_path):
    warnings = []
    monkeypatch.setattr(ui.QMessageBox, "warning", lambda *args: warnings.append(args))
    dialog = REAAnalysisDialog(tmp_path / "input.apk")
    dialog.ed_query.setText("OldQuery")
    dialog.ed_class.setText("com.example.Exact")
    dialog.ed_method.setText("target")
    assert dialog.request() == {"operation": "package", "query": "", "class_name": "", "method_name": "", "overload_index": None}
    dialog.cmb_operation.setCurrentIndex(dialog.cmb_operation.findData("class_search"))
    assert dialog.request()["query"] == "OldQuery"
    assert dialog.request()["class_name"] == ""
    dialog.cmb_operation.setCurrentIndex(dialog.cmb_operation.findData("method"))
    assert dialog.request()["overload_index"] is None
    dialog.spn_overload.setValue(0)
    assert dialog.request()["overload_index"] == 0
    dialog.ed_method.clear()
    dialog._accept_request()
    assert warnings and dialog.result() != QDialog.DialogCode.Accepted
    dialog.ed_method.setText("target")
    dialog._accept_request()
    assert dialog.result() == QDialog.DialogCode.Accepted
    assert dialog.request()["class_name"] == "com.example.Exact"
    dialog.deleteLater()


def test_reference_request_without_method_does_not_invent_an_overload(app, tmp_path):
    dialog = REAAnalysisDialog(tmp_path / "input.apk", {
        "operation": "references", "class_name": "com.example.Target", "overload_index": 3,
    })
    assert dialog.ed_method.isEnabled()
    assert not dialog.spn_overload.isEnabled()
    assert dialog.request()["method_name"] == ""
    assert dialog.request()["overload_index"] is None
    dialog.deleteLater()


def test_settings_check_snapshots_paths_and_blocks_save_until_finished(app):
    dialog = REASettingsDialog({"node_path": "old/node", "timeout_seconds": 123, "_load_error": "old invalid JSON"})
    snapshots = []
    dialog.checkRequested.connect(snapshots.append)
    dialog._fields["node_path"].setText("new/node")
    dialog.btn_check.click()
    assert snapshots[0]["node_path"] == "new/node"
    assert snapshots[0]["timeout_seconds"] == 123
    assert "_load_error" not in snapshots[0]
    assert not dialog.btn_check.isEnabled()
    assert not dialog.buttons.button(QDialogButtonBox.StandardButton.Save).isEnabled()
    assert not dialog._fields["node_path"].isEnabled()
    dialog.set_preflight_result({"ready": False, "errors": ["setup_rea.bat를 실행하세요"]})
    assert dialog.btn_check.isEnabled()
    assert dialog.buttons.button(QDialogButtonBox.StandardButton.Save).isEnabled()
    assert "setup_rea.bat" in dialog.txt_status.toPlainText()
    dialog.deleteLater()


def test_missing_apk_prevents_dialog_and_engine_execution(window, monkeypatch):
    calls = []
    monkeypatch.setattr(ui, "REAAnalysisDialog", lambda *args: calls.append("dialog"))
    monkeypatch.setattr(ui, "run_rea_analysis", lambda *args, **kwargs: calls.append("engine"))
    window.run_rea()
    assert calls == []
    assert window._job is None
    assert window._test_dialogs[0][0] == "warning"


def test_analysis_runs_in_background_with_captured_inputs_and_evidence(window, monkeypatch, tmp_path, app):
    original, changed = tmp_path / "original.apk", tmp_path / "changed.apk"
    original.write_bytes(b"original")
    changed.write_bytes(b"changed")
    window.ed_analyze_apk.setText(str(original))
    request = {"operation": "method", "query": "", "class_name": "a.b.C", "method_name": "method", "overload_index": 0}
    dialog_calls = accepted_analysis(monkeypatch, request)
    settings = {"node_path": "chosen/node", "jar_path": "chosen/mcp.jar"}
    monkeypatch.setattr(ui, "load_rea_settings", lambda: settings)
    entered, release = threading.Event(), threading.Event()
    captured, compute_threads, render_threads = [], [], []
    evidence = {"apk_sha256": "fixture-hash", "resolved_method": {"name": "method", "overload_index": 0}}

    def engine(path, **kwargs):
        compute_threads.append(QThread.currentThread())
        entered.set()
        assert release.wait(3)
        kwargs.pop("progress")("실제 정적 분석 결과 수집 중")
        captured.append((path, kwargs))
        return {"status": "complete", "report": "REA fixture report", "evidence": evidence, "raw_path": "raw.json"}

    monkeypatch.setattr(ui, "run_rea_analysis", engine)
    window.txt_analyze.textChanged.connect(lambda: render_threads.append(QThread.currentThread()))
    ticks = []
    timer = QTimer(window)
    timer.setInterval(5)
    timer.timeout.connect(lambda: ticks.append(1))
    timer.start()
    try:
        window.run_rea()
        spin_until(entered.is_set)
        window.ed_analyze_apk.setText(str(changed))
        settings["node_path"] = "changed/node"
        request["method_name"] = "different"
        QTest.qWait(65)
        assert len(ticks) >= 3
        assert not window.btn_rea_analysis.isEnabled()
        assert not window.btn_rea_settings.isEnabled()
        release.set()
        spin_until(lambda: window._job is None)
        assert captured[0][0] == original.resolve()
        assert captured[0][1]["settings"]["node_path"] == "chosen/node"
        assert captured[0][1]["method_name"] == "method"
        assert captured[0][1]["overload_index"] == 0
        assert compute_threads[0] != app.thread()
        assert render_threads and all(thread == app.thread() for thread in render_threads)
        assert dialog_calls == [(original.resolve(), {})]
        assert window.txt_analyze.toPlainText() == "REA fixture report"
        assert window._last_analysis_text == "REA fixture report"
        assert window._last_analysis_result is None
        assert window._last_rea_evidence == evidence
        assert window._last_rea_result["raw_path"] == "raw.json"
        assert window._last_rea_result["apk_path"] == str(original.resolve())
        assert window._last_rea_result["request"]["method_name"] == "method"
        assert window.btn_rea_analysis.isEnabled()
        assert "완료" in window.lbl_status.text()
    finally:
        release.set()
        timer.stop()


@pytest.mark.parametrize("mode", ["exception", "invalid-result"])
def test_engine_failure_preserves_previous_result_and_never_claims_success(window, monkeypatch, tmp_path, mode):
    path = tmp_path / "input.apk"
    path.write_bytes(b"fixture")
    window.ed_analyze_apk.setText(str(path))
    accepted_analysis(monkeypatch)
    monkeypatch.setattr(ui, "load_rea_settings", lambda: {})
    window._last_analysis_text = "previous report"
    window.txt_analyze.setPlainText("previous report")
    window._last_rea_evidence = {"previous": True}

    def engine(*args, **kwargs):
        if mode == "exception":
            raise RuntimeError("REA 도구 누락: setup_rea.bat를 실행하세요")
        return {"status": "error", "report": "an error is not an analysis", "evidence": {}}

    monkeypatch.setattr(ui, "run_rea_analysis", engine)
    window.run_rea()
    spin_until(lambda: window._job is None)
    assert window.txt_analyze.toPlainText() == "previous report"
    assert window._last_analysis_text == "previous report"
    assert window._last_rea_evidence == {"previous": True}
    assert window.lbl_status.text() in {"작업 실패", "결과 표시 실패"}
    assert any(kind == "critical" for kind, _ in window._test_dialogs)
    assert window.btn_rea_analysis.isEnabled()


def test_partial_result_is_clearly_reported(window, monkeypatch, tmp_path):
    path = tmp_path / "input.apk"
    path.write_bytes(b"fixture")
    window.ed_analyze_apk.setText(str(path))
    accepted_analysis(monkeypatch)
    monkeypatch.setattr(ui, "load_rea_settings", lambda: {})
    monkeypatch.setattr(ui, "run_rea_analysis", lambda *args, **kwargs: {
        "status": "partial", "report": "partial report", "evidence": {"truncated": True}, "raw_path": "partial.json",
    })
    window.run_rea()
    spin_until(lambda: window._job is None)
    assert window.txt_analyze.toPlainText() == "partial report"
    assert "부분 결과" in window.lbl_status.text()
    assert window._last_rea_result["status"] == "partial"


def test_preflight_runs_in_owned_background_job_and_renders_on_gui(window, monkeypatch, app):
    dialog = REASettingsDialog({"node_path": "old/node"}, window)
    dialog.show()
    entered, release = threading.Event(), threading.Event()
    settings = {"node_path": "old/node"}
    captured, threads, render_threads = [], [], []

    def preflight(value):
        threads.append(QThread.currentThread())
        entered.set()
        assert release.wait(3)
        captured.append(value)
        return {"ready": True, "versions": {"node": "v22.0.0"}}

    monkeypatch.setattr(ui, "rea_preflight", preflight)
    dialog.txt_status.textChanged.connect(lambda: render_threads.append(QThread.currentThread()))
    try:
        window._check_rea_settings(dialog, settings)
        spin_until(entered.is_set)
        settings["node_path"] = "changed/node"
        release.set()
        spin_until(lambda: window._job is None)
        assert threads[0] != app.thread()
        assert captured == [{"node_path": "old/node"}]
        assert "v22.0.0" in dialog.txt_status.toPlainText()
        assert render_threads and all(thread == app.thread() for thread in render_threads)
        assert "준비됨" in window.lbl_status.text()
    finally:
        release.set()
        dialog.close()


def test_closing_settings_cancels_its_probe_without_late_render(window, monkeypatch):
    dialog = REASettingsDialog({}, window)
    dialog.show()
    entered = threading.Event()
    renders = []
    monkeypatch.setattr(dialog, "set_preflight_result", renders.append)

    def preflight(settings):
        entered.set()
        while True:
            check_cancelled()
            time.sleep(0.005)

    monkeypatch.setattr(ui, "rea_preflight", preflight)
    window._check_rea_settings(dialog, {})
    spin_until(entered.is_set)
    dialog.reject()
    spin_until(lambda: window._job is None)
    assert renders == []
    assert window.lbl_status.text() == "작업 취소"
    assert window._test_dialogs == []


def test_configure_saves_paths_only_when_dialog_is_accepted(window, monkeypatch):
    settings = {"node_path": "node", "rea_entry": "rea.mjs", "jar_path": "mcp.jar", "java_home": "jdk", "timeout_seconds": 300}
    monkeypatch.setattr(ui, "load_rea_settings", lambda: settings)
    saved = []
    monkeypatch.setattr(ui, "save_rea_settings", saved.append)
    monkeypatch.setattr(REASettingsDialog, "exec", lambda self: QDialog.DialogCode.Accepted)
    monkeypatch.setattr(ui, "rea_preflight", lambda *args: pytest.fail("saving must not run a process on the GUI thread"))
    window.configure_rea()
    assert saved == [settings]
    assert "설정 저장" in window.lbl_status.text()


def test_generation_requires_class_evidence_before_requesting_a_method(window, monkeypatch):
    monkeypatch.setattr(ui, "list_observer_methods", lambda value: pytest.fail("class evidence must exist first"))
    window.run_observer_generation()
    assert window._job is None
    assert "클래스 정보" in str(window._test_dialogs[0])


def test_generation_dialog_uses_verified_method_metadata_without_name_guessing(app, tmp_path):
    profiles = {"logi2": {"label": "로지D2", "package": "com.logisoft.Logi5"}}
    methods = [
        {"name": "a", "overload_index": 0, "label": "a() [()V]"},
        {"name": "a", "overload_index": 1, "label": "a(int) [(I)V]"},
    ]
    dialog = ObserverGenerationDialog(tmp_path / "base.apk", "x.Exact", profiles, methods, str(tmp_path), "logi2")
    dialog.cmb_method.setCurrentIndex(1)
    assert dialog.request() == {"project_path": str(tmp_path), "app_key": "logi2", "method_name": "a", "overload_index": 1}
    dialog._accept_request()
    assert dialog.result() == QDialog.DialogCode.Accepted
    dialog.deleteLater()


def test_class_inventory_remains_available_after_other_rea_queries(window, monkeypatch, tmp_path):
    apk = tmp_path / "input.apk"
    apk.write_bytes(b"fixture")
    window.ed_analyze_apk.setText(str(apk))
    monkeypatch.setattr(ui, "load_rea_settings", lambda: {})
    accepted_analysis(monkeypatch, {"operation": "class", "class_name": "x.Exact", "query": "", "method_name": "", "overload_index": None})
    class_evidence = {"normalized_result": {"class_name": "x.Exact", "methods": [{"name": "method"}]}}
    monkeypatch.setattr(ui, "run_rea_analysis", lambda *args, **kwargs: {"status": "complete", "report": "class inventory", "evidence": class_evidence})
    window.run_rea()
    spin_until(lambda: window._job is None)
    accepted_analysis(monkeypatch)
    monkeypatch.setattr(ui, "run_rea_analysis", lambda *args, **kwargs: {"status": "complete", "report": "package", "evidence": {"package": True}})
    window.run_rea()
    spin_until(lambda: window._job is None)
    assert window._last_rea_class_result["evidence"] == class_evidence
    assert window._last_rea_evidence == {"package": True}


def test_generation_checks_package_then_generates_in_worker_with_captured_target(window, monkeypatch, tmp_path, app):
    apk = tmp_path / "input.apk"
    apk.write_bytes(b"fixture")
    window.ed_analyze_apk.setText(str(apk))
    evidence = {"normalized_result": {"class_name": "x.Exact"}}
    window._last_rea_class_result = {"evidence": evidence, "apk_path": str(apk)}
    monkeypatch.setattr(ui, "list_observer_methods", lambda data: [{"name": "method", "label": "method()", "overload_index": 0}])
    monkeypatch.setattr(ui, "load_profiles", lambda: {"logi2": {"label": "로지D2", "package": "com.logisoft.Logi5"}})
    settings = {"java_home": "chosen/jdk"}
    monkeypatch.setattr(ui, "load_rea_settings", lambda: settings)
    request = {"project_path": str(tmp_path), "app_key": "logi2", "method_name": "method", "overload_index": 0}

    class Dialog:
        def __init__(self, *args):
            pass

        def exec(self):
            return QDialog.DialogCode.Accepted

        def request(self):
            return request

    monkeypatch.setattr(ui, "ObserverGenerationDialog", Dialog)
    calls, threads = [], []
    entered, release = threading.Event(), threading.Event()
    diff = tmp_path / "changes.diff"
    diff.write_text("+ verified observer", encoding="utf-8")

    def package(path, **kwargs):
        threads.append(QThread.currentThread())
        entered.set()
        assert release.wait(3)
        calls.append(("package", path, kwargs["settings"], kwargs["operation"]))
        return {"status": "complete", "evidence": {"verified_package": True}}

    def generate(project, app_key, path, class_evidence, method, overload, *, package_evidence):
        threads.append(QThread.currentThread())
        calls.append(("generate", project, app_key, path, class_evidence, method, overload, package_evidence))
        return {"path": str(tmp_path / "generated"), "manifest": str(tmp_path / "manifest.json"), "diff": str(diff), "report": {"source": "E05.kt"}, "build_status": "not_run"}

    monkeypatch.setattr(ui, "run_rea_analysis", package)
    monkeypatch.setattr(ui, "generate_observer", generate)
    try:
        window.run_observer_generation()
        spin_until(entered.is_set)
        request["method_name"] = "different"
        evidence["normalized_result"]["class_name"] = "changed.Class"
        settings["java_home"] = "changed/jdk"
        release.set()
        spin_until(lambda: window._job is None)
        assert calls[0] == ("package", apk.resolve(), {"java_home": "chosen/jdk"}, "package")
        assert calls[1][0:4] == ("generate", str(tmp_path), "logi2", apk.resolve())
        assert calls[1][4]["normalized_result"]["class_name"] == "x.Exact"
        assert calls[1][5:] == ("method", 0, {"verified_package": True})
        assert threads and all(thread != app.thread() for thread in threads)
        assert "+ verified observer" in window.txt_map.toPlainText()
        assert str(tmp_path / "generated") in window.txt_map.toPlainText()
        assert window._last_generated_result["build_status"] == "not_run"
        assert window.lbl_status.text() == "생성본 저장 — 빌드 미실행"
    finally:
        release.set()


def test_build_requires_a_generated_manifest(window, monkeypatch):
    monkeypatch.setattr(ui, "validate_generated_project", lambda *args, **kwargs: pytest.fail("no generated manifest"))
    window.run_generated_build()
    assert window._job is None
    assert "생성본" in str(window._test_dialogs[0])


@pytest.mark.parametrize("status", ["passed", "failed"])
def test_build_uses_background_worker_and_reports_actual_status(window, monkeypatch, tmp_path, app, status):
    manifest = str(tmp_path / "manifest.json")
    window._last_generated_result = {"manifest": manifest, "build_status": "not_run"}
    window.txt_map.setPlainText("generated diff")
    settings = {"java_home": "chosen/jdk"}
    monkeypatch.setattr(ui, "load_rea_settings", lambda: settings)
    entered, release = threading.Event(), threading.Event()
    captured, threads = [], []

    def validate(path, *, java_home=None, progress=None):
        threads.append(QThread.currentThread())
        entered.set()
        assert release.wait(3)
        captured.append((path, java_home))
        return {"status": status, "report": f"actual build: {status}", "log_path": "build.log", "project_path": "copy", "manifest_path": path}

    monkeypatch.setattr(ui, "validate_generated_project", validate)
    try:
        window.run_generated_build()
        spin_until(entered.is_set)
        settings["java_home"] = "changed/jdk"
        assert not window.btn_build_generated.isEnabled()
        release.set()
        spin_until(lambda: window._job is None)
        assert captured == [(manifest, "chosen/jdk")]
        assert threads[0] != app.thread()
        assert f"actual build: {status}" in window.txt_map.toPlainText()
        assert "generated diff" in window.txt_map.toPlainText()
        assert window._last_generated_result["build_status"] == status
        assert window._last_build_result["log_path"] == "build.log"
        assert ("통과" in window.lbl_status.text()) is (status == "passed")
    finally:
        release.set()


def test_build_error_preserves_generated_diff_without_reporting_a_pass(window, monkeypatch):
    window._last_generated_result = {"manifest": "manifest.json", "build_status": "not_run"}
    window.txt_map.setPlainText("generated diff")
    monkeypatch.setattr(ui, "load_rea_settings", lambda: {})

    def validate(*args, **kwargs):
        raise RuntimeError("Gradle wrapper is missing")

    monkeypatch.setattr(ui, "validate_generated_project", validate)
    window.run_generated_build()
    spin_until(lambda: window._job is None)
    assert window.txt_map.toPlainText() == "generated diff"
    assert window._last_generated_result["build_status"] == "not_run"
    assert window._last_build_result is None
    assert window.lbl_status.text() == "작업 실패"
    assert "Gradle wrapper" in str(window._test_dialogs)


@pytest.mark.parametrize("status", ["passed", "failed"])
def test_build_updates_structured_status_and_keeps_generation_mode_and_diff(window, monkeypatch, tmp_path, status):
    diff = '+ val originalJson = "build_status: not_run"\n+ callback.result = false\n'
    generated = {
        "manifest": str(tmp_path / "manifest.json"), "path": str(tmp_path / "generated"),
        "build_status": "not_run", "diff_text": diff,
        "report": {"build_status": "not_run", "mode": "boolean_false", "debug_only": True,
                   "selected_method": {"class_name": "ar1", "name": "I", "dex_descriptor": "()Z"}},
    }
    window._show_generated_result(generated)
    monkeypatch.setattr(ui, "load_rea_settings", lambda: {})
    detail = "빌드 통과" if status == "passed" else "What went wrong:\nYour project path contains non-ASCII characters."
    result = {"status": status, "report": detail, "log_path": "build.log", "project_path": "copy", "manifest_path": generated["manifest"]}
    monkeypatch.setattr(ui, "validate_generated_project", lambda *args, **kwargs: result)

    window.run_generated_build()
    spin_until(lambda: window._job is None)

    displayed = window.txt_map.toPlainText()
    prefix, remainder = displayed.split("\n\n======== 변경 사항 ========\n", 1)
    report = json.loads(prefix.split("\n\n", 1)[1])
    assert report["build_status"] == status
    assert report["mode"] == "boolean_false" and report["debug_only"] is True
    assert report["selected_method"] == generated["report"]["selected_method"]
    assert remainder.split("\n\n======== 생성본 빌드 검사 ========\n", 1)[0] == diff
    assert f"빌드 상태: {'통과' if status == 'passed' else '실패'}" in prefix
    assert detail in displayed
    assert window._last_generated_result["report"]["build_status"] == status
    assert window._last_build_result is result


@pytest.mark.parametrize("structured", [True, False])
def test_repeated_build_replaces_previous_result_without_stale_pass(window, monkeypatch, tmp_path, structured):
    generated = {"manifest": str(tmp_path / "manifest.json"), "build_status": "not_run"}
    if structured:
        generated.update(path=str(tmp_path / "generated"), diff_text="original diff", report={"build_status": "not_run", "mode": "skip_void"})
        window._show_generated_result(generated)
    else:
        window._last_generated_result = generated
        window.txt_map.setPlainText("빌드 상태: 미실행\n\noriginal diff")
    monkeypatch.setattr(ui, "load_rea_settings", lambda: {})
    results = iter([
        {"status": "passed", "report": "first compile passed", "log_path": "first.log"},
        {"status": "failed", "report": "latest compile failed\ne: syntax problem", "log_path": "second.log"},
    ])
    monkeypatch.setattr(ui, "validate_generated_project", lambda *args, **kwargs: next(results))

    for expected in ("passed", "failed"):
        window.run_generated_build()
        spin_until(lambda: window._job is None)
        assert window._last_build_result["status"] == expected

    displayed = window.txt_map.toPlainText()
    assert displayed.count("======== 생성본 빌드 검사 ========") == 1
    assert "빌드 상태: 실패" in displayed and "빌드 상태: 통과" not in displayed
    assert "first compile passed" not in displayed
    assert "latest compile failed\ne: syntax problem" in displayed
    assert "original diff" in displayed
    assert window._last_generated_result["build_status"] == "failed"
    assert window._last_build_result["log_path"] == "second.log"
    if structured:
        prefix = displayed.split("\n\n======== 변경 사항 ========\n", 1)[0]
        report = json.loads(prefix.split("\n\n", 1)[1])
        assert report["build_status"] == "failed" and report["mode"] == "skip_void"

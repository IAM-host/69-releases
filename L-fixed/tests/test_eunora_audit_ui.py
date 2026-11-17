"""EUNORA audit UI joins verified sources, APK evidence and copy generation."""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import threading
import time

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtCore import QThread, QTimer
from PySide6.QtTest import QTest
from PySide6.QtWidgets import QApplication, QComboBox, QDialog, QLineEdit

from l_app import ui
from l_app.processes import check_cancelled
from l_app.rea_dialogs import AuditObserverDialog, EunoraAuditDialog


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
    monkeypatch.setenv("L_APP_DATA_DIR", str(tmp_path / "L data"))
    monkeypatch.setattr(ui, "find_adb", lambda: None)
    monkeypatch.setattr(ui, "find_modulemain", lambda: None)
    dialogs = []
    for name in ("critical", "warning", "information"):
        monkeypatch.setattr(ui.QMessageBox, name,
                            lambda *args, _name=name, **kwargs: dialogs.append((_name, args)))
    view = ui.MainWindow()
    view._test_dialogs = dialogs
    yield view
    if view._job is not None:
        view._job.cancel()
        spin_until(lambda: view._job is None)
    view.close()
    QApplication.processEvents()


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


@pytest.fixture
def evidence_case(tmp_path):
    apk = tmp_path / "driver.apk"
    apk.write_bytes(b"synthetic APK input")
    project = tmp_path / "Android project"
    source = project / "app/src/main/java/com/example/wheelprobe/E05.kt"
    source.parent.mkdir(parents=True)
    source.write_text("package com.example.wheelprobe\n// original E05\n")
    module = source.with_name("ModuleMain.kt")
    module.write_text("package com.example.wheelprobe\n// original ModuleMain\n")
    class_name = "com.example.Orders"
    evidence = {
        "operation": "inspect_android_class", "provider": {"id": "jadx"},
        "parameters": {"class_name": class_name},
        "subject": {"digest": {"sha256": digest(apk)}},
        "normalized_result": {"class_name": class_name, "methods": [
            {"name": "parse", "overload_index": 1, "is_constructor": False,
             "reported_signature": "parse(java.lang.String): void", "dex_descriptor": "(Ljava/lang/String;)V"},
            {"name": "unrelated", "overload_index": 0, "is_constructor": False,
             "reported_signature": "unrelated(): void", "dex_descriptor": "()V"},
        ]},
    }
    result = {
        "status": "complete", "report": "EUNORA 자동 점검 완료 — 근거 보고서",
        "app_key": "logi", "apk_path": str(apk.resolve()), "project_root": str(project.resolve()),
        "apk_digest": digest(apk),
        "source_files": {p.relative_to(project).as_posix(): digest(p) for p in (source, module)},
        "package_result": {"status": "complete", "evidence": {"package": "old evidence"}},
        "class_results": [{"status": "complete", "operation": "class", "report": "class report",
                           "evidence": evidence, "target": {"class_name": class_name, "methods": ["parse"]}}],
        "rows": [], "counts": {"class_found": 1}, "report_path": str(tmp_path / "report.txt"),
    }
    return {"apk": apk, "project": project, "source": source, "module": module, "result": result}


def accepted_audit(monkeypatch, case):
    captured = []
    request = {"apk_path": str(case["apk"]), "project_path": str(case["project"])}

    class Dialog:
        def __init__(self, apk_path, project_path, parent):
            captured.append((apk_path, project_path))

        def exec(self):
            return QDialog.DialogCode.Accepted

        def request(self):
            return dict(request)

    monkeypatch.setattr(ui, "EunoraAuditDialog", Dialog)
    return captured, request


def accepted_generator(monkeypatch):
    captured = []

    class Dialog:
        def __init__(self, apk_path, project_path, choices, parent):
            captured.append((apk_path, project_path, choices))

        def exec(self):
            return QDialog.DialogCode.Accepted

        def request(self):
            return {"choice_index": 0}

    monkeypatch.setattr(ui, "AuditObserverDialog", Dialog)
    return captured


def test_automatic_dialogs_need_no_class_or_method_typing(app, evidence_case):
    case = evidence_case
    dialog = EunoraAuditDialog(case["apk"], case["project"])
    assert len(dialog.findChildren(QLineEdit)) == 2
    assert not dialog.findChildren(QComboBox)
    assert dialog.request() == {"apk_path": str(case["apk"]), "project_path": str(case["project"])}
    dialog._accept_request()
    assert dialog.result() == QDialog.DialogCode.Accepted
    choices = [{"label": "com.example.Orders — parse(java.lang.String): void"}]
    selection = AuditObserverDialog(case["apk"], case["project"], choices)
    assert not selection.findChildren(QLineEdit)
    assert selection.cmb_target.currentText() == choices[0]["label"]
    assert selection.request() == {"choice_index": 0}
    dialog.deleteLater()
    selection.deleteLater()


def test_audit_runs_off_gui_thread_and_snapshots_user_inputs(window, monkeypatch, evidence_case, app):
    case = evidence_case
    window.ed_analyze_apk.setText(str(case["apk"]))
    window.ed_modulemain.setText(str(case["module"]))
    dialog_calls, request = accepted_audit(monkeypatch, case)
    settings = {"node_path": "chosen-node", "timeout_seconds": 120}
    monkeypatch.setattr(ui, "load_rea_settings", lambda: settings)
    entered, release = threading.Event(), threading.Event()
    compute, rendered, captured = [], [], []

    def analyze(apk_path, project_path, *, settings, progress):
        compute.append(QThread.currentThread())
        captured.append((apk_path, project_path, settings))
        entered.set()
        assert release.wait(3)
        progress("클래스 정보 확인 중")
        return case["result"]

    monkeypatch.setattr(ui, "analyze_eunora_project", analyze)
    window.txt_analyze.textChanged.connect(lambda: rendered.append(QThread.currentThread()))
    ticks = []
    timer = QTimer(window)
    timer.setInterval(5)
    timer.timeout.connect(lambda: ticks.append(1))
    timer.start()
    try:
        window.run_eunora_audit()
        spin_until(entered.is_set)
        settings["node_path"] = "later-node"
        request["project_path"] = "later project"
        window.ed_analyze_apk.setText("later.apk")
        QTest.qWait(65)
        assert len(ticks) >= 3
        assert not window.btn_eunora_audit.isEnabled()
        assert not window.btn_audit_generate.isEnabled()
        release.set()
        spin_until(lambda: window._job is None)
        assert compute[0] != app.thread()
        assert rendered and all(thread == app.thread() for thread in rendered)
        assert Path(captured[0][0]) == case["apk"].resolve()
        assert Path(captured[0][1]) == case["project"].resolve()
        assert captured[0][2]["node_path"] == "chosen-node"
        assert dialog_calls
        assert window.txt_analyze.toPlainText() == case["result"]["report"]
        assert window._last_eunora_audit["app_key"] == "logi"
        assert window.cmb_map_app.currentData() == "logi"
        assert window.btn_eunora_audit.isEnabled()
    finally:
        release.set()
        timer.stop()


@pytest.mark.parametrize("mode", ["exception", "invalid-result"])
def test_failed_audit_preserves_previous_results(window, monkeypatch, evidence_case, mode):
    accepted_audit(monkeypatch, evidence_case)
    monkeypatch.setattr(ui, "load_rea_settings", lambda: {})
    old = {"app_key": "kakao", "report": "previous audit"}
    window._last_eunora_audit = old
    window.txt_analyze.setPlainText("previous report")

    def analyze(*args, **kwargs):
        if mode == "exception":
            raise RuntimeError("APK 또는 프로젝트 변경")
        return {"status": "error", "report": ""}

    monkeypatch.setattr(ui, "analyze_eunora_project", analyze)
    window.run_eunora_audit()
    spin_until(lambda: window._job is None)
    assert window._last_eunora_audit == old
    assert window.txt_analyze.toPlainText() == "previous report"
    assert window._test_dialogs


def test_generation_requires_completed_audit(window, monkeypatch):
    called = []
    monkeypatch.setattr(ui, "generate_observer", lambda *args, **kwargs: called.append(True))
    window.run_audit_generation()
    assert not called
    assert window._job is None
    assert window._test_dialogs


def test_audit_generation_reuses_exact_evidence_and_build_pipeline(window, monkeypatch, evidence_case, tmp_path, app):
    case = evidence_case
    window._last_eunora_audit = case["result"]
    window.ed_analyze_apk.setText(str(case["apk"]))
    captured_dialogs = accepted_generator(monkeypatch)
    monkeypatch.setattr(ui, "load_rea_settings", lambda: {"node_path": "selected-node"})
    package_evidence = {"package": "fresh package evidence"}
    threads, calls = [], []

    def rea(apk_path, **kwargs):
        threads.append(QThread.currentThread())
        assert Path(apk_path) == case["apk"].resolve()
        assert kwargs["operation"] == "package"
        return {"status": "complete", "evidence": package_evidence}

    monkeypatch.setattr(ui, "run_rea_analysis", rea)
    bundle = tmp_path / "generated"
    bundle.mkdir()
    diff = bundle / "changes.diff"
    diff.write_text("generated proof: original preserved")
    manifest = bundle / "manifest.json"
    manifest.write_text("{}")
    generated = {"path": str(bundle), "manifest": str(manifest), "files": {}, "diff": str(diff),
                 "report": {"observation_only": True}, "build_status": "not_run"}

    def generate(project_path, app_key, apk_path, evidence, method_name, overload_index, *, package_evidence):
        threads.append(QThread.currentThread())
        calls.append((project_path, app_key, apk_path, evidence, method_name, overload_index, package_evidence))
        return dict(generated)

    monkeypatch.setattr(ui, "generate_observer", generate)
    window.run_audit_generation()
    spin_until(lambda: window._job is None)
    assert len(captured_dialogs) == 1
    # The unrelated inventory member must not become an automatic EUNORA target.
    assert len(captured_dialogs[0][2]) == 1
    assert len(calls) == 1
    assert Path(calls[0][0]) == case["project"].resolve()
    assert calls[0][1] == "logi"
    assert Path(calls[0][2]) == case["apk"].resolve()
    assert calls[0][3] == case["result"]["class_results"][0]["evidence"]
    assert calls[0][4:6] == ("parse", 1)
    assert calls[0][6] == package_evidence
    assert threads and all(thread != app.thread() for thread in threads)
    assert window._last_generated_result["manifest"] == str(manifest)
    assert window._last_generated_result["build_status"] == "not_run"
    assert "generated proof" in window.txt_map.toPlainText()
    assert case["source"].read_text().endswith("// original E05\n")


@pytest.mark.parametrize("changed", ["apk", "source"])
def test_stale_audit_never_generates_code(window, monkeypatch, evidence_case, changed):
    case = evidence_case
    window._last_eunora_audit = case["result"]
    window.ed_analyze_apk.setText(str(case["apk"]))
    previous = {"manifest": "previous source bundle"}
    window._last_generated_result = previous
    accepted_generator(monkeypatch)
    monkeypatch.setattr(ui, "load_rea_settings", lambda: {})
    monkeypatch.setattr(ui, "run_rea_analysis", lambda *args, **kwargs: {"status": "complete", "evidence": {"package": "fresh"}})
    calls = []
    monkeypatch.setattr(ui, "generate_observer", lambda *args, **kwargs: calls.append(True))
    case[changed].write_text("changed after audit")
    window.run_audit_generation()
    spin_until(lambda: window._job is None)
    assert not calls
    assert window._last_generated_result == previous
    assert window._test_dialogs


def test_source_change_during_package_analysis_is_rejected(window, monkeypatch, evidence_case):
    case = evidence_case
    window._last_eunora_audit = case["result"]
    window.ed_analyze_apk.setText(str(case["apk"]))
    accepted_generator(monkeypatch)
    monkeypatch.setattr(ui, "load_rea_settings", lambda: {})

    def rea(*args, **kwargs):
        case["source"].write_text("changed while package was being analyzed")
        return {"status": "complete", "evidence": {"package": "fresh"}}

    monkeypatch.setattr(ui, "run_rea_analysis", rea)
    calls = []
    monkeypatch.setattr(ui, "generate_observer", lambda *args, **kwargs: calls.append(True))
    window.run_audit_generation()
    spin_until(lambda: window._job is None)
    assert not calls
    assert window._test_dialogs


def test_changing_selected_apk_requires_new_audit(window, monkeypatch, evidence_case, tmp_path):
    case = evidence_case
    window._last_eunora_audit = case["result"]
    replacement = tmp_path / "different app.apk"
    replacement.write_bytes(b"different APK")
    window.ed_analyze_apk.setText(str(replacement))
    accepted_generator(monkeypatch)
    monkeypatch.setattr(ui, "load_rea_settings", lambda: {})
    called = []
    monkeypatch.setattr(ui, "run_rea_analysis", lambda *args, **kwargs: called.append("engine"))
    monkeypatch.setattr(ui, "generate_observer", lambda *args, **kwargs: called.append("generator"))
    window.run_audit_generation()
    spin_until(lambda: window._job is None)
    assert not called
    assert window._test_dialogs


def test_audit_cancellation_does_not_publish_partial_result(window, monkeypatch, evidence_case):
    accepted_audit(monkeypatch, evidence_case)
    monkeypatch.setattr(ui, "load_rea_settings", lambda: {})
    entered = threading.Event()
    window.txt_analyze.setPlainText("retained previous result")

    def analyze(*args, **kwargs):
        entered.set()
        while True:
            check_cancelled()
            time.sleep(0.005)

    monkeypatch.setattr(ui, "analyze_eunora_project", analyze)
    window.run_eunora_audit()
    spin_until(entered.is_set)
    window._job.cancel()
    spin_until(lambda: window._job is None)
    assert window.txt_analyze.toPlainText() == "retained previous result"
    assert window._last_eunora_audit is None
    assert "취소" in window.lbl_status.text()

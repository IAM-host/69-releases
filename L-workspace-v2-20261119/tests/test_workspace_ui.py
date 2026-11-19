"""User-facing regressions for the consolidated workspace, using real Qt events."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import threading
import time

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtTest import QTest
from PySide6.QtWidgets import QApplication, QAbstractButton, QLabel, QLineEdit, QPlainTextEdit

from l_app import ui


def wait_for(predicate, timeout=4):
    until = time.monotonic() + timeout
    while not predicate():
        QApplication.processEvents()
        if time.monotonic() >= until:
            raise AssertionError("Workspace job did not finish")
        QTest.qWait(5)
    QApplication.processEvents()


@pytest.fixture(scope="module")
def app():
    app = QApplication.instance() or QApplication([])
    app.setQuitOnLastWindowClosed(False)
    return app


@pytest.fixture
def window(app, monkeypatch, tmp_path):
    monkeypatch.setenv("L_APP_DATA_DIR", str(tmp_path / "L data"))
    monkeypatch.setattr(ui, "find_adb", lambda: None)
    monkeypatch.setattr(ui, "find_modulemain", lambda: None)
    messages = []
    for level in ("critical", "warning", "information"):
        monkeypatch.setattr(ui.QMessageBox, level,
                            lambda *args, _level=level, **kw: messages.append((_level, args)))
    view = ui.MainWindow()
    view._messages = messages
    yield view
    if view._job is not None:
        view._job.cancel()
        wait_for(lambda: view._job is None)
    view.close()
    QApplication.processEvents()


@pytest.fixture
def inputs(tmp_path):
    apk = tmp_path / "driver.apk"
    apk.write_bytes(b"APK input fixture")
    root = tmp_path / "EUNORA"
    source = root / "app/src/main/java/com/example/wheelprobe/E05.kt"
    source.parent.mkdir(parents=True)
    source.write_text("package com.example.wheelprobe\n// original E05\n")
    module = source.with_name("ModuleMain.kt")
    module.write_text("package com.example.wheelprobe\n// original module\n")
    digest = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
    evidence = {
        "operation": "inspect_android_class", "provider": {"id": "jadx"},
        "parameters": {"class_name": "example.Checks"},
        "subject": {"digest": {"sha256": digest(apk)}},
        "normalized_result": {"class_name": "example.Checks", "methods": [
            {"name": "isRooted", "overload_index": 0, "dex_descriptor": "()Z",
             "reported_signature": "isRooted(): boolean", "is_constructor": False},
        ]},
    }
    candidate = {"id": "root-1", "class_name": "example.Checks", "method_name": "isRooted",
                 "dex_descriptor": "()Z", "categories": ["root_files"],
                 "signals": ["/system/bin/su"], "evidence_kind": "method_literal",
                 "modes": ["observe", "boolean_false"]}
    audit = {"status": "complete", "report": "확인된 대상 1개 — 실제 기기 실행은 별도",
             "app_key": "logi", "apk_path": str(apk.resolve()), "apk_digest": digest(apk),
             "project_root": str(root.resolve()),
             "source_files": {p.relative_to(root).as_posix(): digest(p) for p in (source, module)},
             "counts": {"class_found": 1, "confirmed": 1}, "rows": [],
             "class_results": [{"status": "complete", "evidence": evidence,
                                 "target": {"class_name": "example.Checks", "methods": ["isRooted"]}}],
             "choices": [{"candidate": candidate, "class_evidence": evidence,
                          "method_name": "isRooted", "overload_index": 0,
                          "dex_descriptor": "()Z", "modes": ["observe", "boolean_false"],
                          "label": "example.Checks — isRooted(): boolean"}]}
    return {"apk": apk, "root": root, "source": source, "module": module, "audit": audit}


@pytest.mark.parametrize("mode, engine", [("existing", "analyze_eunora_project"), ("security", "analyze_security_project")])
def test_primary_audit_uses_visible_inputs_without_reopening_file_dialogs(window, inputs, monkeypatch, mode, engine):
    window.cmb_analysis_mode.setCurrentIndex(window.cmb_analysis_mode.findData(mode))
    window.ed_analyze_apk.setText(str(inputs["apk"]))
    window.ed_project.setText(str(inputs["root"]))
    monkeypatch.setattr(ui, "load_rea_settings", lambda: {"node_path": "chosen node"})
    monkeypatch.setattr(ui, "EunoraAuditDialog", lambda *a, **kw: pytest.fail("Primary flow re-requested existing inputs"))
    monkeypatch.setattr(ui, "SecurityAuditDialog", lambda *a, **kw: pytest.fail("Primary flow re-requested existing inputs"))
    captured = []

    def inspect(apk, project, *, settings, progress):
        captured.append((Path(apk), Path(project), dict(settings)))
        return inputs["audit"]

    monkeypatch.setattr(ui, engine, inspect)
    other = "analyze_security_project" if engine == "analyze_eunora_project" else "analyze_eunora_project"
    monkeypatch.setattr(ui, other, lambda *a, **kw: pytest.fail("Wrong audit mode executed"))
    assert window.btn_run_audit.isEnabled()
    window.btn_run_audit.click()
    wait_for(lambda: window._job is None)
    assert captured == [(inputs["apk"].resolve(), inputs["root"].resolve(), {"node_path": "chosen node"})]
    cache = window._last_eunora_audit if mode == "existing" else window._last_security_audit
    assert cache["app_key"] == "logi"
    assert window.btn_generate_hook.isEnabled()
    assert not window.btn_build_generated.isEnabled()
    assert inputs["source"].read_text().endswith("// original E05\n")
    assert inputs["module"].read_text().endswith("// original module\n")


@pytest.mark.parametrize("changed", ["apk", "project", "mode"])
def test_canonical_input_change_invalidates_generation_and_build(window, inputs, tmp_path, changed):
    window.ed_analyze_apk.setText(str(inputs["apk"]))
    window.ed_project.setText(str(inputs["root"]))
    window._last_eunora_audit = inputs["audit"]
    window._last_security_audit = inputs["audit"]
    window._last_generated_result = {"manifest": "old manifest", "build_status": "passed"}
    window._last_build_result = {"status": "passed", "report": "old pass"}
    window._refresh_action_state()
    assert window.btn_build_generated.isEnabled()
    if changed == "apk":
        other = tmp_path / "new.apk"
        other.write_bytes(b"new")
        window.ed_analyze_apk.setText(str(other))
    elif changed == "project":
        other = tmp_path / "new project"
        other.mkdir()
        window.ed_project.setText(str(other))
    else:
        window.cmb_analysis_mode.setCurrentIndex(window.cmb_analysis_mode.findData("security"))
    assert window._last_eunora_audit is None
    assert window._last_security_audit is None
    assert window._last_generated_result is None
    assert window._last_build_result is None
    assert not window.btn_generate_hook.isEnabled()
    assert not window.btn_build_generated.isEnabled()


def test_late_audit_result_cannot_become_current_after_input_change(window, inputs, tmp_path, monkeypatch):
    window.ed_analyze_apk.setText(str(inputs["apk"]))
    window.ed_project.setText(str(inputs["root"]))
    monkeypatch.setattr(ui, "load_rea_settings", lambda: {})
    entered, release = threading.Event(), threading.Event()
    captured = []

    def inspect(apk, project, **kwargs):
        captured.append((Path(apk), Path(project)))
        entered.set()
        assert release.wait(3)
        return inputs["audit"]

    monkeypatch.setattr(ui, "analyze_eunora_project", inspect)
    try:
        window.btn_run_audit.click()
        wait_for(entered.is_set)
        other = tmp_path / "replacement.apk"
        other.write_bytes(b"different APK")
        window.ed_analyze_apk.setText(str(other))
        release.set()
        wait_for(lambda: window._job is None)
        assert captured == [(inputs["apk"].resolve(), inputs["root"].resolve())]
        assert window._last_eunora_audit is None
        assert window._last_generated_result is None
        assert not window.btn_generate_hook.isEnabled()
        assert not window.btn_build_generated.isEnabled()
        assert "입력" in window.lbl_status.text()
        assert "바뀌" in window.lbl_status.text()
    finally:
        release.set()


def test_readiness_is_not_reset_to_enabled_for_all_actions_after_an_error(window, inputs, monkeypatch):
    window.ed_analyze_apk.setText(str(inputs["apk"]))
    window.ed_project.setText(str(inputs["root"]))
    monkeypatch.setattr(ui, "load_rea_settings", lambda: {})
    monkeypatch.setattr(ui, "analyze_eunora_project", lambda *a, **kw: (_ for _ in ()).throw(RuntimeError("REA unavailable")))
    window.btn_run_audit.click()
    wait_for(lambda: window._job is None)
    assert window.btn_run_audit.isEnabled()
    assert not window.btn_generate_hook.isEnabled()
    assert not window.btn_build_generated.isEnabled()
    assert "실패" in window.lbl_status.text()
    assert "REA unavailable" in str(window._messages)


def test_late_phone_extraction_cannot_replace_a_newly_selected_apk(window, inputs, tmp_path, monkeypatch):
    window.ed_analyze_apk.setText(str(inputs["apk"]))
    window.ed_project.setText(str(inputs["root"]))
    window.cmb_device.clear()
    window.cmb_device.addItem("connected-device")
    window.cmb_pull_app.setCurrentIndex(window.cmb_pull_app.findData("kakao"))
    extracted = tmp_path / "phone snapshot" / "base.apk"
    extracted.parent.mkdir()
    extracted.write_bytes(b"phone APK")
    entered, release = threading.Event(), threading.Event()
    captured = []

    def pull(adb, serial, key, stamp, *, progress):
        captured.append((serial, key))
        entered.set()
        assert release.wait(3)
        return {"app_key": key, "base_path": extracted, "report": "extracted fixture"}

    monkeypatch.setattr(ui, "pull_package", pull)
    try:
        window.btn_pull.click()
        wait_for(entered.is_set)
        replacement = tmp_path / "chosen while extracting.apk"
        replacement.write_bytes(b"selected APK")
        window.ed_analyze_apk.setText(str(replacement))
        release.set()
        wait_for(lambda: window._job is None)
        assert captured == [("connected-device", "kakao")]
        assert Path(window.ed_analyze_apk.text()) == replacement
        assert window.last_pull == {}
        assert window._last_eunora_audit is None
        assert not window.btn_generate_hook.isEnabled()
        assert "입력" in window.lbl_status.text() and "바뀌" in window.lbl_status.text()
    finally:
        release.set()


def test_generation_summary_keeps_full_details_collapsed_until_requested(window, tmp_path, monkeypatch):
    output = tmp_path / "generated"
    output.mkdir()
    generated = output / "E05.kt"
    generated.write_text("package com.example.wheelprobe\n")
    exported = output / "E05.txt"
    exported.write_bytes(generated.read_bytes())
    result = {"path": str(output), "manifest": str(output / "manifest.json"),
              "build_status": "not_run", "diff_text": "+ verified generated change",
              "files": {"E05.kt": str(generated), "E05.txt": str(exported)},
              "report": {"mode": "observe", "profile": "logi", "build_status": "not_run",
                         "selected_method": {"class_name": "example.Checks", "name": "isRooted", "dex_descriptor": "()Z"}}}
    window._show_generated_result(result)
    window.navigate("workspace")
    window.show()
    QApplication.processEvents()
    assert not window.txt_map.isVisible()
    assert window.lbl_output_path.text()
    assert window._last_generated_result["build_status"] == "not_run"
    assert window.lbl_build_state.text() == "빌드 전"
    names = [window.list_generated_files.item(i).text() for i in range(window.list_generated_files.count())]
    assert "E05.kt" in names and "E05.txt" in names
    opened = []
    monkeypatch.setattr(window, "_show_text_details", lambda title, text: opened.append((title, text)))
    window.btn_view_changes.click()
    QApplication.processEvents()
    if opened:
        assert "+ verified generated change" in opened[0][1]
    else:
        assert window.txt_map.isVisible()
        assert "+ verified generated change" in window.txt_map.toPlainText()


def test_existing_session_history_remains_readable_without_migrating_user_files(window):
    source = window.session_dir / "session_20250101_190000_logi2_old_device.json"
    original = json.dumps({
        "app": "logi2", "device": "old-device", "line_count": 2,
        "lines": ["EUNORA: LOGI MATCH 여서동", "EUNORA: ACCEPT original"],
        "legacy_extra": {"keep": True},
    }, ensure_ascii=False).encode("utf-8")
    source.write_bytes(original)
    window.reload_session_list()
    window.navigate("history")
    window.list_sessions.setCurrentRow(0)
    QApplication.processEvents()
    assert "여서동" in window.txt_session.toPlainText()
    assert "logi2" in window.txt_summary.toPlainText()
    assert source.read_bytes() == original


def assert_functional_workspace_copy(window):
    """Reject the specific prose the user removed, including hidden leftovers."""
    forbidden = (
        "APK와 EUNORA 소스를 한곳에서 확인하세요",
        "파일을 선택하고 점검을 시작하면",
        "확인된 대상과 추가 점검 항목을 보여줍니다",
        "생성 파일을 확인하고 빌드 검사로 이어가세요",
        "상세 분석 결과입니다. 아래 원문에서",
        "저장된 캡처를 선택하면 요약이 표시됩니다",
        "필요한 경우에만 입력",
        "프로젝트 폴더 또는 ModuleMain.kt",
    )
    for label in window.findChildren(QLabel):
        assert not any(fragment in label.text() for fragment in forbidden), label.text()
    for edit in window.findChildren(QLineEdit) + window.findChildren(QPlainTextEdit):
        assert edit.placeholderText() == "", edit.placeholderText()
    assert not hasattr(window, "lbl_page_description")
    assert not hasattr(window, "lbl_result_description")
    assert not any(button.text() == "폰에서 가져오기" for button in window.findChildren(QAbstractButton))


def test_clean_workspace_copy_and_device_only_extraction(window):
    assert_functional_workspace_copy(window)
    assert window.findChildren(QAbstractButton).count(window.btn_pull) == 1
    assert window.btn_pull.text() in {"추출", "APK 추출"}
    workspace = window.pages.widget(window._page_indices["workspace"])
    logs = window.pages.widget(window._page_indices["logs"])
    assert logs.isAncestorOf(window.btn_pull)
    assert not workspace.isAncestorOf(window.btn_pull)


@pytest.mark.parametrize("state", ["input_reset", "audit_complete", "generation_complete"])
def test_helper_copy_does_not_return_after_workspace_state_changes(window, inputs, tmp_path, monkeypatch, state):
    window.ed_analyze_apk.setText(str(inputs["apk"]))
    window.ed_project.setText(str(inputs["root"]))
    if state == "audit_complete":
        monkeypatch.setattr(ui, "load_rea_settings", lambda: {})
        monkeypatch.setattr(ui, "analyze_eunora_project", lambda *args, **kwargs: inputs["audit"])
        window.btn_run_audit.click()
        wait_for(lambda: window._job is None)
        assert window._last_eunora_audit is not None
    else:
        output = tmp_path / "generated"
        output.mkdir()
        result = {"path": str(output), "manifest": str(output / "manifest.json"),
                  "files": {}, "build_status": "not_run", "diff_text": "+ change",
                  "report": {"mode": "observe", "build_status": "not_run"}}
        window._show_generated_result(result)
        if state == "input_reset":
            window.ed_project.setText(str(tmp_path / "another project"))
            assert window._last_generated_result is None
    assert_functional_workspace_copy(window)


def _saved_generation(tmp_path):
    folder = tmp_path / "generated source"
    folder.mkdir()
    return {"path": str(folder), "manifest": str(folder / "manifest.json"),
            "files": {}, "build_status": "not_run", "diff_text": "+ generated-only change",
            "report": {"mode": "observe", "build_status": "not_run"}}


def test_raw_save_exports_the_selected_report(window, tmp_path, monkeypatch):
    window._last_analysis_text = "analysis-only report"
    window.txt_analyze.setPlainText(window._last_analysis_text)
    window._show_generated_result(_saved_generation(tmp_path))
    window.show()
    for kind, expected in (("generation", window.txt_map.toPlainText()),
                           ("analysis", "analysis-only report")):
        destination = tmp_path / (kind + ".txt")
        monkeypatch.setattr(ui.QFileDialog, "getSaveFileName", lambda *a, _path=destination, **kw: (str(_path), ""))
        if kind == "generation":
            window.set_generation_details_visible(True)
        else:
            window.set_analysis_details_visible(True)
        QApplication.processEvents()
        window.btn_save_raw.click()
        assert destination.read_text(encoding="utf-8") == expected


def test_new_audit_raw_view_replaces_the_previous_generation_context(window, inputs, tmp_path, monkeypatch):
    window.ed_analyze_apk.setText(str(inputs["apk"]))
    window.ed_project.setText(str(inputs["root"]))
    window._show_generated_result(_saved_generation(tmp_path))
    window.set_generation_details_visible(True)
    monkeypatch.setattr(ui, "load_rea_settings", lambda: {})
    monkeypatch.setattr(ui, "analyze_eunora_project", lambda *args, **kwargs: inputs["audit"])
    window.btn_run_audit.click()
    wait_for(lambda: window._job is None)
    window.show()
    window.result_tabbar.setCurrentIndex(1)
    QApplication.processEvents()
    assert window._raw_kind == "analysis"
    assert window.txt_analyze.isVisible()
    assert not window.txt_map.isVisible()
    assert window.txt_analyze.toPlainText() == inputs["audit"]["report"]


def test_changed_inputs_return_files_view_to_the_empty_results_table(window, inputs, tmp_path):
    window.ed_analyze_apk.setText(str(inputs["apk"]))
    window.ed_project.setText(str(inputs["root"]))
    window._show_generated_result(_saved_generation(tmp_path))
    window.result_tabbar.setCurrentIndex(2)
    window.ed_project.setText(str(tmp_path / "different project"))
    window.show()
    QApplication.processEvents()
    assert window.result_tabbar.currentIndex() == window.result_views.currentIndex() == 0
    assert window._raw_kind == "analysis"
    assert window.tbl_findings.rowCount() == 0
    assert window.tbl_findings.isVisible()
    assert not window.btn_build_generated.isEnabled()


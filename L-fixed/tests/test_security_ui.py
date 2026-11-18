"""The security workflow keeps test-result changes explicit and inputs bound."""
from __future__ import annotations

import copy
import hashlib
import os
from pathlib import Path
import threading
import time

import pytest

os.environ.setdefault('QT_QPA_PLATFORM', 'offscreen')

from PySide6.QtCore import QThread, QTimer
from PySide6.QtTest import QTest
from PySide6.QtWidgets import QApplication, QDialog, QLineEdit

from l_app import ui
from l_app.security_dialogs import SecurityAuditDialog, SecurityGenerationDialog


def wait_for(predicate, timeout=4):
    until = time.monotonic() + timeout
    while not predicate():
        QApplication.processEvents()
        if time.monotonic() >= until:
            raise AssertionError('Qt worker timed out')
        QTest.qWait(5)
    QApplication.processEvents()


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


@pytest.fixture(scope='module')
def app():
    result = QApplication.instance() or QApplication([])
    result.setStyle('Fusion')
    result.setQuitOnLastWindowClosed(False)
    return result


@pytest.fixture
def window(app, monkeypatch, tmp_path):
    monkeypatch.setenv('L_APP_DATA_DIR', str(tmp_path / 'L data'))
    monkeypatch.setattr(ui, 'find_adb', lambda: None)
    monkeypatch.setattr(ui, 'find_modulemain', lambda: None)
    errors = []
    for key in ('critical', 'warning', 'information'):
        monkeypatch.setattr(ui.QMessageBox, key,
                            lambda *args, _key=key, **kw: errors.append((_key, args)))
    view = ui.MainWindow()
    view._messages = errors
    yield view
    if view._job:
        view._job.cancel()
        wait_for(lambda: view._job is None)
    view.close()
    QApplication.processEvents()


@pytest.fixture
def case(tmp_path):
    apk = tmp_path / 'co-developed.apk'
    apk.write_bytes(b'APK fixture')
    project = tmp_path / 'EUNORA source'
    source = project / 'app/src/main/java/com/example/wheelprobe/E05.kt'
    source.parent.mkdir(parents=True)
    source.write_text('package com.example.wheelprobe\n// E05 original\n')
    module = source.with_name('ModuleMain.kt')
    module.write_text('package com.example.wheelprobe\n// ModuleMain original\n')
    evidence = {
        'operation': 'inspect_android_class', 'provider': {'id': 'jadx'},
        'parameters': {'class_name': 'example.Checks'},
        'subject': {'digest': {'sha256': sha(apk)}},
        'normalized_result': {'class_name': 'example.Checks', 'methods': [
            {'name': 'isRooted', 'overload_index': 0, 'dex_descriptor': '()Z',
             'reported_signature': 'isRooted(): boolean', 'is_constructor': False},
        ]},
    }
    candidate = {'id': 'candidate-1', 'class_name': 'example.Checks', 'method_name': 'isRooted',
                 'dex_descriptor': '()Z', 'categories': ['root_files'],
                 'signals': ['/system/bin/su'], 'evidence_kind': 'method_literal',
                 'modes': ['observe', 'boolean_false']}
    choice = {'candidate': candidate, 'class_evidence': evidence, 'method_name': 'isRooted',
              'overload_index': 0, 'dex_descriptor': '()Z', 'modes': ['observe', 'boolean_false'],
              'label': 'example.Checks — isRooted(): boolean'}
    audit = {'status': 'partial', 'report': '보안 정적 점검 — 후보 1개', 'app_key': 'logi',
             'apk_path': str(apk.resolve()), 'apk_digest': sha(apk),
             'project_root': str(project.resolve()),
             'source_files': {p.relative_to(project).as_posix(): sha(p) for p in (source, module)},
             'choices': [choice], 'rows': [], 'counts': {'confirmed': 1}}
    return {'apk': apk, 'project': project, 'source': source, 'module': module, 'audit': audit}


def accepted_audit(monkeypatch, case):
    request = {'apk_path': str(case['apk']), 'project_path': str(case['project'])}
    class Dialog:
        def __init__(self, apk, project, parent):
            pass
        def exec(self):
            return QDialog.DialogCode.Accepted
        def request(self):
            return request
    monkeypatch.setattr(ui, 'SecurityAuditDialog', Dialog)
    return request


def accepted_generation(monkeypatch, mode='boolean_false'):
    requests = []
    class Dialog:
        def __init__(self, apk, project, choices, parent):
            requests.append((apk, project, choices))
        def exec(self):
            return QDialog.DialogCode.Accepted
        def request(self):
            return {'choice_index': 0, 'mode': mode}
    monkeypatch.setattr(ui, 'SecurityGenerationDialog', Dialog)
    return requests


def test_dialog_inputs_are_files_only_and_result_change_is_explicit(app, case):
    audit = SecurityAuditDialog(case['apk'], case['project'])
    assert len(audit.findChildren(QLineEdit)) == 2
    assert audit.windowTitle() == '보안 자동 점검'
    choice = copy.deepcopy(case['audit']['choices'][0])
    other = copy.deepcopy(choice)
    other['modes'] = ['observe']
    other['label'] = '관찰만 지원하는 다른 대상'
    dialog = SecurityGenerationDialog(case['apk'], case['project'], [choice, other])
    assert not dialog.findChildren(QLineEdit)
    assert dialog.request() == {'choice_index': 0, 'mode': 'observe'}
    assert '변경하지 않습니다' in dialog.lbl_mode.text()
    dialog.cmb_mode.setCurrentIndex(dialog.cmb_mode.findData('boolean_false'))
    assert dialog.request()['mode'] == 'boolean_false'
    assert 'false로 변경' in dialog.lbl_mode.text()
    assert '빌드 종류로 실행을 제한하지 않습니다' in dialog.lbl_mode.text()
    assert '디버그' not in dialog.lbl_mode.text()
    assert '디버그' not in dialog.cmb_mode.currentText()
    assert '/system/bin/su' in dialog.txt_evidence.toPlainText()
    dialog.cmb_target.setCurrentIndex(1)
    assert dialog.cmb_mode.count() == 1
    assert dialog.request() == {'choice_index': 1, 'mode': None}
    assert not dialog.buttons.button(dialog.buttons.StandardButton.Ok).isEnabled()
    dialog.cmb_mode.setCurrentIndex(0)
    assert dialog.request()['mode'] == 'observe'
    audit.deleteLater()
    dialog.deleteLater()


def test_audit_runs_in_worker_with_frozen_files_and_settings(window, case, monkeypatch, app):
    request = accepted_audit(monkeypatch, case)
    settings = {'node_path': 'chosen node'}
    monkeypatch.setattr(ui, 'load_rea_settings', lambda: settings)
    entered, release = threading.Event(), threading.Event()
    called, rendered, ticks = [], [], []
    def analyze(apk, project, *, settings, progress):
        called.append((apk, project, settings, QThread.currentThread()))
        entered.set()
        assert release.wait(3)
        progress('보안 원형 확인 중')
        return case['audit']
    monkeypatch.setattr(ui, 'analyze_security_project', analyze)
    window.txt_analyze.textChanged.connect(lambda: rendered.append(QThread.currentThread()))
    timer = QTimer(window)
    timer.setInterval(5)
    timer.timeout.connect(lambda: ticks.append(1))
    timer.start()
    try:
        window.run_security_audit()
        wait_for(entered.is_set)
        settings['node_path'] = 'changed node'
        request['apk_path'] = 'changed.apk'
        request['project_path'] = 'changed project'
        window.ed_analyze_apk.setText('later.apk')
        QTest.qWait(60)
        assert len(ticks) >= 3
        assert not window.btn_security_audit.isEnabled()
        assert not window.btn_security_generate.isEnabled()
        release.set()
        wait_for(lambda: window._job is None)
        assert called[0][:2] == (case['apk'].resolve(), str(case['project'].resolve()))
        assert called[0][2] == {'node_path': 'chosen node'}
        assert called[0][3] != app.thread()
        assert rendered and all(thread == app.thread() for thread in rendered)
        assert window.txt_analyze.toPlainText() == case['audit']['report']
        assert window._last_security_audit['apk_digest'] == sha(case['apk'])
        assert window.cmb_map_app.currentData() == 'logi'
        assert window.btn_security_audit.isEnabled()
    finally:
        release.set()
        timer.stop()


def test_audit_failure_keeps_previous_result(window, case, monkeypatch):
    accepted_audit(monkeypatch, case)
    monkeypatch.setattr(ui, 'load_rea_settings', lambda: {})
    window._last_security_audit = {'old': 'result'}
    window.txt_analyze.setPlainText('previous report')
    def failed(*args, **kwargs):
        raise RuntimeError('REA engine error')
    monkeypatch.setattr(ui, 'analyze_security_project', failed)
    window.run_security_audit()
    wait_for(lambda: window._job is None)
    assert window.txt_analyze.toPlainText() == 'previous report'
    assert window._last_security_audit == {'old': 'result'}
    assert 'REA engine error' in str(window._messages)


@pytest.mark.parametrize('mode', ['observe', 'boolean_false', 'skip_void'])
def test_generation_passes_explicit_mode_and_bound_fresh_inputs(window, case, tmp_path, monkeypatch, app, mode):
    accepted_generation(monkeypatch, mode)
    if mode == 'skip_void':
        choice = case['audit']['choices'][0]
        choice['modes'] = ['observe', 'skip_void']
        choice['dex_descriptor'] = choice['candidate']['dex_descriptor'] = '()V'
        choice['candidate']['modes'] = ['observe', 'skip_void']
        choice['class_evidence']['normalized_result']['methods'][0]['dex_descriptor'] = '()V'
    window._last_security_audit = case['audit']
    window.ed_analyze_apk.setText(str(case['apk']))
    monkeypatch.setattr(ui, 'load_rea_settings', lambda: {'node_path': 'selected'})
    fresh = {'status': 'complete', 'evidence': {'fresh': True}}
    package_threads, generated = [], []
    def package(*args, **kwargs):
        package_threads.append(QThread.currentThread())
        assert kwargs['operation'] == 'package'
        return fresh
    monkeypatch.setattr(ui, 'run_rea_analysis', package)
    diff = tmp_path / 'changes.diff'
    diff.write_text('reviewable generated changes')
    def generate(project, app_key, apk, evidence, method, overload, **kwargs):
        generated.append((project, app_key, apk, evidence, method, overload, kwargs, QThread.currentThread()))
        return {'path': str(tmp_path), 'manifest': str(tmp_path / 'manifest.json'),
                'report': {'mode': mode}, 'diff': str(diff), 'build_status': 'not_run'}
    monkeypatch.setattr(ui, 'generate_security_hook', generate)
    window.run_security_generation()
    wait_for(lambda: window._job is None)
    assert package_threads[0] != app.thread()
    assert generated[0][-1] != app.thread()
    assert generated[0][1:3] == ('logi', case['apk'])
    assert generated[0][4:6] == ('isRooted', 0)
    options = generated[0][6]
    assert options['mode'] == mode
    assert options['source_hashes'] == case['audit']['source_files']
    assert options['package_evidence'] == fresh['evidence']
    assert options['candidate']['id'] == 'candidate-1'
    assert window._last_generated_result['report']['mode'] == mode
    assert 'reviewable generated changes' in window.txt_map.toPlainText()
    assert window._last_build_result is None
    expected_label = {'observe': '보안 호출 관찰', 'boolean_false': '반환 false', 'skip_void': 'void 실행 생략'}[mode]
    assert expected_label in window.lbl_status.text()


@pytest.mark.parametrize('edited', ['apk', 'source'])
def test_stale_audit_is_rejected_before_package_or_generation(window, case, monkeypatch, edited):
    accepted_generation(monkeypatch)
    window._last_security_audit = case['audit']
    monkeypatch.setattr(ui, 'load_rea_settings', lambda: {})
    case[edited].write_text('edited after audit')
    called = []
    monkeypatch.setattr(ui, 'run_rea_analysis', lambda *a, **kw: called.append('package'))
    monkeypatch.setattr(ui, 'generate_security_hook', lambda *a, **kw: called.append('generate'))
    window.run_security_generation()
    wait_for(lambda: window._job is None)
    assert not called
    assert '바뀌' in str(window._messages)
    assert window._last_generated_result is None


def test_source_edit_during_fresh_package_query_is_rejected(window, case, monkeypatch):
    accepted_generation(monkeypatch)
    window._last_security_audit = case['audit']
    monkeypatch.setattr(ui, 'load_rea_settings', lambda: {})
    def package(*args, **kwargs):
        case['source'].write_text('modified while REA runs')
        return {'status': 'complete', 'evidence': {'fresh': True}}
    monkeypatch.setattr(ui, 'run_rea_analysis', package)
    generated = []
    monkeypatch.setattr(ui, 'generate_security_hook', lambda *a, **kw: generated.append(True))
    window.run_security_generation()
    wait_for(lambda: window._job is None)
    assert not generated
    assert '바뀌' in str(window._messages)


def test_unsupported_result_change_mode_is_not_silently_observed(window, case, monkeypatch):
    accepted_generation(monkeypatch, 'boolean_false')
    case['audit']['choices'][0]['modes'] = ['observe']
    window._last_security_audit = case['audit']
    monkeypatch.setattr(ui, 'load_rea_settings', lambda: {})
    calls = []
    monkeypatch.setattr(ui, 'generate_security_hook', lambda *a, **kw: calls.append(True))
    window.run_security_generation()
    assert not calls
    assert window._job is None
    assert '지원하는 생성 동작' in str(window._messages)


def test_selected_apk_must_match_cached_security_audit(window, case, tmp_path, monkeypatch):
    window._last_security_audit = case['audit']
    other = tmp_path / 'other.apk'
    other.write_bytes(b'other')
    window.ed_analyze_apk.setText(str(other))
    called = []
    monkeypatch.setattr(ui, 'SecurityGenerationDialog', lambda *a: called.append(True))
    window.run_security_generation()
    assert not called
    assert '현재 APK' in str(window._messages)


def test_missing_audit_asks_for_automatic_scan_instead_of_typed_target(window):
    window.run_security_generation()
    assert window._job is None
    assert '보안 자동 점검' in str(window._messages)


def test_void_skip_dialog_explains_that_the_original_body_is_not_executed(app, case):
    choice = copy.deepcopy(case['audit']['choices'][0])
    choice['modes'] = ['observe', 'skip_void']
    choice['dex_descriptor'] = choice['candidate']['dex_descriptor'] = '()V'
    dialog = SecurityGenerationDialog(case['apk'], case['project'], [choice])
    dialog.cmb_mode.setCurrentIndex(dialog.cmb_mode.findData('skip_void'))
    assert dialog.request()['mode'] == 'skip_void'
    assert '본문을 실행하지 않고' in dialog.lbl_mode.text()
    assert '부수 효과' in dialog.lbl_mode.text()
    assert '빌드 종류로 실행을 제한하지 않습니다' in dialog.lbl_mode.text()
    assert '디버그' not in dialog.lbl_mode.text()
    assert '디버그' not in dialog.cmb_mode.currentText()
    dialog.deleteLater()

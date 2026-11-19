# -*- coding: utf-8 -*-
"""Controllers for the L desktop workspace and its verified tool workflows."""

from __future__ import annotations

import json
import re
import subprocess
import sys
from datetime import datetime
from pathlib import Path

from PySide6.QtCore import Qt, QProcess, QTimer, QUrl, Slot
from PySide6.QtGui import QTextCursor, QDesktopServices
from PySide6.QtWidgets import (
    QApplication,
    QMainWindow,
    QMessageBox,
    QPushButton,
    QPlainTextEdit,
    QVBoxLayout,
    QListWidgetItem,
    QFileDialog,
    QLineEdit,
    QDialog,
)
from .config import APP_LABELS, DEFAULT_HOOKS, DRIVER_APPS
from .paths import apk_dir, app_dir, atomic_write_text, session_path
from .logs import is_interesting, summarize_lines, LogLineBuffer
from .analysis import analyze_apk_structure, diff_apk, format_analysis_report, jadx_xref, pick_deep_xref_symbols
from .adb import find_adb, run_adb_command, pull_package
from .state import find_modulemain, previous_snapshot

from .jobs import BackgroundJob
from .workflows import file_digest
from .workspace import WorkspaceLayoutMixin
from .processes import CancelledError
from .rea import load_rea_settings, save_rea_settings, rea_preflight, run_rea_analysis
from .rea_dialogs import REASettingsDialog, REAAnalysisDialog, ObserverGenerationDialog, EunoraAuditDialog, AuditObserverDialog
from .generator import load_profiles, list_observer_methods, generate_observer
from .build_validation import validate_generated_project
from .eunora_audit import run_eunora_audit as analyze_eunora_project
from .security_audit import run_security_audit as analyze_security_project
from .security_generator import generate_security_hook
from .security_dialogs import SecurityAuditDialog, SecurityGenerationDialog


class MainWindow(WorkspaceLayoutMixin, QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("L · EUNORA Workspace")
        self.resize(1260, 860)
        self.setMinimumSize(1000, 680)

        self.adb_path = find_adb()
        self.log_process: QProcess | None = None
        self._log_lines = LogLineBuffer()
        self._job = None
        self._job_success = None
        self._job_result = None
        self._job_error = None
        self._job_cancelled = False
        self._closing_after_job = False
        self._workspace_revision = 0
        self._job_revision = None
        self._generation_ready = False
        self.capturing = False
        self.session_lines: list[str] = []
        self.session_dir = app_dir() / "sessions"
        self.session_dir.mkdir(exist_ok=True)
        self.hooks_path = app_dir() / "hooks.json"
        self.hooks = self.load_hooks()
        self._apk_added: list[str] = []
        self.last_pull: dict[str, Path] = {}
        self._last_pull_stamp = ""
        self._rea_last_request = {}
        self._last_rea_evidence = None
        self._last_rea_result = None
        self._last_rea_class_result = None
        self._last_generated_result = None
        self._last_build_result = None
        self._generator_last_project = ""
        self._rea_settings_dialog = None
        self._last_eunora_audit = None
        self._last_security_audit = None

        self._build_ui()
        self.ed_analyze_apk.textChanged.connect(self._workspace_inputs_changed)
        self.ed_project.textChanged.connect(self._workspace_inputs_changed)
        self.cmb_analysis_mode.currentIndexChanged.connect(self._workspace_inputs_changed)
        self.refresh_devices()
        self.reload_session_list()
        self.auto_fill_modulemain(silent=True)
        if self._hooks_load_error:
            self.lbl_status.setText("기존 로그 규칙 파일 확인 필요: " + str(self._hooks_load_error)[:160])
        self._refresh_action_state()


    def _start_job(self, label, work, on_success, *, context_sensitive=False) -> bool:
        if self._job is not None or self._closing_after_job:
            self.lbl_status.setText("다른 작업이 진행 중입니다")
            return False
        self._job_success = on_success
        self._job_result = None
        self._job_error = None
        self._job_cancelled = False
        self._job_revision = self._workspace_revision if context_sensitive else None
        worker = BackgroundJob(work, self)
        self._job = worker
        worker.progress.connect(self._on_job_progress)
        worker.succeeded.connect(self._on_job_result)
        worker.failed.connect(self._on_job_error)
        worker.cancelled.connect(self._on_job_cancelled)
        worker.finished.connect(self._on_job_finished)
        self.set_busy(True)
        self._refresh_action_state()
        self.lbl_status.setText(label)
        worker.start()
        return True

    @Slot(str)
    def _on_job_progress(self, message):
        if not self._closing_after_job:
            self.lbl_status.setText(message)

    @Slot(object)
    def _on_job_result(self, result):
        self._job_result = result

    @Slot(str)
    def _on_job_error(self, message):
        self._job_error = message

    @Slot()
    def _on_job_cancelled(self):
        self._job_cancelled = True

    @Slot()
    def _on_job_finished(self):
        worker = self._job
        callback, result, error = self._job_success, self._job_result, self._job_error
        stale = self._job_revision is not None and self._job_revision != self._workspace_revision
        cancelled = self._job_cancelled
        self._job = None
        self._job_revision = None
        self._job_success = None
        if worker is not None:
            worker.wait()
            worker.deleteLater()
        self.set_busy(False)
        if self._closing_after_job:
            QTimer.singleShot(0, self.close)
            return
        if stale:
            self.lbl_status.setText("입력이 바뀌어 이전 작업 결과를 사용하지 않았습니다")
        elif error:
            self.lbl_status.setText("작업 실패")
            QMessageBox.critical(self, "L", error)
        elif cancelled:
            self.lbl_status.setText("작업 취소")
        elif callback:
            try:
                callback(result)
            except Exception as failure:
                self.lbl_status.setText("결과 표시 실패")
                QMessageBox.critical(self, "L", str(failure))
        self._refresh_action_state()

    def _consume_log_output(self, final=False):
        process = self.log_process
        data = bytes(process.readAllStandardOutput()) if process is not None else b""
        for line in self._log_lines.feed(data, final=final):
            line = line.rstrip()
            if line and is_interesting(line, self.cmb_filter.currentIndex()):
                self._append_log(line)
                if self.capturing:
                    self.session_lines.append(line)









    def _workspace_inputs_changed(self, *_args) -> None:
        self._workspace_revision += 1
        self._generation_ready = False
        self._last_eunora_audit = None
        self._last_security_audit = None
        self._last_generated_result = None
        self._last_build_result = None
        self._last_rea_class_result = None
        self._last_rea_evidence = None
        self._last_rea_result = None
        self._last_analysis_result = None
        self._last_analysis_text = ""
        self._generator_last_project = self.ed_project.text().strip()
        self.txt_analyze.clear()
        self.txt_map.clear()
        self.list_generated_files.clear()
        self.list_generated_files.setVisible(False)
        self.tbl_findings.setRowCount(0)
        self.tbl_findings.setVisible(True)
        self.audit_stats.setVisible(False)
        self.set_analysis_details_visible(False)
        self.set_generation_details_visible(False)
        self._raw_kind = "analysis"
        self.result_tabbar.setCurrentIndex(0)
        self._select_result_view(0)
        self.lbl_result_title.setText("결과")
        self._set_result_pill("대기")
        self.lbl_output_path.setText("")
        self.lbl_output_path.setVisible(False)
        if self._job is not None and self._job_revision is not None:
            self._job.cancel()
            self.lbl_status.setText("입력이 변경되어 이전 작업을 정리하고 있습니다")
        self._refresh_action_state()

    def _refresh_action_state(self) -> None:
        busy = self._job is not None or self._closing_after_job
        for button in self.findChildren(QPushButton):
            if button.property("long_job"):
                button.setEnabled(not busy)
        apk = self.ed_analyze_apk.text().strip()
        project = self.ed_project.text().strip()
        inputs_ready = bool(apk and project and Path(apk).is_file() and Path(project).exists())
        self.btn_run_audit.setEnabled(not busy and inputs_ready)
        audit = self._last_security_audit if self.cmb_analysis_mode.currentData() == "security" else self._last_eunora_audit
        self.btn_generate_hook.setEnabled(not busy and self._generation_ready and bool(audit))
        generated = self._last_generated_result
        self.btn_build_generated.setEnabled(not busy and bool(generated and generated.get("manifest")))
        self.btn_open_generated.setEnabled(bool(generated and generated.get("path")))
        self.btn_view_changes.setEnabled(bool(generated))
        self.btn_cancel_job.setEnabled(busy and self._job is not None)
        observer = getattr(self, "btn_observer_generate", None)
        if observer is not None:
            observer.setEnabled(not busy and bool(self._last_rea_class_result))

    def run_workspace_audit(self) -> None:
        if self.cmb_analysis_mode.currentData() == "security":
            self.run_security_audit(inline=True)
        else:
            self.run_eunora_audit(inline=True)

    def run_workspace_generation(self) -> None:
        if self.cmb_analysis_mode.currentData() == "security":
            self.run_security_generation()
        else:
            self.run_audit_generation()

    def browse_project(self) -> None:
        path = QFileDialog.getExistingDirectory(self, "EUNORA 프로젝트 선택", self.ed_project.text().strip())
        if path:
            self.ed_project.setText(path)

    def cancel_current_job(self) -> None:
        if self._job is not None:
            self._job.cancel()
            self.lbl_status.setText("작업을 취소하고 있습니다…")

    def _open_local_path(self, path) -> None:
        target = Path(path).expanduser()
        if not target.exists():
            QMessageBox.warning(self, "L", "파일이나 폴더를 찾을 수 없습니다.")
            return
        if not QDesktopServices.openUrl(QUrl.fromLocalFile(str(target.resolve()))):
            QMessageBox.warning(self, "L", f"경로를 열지 못했습니다.\n{target}")

    def open_generated_folder(self) -> None:
        if self._last_generated_result and self._last_generated_result.get("path"):
            self._open_local_path(self._last_generated_result["path"])

    def open_generated_file(self, item) -> None:
        if not self._last_generated_result:
            return
        path = item.data(Qt.ItemDataRole.UserRole)
        if not path:
            return
        target = Path(path).resolve()
        root = Path(self._last_generated_result["path"]).resolve()
        if target.is_relative_to(root) and target.suffix.lower() in {".kt", ".txt", ".json", ".diff", ".log"}:
            self._open_local_path(target)

    def _show_text_details(self, title, text) -> None:
        dialog = QDialog(self)
        dialog.setWindowTitle(title)
        dialog.resize(920, 650)
        layout = QVBoxLayout(dialog)
        view = QPlainTextEdit()
        view.setReadOnly(True)
        view.setPlainText(text or "표시할 결과가 없습니다.")
        layout.addWidget(view)
        close = QPushButton("닫기")
        close.clicked.connect(dialog.accept)
        layout.addWidget(close, 0, Qt.AlignmentFlag.AlignRight)
        dialog.exec()

    def show_generation_details(self) -> None:
        self._show_text_details("생성 코드와 변경 내역", self.txt_map.toPlainText())

    def show_analysis_details(self) -> None:
        self._show_text_details("분석 결과 상세", self._last_analysis_text or self.txt_analyze.toPlainText())

    def _present_manual_analysis(self, title) -> None:
        self.lbl_result_title.setText(title)
        self._set_result_pill("상세 분석", "info")
        self.audit_stats.setVisible(False)
        self.tbl_findings.setVisible(False)
        self.list_generated_files.setVisible(False)
        self.lbl_output_path.setVisible(False)
        self.set_analysis_details_visible(True)
        self.navigate("workspace")

    def open_data_folder(self) -> None:
        self._open_local_path(app_dir())

    def open_apks_dir(self) -> None:
        path = str(apk_dir())
        if sys.platform == "win32":
            subprocess.Popen(["explorer", path])
        else:
            subprocess.Popen(["xdg-open", path])

    def _pull_one_package(self, serial: str, app_key: str, stamp: str) -> str:
        # Compatibility helper; all GUI actions use the asynchronous batch below.
        return pull_package(self.adb_path, serial, app_key, stamp)["report"]

    def pull_driver_apks(self) -> None:
        serial = self.current_device()
        if not serial:
            QMessageBox.warning(self, "L", "기기를 연결하고 기기 로그 화면에서 선택하세요")
            return
        choice = self.cmb_pull_app.currentData() or "all"
        keys = list(DRIVER_APPS) if choice == "all" else [choice]
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        adb_path = self.adb_path
        def work(progress):
            results = []
            for key in keys:
                progress(f"추출 중 {APP_LABELS.get(key, key)}")
                results.append(pull_package(adb_path, serial, key, stamp, progress=progress))
            return results
        def done(results):
            self._last_pull_stamp = stamp
            reports = [f"추출 {stamp}  device={serial}"]
            successful = {}
            for result in results:
                reports.append(result["report"])
                if result.get("base_path"):
                    successful[result["app_key"]] = result["base_path"]
            self.last_pull = successful
            self.txt_pull.setPlainText("\n".join(reports))
            if successful:
                key, first = next(iter(successful.items()))
                self.ed_analyze_apk.setText(str(first))
                self.ed_apk_new.setText(str(first))
                previous = previous_snapshot(key, first.parent.name)
                self.ed_apk_old.setText(str(previous) if previous else "")
            self.lbl_status.setText(f"추출 완료 — base APK {len(successful)}/{len(results)}")
        self._start_job("APK 추출 중…", work, done, context_sensitive=True)

    def diff_last_pull_against_previous(self) -> None:
        if not self.last_pull:
            QMessageBox.information(self, "L", "먼저 폰에서 APK를 추출하세요")
            return
        choice = self.cmb_pull_app.currentData() or "all"
        selected = [(key, path) for key, path in self.last_pull.items() if choice in ("all", key)]
        def work(progress):
            lines, latest = [], None
            for key, new_path in selected:
                progress(f"이전 APK 비교 중 {APP_LABELS.get(key, key)}")
                old_path = previous_snapshot(key, new_path.parent.name)
                if not old_path:
                    lines.append(f"[{APP_LABELS[key]}] 이전 스냅샷 없음")
                    continue
                result = diff_apk(old_path, new_path)
                lines.append(f"[{APP_LABELS[key]}] {old_path.parent.name} → {new_path.parent.name}  +{len(result['added'])} -{len(result['removed'])}")
                latest = key, old_path, new_path, result
            return lines, latest
        def done(value):
            lines, latest = value
            if lines:
                self.txt_pull.appendPlainText("\n" + "\n".join(lines))
            if latest:
                key, old_path, new_path, result = latest
                self.ed_apk_old.setText(str(old_path))
                self.ed_apk_new.setText(str(new_path))
                self.cmb_apk_app.setCurrentIndex(max(0, self.cmb_apk_app.findData(key)))
                self._show_apk_diff(result)
            else:
                self.lbl_status.setText("비교할 이전 APK 없음")
        self._start_job("이전 APK 비교 중…", work, done)

    def _pick_apk(self, target: QLineEdit) -> None:
        path, _ = QFileDialog.getOpenFileName(self, "APK 선택", "", "APK (*.apk);;All (*.*)")
        if path:
            target.setText(path)

    def _show_apk_diff(self, result):
        self.list_apk_added.clear()
        self.list_apk_removed.clear()
        self._apk_added = result["added"]
        self.list_apk_added.addItems(result["added"])
        self.list_apk_removed.addItems(result["removed"])
        self.lbl_apk_info.setText(
            f"이전 문자열 {result['old_count']} / 새 {result['new_count']}  |  "
            f"추가 {len(result['added'])}  삭제 {len(result['removed'])}"
        )
        self.lbl_status.setText("APK 문자열 비교 완료 — 실행 검증 아님")

    def run_apk_diff(self) -> None:
        old_path = Path(self.ed_apk_old.text().strip())
        new_path = Path(self.ed_apk_new.text().strip())
        if not old_path.is_file() or not new_path.is_file():
            QMessageBox.warning(self, "L", "이전/새 APK 경로를 확인하세요")
            return
        if self._start_job("APK 비교 중…", lambda progress: diff_apk(old_path, new_path), self._show_apk_diff):
            self.lbl_apk_info.setText("비교 중…")


    def browse_analyze_apk(self) -> None:
        path, _ = QFileDialog.getOpenFileName(self, "APK 선택", "", "APK (*.apk);;All (*.*)")
        if path:
            self.ed_analyze_apk.setText(path)

    def run_structure_analysis(self) -> None:
        path = Path(self.ed_analyze_apk.text().strip())
        if not path.is_file():
            QMessageBox.warning(self, "L", "APK 파일을 선택하세요")
            return
        package_filter = self.ed_pkg_filter.text().strip()
        def work(progress):
            result = analyze_apk_structure(path, package_filter=package_filter)
            return result, format_analysis_report(result)
        def done(value):
            result, report = value
            self._last_analysis_result = result
            self._last_analysis_text = report
            self.txt_analyze.setPlainText(report)
            self._present_manual_analysis("구조 분석 결과")
            self.lbl_status.setText(
                f"정적 구조 분석 완료 — 후보 {len(result.get('flags') or [])}개, "
                f"문자열 {result.get('string_count', 0)}"
            )
        self._start_job("구조 분석 중…", work, done, context_sensitive=True)

    def save_analysis_report(self) -> None:
        text = self._last_analysis_text or self.txt_analyze.toPlainText()
        self._save_report_text(text, "apk_analysis.txt")

    def save_visible_report(self) -> None:
        if self._raw_kind == "generation":
            self._save_report_text(self.txt_map.toPlainText(), "generated_report.txt")
        else:
            self.save_analysis_report()

    def _save_report_text(self, text, filename) -> None:
        if not text.strip():
            QMessageBox.information(self, "L", "먼저 분석을 실행하세요")
            return
        path, _ = QFileDialog.getSaveFileName(
            self, "보고서 저장", str(app_dir() / "sessions" / filename), "Text (*.txt);;All (*.*)"
        )
        if not path:
            return
        try:
            atomic_write_text(Path(path), text)
        except OSError as error:
            self.lbl_status.setText("보고서 저장 실패")
            QMessageBox.critical(self, "L", f"저장 실패: {error}")
            return
        QMessageBox.information(self, "L", f"저장됨:\n{path}")



    def run_deep_analysis(self) -> None:
        path = Path(self.ed_analyze_apk.text().strip())
        if not path.is_file():
            QMessageBox.warning(self, "L", "APK 파일을 선택하세요")
            return
        package_filter = self.ed_pkg_filter.text().strip()
        def work(progress):
            progress("심화 분석 1/2 — 구조 분석…")
            result = analyze_apk_structure(path, package_filter=package_filter)
            report = format_analysis_report(result)
            symbols = pick_deep_xref_symbols(result, limit=30)
            report += "\n\n======== 자동 선정 XREF 심볼 ========\n" + "\n".join(f"  - {x}" for x in symbols)
            if not symbols:
                return result, report, "심화 분석 — 선정 심볼 없음"
            progress(f"심화 분석 2/2 — jadx XREF ({len(symbols)}개 심볼)…")
            xref = jadx_xref(path, symbols)
            report += "\n\n======== jadx XREF (자동) ========\n" + xref
            status = "심화 분석 완료 (jadx 진단 — 하단 확인)" if xref.startswith("[jadx") else f"심화 분석 완료 — XREF {len(symbols)}심볼"
            return result, report, status
        def done(value):
            result, report, status = value
            self._last_analysis_result = result
            self._last_analysis_text = report
            self.txt_analyze.setPlainText(report)
            self._present_manual_analysis("심화 분석 결과")
            self.lbl_status.setText(status)
        self._start_job("심화 분석 준비…", work, done, context_sensitive=True)

    def run_jadx_xref(self) -> None:
        path = Path(self.ed_analyze_apk.text().strip())
        if not path.is_file():
            QMessageBox.warning(self, "L", "APK 파일을 선택하세요")
            return
        raw = self.ed_xref_symbols.text().strip()
        symbols = [x.strip() for x in re.split(r"[,\s]+", raw) if x.strip()] if raw else pick_deep_xref_symbols(self._last_analysis_result or {}, limit=30)
        if not symbols:
            QMessageBox.information(self, "L", "먼저 전체 구조 분석을 하거나 XREF 심볼을 입력하세요.")
            return
        prior = self._last_analysis_text or ""
        def done(report):
            combined = prior + "\n\n======== jadx XREF ========\n" + report
            self._last_analysis_text = combined
            self.txt_analyze.setPlainText(combined)
            self._present_manual_analysis("참조 분석 결과")
            self.lbl_status.setText("jadx 진단 — 결과 확인" if report.startswith("[jadx") else "jadx XREF 완료")
        self._start_job("jadx XREF 실행 중…", lambda progress: jadx_xref(path, symbols), done, context_sensitive=True)

    def run_eunora_audit(self, *, inline=False) -> None:
        if self._job is not None:
            self.lbl_status.setText("다른 작업이 진행 중입니다")
            return
        if inline:
            request = {"apk_path": self.ed_analyze_apk.text().strip(), "project_path": self.ed_project.text().strip()}
        else:
            dialog = EunoraAuditDialog(
                self.ed_analyze_apk.text().strip(),
                self._generator_last_project or self.ed_project.text().strip(), self,
            )
            if dialog.exec() != QDialog.DialogCode.Accepted:
                return
            request = dict(dialog.request())
        path = Path(request.get("apk_path") or "").expanduser()
        project = request.get("project_path") or ""
        if not path.is_file() or not project or not Path(project).expanduser().exists():
            QMessageBox.warning(self, "L", "APK와 EUNORA 프로젝트 폴더 또는 ModuleMain.kt를 선택하세요.")
            return
        path = path.resolve()
        project = str(Path(project).expanduser().resolve())
        try:
            settings = json.loads(json.dumps(load_rea_settings()))
        except Exception as error:
            QMessageBox.critical(self, "L", f"REA 설정 읽기 실패: {error}")
            return
        self.ed_analyze_apk.setText(str(path))
        self.ed_project.setText(project)
        self._generator_last_project = project
        def work(progress):
            result = analyze_eunora_project(path, project, settings=settings, progress=progress)
            if not isinstance(result, dict) or not isinstance(result.get("report"), str) or not result["report"].strip():
                raise RuntimeError("EUNORA 점검이 유효한 결과를 반환하지 않았습니다")
            if result.get("app_key") not in DRIVER_APPS:
                raise RuntimeError("점검 결과의 앱 종류를 확인할 수 없습니다")
            if Path(result.get("apk_path") or "").resolve() != path:
                raise RuntimeError("점검 결과의 APK가 선택한 파일과 다릅니다")
            return result
        def done(result):
            snapshot = json.loads(json.dumps(result))
            self._last_eunora_audit = snapshot
            self._last_analysis_text = snapshot["report"]
            self._last_analysis_result = None
            self.txt_analyze.setPlainText(snapshot["report"])
            for name in ("cmb_map_app", "cmb_apk_app"):
                combo = getattr(self, name)
                index = combo.findData(snapshot["app_key"])
                if index >= 0:
                    combo.setCurrentIndex(index)
            self._generation_ready = bool(self._audit_generation_choices(snapshot))
            self.show_audit_summary("existing", snapshot)
            self.lbl_status.setText("EUNORA 정적 점검 완료 — 결과와 추가 확인 항목을 확인하세요")
        self._start_job("EUNORA APK·기존 소스 자동 점검 중…", work, done, context_sensitive=True)

    @staticmethod
    def _audit_generation_choices(audit):
        choices, seen = [], set()
        for result in audit.get("class_results") or []:
            if not isinstance(result, dict) or result.get("status") not in {"complete", "partial"}:
                continue
            evidence = result.get("evidence")
            if not isinstance(evidence, dict):
                continue
            try:
                methods = list_observer_methods(evidence)
            except (ValueError, TypeError, KeyError):
                continue
            target = result.get("target") or {}
            method_names = target.get("methods") or []
            class_name = evidence.get("normalized_result", {}).get("class_name", "")
            for method in methods:
                if method_names and method.get("name") not in method_names:
                    continue
                key = (class_name, method.get("name"), method.get("dex_descriptor"))
                if key in seen:
                    continue
                seen.add(key)
                choices.append({
                    "class_name": class_name, "method": dict(method), "evidence": evidence,
                    "label": f"{class_name} — {method['label']}",
                })
        return choices

    @staticmethod
    def _assert_audit_inputs(audit):
        """Run only in a worker: reject stale APK/source evidence before generation."""
        apk = Path(audit.get("apk_path") or "").expanduser().resolve()
        project = Path(audit.get("project_root") or "").expanduser().resolve()
        sources = audit.get("source_files")
        if not apk.is_file() or file_digest(apk) != audit.get("apk_digest"):
            raise RuntimeError("점검 후 APK가 바뀌었거나 없어졌습니다. EUNORA 자동 점검을 다시 실행하세요.")
        if not project.is_dir() or not isinstance(sources, dict) or not sources:
            raise RuntimeError("점검한 EUNORA 원본 기록이 없습니다. 자동 점검을 다시 실행하세요.")
        for name, expected in sources.items():
            if not isinstance(name, str) or not isinstance(expected, str):
                raise RuntimeError("점검한 원본 기록의 형식이 잘못되었습니다. 자동 점검을 다시 실행하세요.")
            source = (project / name).resolve()
            if not source.is_relative_to(project) or not source.is_file() or file_digest(source) != expected:
                raise RuntimeError("점검 후 EUNORA 원본 코드가 바뀌었거나 없어졌습니다. 자동 점검을 다시 실행하세요.")

    def run_audit_generation(self) -> None:
        if self._job is not None:
            self.lbl_status.setText("다른 작업이 진행 중입니다")
            return
        if not self._last_eunora_audit:
            QMessageBox.information(self, "L", "EUNORA 자동 점검을 먼저 실행하세요. 클래스·메서드 이름을 따로 입력할 필요가 없습니다.")
            return
        try:
            audit = json.loads(json.dumps(self._last_eunora_audit))
            current_apk = self.ed_analyze_apk.text().strip()
            if current_apk and Path(current_apk).expanduser().resolve() != Path(audit["apk_path"]).resolve():
                QMessageBox.warning(self, "L", "선택한 APK가 점검 결과와 다릅니다. 현재 APK로 EUNORA 자동 점검을 다시 실행하세요.")
                return
            choices = self._audit_generation_choices(audit)
            settings = json.loads(json.dumps(load_rea_settings()))
        except Exception as error:
            QMessageBox.critical(self, "L", f"점검 근거 확인 실패: {error}")
            return
        if not choices:
            QMessageBox.information(self, "L", "점검에서 코드 생성에 사용할 정확한 메서드 정보를 확보하지 못했습니다. 결과의 미발견·추가 확인 항목을 확인하세요.")
            return
        dialog = AuditObserverDialog(audit["apk_path"], audit["project_root"], choices, self)
        if dialog.exec() != QDialog.DialogCode.Accepted:
            return
        index = dialog.request().get("choice_index")
        if not isinstance(index, int) or isinstance(index, bool) or not 0 <= index < len(choices):
            QMessageBox.warning(self, "L", "점검에서 확인된 메서드를 하나 선택하세요.")
            return
        selected = json.loads(json.dumps(choices[index]))
        def work(progress):
            progress("점검한 APK와 EUNORA 원본이 유지되는지 확인 중…")
            self._assert_audit_inputs(audit)
            apk = Path(audit["apk_path"])
            package = run_rea_analysis(apk, settings=settings, operation="package", progress=progress)
            if package.get("status") not in {"complete", "partial"} or not package.get("evidence"):
                raise RuntimeError("현재 APK 패키지 근거를 확인하지 못해 코드를 생성할 수 없습니다")
            self._assert_audit_inputs(audit)
            method = selected["method"]
            progress("점검에서 확인된 메서드의 관찰 코드 생성 중…")
            result = generate_observer(
                audit["project_root"], audit["app_key"], apk, selected["evidence"],
                method["name"], method["overload_index"], package_evidence=package["evidence"],
            )
            result["diff_text"] = Path(result["diff"]).read_text(encoding="utf-8")
            return result
        self._start_job("EUNORA 점검 결과로 관찰 코드 생성 중…", work, self._show_generated_result, context_sensitive=True)

    def run_security_audit(self, *, inline=False) -> None:
        if self._job is not None:
            self.lbl_status.setText("다른 작업이 진행 중입니다")
            return
        if inline:
            request = {"apk_path": self.ed_analyze_apk.text().strip(), "project_path": self.ed_project.text().strip()}
        else:
            dialog = SecurityAuditDialog(
                self.ed_analyze_apk.text().strip(),
                self._generator_last_project or self.ed_project.text().strip(), self,
            )
            if dialog.exec() != QDialog.DialogCode.Accepted:
                return
            request = dict(dialog.request())
        path = Path(request.get("apk_path") or "").expanduser()
        project = request.get("project_path") or ""
        if not path.is_file() or not project or not Path(project).expanduser().exists():
            QMessageBox.warning(self, "L", "APK와 EUNORA 프로젝트 폴더 또는 ModuleMain.kt를 선택하세요.")
            return
        path = path.resolve()
        project = str(Path(project).expanduser().resolve())
        try:
            settings = json.loads(json.dumps(load_rea_settings()))
        except Exception as error:
            QMessageBox.critical(self, "L", f"REA 설정 읽기 실패: {error}")
            return
        self.ed_analyze_apk.setText(str(path))
        self.ed_project.setText(project)
        self._generator_last_project = project
        def work(progress):
            result = analyze_security_project(path, project, settings=settings, progress=progress)
            if (not isinstance(result, dict) or result.get("status") not in {"complete", "partial"}
                    or not isinstance(result.get("report"), str) or not result["report"].strip()):
                raise RuntimeError("보안 점검이 유효한 결과를 반환하지 않았습니다")
            if result.get("app_key") not in DRIVER_APPS:
                raise RuntimeError("보안 점검 결과의 앱 종류를 확인할 수 없습니다")
            if Path(result.get("apk_path") or "").resolve() != path:
                raise RuntimeError("보안 점검 결과의 APK가 선택한 파일과 다릅니다")
            return result
        def done(result):
            snapshot = json.loads(json.dumps(result))
            self._last_security_audit = snapshot
            self._last_analysis_text = snapshot["report"]
            self._last_analysis_result = None
            self.txt_analyze.setPlainText(snapshot["report"])
            for name in ("cmb_map_app", "cmb_apk_app"):
                combo = getattr(self, name)
                index = combo.findData(snapshot["app_key"])
                if index >= 0:
                    combo.setCurrentIndex(index)
            self._generation_ready = bool(self._security_generation_choices(snapshot))
            self.show_audit_summary("security", snapshot)
            self.lbl_status.setText("보안 정적 점검 완료 — 후보와 미확인 범위를 확인하세요")
        self._start_job("APK 보안 검사 후보 자동 점검 중…", work, done, context_sensitive=True)

    @staticmethod
    def _security_generation_choices(audit):
        choices = []
        for value in audit.get("choices") or []:
            if not isinstance(value, dict):
                continue
            choice = dict(value)
            evidence = choice.get("class_evidence")
            if not isinstance(evidence, dict):
                evidence = (choice.get("class_result") or {}).get("evidence")
            candidate = choice.get("candidate")
            modes = [mode for mode in (choice.get("modes") or []) if mode in {"observe", "boolean_false", "skip_void"}]
            if (not isinstance(evidence, dict) or not isinstance(candidate, dict) or not modes
                    or not isinstance(choice.get("method_name"), str)
                    or not isinstance(choice.get("overload_index"), int)
                    or isinstance(choice.get("overload_index"), bool)):
                continue
            choice["class_evidence"] = evidence
            choice["modes"] = modes
            choices.append(choice)
        return choices

    @staticmethod
    def _assert_security_inputs(audit):
        try:
            MainWindow._assert_audit_inputs(audit)
        except RuntimeError as error:
            raise RuntimeError(str(error).replace("EUNORA 자동 점검", "보안 자동 점검").replace("자동 점검을 다시", "보안 점검을 다시")) from error

    def run_security_generation(self) -> None:
        if self._job is not None:
            self.lbl_status.setText("다른 작업이 진행 중입니다")
            return
        if not self._last_security_audit:
            QMessageBox.information(self, "L", "보안 자동 점검을 먼저 실행하세요. 클래스·메서드 이름은 직접 입력하지 않습니다.")
            return
        try:
            audit = json.loads(json.dumps(self._last_security_audit))
            current_apk = self.ed_analyze_apk.text().strip()
            if current_apk and Path(current_apk).expanduser().resolve() != Path(audit["apk_path"]).resolve():
                QMessageBox.warning(self, "L", "선택한 APK가 보안 점검 결과와 다릅니다. 현재 APK로 보안 자동 점검을 다시 실행하세요.")
                return
            choices = self._security_generation_choices(audit)
            settings = json.loads(json.dumps(load_rea_settings()))
        except Exception as error:
            QMessageBox.critical(self, "L", f"보안 점검 근거 확인 실패: {error}")
            return
        if not choices:
            QMessageBox.information(self, "L", "코드 생성에 사용할 정확한 보안 검사 메서드를 확보하지 못했습니다. 점검 결과의 보류·지원 범위를 확인하세요.")
            return
        dialog = SecurityGenerationDialog(audit["apk_path"], audit["project_root"], choices, self)
        if dialog.exec() != QDialog.DialogCode.Accepted:
            return
        request = dict(dialog.request())
        index, mode = request.get("choice_index"), request.get("mode")
        if not isinstance(index, int) or isinstance(index, bool) or not 0 <= index < len(choices):
            QMessageBox.warning(self, "L", "점검에서 확인된 메서드를 하나 선택하세요.")
            return
        selected = json.loads(json.dumps(choices[index]))
        if mode not in {"observe", "boolean_false", "skip_void"} or mode not in selected["modes"]:
            QMessageBox.warning(self, "L", "이 대상에서 지원하는 생성 동작을 선택하세요.")
            return
        def work(progress):
            progress("보안 점검의 APK와 EUNORA 원본 확인 중…")
            self._assert_security_inputs(audit)
            apk = Path(audit["apk_path"])
            package = run_rea_analysis(apk, settings=settings, operation="package", progress=progress)
            if package.get("status") not in {"complete", "partial"} or not package.get("evidence"):
                raise RuntimeError("현재 APK 패키지 근거를 확인하지 못해 보안 코드를 생성할 수 없습니다")
            self._assert_security_inputs(audit)
            labels = {
                "observe": "호출 관찰 코드 생성 중…",
                "boolean_false": "Boolean 결과 변경 테스트 코드 생성 중…",
                "skip_void": "void 검사 실행 생략 테스트 코드 생성 중…",
            }
            progress(labels[mode])
            result = generate_security_hook(
                audit["project_root"], audit["app_key"], apk, selected["class_evidence"],
                selected["method_name"], selected["overload_index"], mode=mode,
                package_evidence=package["evidence"], source_hashes=audit["source_files"],
                candidate=selected["candidate"], method_evidence=selected.get("method_evidence"),
            )
            result["diff_text"] = Path(result["diff"]).read_text(encoding="utf-8")
            return result
        def done(result):
            self._show_generated_result(result)
            labels = {"observe": "보안 호출 관찰", "boolean_false": "보안 테스트: 반환 false", "skip_void": "보안 테스트: void 실행 생략"}
            self.lbl_status.setText(labels[mode] + " 생성본 저장 — 빌드 미실행")
        self._start_job("보안 점검 결과로 선택한 테스트 코드 생성 중…", work, done, context_sensitive=True)

    @staticmethod
    def _generated_result_text(result):
        state = {"not_run": "미실행", "passed": "통과", "failed": "실패"}.get(
            result.get("build_status", "not_run"), "미실행"
        )
        summary = json.dumps(result["report"], ensure_ascii=False, indent=2, default=str)
        return f"생성본 폴더: {result['path']}\n빌드 상태: {state}\n\n{summary}\n\n======== 변경 사항 ========\n{result['diff_text']}"

    def _show_generated_result(self, result):
        self._last_generated_result = result
        self._last_build_result = None
        self.txt_map.setPlainText(self._generated_result_text(result))
        self.show_generated_summary(result)
        self.navigate("workspace")
        self._refresh_action_state()
        self.lbl_status.setText("생성본 저장 — 빌드 미실행")

    def configure_rea(self) -> None:
        if self._job is not None:
            self.lbl_status.setText("다른 작업이 진행 중입니다")
            return
        try:
            settings = load_rea_settings()
        except Exception as error:
            QMessageBox.critical(self, "L", f"REA 설정 읽기 실패: {error}")
            return
        dialog = REASettingsDialog(settings, self)
        self._rea_settings_dialog = dialog
        if settings.get("_load_error"):
            dialog.set_preflight_error(settings["_load_error"])
        dialog.checkRequested.connect(lambda value: self._check_rea_settings(dialog, value))
        if dialog.exec() != QDialog.DialogCode.Accepted:
            return
        try:
            save_rea_settings(dialog.settings())
        except Exception as error:
            QMessageBox.critical(self, "L", f"REA 설정 저장 실패: {error}")
            return
        self.lbl_status.setText("REA 설정 저장 — 도구 준비 상태는 사전 검사로 확인")

    def _check_rea_settings(self, dialog, settings) -> None:
        settings = json.loads(json.dumps(settings))
        def work(progress):
            progress("REA 도구 사전 검사 중…")
            try:
                return rea_preflight(settings)
            except CancelledError:
                raise
            except Exception as error:
                return {"ready": False, "status": "error", "errors": [str(error)]}
        def done(result):
            if dialog.isVisible():
                dialog.set_preflight_result(result)
            self.lbl_status.setText("REA 사전 검사 완료 — 준비됨" if result.get("ready") else "REA 사전 검사 완료 — 설정 확인 필요")
        if not self._start_job("REA 도구 사전 검사 중…", work, done):
            dialog.set_preflight_error("다른 작업이 진행 중입니다")
            return
        worker = self._job
        # The existing window-owned job boundary also owns cancellation here.
        dialog.finished.connect(lambda result: worker.cancel() if self._job is worker else None)

    def run_rea(self) -> None:
        if self._job is not None:
            self.lbl_status.setText("다른 작업이 진행 중입니다")
            return
        path = Path(self.ed_analyze_apk.text().strip())
        if not path.is_file():
            QMessageBox.warning(self, "L", "APK 파일을 선택하세요")
            return
        path = path.resolve()
        try:
            settings = load_rea_settings()
        except Exception as error:
            QMessageBox.critical(self, "L", f"REA 설정 읽기 실패: {error}")
            return
        dialog = REAAnalysisDialog(path, self._rea_last_request, self)
        if dialog.exec() != QDialog.DialogCode.Accepted:
            return
        request = dialog.request()
        self._rea_last_request = dict(request)
        settings = json.loads(json.dumps(settings))
        def work(progress):
            return run_rea_analysis(path, settings=settings, progress=progress, **request)
        def done(result):
            if result.get("status") not in {"complete", "partial"} or not isinstance(result.get("report"), str) or not result["report"].strip():
                raise RuntimeError("REA가 유효한 분석 결과를 반환하지 않았습니다")
            report = str(result.get("report") or "")
            self._last_analysis_text = report
            self._last_analysis_result = None
            self._last_rea_evidence = result.get("evidence")
            self._last_rea_result = {**result, "apk_path": str(path), "request": dict(request)}
            if request["operation"] == "class":
                self._last_rea_class_result = json.loads(json.dumps(self._last_rea_result))
            self.txt_analyze.setPlainText(report)
            self._present_manual_analysis("REA 조회 결과")
            state = "부분 결과" if result.get("status") == "partial" else "완료"
            self.lbl_status.setText(f"REA 정적 분석 {state} — 기기 실행 검증 아님")
        self._start_job("REA 정적 분석 중…", work, done, context_sensitive=True)

    def run_observer_generation(self) -> None:
        if self._job is not None:
            self.lbl_status.setText("다른 작업이 진행 중입니다")
            return
        cached = self._last_rea_class_result
        if not cached:
            QMessageBox.information(self, "L", "구조 분석 탭에서 APK를 선택하고 REA 분석 → 클래스 정보를 먼저 실행하세요.")
            return
        path = Path(self.ed_analyze_apk.text().strip())
        if not path.is_file():
            QMessageBox.warning(self, "L", "구조 분석 탭에서 APK 파일을 선택하세요.")
            return
        path = path.resolve()
        try:
            evidence = json.loads(json.dumps(cached["evidence"]))
            methods = list_observer_methods(evidence)
            profiles = load_profiles()
            settings = json.loads(json.dumps(load_rea_settings()))
        except Exception as error:
            QMessageBox.critical(self, "L", f"생성 입력 확인 실패: {error}")
            return
        if not methods:
            QMessageBox.information(self, "L", "클래스 정보에 생성 가능한 메서드가 없습니다. 다른 클래스를 분석하세요.")
            return
        class_name = evidence.get("normalized_result", {}).get("class_name", "")
        project = self._generator_last_project or self.ed_modulemain.text().strip()
        dialog = ObserverGenerationDialog(path, class_name, profiles, methods, project, self.cmb_map_app.currentData(), self)
        if dialog.exec() != QDialog.DialogCode.Accepted:
            return
        request = dict(dialog.request())
        self.ed_project.setText(request["project_path"])
        self._generator_last_project = request["project_path"]
        def work(progress):
            progress("대상 APK·패키지 확인 중…")
            package = run_rea_analysis(path, settings=settings, operation="package", progress=progress)
            if package.get("status") not in {"complete", "partial"} or not package.get("evidence"):
                raise RuntimeError("APK 패키지 분석이 완료되지 않아 코드를 생성할 수 없습니다")
            progress("확인된 메서드의 관찰 코드 생성 중…")
            result = generate_observer(
                request["project_path"], request["app_key"], path, evidence,
                request["method_name"], request["overload_index"], package_evidence=package["evidence"],
            )
            result["diff_text"] = Path(result["diff"]).read_text(encoding="utf-8")
            return result
        self._start_job("관찰 코드 생성 준비 중…", work, self._show_generated_result, context_sensitive=True)

    def run_generated_build(self) -> None:
        if self._job is not None:
            self.lbl_status.setText("다른 작업이 진행 중입니다")
            return
        if not self._last_generated_result or not self._last_generated_result.get("manifest"):
            QMessageBox.information(self, "L", "훅 코드 생성으로 생성본을 먼저 만드세요.")
            return
        manifest = str(self._last_generated_result["manifest"])
        try:
            java_home = load_rea_settings().get("java_home") or None
        except Exception as error:
            QMessageBox.critical(self, "L", f"JDK 설정 읽기 실패: {error}")
            return
        prior = self.txt_map.toPlainText()
        def work(progress):
            return validate_generated_project(manifest, java_home=java_home, progress=progress)
        def done(result):
            if result.get("status") not in {"passed", "failed"} or not isinstance(result.get("report"), str) or not result["report"].strip():
                raise RuntimeError("빌드 검사 결과가 올바르지 않습니다")
            self._last_build_result = result
            generated = self._last_generated_result
            current = generated is not None and generated.get("manifest") == manifest
            if current:
                generated["build_status"] = result["status"]
                if isinstance(generated.get("report"), dict):
                    generated["report"]["build_status"] = result["status"]
            state = "통과" if result["status"] == "passed" else "실패"
            if current and all(key in generated for key in ("path", "report", "diff_text")):
                summary = self._generated_result_text(generated)
            else:
                # Older in-memory results may lack the structured generation
                # fields. Retain their diff, replacing only the status header.
                summary = prior.partition("\n\n======== 생성본 빌드 검사 ========\n")[0]
                summary = re.sub(r"(?m)^빌드 상태: (?:미실행|통과|실패)$", f"빌드 상태: {state}", summary, count=1)
            self.txt_map.setPlainText(summary + "\n\n======== 생성본 빌드 검사 ========\n" + result["report"])
            self.show_generated_summary(generated or {}, build=result)
            self.navigate("workspace")
            self.lbl_status.setText("생성본 빌드 통과 — 기기 실행 검증 별도" if result["status"] == "passed" else "생성본 빌드 실패 — 로그 확인")
        self._start_job("생성본 빌드 검사 중…", work, done, context_sensitive=True)


    # ---------- ADB ----------
    def run_adb(self, args: list[str], timeout: float = 8.0) -> tuple[int, str, str]:
        return run_adb_command(self.adb_path, args, timeout=timeout)

    def refresh_devices(self) -> None:
        if not self.adb_path:
            self.cmb_device.clear()
            self.cmb_device.addItem("(adb 없음)")
            return
        adb_path = self.adb_path
        def done(result):
            code, output, error = result
            self.cmb_device.clear()
            devices = [line.split()[0] for line in output.splitlines()[1:] if len(line.split()) >= 2 and line.split()[1] == "device"] if code == 0 else []
            self.cmb_device.addItems(devices or ["(연결된 기기 없음)"])
            self.lbl_status.setText(f"기기 {len(devices)}대" if devices else "기기 없음" if code == 0 else "ADB 확인 실패: " + (error or output)[:150])
        if self._start_job("기기 확인 중…", lambda progress: run_adb_command(adb_path, ["devices"]), done):
            self.cmb_device.clear()
            self.cmb_device.addItem("(확인 중…)")

    def current_device(self) -> str | None:
        t = self.cmb_device.currentText().strip()
        if not t or t.startswith("("):
            return None
        return t

    def start_logcat(self) -> None:
        if not self.adb_path:
            QMessageBox.warning(self, "L", "adb 없음")
            return
        serial = self.current_device()
        if not serial:
            QMessageBox.warning(self, "L", "기기 선택")
            return
        self.stop_logcat()
        self.run_adb(["-s", serial, "logcat", "-c"])
        self._log_lines = LogLineBuffer()
        self.log_process = QProcess(self)
        self.log_process.setProgram(self.adb_path)
        self.log_process.setArguments(["-s", serial, "logcat", "-v", "time"])
        self.log_process.setProcessChannelMode(QProcess.ProcessChannelMode.MergedChannels)
        self.log_process.readyReadStandardOutput.connect(self._on_log_out)
        self.log_process.finished.connect(self._on_log_finished)
        self.log_process.start()
        self.btn_start_log.setEnabled(False)
        self.btn_stop_log.setEnabled(True)
        self.lbl_status.setText(f"수신 중 [{serial}]")

    def stop_logcat(self) -> None:
        if self.log_process is not None:
            try:
                self.log_process.kill()
                self.log_process.waitForFinished(1500)
            except Exception:
                pass
            self._consume_log_output(final=True)
            self.log_process = None
        self.btn_start_log.setEnabled(True)
        self.btn_stop_log.setEnabled(False)

    def _on_log_finished(self) -> None:
        self._consume_log_output(final=True)
        self.btn_start_log.setEnabled(True)
        self.btn_stop_log.setEnabled(False)

    def _on_log_out(self) -> None:
        self._consume_log_output()

    def _append_log(self, line: str) -> None:
        self.txt_log.appendPlainText(line)
        cur = self.txt_log.textCursor()
        cur.movePosition(QTextCursor.MoveOperation.End)
        self.txt_log.setTextCursor(cur)

    def start_capture(self) -> None:
        if self.capturing:
            return
        self.session_lines = []
        self.capturing = True
        self.btn_cap_start.setEnabled(False)
        self.btn_cap_stop.setEnabled(True)
        self.lbl_status.setText("● 캡처 중")
        self.lbl_status.setStyleSheet("color:#dc2626;font-weight:bold;padding:4px 0;")
        self._append_log(f"----- CAPTURE START {datetime.now().isoformat(timespec='seconds')} -----")

    def stop_capture(self) -> None:
        if not self.capturing:
            return
        self.capturing = False
        self.btn_cap_start.setEnabled(True)
        self.btn_cap_stop.setEnabled(False)
        self.lbl_status.setStyleSheet("color:#64748b;padding:4px 0;")
        self._append_log(f"----- CAPTURE END {datetime.now().isoformat(timespec='seconds')} -----")

        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        device = self.current_device() or "unknown"
        # 캡처 탭 태그 우선, 없으면 세션 탭 태그
        app_tag = ""
        if hasattr(self, "cmb_capture_app"):
            app_tag = self.cmb_capture_app.currentData() or ""
        if not app_tag and hasattr(self, "cmb_session_app"):
            app_tag = self.cmb_session_app.currentData() or ""
        if not app_tag:
            ret = QMessageBox.question(
                self,
                "L",
                "앱 태그가 없습니다.\n그대로 저장할까요?\n\n"
                "(기기 로그 화면에서 대상 앱을 고르면 나중에 찾기 쉽습니다)",
            )
            if ret != QMessageBox.StandardButton.Yes:
                self.capturing = True
                self.btn_cap_start.setEnabled(False)
                self.btn_cap_stop.setEnabled(True)
                self.lbl_status.setText("● 캡처 중")
                self.lbl_status.setStyleSheet(
                    "color:#dc2626;font-weight:bold;padding:4px 0;"
                )
                return
        summary = summarize_lines(self.session_lines)
        app_label = APP_LABELS.get(app_tag, app_tag or "(없음)")
        payload = {
            "saved_at": datetime.now().isoformat(timespec="seconds"),
            "device": device,
            "app": app_tag,
            "app_label": app_label,
            "line_count": len(self.session_lines),
            "summary": summary,
            "lines": self.session_lines,
        }
        try:
            path = session_path(self.session_dir, stamp, app_tag, device)
            atomic_write_text(path, json.dumps(payload, ensure_ascii=False, indent=2))
            atomic_write_text(path.with_suffix(".txt"), f"app={app_tag} ({app_label})\n" + summary + "\n\n" + "\n".join(self.session_lines))
        except (OSError, RuntimeError) as error:
            # Keep the in-memory capture available for another save attempt.
            self.capturing = True
            self.btn_cap_start.setEnabled(False)
            self.btn_cap_stop.setEnabled(True)
            self.lbl_status.setStyleSheet("color:#dc2626;font-weight:bold;padding:4px 0;")
            self.lbl_status.setText("세션 저장 실패 — 캡처 유지")
            QMessageBox.critical(self, "L", str(error))
            return
        self.lbl_status.setText(
            f"저장 [{app_label}] {path.name} ({len(self.session_lines)}줄)"
        )
        self.session_lines = []
        self.reload_session_list()
        QMessageBox.information(
            self, "L", f"저장 완료\n앱: {app_label}\n{path.name}\n\n{summary}"
        )

    def reload_session_list(self) -> None:
        self.list_sessions.clear()
        filt = "all"
        if hasattr(self, "cmb_session_filter"):
            filt = self.cmb_session_filter.currentData()
            if filt is None:
                filt = "all"
        files = sorted(self.session_dir.glob("session_*.json"), reverse=True)
        for f in files:
            app = ""
            app_label = ""
            try:
                data = json.loads(f.read_text(encoding="utf-8"))
                app = data.get("app") or ""
                app_label = data.get("app_label") or APP_LABELS.get(app, "")
            except Exception:
                # 파일명 session_시간_앱_기기.json 추정
                parts = f.stem.split("_")
                for key in APP_LABELS:
                    if key in parts:
                        app = key
                        app_label = APP_LABELS[key]
                        break
            if filt == "all":
                pass
            elif filt == "":
                if app:
                    continue
            else:
                if app != filt:
                    continue
            if app_label:
                title = f"[{app_label}] {f.name}"
            elif app:
                title = f"[{app}] {f.name}"
            else:
                title = f"[없음] {f.name}"
            item = QListWidgetItem(title)
            item.setData(Qt.ItemDataRole.UserRole, str(f))
            self.list_sessions.addItem(item)
        if self.list_sessions.count() > 0:
            self.list_sessions.setCurrentRow(0)

    def open_sessions_dir(self) -> None:
        path = str(self.session_dir)
        if sys.platform == "win32":
            subprocess.Popen(["explorer", path])
        else:
            subprocess.Popen(["xdg-open", path])

    def on_session_selected(self, cur: QListWidgetItem | None, _prev) -> None:
        self.txt_session.setPlainText("")
        self.txt_summary.setPlainText("")
        self.txt_match.setPlainText("")
        if not cur:
            return
        path = Path(cur.data(Qt.ItemDataRole.UserRole))
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            lines = data.get("lines") or []
            summary = summarize_lines(lines)
            app = data.get("app") or ""
            if app:
                summary = f"app={app}\n" + summary
            self.txt_summary.setPlainText(summary)
            header = (
                f"# {path.name}\n# device={data.get('device')} app={app} "
                f"lines={data.get('line_count')}\n\n"
            )
            self.txt_session.setPlainText(header + "\n".join(lines))
            self.match_current_session(silent=True)
        except Exception as e:
            self.txt_session.setPlainText(f"읽기 실패: {e}")

    def match_current_session(self, silent: bool = False) -> None:
        text = self.txt_session.toPlainText()
        if not text.strip():
            if not silent:
                QMessageBox.information(self, "L", "세션을 선택하세요")
            return
        upper = text.upper()
        results = []
        for app_key, items in self.hooks.items():
            for h in items:
                kws = h.get("keywords") or []
                hits = []
                score = 0
                for kw in kws:
                    k = str(kw).strip()
                    if not k:
                        continue
                    if k.upper() in upper:
                        score += 1
                        hits.append(k)
                results.append(
                    {
                        "app": app_key,
                        "id": h.get("id", ""),
                        "note": h.get("note", ""),
                        "score": score,
                        "hits": hits,
                        "total": len([k for k in kws if str(k).strip()]),
                    }
                )
        results.sort(key=lambda x: x["score"], reverse=True)
        lines = [
            f"[{r['app']}] {r['id']}  {r['score']}/{r['total']}  hits={', '.join(r['hits'])}  {r['note']}"
            for r in results
            if r["score"] > 0
        ]
        self.txt_match.setPlainText("\n".join(lines) if lines else "매칭 없음")

    def load_hooks(self) -> dict:
        self._hooks_load_error = None
        if self.hooks_path.exists():
            try:
                value = json.loads(self.hooks_path.read_text(encoding="utf-8-sig"))
                if not isinstance(value, dict) or any(not isinstance(rows, list) or any(not isinstance(row, dict) for row in rows) for rows in value.values()):
                    raise ValueError("hooks.json 형식이 올바르지 않습니다")
                for rows in value.values():
                    for row in rows:
                        keywords = row.get("keywords", [])
                        if not isinstance(keywords, list) or any(not isinstance(word, str) for word in keywords):
                            raise ValueError("keywords는 문자열 목록이어야 합니다")
                return value
            except (OSError, ValueError, UnicodeError) as error:
                self._hooks_load_error = str(error)
        return json.loads(json.dumps(DEFAULT_HOOKS))









    def auto_fill_modulemain(self, silent: bool = False) -> None:
        found = find_modulemain()
        if found:
            self.ed_modulemain.setText(str(found))
        elif not silent and not self.ed_modulemain.text().strip():
            QMessageBox.information(self, "L", "ModuleMain.kt 를 못 찾았다. 찾기로 지정.")






    def closeEvent(self, event) -> None:
        if self._job is not None:
            self._closing_after_job = True
            self._job.cancel()
            self.stop_logcat()
            self.lbl_status.setText("작업 종료 중…")
            event.ignore()
            return
        self.stop_logcat()
        super().closeEvent(event)

def main() -> None:
    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    win = MainWindow()
    win.show()
    sys.exit(app.exec())

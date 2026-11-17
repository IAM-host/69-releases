# -*- coding: utf-8 -*-
"""
L desktop window; visual layout preserved from the uploaded main.py.
"""

from __future__ import annotations

import json
import re
import struct
import subprocess
import sys
import zipfile
from datetime import datetime
from pathlib import Path

from PySide6.QtCore import Qt, QProcess, QTimer, Slot
from PySide6.QtGui import QFont, QTextCursor
from PySide6.QtWidgets import (
    QApplication,
    QComboBox,
    QHBoxLayout,
    QLabel,
    QMainWindow,
    QMessageBox,
    QPushButton,
    QPlainTextEdit,
    QVBoxLayout,
    QWidget,
    QTabWidget,
    QListWidget,
    QListWidgetItem,
    QSplitter,
    QTableWidget,
    QTableWidgetItem,
    QHeaderView,
    QAbstractItemView,
    QFileDialog,
    QLineEdit,
)
from .config import APP_LABELS, DEFAULT_HOOKS, DRIVER_APPS, family_for
from .paths import apk_dir, app_dir, knowledge_path, atomic_write_text, session_path
from .logs import is_interesting, summarize_lines, LogLineBuffer
from .analysis import analyze_apk_structure, apk_meta, check_needles, diff_apk, format_analysis_report, jadx_xref, pick_deep_xref_symbols
from .adb import find_adb, parse_pm_paths, run_adb_command, pull_package
from .state import apk_has_symbols, apply_symbol_replacements, collect_log_text_from_sessions, find_modulemain, load_hook_knowledge, log_symbol_hits, modulemain_symbol_counts, previous_snapshot

from .jobs import BackgroundJob
from .workflows import build_hook_map, create_source_copy


class MainWindow(QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("L")
        self.resize(1120, 760)

        self.adb_path = find_adb()
        self.log_process: QProcess | None = None
        self._log_lines = LogLineBuffer()
        self._job = None
        self._job_success = None
        self._job_result = None
        self._job_error = None
        self._job_cancelled = False
        self._closing_after_job = False
        self._pending_snapshot = None
        self.capturing = False
        self.session_lines: list[str] = []
        self.session_dir = app_dir() / "sessions"
        self.session_dir.mkdir(exist_ok=True)
        self.hooks_path = app_dir() / "hooks.json"
        self.hooks = self.load_hooks()
        self._apk_added: list[str] = []
        self.last_pull: dict[str, Path] = {}
        self._last_pull_stamp = ""
        self.hook_knowledge = load_hook_knowledge()
        self._pending_replaces: list[tuple[str, str]] = []
        self._patched_module_text = ""

        self._build_ui()
        self.refresh_devices()
        self.reload_session_list()
        self.reload_hooks_table()
        self.auto_fill_modulemain(silent=True)
        initial_error = self._hooks_load_error or self.hook_knowledge.get("_load_error")
        if initial_error:
            self.lbl_status.setText("설정 파일 확인 필요: " + str(initial_error)[:160])


    def _start_job(self, label, work, on_success) -> bool:
        if self._job is not None or self._closing_after_job:
            self.lbl_status.setText("다른 작업이 진행 중입니다")
            return False
        self._job_success = on_success
        self._job_result = None
        self._job_error = None
        self._job_cancelled = False
        worker = BackgroundJob(work, self)
        self._job = worker
        worker.progress.connect(self._on_job_progress)
        worker.succeeded.connect(self._on_job_result)
        worker.failed.connect(self._on_job_error)
        worker.cancelled.connect(self._on_job_cancelled)
        worker.finished.connect(self._on_job_finished)
        for button in self.findChildren(QPushButton):
            if button.property("long_job"):
                button.setEnabled(False)
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
        cancelled = self._job_cancelled
        self._job = None
        self._job_success = None
        if worker is not None:
            worker.wait()
            worker.deleteLater()
        for button in self.findChildren(QPushButton):
            if button.property("long_job"):
                button.setEnabled(True)
        if self._closing_after_job:
            QTimer.singleShot(0, self.close)
            return
        if error:
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

    def _consume_log_output(self, final=False):
        process = self.log_process
        data = bytes(process.readAllStandardOutput()) if process is not None else b""
        for line in self._log_lines.feed(data, final=final):
            line = line.rstrip()
            if line and is_interesting(line, self.cmb_filter.currentIndex()):
                self._append_log(line)
                if self.capturing:
                    self.session_lines.append(line)

    def _build_ui(self) -> None:
        root = QWidget()
        self.setCentralWidget(root)
        layout = QVBoxLayout(root)

        row1 = QHBoxLayout()
        self.lbl_adb = QLabel()
        if self.adb_path:
            self.lbl_adb.setText(f"ADB: {self.adb_path}")
            self.lbl_adb.setStyleSheet("color:#16a34a;")
        else:
            self.lbl_adb.setText("ADB 없음")
            self.lbl_adb.setStyleSheet("color:#dc2626;")
        row1.addWidget(self.lbl_adb, 1)
        btn_refresh = QPushButton("기기 새로고침")
        btn_refresh.clicked.connect(self.refresh_devices)
        btn_refresh.setProperty("long_job", True)
        row1.addWidget(btn_refresh)
        layout.addLayout(row1)

        row2 = QHBoxLayout()
        row2.addWidget(QLabel("기기"))
        self.cmb_device = QComboBox()
        self.cmb_device.setMinimumWidth(260)
        row2.addWidget(self.cmb_device)
        row2.addWidget(QLabel("필터"))
        self.cmb_filter = QComboBox()
        self.cmb_filter.addItem("EUNORA만")
        self.cmb_filter.addItem("전체 logcat")
        row2.addWidget(self.cmb_filter)
        row2.addStretch()
        layout.addLayout(row2)

        self.tabs = QTabWidget()
        layout.addWidget(self.tabs, 1)
        self.tabs.addTab(self._tab_log(), "로그·캡처")
        self.tabs.addTab(self._tab_sessions(), "세션")
        self.tabs.addTab(self._tab_hooks(), "후보군")
        self.tabs.addTab(self._tab_apk(), "추출·비교")
        self.tabs.addTab(self._tab_analyze(), "구조 분석")
        self.tabs.addTab(self._tab_map(), "훅 지도")

        self.lbl_status = QLabel("대기 중")
        self.lbl_status.setStyleSheet("color:#64748b;padding:4px 0;")
        layout.addWidget(self.lbl_status)

    def _tab_log(self) -> QWidget:
        w = QWidget()
        layout = QVBoxLayout(w)
        row = QHBoxLayout()
        self.btn_start_log = QPushButton("로그 시작")
        self.btn_start_log.clicked.connect(self.start_logcat)
        row.addWidget(self.btn_start_log)
        self.btn_stop_log = QPushButton("로그 중지")
        self.btn_stop_log.clicked.connect(self.stop_logcat)
        self.btn_stop_log.setEnabled(False)
        row.addWidget(self.btn_stop_log)
        btn_clear = QPushButton("화면 지우기")
        btn_clear.clicked.connect(lambda: self.txt_log.setPlainText(""))
        row.addWidget(btn_clear)
        row.addStretch()
        self.btn_cap_start = QPushButton("캡처 시작")
        self.btn_cap_start.setStyleSheet(
            "background:#2563eb;color:white;font-weight:bold;padding:6px 14px;"
        )
        self.btn_cap_start.clicked.connect(self.start_capture)
        row.addWidget(self.btn_cap_start)
        self.btn_cap_stop = QPushButton("캡처 종료·저장")
        self.btn_cap_stop.setEnabled(False)
        self.btn_cap_stop.clicked.connect(self.stop_capture)
        row.addWidget(self.btn_cap_stop)
        layout.addLayout(row)

        self.txt_log = QPlainTextEdit()
        self.txt_log.setReadOnly(True)
        font = QFont("Consolas", 10)
        if not font.exactMatch():
            font = QFont("Courier New", 10)
        self.txt_log.setFont(font)
        self.txt_log.setStyleSheet(
            "background:#0f172a;color:#e2e8f0;border:1px solid #1e293b;border-radius:8px;"
        )
        layout.addWidget(self.txt_log, 1)
        return w

    def _tab_sessions(self) -> QWidget:
        w = QWidget()
        layout = QHBoxLayout(w)
        split = QSplitter(Qt.Orientation.Horizontal)
        layout.addWidget(split)

        left = QWidget()
        left_l = QVBoxLayout(left)
        row = QHBoxLayout()
        btn_reload = QPushButton("목록 새로고침")
        btn_reload.clicked.connect(self.reload_session_list)
        row.addWidget(btn_reload)
        btn_open = QPushButton("폴더 열기")
        btn_open.clicked.connect(self.open_sessions_dir)
        row.addWidget(btn_open)
        left_l.addLayout(row)
        self.list_sessions = QListWidget()
        self.list_sessions.currentItemChanged.connect(self.on_session_selected)
        left_l.addWidget(self.list_sessions, 1)
        left_l.addWidget(QLabel("앱 태그 (저장 시)"))
        self.cmb_session_app = QComboBox()
        self.cmb_session_app.addItem("(없음)", "")
        for k, label in APP_LABELS.items():
            self.cmb_session_app.addItem(label, k)
        left_l.addWidget(self.cmb_session_app)
        split.addWidget(left)

        right = QWidget()
        right_l = QVBoxLayout(right)
        right_l.addWidget(QLabel("요약"))
        self.txt_summary = QPlainTextEdit()
        self.txt_summary.setReadOnly(True)
        self.txt_summary.setMaximumHeight(180)
        self.txt_summary.setStyleSheet("background:#052e16;color:#bbf7d0;")
        right_l.addWidget(self.txt_summary)

        right_l.addWidget(QLabel("세션 로그"))
        self.txt_session = QPlainTextEdit()
        self.txt_session.setReadOnly(True)
        self.txt_session.setFont(QFont("Consolas", 10))
        self.txt_session.setStyleSheet("background:#0f172a;color:#e2e8f0;")
        right_l.addWidget(self.txt_session, 1)

        right_l.addWidget(QLabel("후보 매칭"))
        self.txt_match = QPlainTextEdit()
        self.txt_match.setReadOnly(True)
        self.txt_match.setMaximumHeight(120)
        self.txt_match.setStyleSheet("background:#111827;color:#a7f3d0;")
        right_l.addWidget(self.txt_match)

        btn_match = QPushButton("후보군 매칭")
        btn_match.clicked.connect(lambda: self.match_current_session(False))
        right_l.addWidget(btn_match)
        split.addWidget(right)
        split.setSizes([300, 800])
        return w

    def _tab_hooks(self) -> QWidget:
        w = QWidget()
        layout = QVBoxLayout(w)
        top = QHBoxLayout()
        top.addWidget(QLabel("앱"))
        self.cmb_app = QComboBox()
        for k, label in APP_LABELS.items():
            self.cmb_app.addItem(label, k)
        self.cmb_app.currentIndexChanged.connect(self.reload_hooks_table)
        top.addWidget(self.cmb_app)
        btn_add = QPushButton("추가")
        btn_add.clicked.connect(self.add_hook_row)
        top.addWidget(btn_add)
        btn_del = QPushButton("삭제")
        btn_del.clicked.connect(self.del_hook_row)
        top.addWidget(btn_del)
        btn_save = QPushButton("hooks.json 저장")
        btn_save.setStyleSheet("background:#16a34a;color:white;font-weight:bold;")
        btn_save.clicked.connect(self.save_hooks)
        top.addWidget(btn_save)
        btn_reset = QPushButton("기본값")
        btn_reset.clicked.connect(self.reset_hooks)
        top.addWidget(btn_reset)
        top.addStretch()
        layout.addLayout(top)

        self.tbl_hooks = QTableWidget(0, 3)
        self.tbl_hooks.setHorizontalHeaderLabels(["ID", "설명", "키워드(쉼표)"])
        self.tbl_hooks.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        self.tbl_hooks.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self.tbl_hooks.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        self.tbl_hooks.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        layout.addWidget(self.tbl_hooks, 1)
        return w


    def _tab_analyze(self) -> QWidget:
        w = QWidget()
        layout = QVBoxLayout(w)

        row = QHBoxLayout()
        row.addWidget(QLabel("APK"))
        self.ed_analyze_apk = QLineEdit()
        self.ed_analyze_apk.setPlaceholderText("")
        row.addWidget(self.ed_analyze_apk, 1)
        btn_browse = QPushButton("찾기")
        btn_browse.clicked.connect(self.browse_analyze_apk)
        row.addWidget(btn_browse)
        btn_run = QPushButton("전체 구조 분석")
        btn_run.clicked.connect(self.run_structure_analysis)
        btn_run.setProperty("long_job", True)
        row.addWidget(btn_run)
        btn_deep = QPushButton("심화 분석")
        btn_deep.clicked.connect(self.run_deep_analysis)
        btn_deep.setProperty("long_job", True)
        row.addWidget(btn_deep)
        btn_save = QPushButton("보고서 저장")
        btn_save.clicked.connect(self.save_analysis_report)
        row.addWidget(btn_save)
        btn_xref = QPushButton("jadx XREF")
        btn_xref.clicked.connect(self.run_jadx_xref)
        btn_xref.setProperty("long_job", True)
        row.addWidget(btn_xref)
        layout.addLayout(row)

        rowx = QHBoxLayout()
        rowx.addWidget(QLabel("XREF 심볼"))
        self.ed_xref_symbols = QLineEdit()
        self.ed_xref_symbols.setPlaceholderText("")
        rowx.addWidget(self.ed_xref_symbols, 1)
        layout.addLayout(rowx)


        rowf = QHBoxLayout()
        rowf.addWidget(QLabel("패키지 필터"))
        self.ed_pkg_filter = QLineEdit()
        self.ed_pkg_filter.setPlaceholderText("")
        rowf.addWidget(self.ed_pkg_filter, 1)
        layout.addLayout(rowf)

        self.txt_analyze = QPlainTextEdit()
        self.txt_analyze.setReadOnly(True)
        self.txt_analyze.setPlaceholderText("")
        mono = QFont("Consolas", 10)
        if not mono.exactMatch():
            mono = QFont("Courier New", 10)
        self.txt_analyze.setFont(mono)
        layout.addWidget(self.txt_analyze, 1)
        self._last_analysis_text = ""
        self._last_analysis_result = None
        return w

    def _tab_map(self) -> QWidget:
        w = QWidget()
        layout = QVBoxLayout(w)

        row = QHBoxLayout()
        row.addWidget(QLabel("ModuleMain.kt"))
        self.ed_modulemain = QLineEdit()
        self.ed_modulemain.setPlaceholderText("")
        row.addWidget(self.ed_modulemain, 1)
        btn_mm = QPushButton("찾기")
        btn_mm.clicked.connect(self.browse_modulemain)
        row.addWidget(btn_mm)
        btn_auto = QPushButton("자동 찾기")
        btn_auto.clicked.connect(self.auto_fill_modulemain)
        row.addWidget(btn_auto)
        layout.addLayout(row)

        row2 = QHBoxLayout()
        row2.addWidget(QLabel("APK"))
        self.ed_map_apk = QLineEdit()
        self.ed_map_apk.setPlaceholderText("")
        row2.addWidget(self.ed_map_apk, 1)
        btn_apk = QPushButton("찾기")
        btn_apk.clicked.connect(self.browse_map_apk)
        row2.addWidget(btn_apk)
        row2.addWidget(QLabel("앱"))
        self.cmb_map_app = QComboBox()
        for k, label in APP_LABELS.items():
            self.cmb_map_app.addItem(label, k)
        row2.addWidget(self.cmb_map_app)
        layout.addLayout(row2)

        row3 = QHBoxLayout()
        btn_scan = QPushButton("지도 대조")
        btn_scan.setStyleSheet("background:#2563eb;color:white;font-weight:bold;padding:6px 14px;")
        btn_scan.clicked.connect(self.run_hook_map)
        btn_scan.setProperty("long_job", True)
        row3.addWidget(btn_scan)
        btn_apply = QPushButton("전체코드 만들기")
        btn_apply.clicked.connect(self.apply_pending_replaces)
        btn_apply.setProperty("long_job", True)
        row3.addWidget(btn_apply)
        btn_copy = QPushButton("전체코드 복사")
        btn_copy.clicked.connect(self.copy_patched_module)
        row3.addWidget(btn_copy)
        btn_reload_k = QPushButton("지식 다시 읽기")
        btn_reload_k.clicked.connect(self.reload_hook_knowledge)
        row3.addWidget(btn_reload_k)
        row3.addStretch()
        layout.addLayout(row3)

        self.tbl_map = QTableWidget(0, 6)
        self.tbl_map.setHorizontalHeaderLabels(
            ["사이트", "역할", "심볼", "ModuleMain", "APK", "로그"]
        )
        self.tbl_map.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        self.tbl_map.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        self.tbl_map.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        self.tbl_map.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        layout.addWidget(self.tbl_map, 1)

        self.txt_map = QPlainTextEdit()
        self.txt_map.setReadOnly(True)
        self.txt_map.setMaximumHeight(280)
        self.txt_map.setFont(QFont("Consolas", 10))
        self.txt_map.setStyleSheet("background:#0f172a;color:#e2e8f0;")
        layout.addWidget(self.txt_map)
        return w

    def _tab_apk(self) -> QWidget:
        w = QWidget()
        layout = QVBoxLayout(w)

        pull = QHBoxLayout()
        pull.addWidget(QLabel("앱"))
        self.cmb_pull_app = QComboBox()
        self.cmb_pull_app.addItem(f"{len(DRIVER_APPS)}개 전부", "all")
        for k, label in APP_LABELS.items():
            self.cmb_pull_app.addItem(label, k)
        pull.addWidget(self.cmb_pull_app)
        btn_pull = QPushButton("폰에서 APK 추출")
        btn_pull.setStyleSheet("background:#0f766e;color:white;font-weight:bold;padding:6px 14px;")
        btn_pull.clicked.connect(self.pull_driver_apks)
        btn_pull.setProperty("long_job", True)
        pull.addWidget(btn_pull)
        btn_prev_diff = QPushButton("방금 추출 vs 이전")
        btn_prev_diff.clicked.connect(self.diff_last_pull_against_previous)
        btn_prev_diff.setProperty("long_job", True)
        pull.addWidget(btn_prev_diff)
        btn_open_apk = QPushButton("apks 폴더")
        btn_open_apk.clicked.connect(self.open_apks_dir)
        pull.addWidget(btn_open_apk)
        pull.addStretch()
        layout.addLayout(pull)

        self.txt_pull = QPlainTextEdit()
        self.txt_pull.setReadOnly(True)
        self.txt_pull.setMaximumHeight(160)
        self.txt_pull.setPlaceholderText("")
        self.txt_pull.setStyleSheet("background:#0f172a;color:#a7f3d0;")
        layout.addWidget(self.txt_pull)

        form = QHBoxLayout()
        form.addWidget(QLabel("이전 APK"))
        self.ed_apk_old = QLineEdit()
        self.ed_apk_old.setPlaceholderText("")
        form.addWidget(self.ed_apk_old, 1)
        btn_old = QPushButton("찾기")
        btn_old.clicked.connect(lambda: self._pick_apk(self.ed_apk_old))
        form.addWidget(btn_old)
        layout.addLayout(form)

        form2 = QHBoxLayout()
        form2.addWidget(QLabel("새 APK"))
        self.ed_apk_new = QLineEdit()
        self.ed_apk_new.setPlaceholderText("")
        form2.addWidget(self.ed_apk_new, 1)
        btn_new = QPushButton("찾기")
        btn_new.clicked.connect(lambda: self._pick_apk(self.ed_apk_new))
        form2.addWidget(btn_new)
        layout.addLayout(form2)

        row = QHBoxLayout()
        row.addWidget(QLabel("후보로 넣을 앱"))
        self.cmb_apk_app = QComboBox()
        for k, label in APP_LABELS.items():
            self.cmb_apk_app.addItem(label, k)
        row.addWidget(self.cmb_apk_app)
        btn_diff = QPushButton("비교 실행")
        btn_diff.setStyleSheet("background:#2563eb;color:white;font-weight:bold;padding:6px 16px;")
        btn_diff.clicked.connect(self.run_apk_diff)
        btn_diff.setProperty("long_job", True)
        row.addWidget(btn_diff)
        btn_add_sel = QPushButton("선택 항목 → 후보군 추가")
        btn_add_sel.clicked.connect(self.add_selected_apk_to_hooks)
        row.addWidget(btn_add_sel)
        row.addStretch()
        layout.addLayout(row)

        self.lbl_apk_info = QLabel("")
        self.lbl_apk_info.setStyleSheet("color:#94a3b8;")
        layout.addWidget(self.lbl_apk_info)

        split = QSplitter(Qt.Orientation.Horizontal)
        left = QWidget()
        ll = QVBoxLayout(left)
        ll.addWidget(QLabel("추가됨"))
        self.list_apk_added = QListWidget()
        self.list_apk_added.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection)
        ll.addWidget(self.list_apk_added)
        split.addWidget(left)

        right = QWidget()
        rl = QVBoxLayout(right)
        rl.addWidget(QLabel("사라짐"))
        self.list_apk_removed = QListWidget()
        rl.addWidget(self.list_apk_removed)
        split.addWidget(right)
        layout.addWidget(split, 1)

        return w

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
            QMessageBox.warning(self, "L", "기기를 연결하고 상단에서 선택하세요")
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
                self.ed_apk_new.setText(str(first))
                previous = previous_snapshot(key, first.parent.name)
                self.ed_apk_old.setText(str(previous) if previous else "")
            self.lbl_status.setText(f"추출 완료 — base APK {len(successful)}/{len(results)}")
        self._start_job("APK 추출 중…", work, done)

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
            self.lbl_status.setText(
                f"정적 구조 분석 완료 — 후보 {len(result.get('flags') or [])}개, "
                f"문자열 {result.get('string_count', 0)}"
            )
        self._start_job("구조 분석 중…", work, done)

    def save_analysis_report(self) -> None:
        text = self._last_analysis_text or self.txt_analyze.toPlainText()
        if not text.strip():
            QMessageBox.information(self, "L", "먼저 분석을 실행하세요")
            return
        path, _ = QFileDialog.getSaveFileName(
            self, "보고서 저장", str(app_dir() / "sessions" / "apk_analysis.txt"), "Text (*.txt);;All (*.*)"
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
            self.lbl_status.setText(status)
        self._start_job("심화 분석 준비…", work, done)

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
            self.lbl_status.setText("jadx 진단 — 결과 확인" if report.startswith("[jadx") else "jadx XREF 완료")
        self._start_job("jadx XREF 실행 중…", lambda progress: jadx_xref(path, symbols), done)

    def add_selected_apk_to_hooks(self) -> None:
        items = self.list_apk_added.selectedItems()
        if not items:
            QMessageBox.information(self, "L", "추가된 목록에서 항목을 선택하세요 (Ctrl 다중 선택)")
            return
        app_key = self.cmb_apk_app.currentData() or "kakao"
        hooks = self.hooks.setdefault(app_key, [])
        # 기존 테이블 반영
        if self.cmb_app.currentData() == app_key:
            self.hooks[app_key] = self.table_to_hooks_for_app()
            hooks = self.hooks[app_key]

        added_n = 0
        for it in items:
            s = it.text().strip()
            if not s:
                continue
            hid = "apk_" + re.sub(r"[^\w]+", "_", s)[:40]
            # 중복 id/키워드 스킵
            if any(s in (h.get("keywords") or []) for h in hooks):
                continue
            hooks.append({"id": hid, "note": "APK diff 추가", "keywords": [s]})
            added_n += 1

        self.hooks[app_key] = hooks
        # 후보군 탭 앱 맞추고 새로고침
        for i in range(self.cmb_app.count()):
            if self.cmb_app.itemData(i) == app_key:
                self.cmb_app.setCurrentIndex(i)
                break
        self.reload_hooks_table()
        self.tabs.setCurrentIndex(2)
        QMessageBox.information(
            self, "L", f"{added_n}개 후보 추가됨\n앱: {app_key}\n후보군 탭에서 hooks.json 저장하세요"
        )

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
                "(캡처 탭에서 카카오/콜마너 등을 고르면 나중에 찾기 쉽습니다)",
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

    def current_app_key(self) -> str:
        return self.cmb_app.currentData() or "kakao"

    def reload_hooks_table(self) -> None:
        key = self.current_app_key()
        items = self.hooks[key] if key in self.hooks else self.hooks.get(family_for(key), [])
        self.tbl_hooks.setRowCount(0)
        for h in items:
            row = self.tbl_hooks.rowCount()
            self.tbl_hooks.insertRow(row)
            self.tbl_hooks.setItem(row, 0, QTableWidgetItem(str(h.get("id", ""))))
            self.tbl_hooks.setItem(row, 1, QTableWidgetItem(str(h.get("note", ""))))
            kws = h.get("keywords") or []
            self.tbl_hooks.setItem(row, 2, QTableWidgetItem(", ".join(str(x) for x in kws)))

    def table_to_hooks_for_app(self) -> list[dict]:
        items = []
        for row in range(self.tbl_hooks.rowCount()):
            id_item = self.tbl_hooks.item(row, 0)
            note_item = self.tbl_hooks.item(row, 1)
            kw_item = self.tbl_hooks.item(row, 2)
            id_v = id_item.text().strip() if id_item else ""
            note_v = note_item.text().strip() if note_item else ""
            kw_raw = kw_item.text() if kw_item else ""
            kws = [x.strip() for x in kw_raw.split(",") if x.strip()]
            if not id_v and not kws:
                continue
            items.append({"id": id_v or f"hook_{row+1}", "note": note_v, "keywords": kws})
        return items

    def add_hook_row(self) -> None:
        row = self.tbl_hooks.rowCount()
        self.tbl_hooks.insertRow(row)
        self.tbl_hooks.setItem(row, 0, QTableWidgetItem(f"new_{row+1}"))
        self.tbl_hooks.setItem(row, 1, QTableWidgetItem(""))
        self.tbl_hooks.setItem(row, 2, QTableWidgetItem(""))

    def del_hook_row(self) -> None:
        rows = sorted({i.row() for i in self.tbl_hooks.selectedIndexes()}, reverse=True)
        for r in rows:
            self.tbl_hooks.removeRow(r)

    def save_hooks(self) -> None:
        key = self.current_app_key()
        updated = dict(self.hooks)
        updated[key] = self.table_to_hooks_for_app()
        try:
            backup = None
            if self._hooks_load_error and self.hooks_path.exists():
                backup = self.hooks_path.with_name(f"hooks.invalid-{datetime.now().strftime('%Y%m%d_%H%M%S_%f')}.json")
                backup.write_bytes(self.hooks_path.read_bytes())
            atomic_write_text(self.hooks_path, json.dumps(updated, ensure_ascii=False, indent=2))
        except OSError as error:
            QMessageBox.critical(self, "L", f"저장 실패: {error}")
            return
        self.hooks = updated
        self._hooks_load_error = None
        self.lbl_status.setText("hooks.json 저장")
        message = "저장 완료" + (f"\n기존 오류 파일 보관: {backup.name}" if backup else "")
        QMessageBox.information(self, "L", message)

    def reset_hooks(self) -> None:
        self.hooks = json.loads(json.dumps(DEFAULT_HOOKS))
        self.reload_hooks_table()

    def browse_modulemain(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self, "ModuleMain.kt", "", "Kotlin (*.kt);;All (*.*)"
        )
        if path:
            self.ed_modulemain.setText(path)

    def auto_fill_modulemain(self, silent: bool = False) -> None:
        found = find_modulemain()
        if found:
            self.ed_modulemain.setText(str(found))
        elif not silent and not self.ed_modulemain.text().strip():
            QMessageBox.information(self, "L", "ModuleMain.kt 를 못 찾았다. 찾기로 지정.")

    def browse_map_apk(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self, "APK", "", "APK (*.apk);;All (*.*)"
        )
        if path:
            self.ed_map_apk.setText(path)

    def reload_hook_knowledge(self) -> None:
        self.hook_knowledge = load_hook_knowledge()
        error = self.hook_knowledge.get("_load_error")
        if error:
            self.lbl_status.setText("지식 파일 읽기 실패")
            QMessageBox.warning(self, "L", str(error))
        else:
            self.lbl_status.setText(f"지식 읽음 {knowledge_path()}")
            QMessageBox.information(self, "L", f"지식 파일\n{knowledge_path()}")

    def run_hook_map(self) -> None:
        app_key = self.cmb_map_app.currentData() or "kakao"
        apps = self.hook_knowledge.get("apps") or {}
        spec = apps[app_key] if app_key in apps else apps.get(family_for(app_key), {})
        spec = json.loads(json.dumps(spec))
        if self.hook_knowledge.get("_load_error"):
            QMessageBox.warning(self, "L", str(self.hook_knowledge["_load_error"]))
            return
        module_path = Path(self.ed_modulemain.text().strip())
        apk_path = Path(self.ed_map_apk.text().strip())
        live = self.txt_log.toPlainText()
        session_dir = self.session_dir
        def done(result):
            self.tbl_map.setRowCount(0)
            for cells in result["rows"]:
                row = self.tbl_map.rowCount()
                self.tbl_map.insertRow(row)
                for col, cell in enumerate(cells):
                    self.tbl_map.setItem(row, col, QTableWidgetItem(cell))
            self._pending_replaces = result["pending"]
            self._pending_snapshot = result
            self.txt_map.setPlainText("\n".join(result["notes"]))
            self.lbl_status.setText("훅 지도 정적 대조 완료")
        self._start_job("훅 지도 대조 중…", lambda progress: build_hook_map(app_key, spec, module_path, apk_path, session_dir, live), done)

    def apply_pending_replaces(self) -> None:
        module_path = Path(self.ed_modulemain.text().strip())
        snapshot = self._pending_snapshot
        if not module_path.is_file() or not snapshot:
            QMessageBox.information(self, "L", "원본 경로를 선택하고 먼저 지도 대조를 실행하세요.")
            return
        if str(module_path.resolve()) != snapshot["source_path"]:
            QMessageBox.information(self, "L", "대조한 원본 경로와 다릅니다. 지도 대조를 다시 실행하세요.")
            return
        if not self._pending_replaces:
            QMessageBox.information(self, "L", "대기 중인 치환 후보가 없습니다.")
            return
        pairs = list(self._pending_replaces)
        def done(result):
            if not result["applied"]:
                QMessageBox.information(self, "L", "원본의 정확한 문자열과 일치하는 치환이 없습니다.")
                return
            self._patched_module_text = result["text"]
            self.txt_map.setPlainText("// 검증 전 치환 복사본\n// " + " ; ".join(result["applied"]) + "\n\n" + result["text"])
            self.lbl_status.setText("치환 복사본 준비 — 빌드·실행 미검증")
            QMessageBox.information(self, "L", f"복사본: {result['path']}\n원본은 유지했습니다. 함수 의미·빌드·실행은 별도 확인이 필요합니다.")
        self._start_job("치환 복사본 생성 중…", lambda progress: create_source_copy(module_path, pairs, snapshot["source_digest"], snapshot["apk_path"], snapshot["apk_digest"]), done)

    def copy_patched_module(self) -> None:
        text = self._patched_module_text or self.txt_map.toPlainText()
        if not text.strip():
            QMessageBox.information(self, "L", "먼저 전체코드를 만드세요")
            return
        QApplication.clipboard().setText(self._patched_module_text or text)
        self.lbl_status.setText("전체코드 클립보드 복사됨")
        QMessageBox.information(self, "L", "복사됨. 스튜디오 ModuleMain.kt에 붙여넣으면 된다.")

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

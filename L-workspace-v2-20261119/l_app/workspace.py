"""Presentation-only compact workbench. All operations remain in ui.py."""
from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import QByteArray, Qt, QSize
from PySide6.QtGui import QColor, QFont, QIcon, QPainter, QPainterPath, QPen, QPixmap
from PySide6.QtWidgets import (
    QAbstractItemView, QButtonGroup, QComboBox, QFrame, QHBoxLayout, QLabel,
    QLineEdit, QListWidget, QListWidgetItem, QPlainTextEdit, QProgressBar,
    QPushButton, QScrollArea, QSplitter, QStackedWidget, QTabBar, QTableWidget,
    QTableWidgetItem, QHeaderView, QVBoxLayout, QWidget,
)

from .config import APP_LABELS
from .theme import STYLESHEET, interface_font


class _ComboBox(QComboBox):
    def paintEvent(self, event):
        super().paintEvent(event)
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        painter.setPen(QPen(QColor("#8c9bae" if self.isEnabled() else "#536172"), 1.3))
        x, y = self.width() - 13, self.height() / 2
        path = QPainterPath()
        path.moveTo(x - 3.5, y - 1.5)
        path.lineTo(x, y + 2)
        path.lineTo(x + 3.5, y - 1.5)
        painter.drawPath(path)


def _label(text="", role=""):
    label = QLabel(text)
    if role:
        label.setProperty("role", role)
    return label


def _icon(name, color="#8d9aac"):
    paths = {
        "workspace": '<rect x="3" y="4" width="18" height="16" rx="1"/><path d="M3 9h18M8 9v11"/>',
        "logs": '<path d="M5 4h14v16H5zM8 8h8M8 12h5M8 16h8"/>',
        "history": '<path d="M4 10a8 8 0 1 1 1 8M4 4v6h6M12 8v5l3 2"/>',
        "settings": '<path d="M4 6h16M4 12h16M4 18h16"/><path d="M8 4v4M15 10v4M10 16v4"/>',
        "document": '<path d="M6 3h8l4 4v14H6zM14 3v5h4M9 12h6M9 16h6"/>',
    }
    svg = f'<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="{color}" stroke-width="1.4" stroke-linecap="round" stroke-linejoin="round">{paths.get(name, paths["document"])}</svg>'
    pixmap = QPixmap()
    pixmap.loadFromData(QByteArray(svg.encode()), "SVG")
    return QIcon(pixmap)


class WorkspaceLayoutMixin:
    def _button(self, text, callback, *, variant="", long_job=False):
        button = QPushButton(text)
        if variant:
            button.setProperty("variant", variant)
        if long_job:
            button.setProperty("long_job", True)
        button.clicked.connect(callback)
        return button

    @staticmethod
    def _panel():
        panel = QFrame()
        panel.setObjectName("Panel")
        box = QVBoxLayout(panel)
        box.setContentsMargins(12, 11, 12, 11)
        box.setSpacing(9)
        return panel, box

    @staticmethod
    def _rule():
        line = QFrame()
        line.setObjectName("Rule")
        line.setFixedHeight(1)
        return line

    @staticmethod
    def _scroll(content):
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        scroll.setWidget(content)
        return scroll

    @staticmethod
    def _code_view():
        view = QPlainTextEdit()
        view.setReadOnly(True)
        view.setObjectName("CodeView")
        view.setFont(QFont("Consolas", 10))
        return view

    def _build_ui(self):
        self.setWindowTitle("L")
        self.resize(1220, 820)
        self.setMinimumSize(1000, 680)
        self.setFont(interface_font())
        self.setStyleSheet(STYLESHEET)
        shell = QWidget()
        shell.setObjectName("Shell")
        self.setCentralWidget(shell)
        outer = QHBoxLayout(shell)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(0)
        sidebar = QFrame()
        sidebar.setObjectName("Sidebar")
        sidebar.setFixedWidth(164)
        side = QVBoxLayout(sidebar)
        side.setContentsMargins(0, 0, 0, 0)
        side.setSpacing(1)
        brand = QLabel("L")
        brand.setObjectName("Brand")
        brand.setContentsMargins(17, 13, 0, 12)
        side.addWidget(brand)
        side.addWidget(self._rule())
        side.addSpacing(9)
        self.nav_buttons = {}
        nav_group = QButtonGroup(self)
        nav_group.setExclusive(True)
        for key, text in (("workspace", "작업 공간"), ("logs", "기기 로그"),
                          ("history", "기록"), ("settings", "설정")):
            button = QPushButton(text)
            button.setObjectName("NavButton")
            button.setCheckable(True)
            button.setIcon(_icon(key))
            button.setIconSize(QSize(17, 17))
            button.clicked.connect(lambda checked=False, page=key: self.navigate(page))
            nav_group.addButton(button)
            self.nav_buttons[key] = button
            side.addWidget(button)
        side.addStretch()
        outer.addWidget(sidebar)
        main = QVBoxLayout()
        main.setContentsMargins(0, 0, 0, 0)
        main.setSpacing(0)
        header = QFrame()
        header.setObjectName("PageHeader")
        title_row = QHBoxLayout(header)
        title_row.setContentsMargins(19, 10, 18, 10)
        self.lbl_page_title = _label("작업 공간", "title")
        title_row.addWidget(self.lbl_page_title, 1)
        self.btn_cancel_job = self._button("취소", self.cancel_current_job, variant="quiet")
        self.btn_cancel_job.setVisible(False)
        title_row.addWidget(self.btn_cancel_job)
        main.addWidget(header)
        self.progress = QProgressBar()
        self.progress.setRange(0, 0)
        self.progress.setTextVisible(False)
        self.progress.setFixedHeight(2)
        self.progress.setVisible(False)
        main.addWidget(self.progress)
        self.pages = QStackedWidget()
        self._page_indices = {}
        for key, page in (("workspace", self._workspace_page()), ("logs", self._logs_page()),
                          ("history", self._history_page()), ("settings", self._settings_page())):
            self._page_indices[key] = self.pages.addWidget(page)
        main.addWidget(self.pages, 1)
        status = QFrame()
        status.setObjectName("StatusBar")
        status_row = QHBoxLayout(status)
        status_row.setContentsMargins(18, 5, 18, 5)
        self.lbl_status = QLabel("대기")
        self.lbl_status.setObjectName("StatusLabel")
        status_row.addWidget(self.lbl_status)
        main.addWidget(status)
        outer.addLayout(main, 1)
        self.navigate("workspace")

    def navigate(self, page):
        if page not in self._page_indices:
            raise ValueError(f"Unknown workspace page: {page}")
        self.pages.setCurrentIndex(self._page_indices[page])
        self.nav_buttons[page].setChecked(True)
        self.lbl_page_title.setText({"workspace": "작업 공간", "logs": "기기 로그", "history": "기록", "settings": "설정"}[page])

    def _workspace_page(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(18, 15, 18, 15)
        layout.setSpacing(10)
        inputs, form = self._panel()
        for text, name, callback in (("APK", "ed_analyze_apk", self.browse_analyze_apk),
                                     ("EUNORA", "ed_project", self.browse_project)):
            row = QHBoxLayout()
            row.setSpacing(9)
            label = _label(text, "field")
            label.setFixedWidth(63)
            row.addWidget(label)
            edit = QLineEdit()
            setattr(self, name, edit)
            row.addWidget(edit, 1)
            browse = self._button("찾기", callback)
            browse.setAccessibleName(f"{text} 찾기")
            row.addWidget(browse)
            form.addLayout(row)
        self.ed_modulemain = self.ed_project
        layout.addWidget(inputs)
        toolbar = QHBoxLayout()
        toolbar.setSpacing(7)
        self.cmb_analysis_mode = _ComboBox()
        self.cmb_analysis_mode.addItem("기존 훅 점검", "existing")
        self.cmb_analysis_mode.addItem("보안 검사 점검", "security")
        self.cmb_analysis_mode.setMinimumWidth(176)
        toolbar.addWidget(self.cmb_analysis_mode)
        self.btn_run_audit = self._button("점검", self.run_workspace_audit, variant="primary", long_job=True)
        self.btn_generate_hook = self._button("코드 생성", self.run_workspace_generation, long_job=True)
        self.btn_build_generated = self._button("빌드", self.run_generated_build, long_job=True)
        self.btn_generate_hook.setEnabled(False)
        self.btn_build_generated.setEnabled(False)
        toolbar.addWidget(self.btn_run_audit)
        toolbar.addWidget(self.btn_generate_hook)
        toolbar.addWidget(self.btn_build_generated)
        toolbar.addStretch()
        layout.addLayout(toolbar)

        output = QFrame()
        output.setObjectName("Panel")
        body = QVBoxLayout(output)
        body.setContentsMargins(0, 0, 0, 0)
        body.setSpacing(0)
        result_header = QHBoxLayout()
        result_header.setContentsMargins(12, 8, 12, 8)
        self.lbl_result_title = _label("결과", "section")
        result_header.addWidget(self.lbl_result_title)
        self.audit_stats = QWidget()
        stats = QHBoxLayout(self.audit_stats)
        stats.setContentsMargins(12, 0, 0, 0)
        stats.setSpacing(18)
        self.lbl_result_app = _label("", "muted")
        self.lbl_result_count = _label("", "muted")
        self.lbl_result_review = _label("", "muted")
        for value in (self.lbl_result_app, self.lbl_result_count, self.lbl_result_review):
            stats.addWidget(value)
        self.audit_stats.setVisible(False)
        result_header.addWidget(self.audit_stats)
        result_header.addStretch()
        self.lbl_build_state = QLabel("대기")
        self.lbl_build_state.setObjectName("StatePill")
        result_header.addWidget(self.lbl_build_state)
        body.addLayout(result_header)
        body.addWidget(self._rule())
        self.result_tabbar = QTabBar()
        self.result_tabbar.setExpanding(False)
        self.result_tabbar.setDrawBase(False)
        for text in ("결과", "원문", "파일"):
            self.result_tabbar.addTab(text)
        body.addWidget(self.result_tabbar)
        self.result_views = QStackedWidget()
        self.tbl_findings = QTableWidget(0, 3)
        self.tbl_findings.setHorizontalHeaderLabels(["대상", "상태", "내용"])
        self.tbl_findings.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.tbl_findings.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.tbl_findings.verticalHeader().setVisible(False)
        self.tbl_findings.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        self.tbl_findings.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        self.tbl_findings.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        self.tbl_findings.setFont(QFont("Consolas", 10))
        self.result_views.addWidget(self.tbl_findings)
        raw = QWidget()
        raw_layout = QVBoxLayout(raw)
        raw_layout.setContentsMargins(0, 0, 0, 0)
        raw_layout.setSpacing(0)
        raw_tools = QHBoxLayout()
        raw_tools.setContentsMargins(6, 5, 8, 5)
        self.btn_view_analysis = self._button("분석", lambda: self.set_analysis_details_visible(True))
        self.btn_view_analysis.setProperty("view", "true")
        self.btn_view_analysis.setCheckable(True)
        self.btn_view_changes = self._button("생성·빌드", lambda: self.set_generation_details_visible(True))
        self.btn_view_changes.setProperty("view", "true")
        self.btn_view_changes.setCheckable(True)
        self.btn_view_changes.setEnabled(False)
        raw_tools.addWidget(self.btn_view_analysis)
        raw_tools.addWidget(self.btn_view_changes)
        raw_tools.addStretch()
        self.btn_save_raw = self._button("저장", self.save_visible_report, variant="quiet")
        raw_tools.addWidget(self.btn_save_raw)
        raw_layout.addLayout(raw_tools)
        raw_stack_host = QWidget()
        raw_stack = QVBoxLayout(raw_stack_host)
        raw_stack.setContentsMargins(0, 0, 0, 0)
        raw_stack.setSpacing(0)
        self.analysis_details_body = QWidget()
        analysis = QVBoxLayout(self.analysis_details_body)
        analysis.setContentsMargins(0, 0, 0, 0)
        self.txt_analyze = self._code_view()
        analysis.addWidget(self.txt_analyze)
        raw_stack.addWidget(self.analysis_details_body)
        self.generation_details_body = QWidget()
        generated = QVBoxLayout(self.generation_details_body)
        generated.setContentsMargins(0, 0, 0, 0)
        self.txt_map = self._code_view()
        generated.addWidget(self.txt_map)
        raw_stack.addWidget(self.generation_details_body)
        raw_layout.addWidget(raw_stack_host, 1)
        self.analysis_details_body.setVisible(False)
        self.generation_details_body.setVisible(False)
        self._raw_kind = "analysis"
        self.result_views.addWidget(raw)
        files = QWidget()
        files_layout = QVBoxLayout(files)
        files_layout.setContentsMargins(0, 0, 0, 0)
        files_layout.setSpacing(0)
        file_tools = QHBoxLayout()
        file_tools.setContentsMargins(11, 6, 8, 6)
        self.lbl_output_path = _label("", "muted")
        self.lbl_output_path.setWordWrap(True)
        self.lbl_output_path.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        self.lbl_output_path.setVisible(False)
        file_tools.addWidget(self.lbl_output_path, 1)
        self.btn_open_generated = self._button("폴더", self.open_generated_folder, variant="quiet")
        self.btn_open_generated.setEnabled(False)
        file_tools.addWidget(self.btn_open_generated)
        files_layout.addLayout(file_tools)
        self.list_generated_files = QListWidget()
        self.list_generated_files.setFont(QFont("Consolas", 10))
        self.list_generated_files.itemDoubleClicked.connect(self.open_generated_file)
        files_layout.addWidget(self.list_generated_files, 1)
        self.result_views.addWidget(files)
        self.result_tabbar.currentChanged.connect(self._select_result_view)
        body.addWidget(self.result_views, 1)
        layout.addWidget(output, 1)
        return page

    def _select_result_view(self, index):
        self.result_views.setCurrentIndex(index)
        if index == 0:
            self.tbl_findings.setVisible(True)
        elif index == 1:
            self.analysis_details_body.setVisible(self._raw_kind == "analysis")
            self.generation_details_body.setVisible(self._raw_kind == "generation")
            self.btn_view_analysis.setChecked(self._raw_kind == "analysis")
            self.btn_view_changes.setChecked(self._raw_kind == "generation")
        elif index == 2:
            self.list_generated_files.setVisible(True)

    def _logs_page(self):
        page = QWidget()
        box = QVBoxLayout(page)
        box.setContentsMargins(18, 15, 18, 15)
        box.setSpacing(10)
        device_panel, device = self._panel()
        row = QHBoxLayout()
        row.addWidget(_label("기기", "field"))
        self.cmb_device = _ComboBox()
        self.cmb_device.setMinimumWidth(180)
        row.addWidget(self.cmb_device)
        self.btn_refresh_devices = self._button("새로고침", self.refresh_devices, long_job=True)
        row.addWidget(self.btn_refresh_devices)
        row.addStretch()
        self.lbl_adb = _label("ADB 준비" if self.adb_path else "ADB 없음", "muted")
        row.addWidget(self.lbl_adb)
        device.addLayout(row)
        options = QHBoxLayout()
        self.cmb_filter = _ComboBox()
        self.cmb_filter.addItems(["EUNORA만", "전체 logcat"])
        options.addWidget(self.cmb_filter)
        self.cmb_session_app = _ComboBox()
        self.cmb_session_app.addItem("앱 태그", "")
        for key, label in APP_LABELS.items():
            self.cmb_session_app.addItem(label, key)
        self.cmb_capture_app = self.cmb_session_app
        options.addWidget(self.cmb_session_app)
        options.addStretch()
        self.btn_start_log = self._button("로그 시작", self.start_logcat, variant="primary")
        self.btn_stop_log = self._button("중지", self.stop_logcat)
        self.btn_stop_log.setEnabled(False)
        self.btn_cap_start = self._button("캡처", self.start_capture)
        self.btn_cap_stop = self._button("종료·저장", self.stop_capture)
        self.btn_cap_stop.setEnabled(False)
        for button in (self.btn_start_log, self.btn_stop_log, self.btn_cap_start, self.btn_cap_stop):
            options.addWidget(button)
        device.addLayout(options)
        box.addWidget(device_panel)
        extraction = QHBoxLayout()
        extraction.addWidget(_label("APK 추출", "field"))
        self.cmb_map_app = _ComboBox()
        for key, label in APP_LABELS.items():
            self.cmb_map_app.addItem(label, key)
        self.cmb_map_app.setMinimumWidth(165)
        self.cmb_pull_app = self.cmb_map_app
        extraction.addWidget(self.cmb_pull_app)
        self.btn_pull = self._button("추출", self.pull_driver_apks, long_job=True)
        extraction.addWidget(self.btn_pull)
        extraction.addWidget(self._button("이전 비교", self.diff_last_pull_against_previous, long_job=True))
        extraction.addWidget(self._button("APK 폴더", self.open_apks_dir, variant="quiet"))
        extraction.addStretch()
        extraction.addWidget(self._button("지우기", lambda: self.txt_log.clear(), variant="quiet"))
        box.addLayout(extraction)
        self.txt_pull = self._code_view()
        self.txt_pull.setMaximumHeight(120)
        self.txt_pull.setVisible(False)
        self.txt_pull.textChanged.connect(lambda: self.txt_pull.setVisible(bool(self.txt_pull.toPlainText())))
        box.addWidget(self.txt_pull)
        self.txt_log = self._code_view()
        box.addWidget(self.txt_log, 1)
        return page

    def _history_page(self):
        page = QWidget()
        box = QHBoxLayout(page)
        box.setContentsMargins(18, 15, 18, 15)
        split = QSplitter(Qt.Orientation.Horizontal)
        split.setHandleWidth(2)
        left, listing = self._panel()
        self.cmb_session_filter = _ComboBox()
        self.cmb_session_filter.addItem("모든 앱", "all")
        self.cmb_session_filter.addItem("태그 없음", "")
        for key, label in APP_LABELS.items():
            self.cmb_session_filter.addItem(label, key)
        listing.addWidget(self.cmb_session_filter)
        self.list_sessions = QListWidget()
        self.list_sessions.setMinimumWidth(205)
        self.list_sessions.currentItemChanged.connect(self.on_session_selected)
        listing.addWidget(self.list_sessions, 1)
        tools = QHBoxLayout()
        tools.addWidget(self._button("새로고침", self.reload_session_list))
        tools.addWidget(self._button("폴더", self.open_sessions_dir))
        listing.addLayout(tools)
        split.addWidget(left)
        right = QWidget()
        details = QVBoxLayout(right)
        details.setContentsMargins(12, 0, 0, 0)
        details.setSpacing(0)
        tabbar = QTabBar()
        tabbar.setExpanding(False)
        for text in ("로그", "요약", "매칭"):
            tabbar.addTab(text)
        details.addWidget(tabbar)
        views = QStackedWidget()
        self.txt_session = self._code_view()
        self.txt_summary = self._code_view()
        self.txt_match = self._code_view()
        for view in (self.txt_session, self.txt_summary, self.txt_match):
            views.addWidget(view)
        tabbar.currentChanged.connect(views.setCurrentIndex)
        details.addWidget(views, 1)
        split.addWidget(right)
        split.setSizes([265, 700])
        box.addWidget(split)
        self.cmb_session_filter.currentIndexChanged.connect(self.reload_session_list)
        return page

    def _settings_page(self):
        page = QWidget()
        box = QVBoxLayout(page)
        box.setContentsMargins(18, 16, 18, 16)
        box.setSpacing(14)
        row = QHBoxLayout()
        row.addWidget(_label("REA", "section"))
        row.addStretch()
        self.btn_rea_settings = self._button("설정", self.configure_rea, long_job=True)
        row.addWidget(self.btn_rea_settings)
        box.addLayout(row)
        box.addWidget(self._rule())
        box.addWidget(_label("상세 분석", "section"))
        for title, name in (("패키지 필터", "ed_pkg_filter"), ("참조 심볼", "ed_xref_symbols")):
            line = QHBoxLayout()
            label = _label(title, "field")
            label.setFixedWidth(84)
            line.addWidget(label)
            edit = QLineEdit()
            setattr(self, name, edit)
            line.addWidget(edit)
            box.addLayout(line)
        actions = QHBoxLayout()
        self.btn_structure_analysis = self._button("구조", self.run_structure_analysis, long_job=True)
        self.btn_deep_analysis = self._button("심화", self.run_deep_analysis, long_job=True)
        self.btn_rea_analysis = self._button("REA 조회", self.run_rea, long_job=True)
        self.btn_xref = self._button("참조", self.run_jadx_xref, long_job=True)
        self.btn_observer_generate = self._button("메서드 관찰 코드", self.run_observer_generation, long_job=True)
        for button in (self.btn_structure_analysis, self.btn_deep_analysis, self.btn_rea_analysis, self.btn_xref, self.btn_observer_generate):
            actions.addWidget(button)
        actions.addStretch()
        box.addLayout(actions)
        box.addWidget(self._rule())
        box.addWidget(_label("APK 비교", "section"))
        for title, name in (("이전 APK", "ed_apk_old"), ("새 APK", "ed_apk_new")):
            line = QHBoxLayout()
            label = _label(title, "field")
            label.setFixedWidth(84)
            line.addWidget(label)
            edit = QLineEdit()
            setattr(self, name, edit)
            line.addWidget(edit, 1)
            line.addWidget(self._button("찾기", lambda checked=False, target=edit: self._pick_apk(target)))
            box.addLayout(line)
        compare_tools = QHBoxLayout()
        self.cmb_apk_app = _ComboBox()
        for key, label in APP_LABELS.items():
            self.cmb_apk_app.addItem(label, key)
        compare_tools.addWidget(self.cmb_apk_app)
        compare_tools.addWidget(self._button("비교", self.run_apk_diff, variant="primary", long_job=True))
        compare_tools.addWidget(self._button("최근 추출 비교", self.diff_last_pull_against_previous, long_job=True))
        compare_tools.addStretch()
        box.addLayout(compare_tools)
        self.lbl_apk_info = _label("", "muted")
        box.addWidget(self.lbl_apk_info)
        lists = QHBoxLayout()
        for title, name in (("추가", "list_apk_added"), ("삭제", "list_apk_removed")):
            column = QVBoxLayout()
            column.addWidget(_label(title, "muted"))
            view = QListWidget()
            view.setMinimumHeight(155)
            setattr(self, name, view)
            column.addWidget(view)
            lists.addLayout(column)
        box.addLayout(lists)
        box.addStretch()
        return self._scroll(page)

    def set_busy(self, busy):
        self.progress.setVisible(busy)
        self.btn_cancel_job.setVisible(busy)

    def set_analysis_details_visible(self, visible):
        if visible:
            self._raw_kind = "analysis"
            self.result_tabbar.setCurrentIndex(1)
            self._select_result_view(1)
        else:
            self.analysis_details_body.setVisible(False)
            if self._raw_kind == "analysis" and self.result_tabbar.currentIndex() == 1:
                self.result_tabbar.setCurrentIndex(0)

    def set_generation_details_visible(self, visible):
        if visible:
            self._raw_kind = "generation"
            self.result_tabbar.setCurrentIndex(1)
            self._select_result_view(1)
        else:
            self.generation_details_body.setVisible(False)
            if self._raw_kind == "generation" and self.result_tabbar.currentIndex() == 1:
                self.result_tabbar.setCurrentIndex(0)

    def _set_result_pill(self, text, tone=""):
        self.lbl_build_state.setText(text)
        self.lbl_build_state.setProperty("tone", tone)
        self.lbl_build_state.style().unpolish(self.lbl_build_state)
        self.lbl_build_state.style().polish(self.lbl_build_state)

    def show_audit_summary(self, kind, result):
        self._raw_kind = "analysis"
        counts = result.get("counts") or {}
        rows = result.get("rows") or []
        self.lbl_result_title.setText("보안 검사" if kind == "security" else "기존 훅")
        partial = result.get("status") == "partial"
        self._set_result_pill("일부 확인" if partial else "완료", "warning" if partial else "success")
        self.lbl_result_app.setText(APP_LABELS.get(result.get("app_key"), result.get("app_key") or ""))
        total = counts.get("total", len(rows))
        review = sum(counts.get(key, 0) or 0 for key in ("not_found", "needs_review", "error", "deferred", "unresolved", "unsupported", "rows_omitted"))
        self.lbl_result_count.setText(f"대상 {total}")
        self.lbl_result_review.setText(f"추가 확인 {review}" if counts else "")
        self.audit_stats.setVisible(True)
        self.tbl_findings.setRowCount(0)
        statuses = {"class_found": "클래스 확인", "method_name_found": "메서드 이름 확인",
                    "not_found": "미발견", "needs_review": "추가 확인", "error": "조회 오류",
                    "deferred": "정밀 조회 대기", "ready": "생성 가능", "unsupported": "지원 범위 밖"}
        for value in rows:
            if not isinstance(value, dict):
                continue
            candidate = value.get("candidate") or {}
            target = value.get("class_name") or value.get("class") or value.get("name") or (value.get("target") or {}).get("class_name") or candidate.get("class_name") or ""
            if candidate.get("method_name"):
                target += "." + str(candidate["method_name"])
            status = value.get("status") or "needs_review"
            note = value.get("note") or value.get("reason") or ", ".join(map(str, value.get("methods") or []))
            row = self.tbl_findings.rowCount()
            self.tbl_findings.insertRow(row)
            for column, text in enumerate((target, statuses.get(status, status), note)):
                item = QTableWidgetItem(str(text))
                item.setToolTip(str(text))
                self.tbl_findings.setItem(row, column, item)
        self.tbl_findings.setVisible(True)
        self.list_generated_files.setVisible(False)
        self.lbl_output_path.setVisible(False)
        self.result_tabbar.setCurrentIndex(0)
        self.navigate("workspace")

    def show_generated_summary(self, result, build=None):
        report = result.get("report") or {}
        mode = report.get("mode") or ("observe" if report.get("observation_only") else "")
        self.lbl_result_title.setText({"observe": "호출 관찰", "boolean_false": "결과 변경", "skip_void": "실행 생략"}.get(mode, "생성 코드"))
        state = (build or {}).get("status") or result.get("build_status") or report.get("build_status") or "not_run"
        self._set_result_pill({"passed": "빌드 통과", "failed": "빌드 실패"}.get(state, "빌드 전"),
                              {"passed": "success", "failed": "error"}.get(state, "info"))
        self.audit_stats.setVisible(False)
        self.list_generated_files.clear()
        for relative, value in sorted((result.get("files") or {}).items()):
            if not str(relative).endswith((".kt", ".txt")):
                continue
            path = value.get("path") if isinstance(value, dict) else value
            if not path:
                continue
            item = QListWidgetItem(_icon("document"), Path(relative).name)
            item.setData(Qt.ItemDataRole.UserRole, str(path))
            item.setToolTip(str(path))
            self.list_generated_files.addItem(item)
        self.list_generated_files.setVisible(True)
        self.lbl_output_path.setText(str(result.get("path") or ""))
        self.lbl_output_path.setToolTip(str(result.get("path") or ""))
        self.lbl_output_path.setVisible(bool(result.get("path")))
        self._raw_kind = "generation"
        if build:
            self.set_generation_details_visible(True)
        else:
            self.result_tabbar.setCurrentIndex(2)
        self.navigate("workspace")

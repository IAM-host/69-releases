"""REA-only configuration and explicit static-analysis requests; no model connection."""
from __future__ import annotations

import json
from pathlib import Path

from PySide6.QtCore import Signal
from PySide6.QtWidgets import (
    QComboBox, QDialog, QDialogButtonBox, QFileDialog, QFormLayout,
    QHBoxLayout, QLabel, QLineEdit, QMessageBox, QPlainTextEdit,
    QPushButton, QSpinBox, QVBoxLayout, QWidget,
)


class REASettingsDialog(QDialog):
    checkRequested = Signal(dict)

    def __init__(self, settings: dict, parent=None):
        super().__init__(parent)
        self.setWindowTitle("REA 설정")
        self.resize(700, 430)
        self._initial_settings = dict(settings)
        self._fields = {}
        self._path_rows = []
        layout = QVBoxLayout(self)
        note = QLabel(
            "Node·REA 실행 파일과 REA 전용 JADX MCP JAR을 지정합니다.\n"
            "일반 jadx CLI JAR과는 다릅니다. 설치가 필요하면 setup_rea.bat를 실행하세요."
        )
        note.setWordWrap(True)
        layout.addWidget(note)
        form = QFormLayout()
        for key, label, directory, file_filter in (
            ("node_path", "Node 실행 파일", False, "실행 파일 (*.exe);;모든 파일 (*)"),
            ("rea_entry", "REA 진입 파일", False, "JavaScript (*.mjs);;모든 파일 (*)"),
            ("jar_path", "REA 전용 JADX MCP JAR", False, "Java archive (*.jar);;모든 파일 (*)"),
            ("java_home", "JDK 폴더 (선택)", True, ""),
        ):
            row = QWidget()
            row_layout = QHBoxLayout(row)
            row_layout.setContentsMargins(0, 0, 0, 0)
            entry = QLineEdit(str(settings.get(key) or ""))
            self._fields[key] = entry
            row_layout.addWidget(entry, 1)
            browse = QPushButton("찾기")
            browse.clicked.connect(
                lambda checked=False, k=key, d=directory, f=file_filter: self._browse(k, d, f)
            )
            row_layout.addWidget(browse)
            self._path_rows.append(row)
            form.addRow(label, row)
        layout.addLayout(form)
        self.btn_check = QPushButton("사전 검사")
        self.btn_check.clicked.connect(self._request_check)
        layout.addWidget(self.btn_check)
        self.txt_status = QPlainTextEdit()
        self.txt_status.setReadOnly(True)
        self.txt_status.setPlainText(
            "사전 검사는 백그라운드에서 실행됩니다. 실제 APK 분석 결과와는 구분됩니다."
        )
        layout.addWidget(self.txt_status, 1)
        self.buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Save | QDialogButtonBox.StandardButton.Cancel
        )
        self.buttons.accepted.connect(self.accept)
        self.buttons.rejected.connect(self.reject)
        layout.addWidget(self.buttons)

    def _browse(self, key, directory, file_filter):
        current = self._fields[key].text().strip()
        if directory:
            path = QFileDialog.getExistingDirectory(self, "JDK 폴더 선택", current)
        else:
            path, _ = QFileDialog.getOpenFileName(self, "REA 도구 선택", current, file_filter)
        if path:
            self._fields[key].setText(path)

    def settings(self) -> dict:
        settings = {
            **self._initial_settings,
            **{key: entry.text().strip() for key, entry in self._fields.items()},
        }
        settings.pop("_load_error", None)
        return settings

    def _request_check(self):
        self.btn_check.setEnabled(False)
        self.buttons.button(QDialogButtonBox.StandardButton.Save).setEnabled(False)
        for row in self._path_rows:
            row.setEnabled(False)
        self.txt_status.setPlainText("사전 검사 중…")
        self.checkRequested.emit(self.settings())

    def set_preflight_result(self, result):
        self.btn_check.setEnabled(True)
        self.buttons.button(QDialogButtonBox.StandardButton.Save).setEnabled(True)
        for row in self._path_rows:
            row.setEnabled(True)
        self.txt_status.setPlainText(
            "사전 검사 결과\n" + json.dumps(result, ensure_ascii=False, indent=2, default=str)
        )

    def set_preflight_error(self, message):
        self.btn_check.setEnabled(True)
        self.buttons.button(QDialogButtonBox.StandardButton.Save).setEnabled(True)
        for row in self._path_rows:
            row.setEnabled(True)
        self.txt_status.setPlainText("사전 검사 실패\n" + str(message))


class REAAnalysisDialog(QDialog):
    OPERATIONS = (
        ("APK 개요", "package"),
        ("클래스 검색", "class_search"),
        ("클래스 정보", "class"),
        ("메서드 분석", "method"),
        ("참조 추적", "references"),
    )

    def __init__(self, apk_path: Path, previous=None, parent=None):
        super().__init__(parent)
        self.setWindowTitle("REA 분석")
        self.resize(620, 330)
        previous = previous or {}
        layout = QVBoxLayout(self)
        apk = QLabel(str(apk_path))
        apk.setWordWrap(True)
        layout.addWidget(apk)
        form = QFormLayout()
        self.cmb_operation = QComboBox()
        for label, key in self.OPERATIONS:
            self.cmb_operation.addItem(label, key)
        self.cmb_operation.setCurrentIndex(max(0, self.cmb_operation.findData(previous.get("operation", "package"))))
        form.addRow("분석 종류", self.cmb_operation)
        self.ed_query = QLineEdit(str(previous.get("query") or ""))
        form.addRow("검색어 (비우면 전체)", self.ed_query)
        self.ed_class = QLineEdit(str(previous.get("class_name") or ""))
        self.ed_class.setPlaceholderText("예: com.example.Example 또는 정확한 난독화 클래스 이름")
        form.addRow("정확한 클래스 이름", self.ed_class)
        self.ed_method = QLineEdit(str(previous.get("method_name") or ""))
        form.addRow("정확한 메서드 이름", self.ed_method)
        self.spn_overload = QSpinBox()
        self.spn_overload.setRange(-1, 100000)
        self.spn_overload.setSpecialValueText("미지정 — 유일한 메서드일 때만")
        index = previous.get("overload_index")
        self.spn_overload.setValue(-1 if index is None else int(index))
        form.addRow("오버로드 번호 (0부터)", self.spn_overload)
        layout.addLayout(form)
        note = QLabel("동일 이름 메서드가 여러 개이면 클래스 정보에서 번호를 확인해 지정하세요. APK는 실행하지 않습니다.")
        note.setWordWrap(True)
        layout.addWidget(note)
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        buttons.button(QDialogButtonBox.StandardButton.Ok).setText("분석 실행")
        buttons.button(QDialogButtonBox.StandardButton.Cancel).setText("취소")
        buttons.accepted.connect(self._accept_request)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)
        self.cmb_operation.currentIndexChanged.connect(self._update_fields)
        self.ed_method.textChanged.connect(self._update_fields)
        self._update_fields()

    def _update_fields(self, *args):
        operation = self.cmb_operation.currentData()
        self.ed_query.setEnabled(operation == "class_search")
        self.ed_class.setEnabled(operation in {"class", "method", "references"})
        self.ed_method.setEnabled(operation in {"method", "references"})
        self.spn_overload.setEnabled(operation == "method" or (operation == "references" and bool(self.ed_method.text().strip())))

    def request(self) -> dict:
        operation = self.cmb_operation.currentData()
        return {
            "operation": operation,
            "query": self.ed_query.text().strip() if operation == "class_search" else "",
            "class_name": self.ed_class.text().strip() if operation in {"class", "method", "references"} else "",
            "method_name": self.ed_method.text().strip() if operation in {"method", "references"} else "",
            "overload_index": self.spn_overload.value() if self.spn_overload.isEnabled() and self.spn_overload.value() >= 0 else None,
        }

    def _accept_request(self):
        request = self.request()
        if request["operation"] in {"class", "method", "references"} and not request["class_name"]:
            QMessageBox.warning(self, "L", "정확한 클래스 이름을 입력하세요.")
            return
        if request["operation"] == "method" and not request["method_name"]:
            QMessageBox.warning(self, "L", "정확한 메서드 이름을 입력하세요.")
            return
        self.accept()


class ObserverGenerationDialog(QDialog):
    """Select only methods already present in a verified REA class inventory."""

    def __init__(self, apk_path, class_name, profiles, methods, project_path="", app_key="", parent=None):
        super().__init__(parent)
        self.setWindowTitle("훅 코드 생성")
        self.resize(730, 310)
        layout = QVBoxLayout(self)
        source = QLabel(f"APK: {apk_path}\n클래스: {class_name}")
        source.setWordWrap(True)
        layout.addWidget(source)
        form = QFormLayout()
        row = QWidget()
        row_layout = QHBoxLayout(row)
        row_layout.setContentsMargins(0, 0, 0, 0)
        self.ed_project = QLineEdit(str(project_path))
        row_layout.addWidget(self.ed_project, 1)
        browse = QPushButton("찾기")
        browse.clicked.connect(self._browse_project)
        row_layout.addWidget(browse)
        form.addRow("EUNORA 프로젝트 / ModuleMain.kt", row)
        self.cmb_profile = QComboBox()
        for key, profile in profiles.items():
            self.cmb_profile.addItem(f"{profile['label']} — {profile['package']}", key)
        index = self.cmb_profile.findData(app_key)
        if index >= 0:
            self.cmb_profile.setCurrentIndex(index)
        form.addRow("대상 앱", self.cmb_profile)
        self.cmb_method = QComboBox()
        for method in methods:
            self.cmb_method.addItem(method["label"], dict(method))
        form.addRow("확인된 메서드", self.cmb_method)
        layout.addLayout(form)
        note = QLabel("선택한 메서드의 실행 여부를 로그로 관찰하는 코드를 생성합니다.\n원본을 보존하고 생성본·차이점·TXT를 새 폴더에 저장합니다. 빌드 검사는 별도로 실행하세요.")
        note.setWordWrap(True)
        layout.addWidget(note)
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        buttons.button(QDialogButtonBox.StandardButton.Ok).setText("생성본 만들기")
        buttons.button(QDialogButtonBox.StandardButton.Cancel).setText("취소")
        buttons.accepted.connect(self._accept_request)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    def _browse_project(self):
        selected = QFileDialog.getExistingDirectory(self, "EUNORA 프로젝트 폴더 선택", self.ed_project.text().strip())
        if selected:
            self.ed_project.setText(selected)

    def request(self):
        method = self.cmb_method.currentData() or {}
        return {
            "project_path": self.ed_project.text().strip(),
            "app_key": self.cmb_profile.currentData(),
            "method_name": method.get("name"),
            "overload_index": method.get("overload_index"),
        }

    def _accept_request(self):
        request = self.request()
        if not request["project_path"] or not Path(request["project_path"]).exists():
            QMessageBox.warning(self, "L", "EUNORA 프로젝트 폴더 또는 ModuleMain.kt를 선택하세요.")
            return
        if not request["app_key"] or not request["method_name"]:
            QMessageBox.warning(self, "L", "확인된 앱과 메서드를 선택하세요.")
            return
        self.accept()

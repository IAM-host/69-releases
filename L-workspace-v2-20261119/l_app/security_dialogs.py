"""Security audit input and explicit local-test generation selection."""
from __future__ import annotations

from PySide6.QtWidgets import (
    QComboBox, QDialog, QDialogButtonBox, QLabel, QMessageBox,
    QPlainTextEdit, QVBoxLayout,
)

from .rea_dialogs import EunoraAuditDialog


class SecurityAuditDialog(EunoraAuditDialog):
    """Reuse the APK/project-only input without requiring typed class names."""

    def __init__(self, apk_path="", project_path="", parent=None):
        super().__init__(apk_path, project_path, parent)
        self.setWindowTitle("보안 자동 점검")
        note = self.layout().itemAt(0).widget()
        if isinstance(note, QLabel):
            note.setText(
                "APK에서 root·su·Magisk·후킹 관련 검사 후보를 찾고 정확한 메서드 정보를 확인합니다.\n"
                "APK와 EUNORA 프로젝트만 선택하세요. 결과는 후보·미확인·지원 범위를 구분합니다."
            )
        buttons = self.findChild(QDialogButtonBox)
        buttons.button(QDialogButtonBox.StandardButton.Ok).setText("보안 점검 실행")


class SecurityGenerationDialog(QDialog):
    """Select a confirmed candidate and an explicit, supported generation mode."""

    MODES = {
        "observe": "호출 관찰 — 반환값 유지",
        "boolean_false": "테스트: Boolean 결과 false",
        "skip_void": "테스트: void 검사 실행 생략",
    }

    def __init__(self, apk_path, project_path, choices, parent=None):
        super().__init__(parent)
        self.setWindowTitle("보안 테스트 훅 생성")
        self.resize(850, 440)
        self._choices = choices
        layout = QVBoxLayout(self)
        paths = QLabel(f"APK: {apk_path}\nEUNORA: {project_path}")
        paths.setWordWrap(True)
        layout.addWidget(paths)
        layout.addWidget(QLabel("APK에서 원형을 확인한 보안 검사 후보"))
        self.cmb_target = QComboBox()
        for index, choice in enumerate(choices):
            self.cmb_target.addItem(str(choice.get("label") or "확인된 메서드"), index)
        layout.addWidget(self.cmb_target)
        self.cmb_mode = QComboBox()
        layout.addWidget(QLabel("생성할 동작"))
        layout.addWidget(self.cmb_mode)
        self.txt_evidence = QPlainTextEdit()
        self.txt_evidence.setReadOnly(True)
        layout.addWidget(self.txt_evidence, 1)
        self.lbl_mode = QLabel()
        self.lbl_mode.setWordWrap(True)
        layout.addWidget(self.lbl_mode)
        self.buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        self.buttons.button(QDialogButtonBox.StandardButton.Ok).setText("선택한 코드 사본 생성")
        self.buttons.button(QDialogButtonBox.StandardButton.Cancel).setText("취소")
        self.buttons.accepted.connect(self._accept_request)
        self.buttons.rejected.connect(self.reject)
        layout.addWidget(self.buttons)
        self.cmb_target.currentIndexChanged.connect(self._update_target)
        self.cmb_mode.currentIndexChanged.connect(self._update_mode)
        self._update_target()

    def _update_target(self, *args):
        index = self.cmb_target.currentData()
        choice = self._choices[index] if isinstance(index, int) and 0 <= index < len(self._choices) else {}
        candidate = choice.get("candidate") or {}
        previous_mode = self.cmb_mode.currentData()
        self.cmb_mode.blockSignals(True)
        self.cmb_mode.clear()
        for mode, label in self.MODES.items():
            if mode in (choice.get("modes") or []):
                self.cmb_mode.addItem(label, mode)
        preferred = previous_mode if previous_mode is not None else "observe"
        self.cmb_mode.setCurrentIndex(self.cmb_mode.findData(preferred))
        self.cmb_mode.blockSignals(False)
        signals = candidate.get("signals") or []
        lines = [str(choice.get("label") or ""),
                 "분류: " + ", ".join(map(str, candidate.get("categories") or [])),
                 "정적 단서: " + ", ".join(map(str, signals)),
                 "원형: " + str(choice.get("dex_descriptor") or candidate.get("dex_descriptor") or ""),
                 "후보의 실제 역할과 실행 결과는 기기에서 별도로 확인해야 합니다."]
        if candidate.get("note"):
            lines.append(str(candidate["note"]))
        self.txt_evidence.setPlainText("\n".join(lines))
        self._update_mode()

    def _update_mode(self, *args):
        mode = self.cmb_mode.currentData()
        self.buttons.button(QDialogButtonBox.StandardButton.Ok).setEnabled(mode in self.MODES)
        if mode is None:
            self.lbl_mode.setText("이 대상에서 생성할 동작을 선택하세요. 이전 동작을 지원하지 않으면 다른 동작으로 자동 대체하지 않습니다.")
        elif mode == "boolean_false":
            self.lbl_mode.setText(
                "이 모드는 선택한 메서드가 정상 반환한 Boolean 결과를 false로 변경하는 테스트 코드를 생성합니다.\n"
                "예외는 유지하며 선택한 로컬 메서드의 반환값에 적용합니다. 빌드 종류로 실행을 제한하지 않습니다.\n"
                "원본은 보존하고 전체 E파일·ModuleMain 사본, TXT와 변경 내역을 저장합니다."
            )
        elif self.cmb_mode.currentData() == "skip_void":
            self.lbl_mode.setText(
                "이 모드는 선택한 void 검사 메서드의 본문을 실행하지 않고 반환하는 테스트 코드를 생성합니다.\n"
                "해당 메서드의 부수 효과와 예외 발생도 생략되므로 대상의 실제 역할을 확인해야 합니다.\n"
                "선택한 로컬 검사 메서드에 적용하며 빌드 종류로 실행을 제한하지 않습니다.\n"
                "원본은 보존하고 전체 E파일·ModuleMain 사본, TXT와 변경 내역을 저장합니다."
            )
        else:
            self.lbl_mode.setText(
                "이 모드는 메서드 호출을 기록합니다. 인자·반환값·예외를 변경하지 않습니다.\n"
                "원본은 보존하고 전체 E파일·ModuleMain 사본, TXT와 변경 내역을 저장합니다."
            )

    def request(self):
        return {"choice_index": self.cmb_target.currentData(), "mode": self.cmb_mode.currentData()}

    def _accept_request(self):
        request = self.request()
        index = request["choice_index"]
        if not isinstance(index, int) or isinstance(index, bool) or not 0 <= index < len(self._choices):
            QMessageBox.warning(self, "L", "점검에서 확인된 메서드를 선택하세요.")
            return
        if request["mode"] not in self.MODES or request["mode"] not in (self._choices[index].get("modes") or []):
            QMessageBox.warning(self, "L", "이 대상에서 지원하는 생성 동작을 선택하세요.")
            return
        self.accept()

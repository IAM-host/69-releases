"""Compact dark workbench styling; no external visual assets."""
from PySide6.QtGui import QFont, QFontDatabase


def interface_font():
    available = set(QFontDatabase.families())
    for family in ("Malgun Gothic", "맑은 고딕", "Noto Sans CJK KR", "Segoe UI"):
        if family in available:
            return QFont(family, 10)
    return QFont("Sans Serif", 10)


STYLESHEET = """
QMainWindow, QWidget#Shell { background: #20242b; color: #d4d8df; }
QWidget { font-size: 12px; }
QLabel { background: transparent; color: #bac2ce; }
QLabel[role="title"] { font-size: 16px; font-weight: 600; color: #e0e5ec; }
QLabel[role="section"] { font-size: 12px; font-weight: 600; color: #cbd3de; }
QLabel[role="field"] { color: #97a4b5; }
QLabel[role="muted"] { color: #7e8b9d; font-size: 11px; }
QFrame#Sidebar { background: #171b22; border: none; border-right: 1px solid #303640; }
QFrame#Sidebar QLabel#Brand { color: #e3e8ef; font-size: 19px; font-weight: 600; }
QPushButton#NavButton { background: transparent; border: none; border-left: 2px solid transparent;
    border-radius: 0; text-align: left; padding: 11px 13px; color: #8d99aa; font-size: 12px; }
QPushButton#NavButton:hover { background: #202630; color: #d7dfe9; }
QPushButton#NavButton:checked { background: #252e3a; border-left-color: #7393b4; color: #dbe6f1; }
QFrame#PageHeader { background: #20242b; border-bottom: 1px solid #343b46; }
QFrame#Panel { background: #242a32; border: 1px solid #373f4b; border-radius: 2px; }
QFrame#Rule { background: #373f4b; border: none; max-height: 1px; }
QLabel#StatePill { color: #8999ac; font-size: 11px; padding: 1px 3px; }
QLabel#StatePill[tone="success"] { color: #94b4a2; }
QLabel#StatePill[tone="warning"] { color: #c5b48a; }
QLabel#StatePill[tone="error"] { color: #cf979b; }
QLabel#StatePill[tone="info"] { color: #8fa9c4; }
QLineEdit, QComboBox { background: #1d222a; color: #cbd3df; border: 1px solid #3b4553;
    border-radius: 2px; padding: 5px 8px; min-height: 20px; selection-background-color: #3b536c; }
QLineEdit:focus, QComboBox:focus { border-color: #6a829e; }
QLineEdit:disabled, QComboBox:disabled { color: #586474; background: #222730; border-color: #303944; }
QComboBox { padding-right: 25px; }
QComboBox::drop-down { width: 23px; border: none; }
QComboBox::down-arrow { image: none; width: 0; height: 0; }
QComboBox QAbstractItemView { background: #252b34; color: #d0d7e2; border: 1px solid #465365;
    selection-background-color: #364657; selection-color: #edf3f9; padding: 3px; }
QPushButton { background: #2b323c; color: #bdc7d5; border: 1px solid #45505e;
    border-radius: 2px; padding: 5px 12px; min-height: 20px; }
QPushButton:hover { background: #353f4d; border-color: #64788f; color: #e0e8f1; }
QPushButton:pressed { background: #26303d; }
QPushButton:disabled { background: #242a32; border-color: #343d49; color: #596576; }
QPushButton[variant="primary"] { background: #3c566f; border-color: #57728d; color: #e0e9f3; }
QPushButton[variant="primary"]:hover { background: #496782; border-color: #708ba6; }
QPushButton[variant="primary"]:disabled { background: #2b3541; border-color: #374554; color: #64778b; }
QPushButton[variant="quiet"] { background: transparent; border-color: transparent; color: #8e9db0; }
QPushButton[variant="quiet"]:hover { background: #303a47; border-color: #45505e; color: #d5e0ec; }
QPushButton[variant="quiet"]:disabled { background: transparent; border-color: transparent; color: #536071; }
QPushButton[view="true"] { background: transparent; border: none; border-radius: 0;
    padding: 4px 10px; min-height: 18px; color: #8492a5; }
QPushButton[view="true"]:checked { background: #303b49; color: #cbd9e8; }
QPlainTextEdit { background: #1b2027; color: #bfcada; border: 1px solid #333d49;
    border-radius: 1px; padding: 8px; selection-background-color: #3b536c; }
QPlainTextEdit#CodeView { border: none; background: #1b2027; color: #bfcada; }
QListWidget, QTableWidget { background: #1e232b; color: #b8c4d3; border: none;
    border-radius: 0; outline: none; selection-background-color: #304155; selection-color: #e3edf9; }
QListWidget::item { padding: 8px 10px; border-bottom: 1px solid #282f39; }
QListWidget::item:hover { background: #28323f; }
QListWidget::item:selected { background: #304155; color: #e3edf9; }
QTableWidget { gridline-color: #2d3540; }
QHeaderView::section { background: #272e38; color: #8e9daf; border: none;
    border-bottom: 1px solid #3b4552; padding: 7px 9px; font-weight: 500; text-align: left; }
QTableCornerButton::section { background: #272e38; border: none; }
QTabBar::tab { background: transparent; color: #7e8d9f; border: none;
    border-bottom: 2px solid transparent; padding: 8px 17px; }
QTabBar::tab:selected { color: #d4e0ed; border-bottom-color: #7691ad; }
QTabBar::tab:hover { color: #b6c6d9; background: #29313d; }
QScrollArea { border: none; background: transparent; }
QScrollArea > QWidget > QWidget { background: transparent; }
QScrollBar:vertical { background: #20262e; width: 8px; margin: 0; }
QScrollBar::handle:vertical { background: #465466; min-height: 28px; border-radius: 2px; }
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { height: 0; }
QScrollBar::add-page:vertical, QScrollBar::sub-page:vertical { background: transparent; }
QProgressBar { background: #2b3542; border: none; max-height: 2px; }
QProgressBar::chunk { background: #7891ab; }
QFrame#StatusBar { background: #1b2027; border-top: 1px solid #343c48; }
QLabel#StatusLabel { color: #78899d; font-size: 11px; }
QSplitter::handle { background: #343d49; }
QToolTip { background: #141920; color: #d0dbe8; border: 1px solid #465466; padding: 5px; }
QMenu { background: #252c36; color: #c5d0de; border: 1px solid #465466; padding: 4px; }
QMenu::item { padding: 6px 15px; }
QMenu::item:selected { background: #344457; }
"""

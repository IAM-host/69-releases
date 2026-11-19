"""Qt background task boundary; worker code receives snapshots, never widgets."""
from __future__ import annotations

import threading
from PySide6.QtCore import QThread, Signal

from .processes import CancelledError, bind_cancel_event, check_cancelled


class BackgroundJob(QThread):
    succeeded = Signal(object)
    failed = Signal(str)
    progress = Signal(str)
    cancelled = Signal()

    def __init__(self, work, parent=None):
        super().__init__(parent)
        self._work = work
        self._cancel_event = threading.Event()

    def cancel(self) -> None:
        self._cancel_event.set()
        self.requestInterruption()

    def _report(self, message: str) -> None:
        check_cancelled()
        self.progress.emit(str(message))

    def run(self) -> None:
        with bind_cancel_event(self._cancel_event):
            try:
                check_cancelled()
                result = self._work(self._report)
                check_cancelled()
            except CancelledError:
                self.cancelled.emit()
            except Exception as error:
                self.failed.emit(f"{type(error).__name__}: {error}")
            else:
                self.succeeded.emit(result)

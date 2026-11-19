"""Cancellable subprocess execution shared by analysis and ADB services."""
from __future__ import annotations

from contextlib import contextmanager
import os
import signal
import subprocess
import threading
import time
from typing import Iterator, Sequence


class CancelledError(RuntimeError):
    """The current background task was cancelled by its owner."""


_local = threading.local()


@contextmanager
def bind_cancel_event(event: threading.Event) -> Iterator[None]:
    previous = getattr(_local, "cancel_event", None)
    _local.cancel_event = event
    try:
        yield
    finally:
        _local.cancel_event = previous


def check_cancelled() -> None:
    event = getattr(_local, "cancel_event", None)
    if event is not None and event.is_set():
        raise CancelledError("작업이 취소되었습니다")


class _WindowsJob:
    """Best-effort job ownership, without killing normal detached tool daemons."""

    def __init__(self, process):
        self.handle = None
        if os.name != "nt":
            return
        import ctypes
        from ctypes import wintypes
        self.api = ctypes.WinDLL("kernel32", use_last_error=True)
        self.api.CreateJobObjectW.argtypes = [ctypes.c_void_p, wintypes.LPCWSTR]
        self.api.CreateJobObjectW.restype = wintypes.HANDLE
        self.api.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
        self.api.AssignProcessToJobObject.restype = wintypes.BOOL
        self.api.TerminateJobObject.argtypes = [wintypes.HANDLE, wintypes.UINT]
        self.api.TerminateJobObject.restype = wintypes.BOOL
        self.api.CloseHandle.argtypes = [wintypes.HANDLE]
        self.api.CloseHandle.restype = wintypes.BOOL
        handle = self.api.CreateJobObjectW(None, None)
        if handle and self.api.AssignProcessToJobObject(handle, int(process._handle)):
            self.handle = handle
        elif handle:
            self.api.CloseHandle(handle)

    def terminate(self):
        return bool(self.handle and self.api.TerminateJobObject(self.handle, 1))

    def close(self):
        if self.handle:
            # No KILL_ON_JOB_CLOSE: a successful adb start-server may leave a daemon.
            self.api.CloseHandle(self.handle)
            self.handle = None


def _terminate_owned_process(process: subprocess.Popen, job=None) -> None:
    """Terminate our process tree even if its leader has already exited."""
    if os.name == "nt":
        killed_job = bool(job and job.terminate())
        if not killed_job and process.poll() is None:
            try:
                subprocess.run(
                    ["taskkill", "/PID", str(process.pid), "/T", "/F"],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                    timeout=2,
                    creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
                )
            except (OSError, subprocess.SubprocessError):
                pass
    else:
        # The leader can exit while its children still own our pipe handles.
        # start_new_session gives this invocation its own process group.
        for sig in (signal.SIGTERM, signal.SIGKILL):
            try:
                os.killpg(process.pid, sig)
            except ProcessLookupError:
                break
            except OSError:
                break
    if process.poll() is None:
        try:
            process.kill()
        except OSError:
            pass
    try:
        process.wait(timeout=1)
    except subprocess.TimeoutExpired:
        # Never perform an unbounded communicate() while a descendant owns pipes.
        pass


def _read_pipe(stream) -> bytes | None:
    """Return available bytes, b'' if not ready, or None at EOF; never block."""
    if os.name == "nt":
        import ctypes
        import msvcrt
        from ctypes import wintypes
        available = wintypes.DWORD()
        api = ctypes.WinDLL("kernel32", use_last_error=True)
        peek = api.PeekNamedPipe
        peek.argtypes = [wintypes.HANDLE, ctypes.c_void_p, wintypes.DWORD,
                         ctypes.c_void_p, ctypes.POINTER(wintypes.DWORD), ctypes.c_void_p]
        peek.restype = wintypes.BOOL
        if not peek(msvcrt.get_osfhandle(stream.fileno()), None, 0, None,
                    ctypes.byref(available), None):
            error = ctypes.get_last_error()
            if error in (6, 109, 232):  # invalid handle / broken pipe / no data
                return None
            raise ctypes.WinError(error)
        if not available.value:
            return b""
        data = os.read(stream.fileno(), min(available.value, 65536))
    else:
        try:
            data = os.read(stream.fileno(), 65536)
        except BlockingIOError:
            return b""
    return data if data else None


def run_process(
    args: Sequence[str], *, timeout: float = 30, cwd=None,
    encoding: str = "utf-8", errors: str = "replace", env=None,
) -> subprocess.CompletedProcess[str]:
    """Run an argument vector without a shell and honor the owning task's cancellation."""
    check_cancelled()
    if isinstance(args, (str, bytes)) or not args:
        raise ValueError("명령은 비어 있지 않은 인자 목록이어야 합니다")
    command = [os.fspath(arg) for arg in args]
    options = dict(stdout=subprocess.PIPE, stderr=subprocess.PIPE, bufsize=0,
                   cwd=cwd, env=env, shell=False)
    if os.name == "nt":
        options["creationflags"] = subprocess.CREATE_NO_WINDOW | subprocess.CREATE_NEW_PROCESS_GROUP
    else:
        options["start_new_session"] = True
    process = subprocess.Popen(command, **options)
    job = _WindowsJob(process)
    streams = {process.stdout: bytearray(), process.stderr: bytearray()}
    opened = set(streams)
    if os.name != "nt":
        for stream in opened:
            os.set_blocking(stream.fileno(), False)
    deadline = time.monotonic() + timeout
    try:
        while opened or process.poll() is None:
            check_cancelled()
            if time.monotonic() >= deadline:
                raise subprocess.TimeoutExpired(command, timeout)
            progressed = False
            for stream in tuple(opened):
                data = _read_pipe(stream)
                if data is None:
                    opened.remove(stream)
                elif data:
                    streams[stream].extend(data)
                    progressed = True
            if not progressed:
                time.sleep(min(0.02, max(0, deadline - time.monotonic())))
        check_cancelled()
        def decode(data):
            return bytes(data).decode(encoding, errors).replace("\r\n", "\n").replace("\r", "\n")
        return subprocess.CompletedProcess(command, process.returncode,
                                           decode(streams[process.stdout]),
                                           decode(streams[process.stderr]))
    except BaseException:
        _terminate_owned_process(process, job)
        raise
    finally:
        job.close()
        # FileIO is unbuffered and no background reader thread holds these handles.
        for stream in streams:
            stream.close()

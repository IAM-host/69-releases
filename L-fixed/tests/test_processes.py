import sys
import threading
import time
import subprocess
from pathlib import Path

import pytest
from l_app.processes import bind_cancel_event, check_cancelled, CancelledError, run_process


def test_argument_vector_and_channels():
    value = '한글 & ; $(literal) "quoted"'
    result = run_process([sys.executable, '-c', 'import sys;print(sys.argv[1]);sys.stderr.write("error\\r\\n")', value])
    assert result.returncode == 0
    assert result.stdout == value + '\n'
    assert result.stderr == 'error\n'


def test_nonzero_return_preserved():
    result = run_process([sys.executable, '-c', 'import sys;sys.stderr.write("bad");sys.exit(7)'])
    assert result.returncode == 7
    assert result.stderr == 'bad'


def test_cancellation_before_launch(tmp_path):
    marker = tmp_path / 'must-not-exist'
    event = threading.Event()
    event.set()
    with bind_cancel_event(event), pytest.raises(CancelledError):
        run_process([sys.executable, '-c', f'open({str(marker)!r},"w").write("bad")'])
    assert not marker.exists()
    check_cancelled()  # context restored


def test_direct_child_cancel_is_bounded():
    event = threading.Event()
    timer = threading.Timer(.15, event.set)
    timer.start()
    started = time.monotonic()
    try:
        with bind_cancel_event(event), pytest.raises(CancelledError):
            run_process([sys.executable, '-c', 'import time;time.sleep(5)'], timeout=8)
    finally:
        timer.join()
    assert time.monotonic() - started < 2


def _orphan_command():
    return [sys.executable, '-c',
            'import subprocess,sys;subprocess.Popen([sys.executable,"-c","import time;time.sleep(3)"])']


def test_exited_leader_inherited_pipe_cancel_is_bounded():
    event = threading.Event()
    timer = threading.Timer(.2, event.set)
    timer.start()
    started = time.monotonic()
    try:
        with bind_cancel_event(event), pytest.raises(CancelledError):
            run_process(_orphan_command(), timeout=8)
    finally:
        timer.join()
    assert time.monotonic() - started < 1.5


def test_exited_leader_inherited_pipe_timeout_is_bounded():
    started = time.monotonic()
    with pytest.raises(subprocess.TimeoutExpired):
        run_process(_orphan_command(), timeout=.2)
    assert time.monotonic() - started < 1.5


def test_large_both_pipe_outputs_are_drained():
    result = run_process([sys.executable, '-c',
                          'import sys;sys.stdout.write("x"*200000);sys.stderr.write("y"*200000)'])
    assert len(result.stdout) == 200000
    assert len(result.stderr) == 200000


def test_nested_cancel_context_is_restored():
    outside = threading.Event()
    inside = threading.Event()
    outside.set()
    with bind_cancel_event(outside):
        with bind_cancel_event(inside):
            check_cancelled()
        with pytest.raises(CancelledError):
            check_cancelled()
    check_cancelled()


@pytest.mark.parametrize('command', ['', [], 'echo test'])
def test_reject_shell_command_text(command):
    with pytest.raises(ValueError):
        run_process(command)

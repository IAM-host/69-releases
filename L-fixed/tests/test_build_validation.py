"""Build validation must compile copies and never overwrite Android originals."""
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import threading
import shutil
import tempfile

import pytest

from l_app import build_validation as bv
from l_app.processes import CancelledError, bind_cancel_event


def _sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


@pytest.fixture
def bundle(tmp_path):
    project = tmp_path / "Android source"
    source = project / "app/src/main/java/ModuleMain.kt"
    source.parent.mkdir(parents=True)
    source.write_text("original")
    (project / "app/build").mkdir()
    (project / "app/build/old.class").write_text("stale")
    (project / "app/src/release").mkdir()
    (project / "app/src/release/keep.xml").write_text("flavor source")
    output = tmp_path / "generated copies"
    output.mkdir()
    generated = output / "ModuleMain.kt"
    generated.write_text("generated")
    name = source.relative_to(project).as_posix()
    manifest = output / "manifest.json"
    manifest.write_text(json.dumps({
        "project_root": str(project), "originals": {name: _sha(source)},
        "generated": {name: {"path": str(generated), "sha256": _sha(generated)}},
        "build_status": "not_run", "runtime_status": "unverified",
    }))
    return manifest, project, source, generated, name


def test_build_uses_only_copies_and_keeps_flavor_sources(bundle, monkeypatch):
    manifest, project, source, generated, name = bundle
    def run(args, **options):
        copied = Path(options["cwd"])
        assert copied != project
        assert (copied / name).read_text() == "generated"
        assert not (copied / "app/build").exists()
        assert (copied / "app/src/release/keep.xml").is_file()
        assert ":app:compileDebugKotlin" in args
        return subprocess.CompletedProcess(args, 0, "BUILD SUCCESSFUL", "")
    monkeypatch.setattr(bv, "run_process", run)
    result = bv.validate_generated_project(manifest, gradle_command=["gradle"])
    assert result["status"] == "passed"
    assert Path(result["log_path"]).read_text() == "BUILD SUCCESSFUL"
    assert source.read_text() == "original"
    assert generated.read_text() == "generated"
    recorded = json.loads(manifest.read_text())
    assert recorded["build_status"] == "passed"
    assert recorded["runtime_status"] == "unverified"


@pytest.mark.parametrize("which", ["original", "generated"])
def test_edits_after_generation_are_rejected(bundle, which):
    manifest, project, source, generated, name = bundle
    (source if which == "original" else generated).write_text("edited")
    with pytest.raises(bv.BuildValidationError, match="바뀌"):
        bv.validate_generated_project(manifest, gradle_command=["gradle"])
    assert not (manifest.parent / "build_checks").exists()


@pytest.mark.parametrize("name", ["../outside.kt", "/outside.kt", "C:/outside.kt", "app\\outside.kt", "app/build/fake.kt"])
def test_manifest_paths_cannot_escape_project(bundle, name):
    manifest = bundle[0]
    data = json.loads(manifest.read_text())
    original = next(iter(data["originals"].values()))
    generated = next(iter(data["generated"].values()))
    data["originals"] = {name: original}
    data["generated"] = {name: generated}
    manifest.write_text(json.dumps(data))
    with pytest.raises(bv.BuildValidationError):
        bv.validate_generated_project(manifest, gradle_command=["gradle"])


def test_nonzero_build_reports_failure_with_full_log(bundle, monkeypatch):
    monkeypatch.setattr(bv, "run_process", lambda args, **kw: subprocess.CompletedProcess(args, 1, "compile output", "syntax error"))
    result = bv.validate_generated_project(bundle[0], gradle_command=["gradle"])
    assert result["status"] == "failed"
    assert "syntax error" in Path(result["log_path"]).read_text()
    assert json.loads(bundle[0].read_text())["build_status"] == "failed"


def test_project_symlink_is_rejected(bundle, tmp_path):
    external = tmp_path / "external.txt"
    external.write_text("outside")
    (bundle[1] / "linked.txt").symlink_to(external)
    with pytest.raises(bv.BuildValidationError, match="심볼릭 링크"):
        bv.validate_generated_project(bundle[0], gradle_command=["gradle"])


def test_cancellation_is_preserved(bundle, monkeypatch):
    def cancel(*args, **kw):
        raise CancelledError("cancelled")
    monkeypatch.setattr(bv, "run_process", cancel)
    with pytest.raises(CancelledError):
        bv.validate_generated_project(bundle[0], gradle_command=["gradle"])
    assert json.loads(bundle[0].read_text())["build_status"] == "not_run"
    assert bundle[2].read_text() == "original"


def test_real_child_process_runs_in_isolated_copy(bundle):
    code = "from pathlib import Path; import sys; assert Path('app/src/main/java/ModuleMain.kt').read_text()=='generated'; print('copied build entry'); sys.exit(0)"
    result = bv.validate_generated_project(bundle[0], gradle_command=[sys.executable, "-c", code])
    assert result["status"] == "passed"
    assert "copied build entry" in Path(result["log_path"]).read_text()
    assert bundle[2].read_text() == "original"


@pytest.fixture
def windows_paths(tmp_path, monkeypatch):
    # Keep the simulated Windows base short regardless of pytest's test name.
    base = Path(tempfile.mkdtemp(prefix="lwin_", dir=tmp_path.parent))
    monkeypatch.setattr(bv, "_is_windows", lambda: True)
    monkeypatch.delenv("L_BUILD_DIR", raising=False)
    for variable, leaf in (("LOCALAPPDATA", "local"), ("PUBLIC", "public"), ("TEMP", "temp")):
        monkeypatch.setenv(variable, str(base / leaf))
    monkeypatch.setattr(bv.tempfile, "gettempdir", lambda: str(base / "fallback"))
    return base


def _desktop_bundle(bundle):
    manifest, project, source, generated, name = bundle
    desktop = manifest.parent.parent / "바탕 화면" / "생성본"
    shutil.copytree(manifest.parent, desktop)
    data = json.loads(manifest.read_text())
    data["generated"][name]["path"] = str(desktop / generated.name)
    copied_manifest = desktop / manifest.name
    copied_manifest.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")
    return copied_manifest


def test_windows_build_from_unicode_bundle_uses_ascii_project_and_keeps_logs(bundle, windows_paths):
    manifest = _desktop_bundle(bundle)
    # A real subprocess checks cwd and the overlaid source. Linux exercises the
    # Windows workspace-selection branch; this does not emulate the Windows JVM.
    code = (
        "from pathlib import Path; "
        "assert str(Path.cwd()).isascii(); "
        "assert Path('app/src/main/java/ModuleMain.kt').read_text()=='generated'; "
        "print('ASCII build directory verified')"
    )
    result = bv.validate_generated_project(manifest, gradle_command=[sys.executable, "-c", code])
    copied = Path(result["project_path"])
    assert result["status"] == "passed"
    assert copied.is_relative_to(windows_paths / "local" / "L-build")
    assert not copied.is_relative_to(manifest.parent)
    assert str(copied).isascii()
    assert Path(result["log_path"]).is_relative_to(manifest.parent / "build_checks")
    assert "ASCII build directory verified" in Path(result["log_path"]).read_text()
    assert bundle[2].read_text() == "original"
    assert bundle[3].read_text() == "generated"


def test_windows_unicode_user_profile_falls_back_to_public(bundle, windows_paths, monkeypatch):
    monkeypatch.setenv("LOCALAPPDATA", str(windows_paths / "사용자"))
    work = bv._create_windows_workspace(bundle[1])
    assert work.is_relative_to(windows_paths / "public" / "L-build")
    assert str(work).isascii()


def test_windows_unwritable_local_cache_falls_back_to_public(bundle, windows_paths, monkeypatch):
    blocked = windows_paths / "local" / "L-build"
    original_mkdir = Path.mkdir
    def mkdir(path, *args, **kwargs):
        if path == blocked:
            raise PermissionError("local app data is read-only")
        return original_mkdir(path, *args, **kwargs)
    monkeypatch.setattr(Path, "mkdir", mkdir)
    work = bv._create_windows_workspace(bundle[1])
    assert work.is_relative_to(windows_paths / "public" / "L-build")
    assert not blocked.exists()


@pytest.mark.parametrize("kind", ["unicode", "relative", "inside_project", "too_long"])
def test_windows_explicit_invalid_cache_is_actionable_and_never_runs_build(bundle, windows_paths, monkeypatch, kind):
    paths = {
        "unicode": windows_paths / "한글",
        "relative": Path("relative-cache"),
        "inside_project": bundle[1] / "cache",
        "too_long": windows_paths / ("a" * 101),
    }
    monkeypatch.setenv("L_BUILD_DIR", str(paths[kind]))
    monkeypatch.setattr(bv, "run_process", lambda *args, **kwargs: pytest.fail("invalid workspace must not run Gradle"))
    with pytest.raises(bv.BuildValidationError, match="L_BUILD_DIR"):
        bv.validate_generated_project(bundle[0], gradle_command=["gradle"])
    assert bundle[2].read_text() == "original"


def test_windows_cache_resolves_unicode_symlink_before_accepting_ascii_alias(bundle, windows_paths, monkeypatch):
    target = windows_paths / "한글"
    target.mkdir()
    alias = windows_paths / "ascii_alias"
    alias.symlink_to(target, target_is_directory=True)
    monkeypatch.setenv("L_BUILD_DIR", str(alias))
    with pytest.raises(bv.BuildValidationError, match="L_BUILD_DIR"):
        bv._create_windows_workspace(bundle[1])
    assert not list(target.iterdir())


def test_windows_unique_workspaces_do_not_overwrite_previous_build(bundle, windows_paths):
    first = bv._create_windows_workspace(bundle[1])
    saved = first / "keep.txt"
    saved.write_text("earlier build")
    second = bv._create_windows_workspace(bundle[1])
    assert first != second
    assert saved.read_text() == "earlier build"


def test_actual_non_ascii_error_is_reported_inline_and_full_log_remains(bundle, monkeypatch):
    output = (
        "Starting Gradle\nFAILURE: Build failed with an exception.\n\n"
        "* Where:\nBuild file 'C:/Users/name/바탕 화면/project/app/build.gradle.kts' line: 1\n\n"
        "* What went wrong:\nAn exception occurred applying plugin request\n"
        "> Your project path contains non-ASCII characters.\n\n"
        "* Try:\nRun with --stacktrace\nBUILD FAILED in 6s\n"
    )
    monkeypatch.setattr(bv, "run_process", lambda args, **kw: subprocess.CompletedProcess(args, 1, output, ""))
    result = bv.validate_generated_project(bundle[0], gradle_command=["gradle"])
    assert result["status"] == "failed"
    assert result["failure_kind"] == "non_ascii_project_path"
    assert "Your project path contains non-ASCII characters" in result["report"]
    assert "L_BUILD_DIR" in result["report"]
    assert "* What went wrong:" in result["log_excerpt"]
    assert Path(result["log_path"]).read_text() == output
    assert not (bundle[1] / "gradle.properties").exists()


def test_kotlin_error_excerpt_preserves_cause_and_removes_console_color(bundle, monkeypatch):
    output = "\n".join(["download progress"] * 100) + "\n\x1b[31me: file:///project/E02.kt:20: Unresolved reference: target\x1b[0m\n"
    monkeypatch.setattr(bv, "run_process", lambda args, **kw: subprocess.CompletedProcess(args, 1, output, ""))
    result = bv.validate_generated_project(bundle[0], gradle_command=["gradle"])
    assert "Unresolved reference: target" in result["report"]
    assert "download progress" not in result["log_excerpt"]
    assert "\x1b" not in result["log_excerpt"]
    assert "\x1b" in Path(result["log_path"]).read_text()

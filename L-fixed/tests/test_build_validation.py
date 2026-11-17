"""Build validation must compile copies and never overwrite Android originals."""
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import threading

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

"""Pinned local setup with fake tools and downloads; no network or OS install."""
import hashlib
import io
import json
from pathlib import Path
import subprocess

import pytest

import install_rea as setup


class Response(io.BytesIO):
    def __init__(self, data, declared=None):
        super().__init__(data)
        self.headers = {"Content-Length": str(len(data) if declared is None else declared)}


@pytest.mark.parametrize("value, expected", [
    ((22, 23, 4), True), ((22, 23, 3), False), ((24, 22, 1), True),
    ((24, 21, 9), False), ((26, 12, 1), True), ((26, 12, 0), False),
    ((27, 0, 0), True), ((25, 99, 99), False), ((20, 99, 99), False),
])
def test_exact_supported_node_engine_ranges(value, expected):
    assert setup.node_version_supported(value) is expected


def test_parse_node_version_rejects_extra_command_text():
    assert setup.parse_node_version("v24.22.2\n") == (24, 22, 2)
    with pytest.raises(setup.SetupError):
        setup.parse_node_version("v24.22.2 & another command")


def test_download_promotes_only_verified_complete_file(tmp_path, monkeypatch):
    target = tmp_path / "engine.jar"
    target.write_bytes(b"previous")
    data = b"complete engine fixture"
    requests = []
    def response(request, timeout):
        requests.append((request.full_url, timeout))
        return Response(data)
    monkeypatch.setattr(setup.urllib.request, "urlopen", response)
    setup.download_verified(setup.JAR_URL, target, hashlib.sha256(data).hexdigest())
    assert target.read_bytes() == data
    assert requests == [(setup.JAR_URL, 60)]
    assert not list(tmp_path.glob("*.part"))


def test_bad_download_digest_preserves_old_file_and_cleans_partial(tmp_path, monkeypatch):
    target = tmp_path / "engine.jar"
    target.write_bytes(b"previous")
    monkeypatch.setattr(setup.urllib.request, "urlopen", lambda *a, **k: Response(b"wrong"))
    with pytest.raises(setup.SetupError, match="SHA-256"):
        setup.download_verified(setup.JAR_URL, target, "0" * 64)
    assert target.read_bytes() == b"previous"
    assert not list(tmp_path.glob("*.part"))


def test_truncated_download_is_not_published(tmp_path, monkeypatch):
    target = tmp_path / "engine.jar"
    monkeypatch.setattr(setup.urllib.request, "urlopen", lambda *a, **k: Response(b"part", declared=100))
    with pytest.raises(setup.SetupError, match="끝나지"):
        setup.download_verified(setup.JAR_URL, target, hashlib.sha256(b"part").hexdigest())
    assert not target.exists()
    assert not list(tmp_path.glob("*.part"))


def test_interrupted_download_cleans_partial(tmp_path, monkeypatch):
    class Interrupted(Response):
        def read(self, size):
            raise OSError("connection interrupted")
    target = tmp_path / "engine.jar"
    monkeypatch.setattr(setup.urllib.request, "urlopen", lambda *a, **k: Interrupted(b"fixture"))
    with pytest.raises(OSError):
        setup.download_verified(setup.JAR_URL, target, "0" * 64)
    assert not target.exists()
    assert not list(tmp_path.glob("*.part"))


def test_download_retry_removes_bad_partial_before_success(tmp_path, monkeypatch):
    target = tmp_path / "engine.jar"
    data = b"good fixture"
    attempts = []
    def response(*args, **kwargs):
        assert len(list(tmp_path.glob("*.part"))) == 1
        attempts.append(True)
        return Response(b"bad" if len(attempts) == 1 else data)
    monkeypatch.setattr(setup.urllib.request, "urlopen", response)
    setup.download_verified(setup.JAR_URL, target, hashlib.sha256(data).hexdigest())
    assert len(attempts) == 2
    assert target.read_bytes() == data
    assert not list(tmp_path.glob("*.part"))


def test_subprocess_uses_argument_vector_without_shell(monkeypatch):
    seen = []
    arguments = [r"C:\Node & Space\node.exe", r"C:\Node & Space\npm-cli.js", "install", "rea-agents@6.8.0"]
    def run(command, **kwargs):
        seen.append((command, kwargs))
        return subprocess.CompletedProcess(command, 0, "ok", "")
    monkeypatch.setattr(setup.subprocess, "run", run)
    setup.run_command(arguments)
    assert seen[0][0] == arguments
    assert seen[0][1]["shell"] is False


def test_npm_command_is_node_plus_js_argument_vector(tmp_path, monkeypatch):
    node = tmp_path / "Node & Space" / "node"
    node.parent.mkdir()
    node.write_text("fixture")
    cli = node.parent / "node_modules/npm/bin/npm-cli.js"
    cli.parent.mkdir(parents=True)
    cli.write_text("fixture")
    assert setup.find_npm_cli(node) == cli.resolve()
    assert setup.find_npm_cli(node, str(cli)) == cli.resolve()
    with pytest.raises(setup.SetupError):
        setup.find_npm_cli(node, str(tmp_path / "missing.js"))


def _fixture(tmp_path, monkeypatch, *, bad_npm=False, wrong_version=False):
    node = tmp_path / "Node & Space" / "node"
    node.parent.mkdir()
    node.write_text("fixture")
    npm = node.parent / "node_modules/npm/bin/npm-cli.js"
    npm.parent.mkdir(parents=True)
    npm.write_text("fixture")
    java_home = tmp_path / "JDK & Space"
    java = java_home / "bin" / ("java.exe" if setup.os.name == "nt" else "java")
    java.parent.mkdir(parents=True)
    java.write_text("fixture")
    calls = []
    def run(arguments, *, timeout=30):
        calls.append(arguments)
        if arguments[1] == "--version":
            return subprocess.CompletedProcess(arguments, 0, "v24.22.2\n", "")
        if arguments[1] == "--list-modules":
            return subprocess.CompletedProcess(arguments, 0, "java.base@21.0.8\njdk.compiler@21.0.8\n", "")
        if bad_npm:
            raise setup.SetupError("npm failed")
        prefix = Path(arguments[arguments.index("--prefix") + 1])
        package = prefix / "node_modules/rea-agents"
        (package / "scripts").mkdir(parents=True)
        (package / "scripts/rea.mjs").write_text("fixture")
        (package / "package.json").write_text(json.dumps({"name": "rea-agents", "version": "0.0.0" if wrong_version else setup.REA_VERSION}))
        return subprocess.CompletedProcess(arguments, 0, "installed", "")
    monkeypatch.setattr(setup, "run_command", run)
    data = b"verified engine fixture"
    monkeypatch.setattr(setup, "JAR_SHA256", hashlib.sha256(data).hexdigest())
    monkeypatch.setattr(setup.urllib.request, "urlopen", lambda *a, **k: Response(data))
    return node, java_home, calls, data


def test_complete_install_pins_npm_and_preserves_other_settings(tmp_path, monkeypatch):
    node, java_home, calls, data = _fixture(tmp_path, monkeypatch)
    app = tmp_path / "L & Desktop"
    app.mkdir()
    settings_path = app / "rea_settings.json"
    settings_path.write_text(json.dumps({"timeout_seconds": 456, "custom": "그대로"}))
    result = setup.install(app, node_path=str(node), java_home=str(java_home), progress=lambda message: None)
    npm_call = next(c for c in calls if len(c) > 2 and c[2] == "install")
    assert npm_call[0] == str(node.resolve())
    assert npm_call[1].endswith("npm-cli.js")
    assert "--omit=optional" in npm_call
    assert npm_call[-1] == "rea-agents@6.8.0"
    assert str(app / "tools/rea") in npm_call
    assert result["timeout_seconds"] == 456 and result["custom"] == "그대로"
    assert Path(result["jar_path"]).read_bytes() == data
    assert json.loads(settings_path.read_text()) == result
    assert not (app / ".l-rea-setup.lock").exists()


def test_failed_npm_keeps_existing_settings_exactly(tmp_path, monkeypatch):
    node, java_home, calls, data = _fixture(tmp_path, monkeypatch, bad_npm=True)
    app = tmp_path / "L"
    app.mkdir()
    raw = b'{"custom":"keep original formatting"}\n'
    (app / "rea_settings.json").write_bytes(raw)
    with pytest.raises(setup.SetupError, match="npm failed"):
        setup.install(app, node_path=str(node), java_home=str(java_home), progress=lambda message: None)
    assert (app / "rea_settings.json").read_bytes() == raw
    assert not (app / ".l-rea-setup.lock").exists()
    assert not list(app.rglob("*.part"))


def test_wrong_installed_version_does_not_publish_settings(tmp_path, monkeypatch):
    node, java_home, calls, data = _fixture(tmp_path, monkeypatch, wrong_version=True)
    app = tmp_path / "L"
    with pytest.raises(setup.SetupError, match="6.8.0"):
        setup.install(app, node_path=str(node), java_home=str(java_home), progress=lambda message: None)
    assert not (app / "rea_settings.json").exists()
    assert not (app / ".l-rea-setup.lock").exists()


def test_bad_jar_keeps_settings_and_existing_engine(tmp_path, monkeypatch):
    node, java_home, calls, data = _fixture(tmp_path, monkeypatch)
    app = tmp_path / "L"
    app.mkdir()
    raw = b'{"custom":"keep old settings"}\n'
    (app / "rea_settings.json").write_bytes(raw)
    jar = app / "tools/rea" / setup.JAR_NAME
    jar.parent.mkdir(parents=True)
    jar.write_bytes(b"old engine")
    monkeypatch.setattr(setup.urllib.request, "urlopen", lambda *a, **k: Response(b"bad hash"))
    with pytest.raises(setup.SetupError, match="SHA-256"):
        setup.install(app, node_path=str(node), java_home=str(java_home), progress=lambda message: None)
    assert (app / "rea_settings.json").read_bytes() == raw
    assert jar.read_bytes() == b"old engine"
    assert not list(app.rglob("*.part"))
    assert not (app / ".l-rea-setup.lock").exists()


def test_valid_existing_external_engine_selection_is_preserved(tmp_path, monkeypatch):
    node, java_home, calls, data = _fixture(tmp_path, monkeypatch)
    external = tmp_path / "external/rea-agents"
    (external / "scripts").mkdir(parents=True)
    entry = external / "scripts/rea.mjs"
    entry.write_text("fixture")
    (external / "package.json").write_text(json.dumps({"name": "rea-agents", "version": setup.REA_VERSION}))
    jar = tmp_path / "external/engine.jar"
    jar.write_bytes(data)
    app = tmp_path / "L"
    app.mkdir()
    (app / "rea_settings.json").write_text(json.dumps({"rea_entry": str(entry), "jar_path": str(jar)}))
    def no_download(*args, **kwargs):
        raise AssertionError("Verified existing JAR must be reused")
    monkeypatch.setattr(setup.urllib.request, "urlopen", no_download)
    result = setup.install(app, node_path=str(node), java_home=str(java_home), progress=lambda message: None)
    assert result["rea_entry"] == str(entry.resolve())
    assert result["jar_path"] == str(jar.resolve())


def test_bad_settings_are_not_reset_or_overwritten(tmp_path, monkeypatch):
    app = tmp_path / "L"
    app.mkdir()
    raw = b'{"node_path": '
    (app / "rea_settings.json").write_bytes(raw)
    with pytest.raises(setup.SetupError, match="기존 파일"):
        setup.install(app, progress=lambda message: None)
    assert (app / "rea_settings.json").read_bytes() == raw
    assert not (app / "tools").exists()


def test_jre_without_compiler_module_is_rejected(tmp_path, monkeypatch):
    node, java_home, calls, data = _fixture(tmp_path, monkeypatch)
    monkeypatch.setattr(setup, "run_command", lambda *a, **k: subprocess.CompletedProcess(a, 0, "java.base@21.0.8\n", ""))
    with pytest.raises(setup.SetupError, match="jdk.compiler"):
        setup.select_java_home(str(java_home), {})


def test_existing_install_lock_is_preserved(tmp_path):
    lock = tmp_path / ".l-rea-setup.lock"
    lock.write_text("existing owner")
    with pytest.raises(setup.SetupError, match="이미 진행"):
        setup.install(tmp_path, progress=lambda message: None)
    assert lock.read_text() == "existing owner"

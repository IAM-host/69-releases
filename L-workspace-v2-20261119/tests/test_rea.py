"""REA adapter contracts, using synthetic APKs and CLI Evidence only."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import subprocess
import threading
import zipfile

import pytest

from l_app import rea
from l_app.processes import CancelledError, bind_cancel_event


@pytest.fixture
def tools(tmp_path, monkeypatch):
    data = tmp_path / "portable app 한글"
    data.mkdir()
    monkeypatch.setenv("L_APP_DATA_DIR", str(data))
    for key in ("L_REA_NODE", "L_REA_ENTRY", "REA_JADX_MCP_JAR", "JAVA_HOME"):
        monkeypatch.delenv(key, raising=False)
    node = data / "node.exe"
    node.touch()
    entry = data / "node_modules" / "rea-agents" / "scripts" / "rea.mjs"
    entry.parent.mkdir(parents=True)
    entry.write_text("// Synthetic fixture; never executed", encoding="utf-8")
    java_home = data / "jdk"
    java = java_home / "bin" / ("java.exe" if rea.os.name == "nt" else "java")
    java.parent.mkdir(parents=True)
    java.touch()
    jar = data / "jadx-headless-mcp-0.7.1-all.jar"
    with zipfile.ZipFile(jar, "w") as archive:
        for name in sorted(rea.JADX_REQUIRED_CLASSES):
            archive.writestr(name, b"synthetic class")
    monkeypatch.setattr(rea, "JADX_SHA256", hashlib.sha256(jar.read_bytes()).hexdigest())
    apk = data / "sample $() 한글.apk"
    with zipfile.ZipFile(apk, "w") as archive:
        archive.writestr("AndroidManifest.xml", '<manifest package="com.example.fixture"/>')
        archive.writestr("classes.dex", b"Synthetic DEX; engine is mocked")
    return {
        "node_path": str(node), "rea_entry": str(entry), "jar_path": str(jar),
        "java_home": str(java_home), "timeout_seconds": 180,
    }, apk


def evidence(apk, operation="package", **selectors):
    digest = hashlib.sha256(apk.read_bytes()).hexdigest()
    engine = {"name": "jadx-headless-mcp", "version": "0.7.1", "artifact_sha256": rea.JADX_SHA256,
              "source_revision": "5844800a486d2248fa949b74c9896285f5b54de2",
              "worker_count": 1, "heap_limit_mib": 1024}
    method = {"name": "inspect", "reported_signature": "inspect(java.lang.String)",
              "overload_index": 1, "is_constructor": False, "dex_descriptor": "(Ljava/lang/String;)V"}
    results = {
        "package": {"engine": engine, "package_name": "com.example.fixture", "version_name": "1.0",
                    "version_code": "1", "min_sdk": "26", "target_sdk": "35",
                    "permissions": ["android.permission.INTERNET"],
                    "manifest": {"status": "complete", "text": "<manifest/>", "reported_total_bytes": 11},
                    "components": {"status": "complete", "items": [], "limitations": []},
                    "class_count": 4, "resource_count": 7, "signature_verification": "not_performed"},
        "class_search": {"engine": engine, "query": selectors.get("query", "Target"), "total_classes": 4,
                         "matches": ["com.example.Target"], "duplicate_names": [], "coverage": "complete"},
        "class": {"engine": engine, "class_name": "com.example.Target", "methods": [method],
                  "fields": [{"name": "label", "reported_type": "java.lang.String", "dex_static_value": None}],
                  "inner_classes": ["com.example.Target.Inner"]},
        "method": {"engine": engine, "class_name": "com.example.Target", "method": method,
                   "overload_count": 2, "representation": "java", "body_status": "available",
                   "fell_back": False, "markers": [],
                   "source": {"status": "complete", "text": "public void inspect(String s) {}", "reported_total_bytes": 32}},
        "references": {"engine": engine, "class_name": "com.example.Target",
                       "method_name": selectors.get("method_name"), "overload_index": selectors.get("overload_index"),
                       "reported_signature": None, "dex_descriptor": None, "total": 1,
                       "references": [{"kind": "method", "name": "caller", "reported_full_name": "com.example.Caller.caller()",
                                       "containing_class": "com.example.Caller", "top_class": "com.example.Caller",
                                       "source_line": None, "dex_offset": None, "direct_invokes": None,
                                       "direct_invokes_exhaustive": None}],
                       "coverage": "complete", "reference_unit": "using_node"},
    }
    parameters = {"path": str(apk.resolve()), **selectors}
    return {
        "evidence_id": "ev_" + "a" * 64,
        "subject": {"name": apk.name, "digest": {"sha256": digest}, "local_path": str(apk),
                    "format": "apk", "architecture": None},
        "provider": {"id": "jadx", "name": "JADX headless", "version": "0.7.1"},
        "analysis_profile": None, "predicate_type": "rea.analysis",
        "operation": rea._OPERATIONS[operation][1], "parameters": parameters,
        "raw_result": {"synthetic": True, "unabridged_payload": "local-only fixture"},
        "normalized_result": results[operation], "confidence": "derived" if operation == "method" else "observed",
        "authority": "shipped-artifact", "environment": None, "limitations": ["Static observations only."],
        "relationship_coverage": None, "locations": [], "evidence_links": [],
    }


def fake_runner(monkeypatch, settings, result=None, *, stdout=None, stderr="", returncode=0,
                node_version="v24.22.2\n", rea_version="6.8.0\n", modules=None, on_analysis=None):
    calls = []
    if modules is None:
        modules = "java.base@21.0.9\njdk.compiler@21.0.9\n"
    def run(args, **kwargs):
        calls.append((list(args), kwargs))
        if args == [settings["node_path"], "--version"]:
            return subprocess.CompletedProcess(args, 0, node_version, "")
        if args == [settings["node_path"], settings["rea_entry"], "--version"]:
            return subprocess.CompletedProcess(args, 0, rea_version, "")
        if args[-1] == "--list-modules":
            return subprocess.CompletedProcess(args, 0, modules, "")
        if on_analysis:
            on_analysis()
        output = stdout if stdout is not None else json.dumps({"ok": True, "data": result, "meta": {"duration": "1ms"}})
        return subprocess.CompletedProcess(args, returncode, output, stderr)
    monkeypatch.setattr(rea, "run_process", run)
    return calls


def test_settings_load_is_filesystem_only_and_saves_only_whitelisted_fields(tools, monkeypatch):
    settings, _ = tools
    monkeypatch.setattr(rea, "run_process", lambda *a, **k: pytest.fail("load must not spawn a process"))
    rea.save_rea_settings({**settings, "API_TOKEN": "never-save", "settings_status": {"secret": True}})
    persisted = json.loads((rea.app_dir() / "rea_settings.json").read_text())
    assert persisted == settings
    assert rea.load_rea_settings() == settings


def test_settings_environment_and_portable_defaults(tools, monkeypatch):
    settings, _ = tools
    monkeypatch.setenv("L_REA_NODE", settings["node_path"])
    monkeypatch.setenv("L_REA_ENTRY", settings["rea_entry"])
    monkeypatch.setenv("REA_JADX_MCP_JAR", settings["jar_path"])
    monkeypatch.setenv("JAVA_HOME", settings["java_home"])
    loaded = rea.load_rea_settings()
    assert all(loaded[key] == settings[key] for key in rea._PATH_KEYS)


@pytest.mark.parametrize("contents", ["{broken", "[]", '{"timeout_seconds":true}', '{"node_path":123}'])
def test_corrupt_settings_are_visible_and_can_be_repaired(tools, monkeypatch, contents):
    settings, _ = tools
    (rea.app_dir() / "rea_settings.json").write_text(contents)
    assert "_load_error" in rea.load_rea_settings()
    fake_runner(monkeypatch, settings)
    assert not rea.rea_preflight()["ready"]
    assert rea.rea_preflight(settings)["ready"]
    rea.save_rea_settings(settings)
    assert "_load_error" not in rea.load_rea_settings()


@pytest.mark.parametrize("timeout", [True, -1, 0, 29, 7201, "300", float("inf"), float("nan")])
def test_invalid_timeout_rejected_without_overwriting_settings(tools, timeout):
    settings, _ = tools
    rea.save_rea_settings(settings)
    original = (rea.app_dir() / "rea_settings.json").read_bytes()
    with pytest.raises(ValueError):
        rea.save_rea_settings({**settings, "timeout_seconds": timeout})
    assert (rea.app_dir() / "rea_settings.json").read_bytes() == original


def test_preflight_checks_actual_executables_versions_jar_and_compiler(tools, monkeypatch):
    settings, _ = tools
    calls = fake_runner(monkeypatch, settings)
    result = rea.rea_preflight(settings)
    assert result["ready"] is True
    assert result["versions"]["node"] == "24.22.2"
    assert result["versions"]["rea"] == "6.8.0"
    assert result["versions"]["java"] == "21.0.9"
    assert result["versions"]["jar_sha256"] == rea.JADX_SHA256
    assert len(calls) == 3
    assert all(isinstance(args, list) for args, _ in calls)


@pytest.mark.parametrize("version,ready", [
    ("v22.23.3\n", False), ("v22.23.4\n", True), ("v23.9.0\n", False),
    ("v24.22.0\n", False), ("v24.22.1\n", True), ("v25.0.0\n", False),
    ("v26.12.0\n", False), ("v26.12.1\n", True), ("v27.0.0\n", True),
    ("not a version", False),
])
def test_node_supported_ranges(tools, monkeypatch, version, ready):
    settings, _ = tools
    fake_runner(monkeypatch, settings, node_version=version)
    assert rea.rea_preflight(settings)["ready"] is ready


def test_unsupported_rea_version_is_actionable(tools, monkeypatch):
    settings, _ = tools
    fake_runner(monkeypatch, settings, rea_version="6.7.9\n")
    result = rea.rea_preflight(settings)
    assert not result["ready"]
    assert "6.8.0" in "\n".join(result["errors"])


def test_normal_jadx_cli_jar_is_refused_even_when_zip_valid(tools, monkeypatch):
    settings, _ = tools
    with zipfile.ZipFile(settings["jar_path"], "w") as archive:
        archive.writestr("jadx/cli/JadxCLI.class", b"not the REA bridge")
    fake_runner(monkeypatch, settings)
    result = rea.rea_preflight(settings)
    assert not result["ready"]
    assert any("SHA-256" in error for error in result["errors"])
    assert any("필수 클래스" in error for error in result["errors"])


def test_jre_is_not_a_full_jdk(tools, monkeypatch):
    settings, _ = tools
    fake_runner(monkeypatch, settings, modules="java.base@21.0.9\njava.logging@21.0.9\n")
    assert "jdk.compiler" in "\n".join(rea.rea_preflight(settings)["errors"])


def test_old_full_jdk_is_rejected_before_running_analysis(tools, monkeypatch):
    settings, _ = tools
    fake_runner(monkeypatch, settings, modules="java.base@11.0.9\njdk.compiler@11.0.9\n")
    result = rea.rea_preflight(settings)
    assert not result["ready"]
    assert "17" in "\n".join(result["errors"])


def test_carrying_load_warning_does_not_silently_ignore_broken_config(tools, monkeypatch):
    settings, _ = tools
    fake_runner(monkeypatch, settings)
    result = rea.rea_preflight({**settings, "_load_error": "Broken saved configuration"})
    assert not result["ready"]
    assert "Broken saved configuration" in result["errors"]


def test_missing_tools_do_not_run_a_shell_or_install_anything(tools, monkeypatch):
    settings, _ = tools
    Path(settings["node_path"]).unlink()
    calls = fake_runner(monkeypatch, settings)
    result = rea.rea_preflight(settings)
    assert not result["ready"]
    assert all(args[-1] == "--list-modules" for args, _ in calls)


@pytest.mark.parametrize("operation,selectors", [
    ("package", {}), ("class_search", {"query": "Target"}), ("class_search", {"query": ""}),
    ("class", {"class_name": "com.example.Target"}),
    ("method", {"class_name": "com.example.Target", "method_name": "inspect", "overload_index": 1}),
    ("references", {"class_name": "com.example.Target"}),
    ("references", {"class_name": "com.example.Target", "method_name": "inspect", "overload_index": 1}),
])
def test_real_cli_contract_and_full_evidence_retention(tools, monkeypatch, operation, selectors):
    settings, apk = tools
    payload = evidence(apk, operation, **selectors)
    calls = fake_runner(monkeypatch, settings, payload, stderr="diagnostic only\n")
    updates = []
    result = rea.run_rea_analysis(apk, settings=settings, operation=operation, progress=updates.append, **selectors)
    args, options = calls[-1]
    assert args[:4] == [settings["node_path"], settings["rea_entry"], rea._OPERATIONS[operation][0], str(apk.resolve())]
    assert args[-3:] == ["--format", "json", "--full-output"]
    if operation == "class_search":
        assert args[4] == selectors["query"]
    if "overload_index" in selectors:
        index = args.index("--overloadIndex")
        assert args[index + 1] == "1"
    if operation == "references" and "method_name" in selectors:
        index = args.index("--methodName")
        assert args[index + 1] == "inspect"
    assert options["timeout"] == 180
    assert options["env"]["REA_JADX_MCP_JAR"] == settings["jar_path"]
    assert options["env"]["JAVA_HOME"] == settings["java_home"]
    assert options["env"]["REA_JADX_OPERATION_TIMEOUT_MS"] == "150000"
    assert options["cwd"] == str(apk.parent)
    assert result["status"] == "complete"
    assert result["evidence"] == payload
    saved = json.loads(Path(result["raw_path"]).read_text())
    assert saved["data"] == payload
    assert Path(result["stderr_path"]).read_text() == "diagnostic only\n"
    assert "unabridged_payload" not in result["report"]
    assert "APK SHA-256" in result["report"]
    assert updates and len(updates) >= 3


def test_direct_evidence_document_also_supported(tools, monkeypatch):
    settings, apk = tools
    payload = evidence(apk)
    fake_runner(monkeypatch, settings, stdout=json.dumps(payload))
    assert rea.run_rea_analysis(apk, settings=settings)["evidence"] == payload


@pytest.mark.parametrize("partial_field,partial_value", [("manifest", "partial"), ("components", "unavailable")])
def test_partial_package_evidence_is_not_reported_as_complete(tools, monkeypatch, partial_field, partial_value):
    settings, apk = tools
    payload = evidence(apk)
    payload["normalized_result"][partial_field]["status"] = partial_value
    fake_runner(monkeypatch, settings, payload)
    result = rea.run_rea_analysis(apk, settings=settings)
    assert result["status"] == "partial"
    assert "일부 결과" in result["report"]


def test_partial_method_and_full_source_are_retained(tools, monkeypatch):
    settings, apk = tools
    selectors = {"class_name": "com.example.Target", "method_name": "inspect", "overload_index": 1}
    payload = evidence(apk, "method", **selectors)
    payload["normalized_result"]["source"].update(status="partial", text="sample-body" * 10000)
    fake_runner(monkeypatch, settings, payload)
    result = rea.run_rea_analysis(apk, settings=settings, operation="method", **selectors)
    assert result["status"] == "partial"
    assert len(result["report"]) < 90000
    saved = json.loads(Path(result["raw_path"]).read_text())
    assert len(saved["data"]["normalized_result"]["source"]["text"]) == 110000


@pytest.mark.parametrize("output", ["", "progress\n{}", "[]", "{}", '{"ok":true}', "{broken",
                                     '{"value":NaN}', '{"value":1e9999}', '{"ok":false,"ok":true}'])
def test_invalid_or_non_evidence_json_fails_and_keeps_diagnostics(tools, monkeypatch, output):
    settings, apk = tools
    fake_runner(monkeypatch, settings, stdout=output, stderr="separate stderr")
    with pytest.raises(rea.ReaAnalysisError) as caught:
        rea.run_rea_analysis(apk, settings=settings)
    saved = json.loads(Path(caught.value.raw_path).read_text())
    assert saved["status"] == "failed"
    assert saved["stdout"] == output
    assert list(Path(caught.value.raw_path).parent.glob("*.stderr.txt"))[0].read_text() == "separate stderr"


@pytest.mark.parametrize("exitcode", [0, 1])
def test_error_envelope_is_failure_even_with_zero_exitcode(tools, monkeypatch, exitcode):
    settings, apk = tools
    output = {"ok": False, "error": {"code": "invalid_input", "message": "Select one of 2 overloads",
                                        "remediation": {"action": "Specify overload_index"}}, "meta": {}}
    fake_runner(monkeypatch, settings, stdout=json.dumps(output), returncode=exitcode)
    with pytest.raises(rea.ReaAnalysisError, match="Select one of 2 overloads"):
        rea.run_rea_analysis(apk, settings=settings)


def test_nonzero_exitcode_never_succeeds_with_a_valid_looking_payload(tools, monkeypatch):
    settings, apk = tools
    fake_runner(monkeypatch, settings, evidence(apk), returncode=9)
    with pytest.raises(rea.ReaAnalysisError, match="종료 코드 9"):
        rea.run_rea_analysis(apk, settings=settings)


@pytest.mark.parametrize("mutation", [
    lambda p: p.update(operation="inspect_android_class"),
    lambda p: p["subject"]["digest"].update(sha256="0" * 64),
    lambda p: p.update(parameters={"path": "a different APK"}),
    lambda p: p.update(provider={}),
    lambda p: p["normalized_result"]["engine"].update(artifact_sha256="0" * 64),
    lambda p: p["normalized_result"].pop("class_count"),
    lambda p: p["normalized_result"]["manifest"].pop("status"),
    lambda p: p.update(limitations="not a list"),
])
def test_mismatched_or_malformed_evidence_never_becomes_a_success(tools, monkeypatch, mutation):
    settings, apk = tools
    payload = evidence(apk)
    mutation(payload)
    fake_runner(monkeypatch, settings, payload)
    with pytest.raises(rea.ReaAnalysisError):
        rea.run_rea_analysis(apk, settings=settings)


def test_source_apk_changed_during_analysis_is_detected(tools, monkeypatch):
    settings, apk = tools
    payload = evidence(apk)
    fake_runner(monkeypatch, settings, payload, on_analysis=lambda: apk.write_bytes(apk.read_bytes() + b"changed"))
    with pytest.raises(rea.ReaAnalysisError, match="APK가 변경"):
        rea.run_rea_analysis(apk, settings=settings)


@pytest.mark.parametrize("selectors", [
    {"operation": "unknown"}, {"operation": "class"},
    {"operation": "method", "class_name": "com.example.Target"},
    {"operation": "references", "class_name": "com.example.Target", "overload_index": 0},
    {"operation": "method", "class_name": "C", "method_name": "m", "overload_index": -1},
    {"operation": "method", "class_name": "C", "method_name": "m", "overload_index": True},
    {"operation": "class_search", "query": "bad\x00query"},
])
def test_invalid_input_does_not_invoke_tools(tools, monkeypatch, selectors):
    settings, apk = tools
    monkeypatch.setattr(rea, "run_process", lambda *a, **k: pytest.fail("invalid request must not spawn tools"))
    with pytest.raises(ValueError):
        rea.run_rea_analysis(apk, settings=settings, **selectors)


def test_non_apk_or_missing_manifest_is_rejected(tools, monkeypatch):
    settings, apk = tools
    monkeypatch.setattr(rea, "run_process", lambda *a, **k: pytest.fail("invalid APK must not spawn tools"))
    apk.write_bytes(b"not a zip")
    with pytest.raises(ValueError, match="정상 APK"):
        rea.run_rea_analysis(apk, settings=settings)


def test_preflight_failure_never_falls_back_to_builtin_analysis(tools, monkeypatch):
    settings, apk = tools
    Path(settings["jar_path"]).unlink()
    calls = fake_runner(monkeypatch, settings)
    with pytest.raises(rea.ReaAnalysisError, match="환경 설정"):
        rea.run_rea_analysis(apk, settings=settings)
    assert not any("inspect-android-package" in args for args, _ in calls)


def test_timeout_keeps_local_diagnostic_not_a_partial_success(tools, monkeypatch):
    settings, apk = tools
    fake_runner(monkeypatch, settings, on_analysis=lambda: (_ for _ in ()).throw(subprocess.TimeoutExpired("rea", 180)))
    with pytest.raises(rea.ReaAnalysisError, match="180초") as caught:
        rea.run_rea_analysis(apk, settings=settings)
    assert json.loads(Path(caught.value.raw_path).read_text())["status"] == "failed"


def test_cancelled_process_propagates_without_writing_failure_evidence(tools, monkeypatch):
    settings, apk = tools
    fake_runner(monkeypatch, settings, on_analysis=lambda: (_ for _ in ()).throw(CancelledError("cancelled")))
    with pytest.raises(CancelledError):
        rea.run_rea_analysis(apk, settings=settings)
    assert not (rea.app_dir() / "rea_results").exists()


def test_storage_failure_cannot_be_reported_as_a_success(tools, monkeypatch):
    settings, apk = tools
    fake_runner(monkeypatch, settings, evidence(apk))
    def deny_write(*args, **kwargs):
        raise PermissionError("read-only result folder")
    monkeypatch.setattr(rea, "atomic_write_text", deny_write)
    with pytest.raises(rea.ReaAnalysisError, match="저장 실패"):
        rea.run_rea_analysis(apk, settings=settings)


def test_already_cancelled_task_does_not_probe_tools(tools, monkeypatch):
    settings, apk = tools
    monkeypatch.setattr(rea, "run_process", lambda *a, **k: pytest.fail("cancelled task must not spawn tools"))
    event = threading.Event()
    event.set()
    with bind_cancel_event(event), pytest.raises(CancelledError):
        rea.run_rea_analysis(apk, settings=settings)


def test_repeat_analysis_keeps_distinct_evidence_files(tools, monkeypatch):
    settings, apk = tools
    fake_runner(monkeypatch, settings, evidence(apk))
    first = rea.run_rea_analysis(apk, settings=settings)
    second = rea.run_rea_analysis(apk, settings=settings)
    assert first["raw_path"] != second["raw_path"]
    assert Path(first["raw_path"]).exists() and Path(second["raw_path"]).exists()

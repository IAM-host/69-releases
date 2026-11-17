"""Local test-hook generation is bound to exact APK evidence and source copies."""
from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
import re
import threading
import zipfile

import pytest

from l_app import security_generator as sg
from l_app.processes import CancelledError, bind_cancel_event
from test_generator import make_dex, make_evidence


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def source_hashes(case):
    return {case[key].relative_to(case["project"]).as_posix(): sha(case[key])
            for key in ("module", "family")}


def replace_methods(case, methods):
    with zipfile.ZipFile(case["apk"], "w") as archive:
        archive.writestr("classes.dex", make_dex("Lexample/SecurityChecks;", methods))
    case["evidence"], case["package"] = make_evidence(case["apk"], "example.SecurityChecks", methods)
    name, descriptor, access = methods[0]
    case["candidate"].update(apk_digest=sha(case["apk"]), method_name=name,
                             dex_descriptor=descriptor, access_flags=access)


@pytest.fixture
def case(tmp_path, monkeypatch):
    monkeypatch.setenv("L_APP_DATA_DIR", str(tmp_path / "data"))
    project = tmp_path / "project"
    sources = project / "app/src/main/java/com/example/wheelprobe"
    sources.mkdir(parents=True)
    module = sources / "ModuleMain.kt"
    module.write_bytes(("package com.example.wheelprobe\r\n\r\nclass ModuleMain {\r\n"
                        "    fun onPackageLoaded() {\r\n        val pkg = \"com.logisoft.Logi4\"\r\n"
                        "        val classLoader = javaClass.classLoader!!\r\n"
                        "        installLogiGpsSpoof(classLoader)\r\n    }\r\n}\r\n").encode())
    family = sources / "E05.kt"
    family.write_bytes(b"package com.example.wheelprobe\r\n\r\n// Existing handlers remain byte-for-byte.\r\n")
    apk = tmp_path / "fixture.apk"
    candidate = {
        "id": "fixture-root", "class_name": "example.SecurityChecks", "method_name": "isRooted",
        "dex_descriptor": "()Z", "access_flags": 9, "categories": ["root_files"],
        "signals": ["/system/bin/su"], "evidence_kind": "method_literal",
        "modes": ["observe", "boolean_false"],
    }
    data = dict(project=project, module=module, family=family, apk=apk, candidate=candidate, tmp=tmp_path)
    replace_methods(data, [("isRooted", "()Z", 9)])
    data["hashes"] = source_hashes(data)
    # The classifier is tested independently. Here its proof is re-read and
    # the exact method declaration is still checked against the real DEX bytes.
    monkeypatch.setattr(sg, "scan_security_candidates", lambda path, **kw: {
        "apk_digest": sha(path), "candidates": [copy.deepcopy(data["candidate"])],
        "coverage": {}, "limitations": [],
    })
    return data


def generate(case, **overrides):
    arguments = dict(project_path=case["project"], app_key="logi", apk_path=case["apk"],
                     class_evidence=case["evidence"], method_name="isRooted", overload_index=0,
                     mode="boolean_false", package_evidence=case["package"],
                     candidate=copy.deepcopy(case["candidate"]), source_hashes=case["hashes"])
    arguments.update(overrides)
    return sg.generate_security_hook(**arguments)


def kotlin_outputs(result):
    return {Path(path).name: Path(path).read_bytes() for path in result["files"].values()
            if Path(path).suffix == ".kt"}


def test_debug_test_hook_preserves_origin_exceptions_and_arguments(case):
    code = kotlin_outputs(generate(case))["E05.kt"].decode()
    assert "FLAG_DEBUGGABLE" in code
    assert "com.example.wheelprobe" in code
    assert "applicationInfo" in code or "getApplicationInfo" in code
    assert "@io.github.libxposed.api.annotations.AfterInvocation" in code or "@AfterInvocation" in code
    assert re.search(r"callback\.result\s*=\s*false", code)
    assert "callback.throwable" in code
    assert "example.SecurityChecks" in code and "isRooted" in code
    assert "parameterTypes.contentEquals" in code and "returnType" in code
    for forbidden in ("returnAndSkip", "BeforeInvocation", "setThrowable", "invokeOrigin", "Runtime.getRuntime", "PackageManager.class"):
        assert forbidden not in code
    assert not re.search(r"callback\.args\s*\[.*?\]\s*=", code)
    assert not re.search(r"callback\.throwable\s*=", code)


def test_full_source_copies_txt_and_manifest_match_without_input_edits(case):
    originals = {key: case[key].read_bytes() for key in ("module", "family", "apk")}
    result = generate(case)
    outputs = kotlin_outputs(result)
    assert set(outputs) == {"ModuleMain.kt", "E05.kt"}
    assert b"Existing handlers remain byte-for-byte." in outputs["E05.kt"]
    assert result["build_status"] == "not_run"
    assert Path(result["diff"]).is_file()
    manifest = json.loads(Path(result["manifest"]).read_text())
    assert manifest["build_status"] == "not_run"
    assert manifest["runtime_status"] == "unverified"
    assert manifest["apk_sha256"] == sha(case["apk"])
    assert manifest["originals"] == case["hashes"]
    for relative, record in manifest["generated"].items():
        target = Path(record["path"])
        assert sha(target) == record["sha256"]
        assert target.with_suffix(".txt").read_bytes() == target.read_bytes()
    for content in outputs.values():
        assert b"\n" not in content.replace(b"\r\n", b"")
    for key, before in originals.items():
        assert case[key].read_bytes() == before


def test_observe_mode_still_only_observes(case):
    output = kotlin_outputs(generate(case, mode="observe"))["E05.kt"].decode()
    assert "L_OBSERVER" in output
    assert not re.search(r"callback\.result\s*=", output)
    assert "FLAG_DEBUGGABLE" not in output


@pytest.mark.parametrize("which", ["evidence", "package"])
def test_each_rea_evidence_is_bound_to_apk(case, which):
    case[which]["subject"]["digest"]["sha256"] = "0" * 64
    with pytest.raises(ValueError):
        generate(case)


def test_selected_package_must_match_app_profile(case):
    case["package"]["normalized_result"]["package_name"] = "com.logisoft.Logi5"
    with pytest.raises(ValueError):
        generate(case)


def test_missing_scan_candidate_is_rejected(case, monkeypatch):
    monkeypatch.setattr(sg, "scan_security_candidates", lambda *a, **kw: {"apk_digest": sha(case["apk"]), "candidates": []})
    with pytest.raises(ValueError):
        generate(case)


@pytest.mark.parametrize("field,value", [
    ("id", "stale-id"), ("class_name", "different.Owner"),
    ("method_name", "otherMethod"), ("dex_descriptor", "(I)Z"),
    ("apk_digest", "0" * 64),
])
def test_selected_candidate_cannot_disagree_with_fresh_scan(case, field, value):
    selected = copy.deepcopy(case["candidate"])
    selected[field] = value
    with pytest.raises(ValueError):
        generate(case, candidate=selected)


def test_scan_digest_is_bound_to_current_apk(case, monkeypatch):
    monkeypatch.setattr(sg, "scan_security_candidates", lambda *a, **kw: {
        "apk_digest": "0" * 64, "candidates": [case["candidate"]],
    })
    with pytest.raises(ValueError):
        generate(case)


def test_candidate_must_allow_false_mode(case):
    case["candidate"]["modes"] = ["observe"]
    with pytest.raises(ValueError):
        generate(case)


def test_integrity_candidate_cannot_generate_false_return(case):
    case["candidate"]["categories"] = ["root_files", "integrity"]
    with pytest.raises(ValueError):
        generate(case)


@pytest.mark.parametrize("descriptor,access,name", [
    ("()Ljava/lang/Boolean;", 9, "isRooted"), ("()I", 9, "isRooted"),
    ("()V", 9, "isRooted"), ("()Z", 0x109, "isRooted"),
    ("()Z", 0x401, "isRooted"), ("()V", 0x10001, "<init>"),
])
def test_only_concrete_declared_primitive_boolean_methods_are_supported(case, descriptor, access, name):
    replace_methods(case, [(name, descriptor, access)])
    with pytest.raises(ValueError):
        generate(case, method_name=name)


def test_exact_rea_descriptor_must_be_declared_in_dex(case):
    case["evidence"]["normalized_result"]["methods"][0]["dex_descriptor"] = "(I)Z"
    with pytest.raises(ValueError):
        generate(case)


@pytest.mark.parametrize("which", ["module", "family"])
def test_source_changes_after_scan_are_rejected(case, which):
    case[which].write_bytes(case[which].read_bytes() + b"// user edit\r\n")
    with pytest.raises(ValueError):
        generate(case)
    assert not (case["tmp"] / "data/generated_hooks").exists()


def test_unknown_mode_is_rejected(case):
    with pytest.raises(ValueError):
        generate(case, mode="replace_everything")


def test_generated_test_blocks_are_idempotent(case):
    first = generate(case)
    output = kotlin_outputs(first)
    case["module"].write_bytes(output["ModuleMain.kt"])
    case["family"].write_bytes(output["E05.kt"])
    case["hashes"] = source_hashes(case)
    second = kotlin_outputs(generate(case))
    assert output == second


def test_cancelled_generation_publishes_no_bundle(case):
    event = threading.Event()
    event.set()
    with bind_cancel_event(event), pytest.raises(CancelledError):
        generate(case)
    assert not (case["tmp"] / "data/generated_hooks").exists()


def test_source_edit_during_rescan_cannot_publish_stale_bundle(case, monkeypatch):
    def scan(path, **kwargs):
        case["family"].write_bytes(case["family"].read_bytes() + b"// concurrent user edit\r\n")
        return {"apk_digest": sha(path), "candidates": [copy.deepcopy(case["candidate"])]}
    monkeypatch.setattr(sg, "scan_security_candidates", scan)
    with pytest.raises(ValueError):
        generate(case)
    output = case["tmp"] / "data/generated_hooks"
    assert not output.exists() or not list(output.iterdir())


def test_cancellation_during_publish_cleans_incomplete_files(case, monkeypatch):
    event = threading.Event()
    original = Path.write_bytes
    before = {key: case[key].read_bytes() for key in ("module", "family")}
    def write(path, data):
        result = original(path, data)
        if path.suffix == ".kt" and any(part.startswith(".pending") for part in path.parts):
            event.set()
        return result
    monkeypatch.setattr(Path, "write_bytes", write)
    with bind_cancel_event(event), pytest.raises(CancelledError):
        generate(case)
    output = case["tmp"] / "data/generated_hooks"
    assert not output.exists() or not list(output.iterdir())
    for key, contents in before.items():
        assert case[key].read_bytes() == contents


def make_void_case(case):
    replace_methods(case, [("populateRootFlags", "(Ljava/lang/String;)V", 9)])
    case["candidate"]["modes"] = ["observe", "skip_void"]


def test_void_skip_is_explicit_debug_guarded_and_typed(case):
    make_void_case(case)
    result = generate(case, method_name="populateRootFlags", mode="skip_void")
    code = kotlin_outputs(result)["E05.kt"].decode()
    assert "BeforeInvocation" in code
    assert "returnAndSkip(null)" in code
    assert "FLAG_DEBUGGABLE" in code and "com.example.wheelprobe" in code
    assert "java.lang.Void.TYPE" in code
    assert "parameterTypes.contentEquals" in code
    assert "java.lang.String" in code
    assert "populateRootFlags" in code
    assert not re.search(r"callback\.result\s*=", code)
    assert not re.search(r"callback\.args\s*\[.*?\]\s*=", code)
    manifest = json.loads(Path(result["manifest"]).read_text())
    assert manifest["mode"] == "skip_void"
    assert manifest["debug_only"] is True
    assert manifest["observation_only"] is False
    assert manifest["original_execution_preserved"] is False


def test_skip_void_mode_rejects_boolean_return(case):
    case["candidate"]["modes"].append("skip_void")
    with pytest.raises(ValueError):
        generate(case, mode="skip_void")


def test_skip_void_mode_requires_matching_scan_permission(case):
    make_void_case(case)
    case["candidate"]["modes"] = ["observe"]
    with pytest.raises(ValueError):
        generate(case, method_name="populateRootFlags", mode="skip_void")


def test_skip_void_mode_excludes_integrity_even_with_mixed_category(case):
    make_void_case(case)
    case["candidate"]["categories"].append("integrity")
    with pytest.raises(ValueError):
        generate(case, method_name="populateRootFlags", mode="skip_void")


def test_skip_void_generation_is_idempotent(case):
    make_void_case(case)
    first = kotlin_outputs(generate(case, method_name="populateRootFlags", mode="skip_void"))
    case["module"].write_bytes(first["ModuleMain.kt"])
    case["family"].write_bytes(first["E05.kt"])
    case["hashes"] = source_hashes(case)
    assert kotlin_outputs(generate(case, method_name="populateRootFlags", mode="skip_void")) == first

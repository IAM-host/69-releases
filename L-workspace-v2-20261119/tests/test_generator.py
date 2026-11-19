"""Observer generation uses declared DEX evidence and never edits input projects."""
from __future__ import annotations

import copy
import hashlib
import json
import re
import struct
import zipfile
from pathlib import Path

import pytest

from l_app import generator


def _uleb(value: int) -> bytes:
    output = bytearray()
    while value > 127:
        output.append((value & 127) | 128)
        value >>= 7
    output.append(value)
    return bytes(output)


def _types(descriptor: str) -> list[str]:
    return re.findall(r"\[*L[^;]+;|\[*[VZBSCIJFD]", descriptor)


def make_dex(owner: str, methods: list[tuple[str, str, int]]) -> bytes:
    """Build a small declared class, method IDs, prototypes and class_data table.

    This fixture deliberately has no executable third-party code; code offsets
    point to an inert return-void item, used solely to distinguish declarations
    from abstract/native methods during static inspection.
    """
    descriptors = list(dict.fromkeys([owner, "Ljava/lang/Object;"] + [
        item for _, signature, _ in methods for item in _types(signature)
    ]))
    strings = list(dict.fromkeys(descriptors + [name for name, _, _ in methods] + ["V"]))
    string_index = {value: index for index, value in enumerate(strings)}
    type_index = {value: index for index, value in enumerate(descriptors)}
    signatures = list(dict.fromkeys(signature for _, signature, _ in methods))
    proto_index = {value: index for index, value in enumerate(signatures)}
    string_off = 112
    type_off = string_off + len(strings) * 4
    proto_off = type_off + len(descriptors) * 4
    method_off = proto_off + len(signatures) * 12
    class_off = method_off + len(methods) * 8
    data_off = class_off + 32
    content = bytearray(data_off)
    content[:8] = b"dex\n035\0"
    struct.pack_into("<II", content, 36, 112, 0x12345678)
    for offset, size, table in [(56, len(strings), string_off), (64, len(descriptors), type_off),
                                (72, len(signatures), proto_off), (88, len(methods), method_off),
                                (96, 1, class_off)]:
        struct.pack_into("<II", content, offset, size, table)
    for index, value in enumerate(strings):
        struct.pack_into("<I", content, string_off + index * 4, len(content))
        content.extend(_uleb(len(value)) + value.encode() + b"\0")
    for index, value in enumerate(descriptors):
        struct.pack_into("<I", content, type_off + index * 4, string_index[value])
    for index, signature in enumerate(signatures):
        arguments, result = signature[1:].split(")")
        argument_types = _types(arguments)
        parameters_off = 0
        if argument_types:
            content.extend(b"\0" * (-len(content) % 4))
            parameters_off = len(content)
            content.extend(struct.pack("<I", len(argument_types)))
            content.extend(struct.pack("<" + "H" * len(argument_types), *[type_index[t] for t in argument_types]))
        struct.pack_into("<III", content, proto_off + index * 12,
                         string_index["V"], type_index[result], parameters_off)
    for index, (name, signature, _) in enumerate(methods):
        struct.pack_into("<HHI", content, method_off + index * 8,
                         type_index[owner], proto_index[signature], string_index[name])
    content.extend(b"\0" * (-len(content) % 4))
    code_off = len(content)
    content.extend(struct.pack("<HHHHIIH", 8, 0, 0, 0, 0, 1, 0x000e))
    class_data_off = len(content)
    content.extend(_uleb(0) + _uleb(0) + _uleb(len(methods)) + _uleb(0))
    previous = 0
    for index, (_, _, access) in enumerate(methods):
        content.extend(_uleb(index - previous) + _uleb(access) + _uleb(0 if access & (0x400 | 0x100) else code_off))
        previous = index
    struct.pack_into("<IIIIIIII", content, class_off, type_index[owner], 1,
                     type_index["Ljava/lang/Object;"], 0, 0xffffffff, 0, class_data_off, 0)
    struct.pack_into("<I", content, 32, len(content))
    struct.pack_into("<II", content, 104, len(content) - data_off, data_off)
    content[12:32] = hashlib.sha1(content[32:]).digest()
    import zlib
    struct.pack_into("<I", content, 8, zlib.adler32(content[12:]) & 0xffffffff)
    return bytes(content)


def make_evidence(apk: Path, class_name: str, methods: list[tuple[str, str, int]]) -> tuple[dict, dict]:
    common = {"provider": {"id": "jadx"}, "subject": {"digest": {"sha256": hashlib.sha256(apk.read_bytes()).hexdigest()}}}
    overloads: dict[str, int] = {}
    reported = []
    for name, descriptor, _ in methods:
        index = overloads.get(name, 0)
        overloads[name] = index + 1
        reported.append({"name": name, "dex_descriptor": descriptor, "overload_index": index,
                         "is_constructor": name in {"<init>", "<clinit>"}})
    evidence = dict(copy.deepcopy(common), operation="inspect_android_class", parameters={"class_name": class_name},
                    normalized_result={"class_name": class_name, "methods": reported})
    package = dict(copy.deepcopy(common), operation="inspect_android_package", parameters={},
                   normalized_result={"package_name": "com.logisoft.Logi4"})
    return evidence, package


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
    family.write_bytes(b"package com.example.wheelprobe\r\n\r\n// Existing family code stays intact.\r\n")
    methods = [("observe", "(I[ILjava/lang/String;)V", 9)]
    apk = tmp_path / "fixture.apk"
    with zipfile.ZipFile(apk, "w") as archive:
        archive.writestr("classes.dex", make_dex("Lexample/Target;", methods))
    evidence, package = make_evidence(apk, "example.Target", methods)
    return {"project": project, "module": module, "family": family, "apk": apk,
            "evidence": evidence, "package": package, "tmp": tmp_path}


def generate(case, **overrides):
    arguments = dict(project_path=case["project"], app_key="logi", apk_path=case["apk"],
                     class_evidence=case["evidence"], method_name="observe", package_evidence=case["package"])
    arguments.update(overrides)
    return generator.generate_observer(**arguments)


def kotlin_outputs(result) -> dict[str, bytes]:
    return {Path(path).name: Path(path).read_bytes() for path in result["files"].values()
            if Path(path).suffix == ".kt"}


def replace_apk(case, owner, methods):
    with zipfile.ZipFile(case["apk"], "w") as archive:
        archive.writestr("classes.dex", make_dex(owner, methods))
    case["evidence"], case["package"] = make_evidence(case["apk"], owner[1:-1].replace("/", "."), methods)


def test_profiles_cover_seven_existing_apps():
    assert set(generator.load_profiles()) == {"kakao", "tmap", "callmaner", "callmaner2", "logi", "logi2", "idrive"}


def test_originals_untouched_and_reviewable_copies_preserve_crlf(case):
    originals = {key: case[key].read_bytes() for key in ("module", "family", "apk")}
    result = generate(case)
    assert result["build_status"] == "not_run"
    manifest = json.loads(Path(result["manifest"]).read_text())
    assert manifest["build_status"] == "not_run"
    for key in ("module", "family"):
        assert hashlib.sha256(originals[key]).hexdigest() in json.dumps(manifest)
    assert result["diff"]
    assert Path(result["path"]).is_dir()
    outputs = kotlin_outputs(result)
    assert set(outputs) == {"ModuleMain.kt", "E05.kt"}
    assert b"Existing family code stays intact." in outputs["E05.kt"]
    for content in outputs.values():
        assert b"\n" not in content.replace(b"\r\n", b"")
    assert any(Path(path).suffix == ".txt" for path in result["files"].values())
    for key, before in originals.items():
        assert case[key].read_bytes() == before


def test_observer_has_exact_types_and_never_replaces_result_or_arguments(case):
    text = kotlin_outputs(generate(case))["E05.kt"].decode()
    assert "example.Target" in text
    assert "observe" in text
    assert "java.lang.String" in text
    assert "[I" in text
    assert "Integer.TYPE" in text or "Int::class.javaPrimitiveType" in text
    for forbidden in ["returnAndSkip", "setResult", "setThrowable", "invokeOrigin", "args[0] =", "result ="]:
        assert forbidden not in text


def test_rea_envelope_is_accepted(case):
    result = generate(case, class_evidence={"ok": True, "data": case["evidence"]},
                      package_evidence={"ok": True, "data": case["package"]})
    assert set(kotlin_outputs(result)) == {"E05.kt", "ModuleMain.kt"}


def test_ambiguous_overload_requires_explicit_index(case):
    replace_apk(case, "Lexample/Target;", [("observe", "()V", 9), ("observe", "(I)V", 9)])
    with pytest.raises(ValueError):
        generate(case)
    assert "Integer.TYPE" in kotlin_outputs(generate(case, overload_index=1))["E05.kt"].decode()


def test_method_must_exist_in_actual_dex(case):
    case["evidence"]["normalized_result"]["methods"][0]["dex_descriptor"] = "(J)V"
    with pytest.raises(ValueError):
        generate(case)


@pytest.mark.parametrize("access,name", [(0x401, "observe"), (0x109, "observe"), (0x10001, "<init>")])
def test_unsupported_declarations_are_refused(case, access, name):
    replace_apk(case, "Lexample/Target;", [(name, "()V", access)])
    with pytest.raises(ValueError):
        generate(case, method_name=name)


@pytest.mark.parametrize("which", ["evidence", "package"])
def test_each_evidence_must_belong_to_selected_apk(case, which):
    case[which]["subject"]["digest"]["sha256"] = "0" * 64
    with pytest.raises(ValueError):
        generate(case)


def test_package_must_match_selected_app(case):
    case["package"]["normalized_result"]["package_name"] = "example.other"
    with pytest.raises(ValueError):
        generate(case)


def test_duplicate_installation_anchor_is_rejected(case):
    case["module"].write_bytes(case["module"].read_bytes().replace(
        b"installLogiGpsSpoof(classLoader)", b"installLogiGpsSpoof(classLoader)\r\n        installLogiGpsSpoof(classLoader)"))
    with pytest.raises(ValueError):
        generate(case)


def test_inner_class_binary_name_is_kotlin_escaped(case):
    replace_apk(case, "Lexample/Outer$Inner;", [("observe", "()V", 9)])
    case["evidence"]["normalized_result"]["class_name"] = "example.Outer.Inner"
    case["evidence"]["parameters"]["class_name"] = "example.Outer.Inner"
    text = kotlin_outputs(generate(case))["E05.kt"].decode()
    assert r"example.Outer\$Inner" in text


def test_defpackage_alias_resolves_only_actual_declared_owner(case):
    replace_apk(case, "Ldi;", [("observe", "()V", 9)])
    case["evidence"]["normalized_result"]["class_name"] = "defpackage.di"
    case["evidence"]["parameters"]["class_name"] = "defpackage.di"
    text = kotlin_outputs(generate(case))["E05.kt"].decode()
    assert '"di"' in text


def test_regeneration_updates_same_blocks_without_duplication(case):
    first = generate(case)
    for name, content in kotlin_outputs(first).items():
        (case["module"].parent / name).write_bytes(content)
    second = generate(case)
    assert kotlin_outputs(first) == kotlin_outputs(second)


@pytest.mark.parametrize("operation", ["inspect_android_package", "execute_tool"])
def test_class_evidence_operation_is_validated(case, operation):
    case["evidence"]["operation"] = operation
    with pytest.raises(ValueError):
        generate(case)


def test_class_evidence_parameter_name_cannot_disagree(case):
    case["evidence"]["parameters"]["class_name"] = "example.Another"
    with pytest.raises(ValueError):
        generate(case)


@pytest.mark.parametrize("descriptor", ["(V)V", "([V)V", "(Ljava/lang/String)V", "()Vextra", "(I)"])
def test_malformed_reported_descriptor_is_rejected(case, descriptor):
    case["evidence"]["normalized_result"]["methods"][0]["dex_descriptor"] = descriptor
    with pytest.raises(ValueError):
        generate(case)


def test_method_id_reference_without_declared_method_is_insufficient(case):
    methods = [("observe", "(I)V", 9)]
    dex = bytearray(make_dex("Lexample/Target;", methods))
    class_off = struct.unpack_from("<I", dex, 100)[0]
    class_data = struct.unpack_from("<I", dex, class_off + 24)[0]
    dex[class_data + 2] = 0  # Keep method_ids, remove direct method declaration.
    with zipfile.ZipFile(case["apk"], "w") as archive:
        archive.writestr("classes.dex", dex)
    case["evidence"], case["package"] = make_evidence(case["apk"], "example.Target", methods)
    with pytest.raises(ValueError):
        generate(case)


def test_source_changed_during_generation_is_not_published(case, monkeypatch):
    actual = generator._observer_code

    def race(*args, **kwargs):
        case["module"].write_bytes(case["module"].read_bytes() + b"// Changed while generation ran.\r\n")
        return actual(*args, **kwargs)

    monkeypatch.setattr(generator, "_observer_code", race)
    with pytest.raises(ValueError):
        generate(case)
    assert not list((case["tmp"] / "data/generated_hooks").glob("*/manifest.json"))


def test_resolve_project_accepts_exact_module_file(case):
    assert generator.resolve_project(case["module"]) == case["project"]
    assert set(kotlin_outputs(generate(case, project_path=case["module"]))) == {"E05.kt", "ModuleMain.kt"}


def test_resolve_project_accepts_directory_with_one_project_child(case):
    assert generator.resolve_project(case["project"].parent) == case["project"]


def test_related_packages_share_one_member_registry(case):
    first = generate(case)
    for name, content in kotlin_outputs(first).items():
        (case["module"].parent / name).write_bytes(content)
    second_package = copy.deepcopy(case["package"])
    second_package["normalized_result"]["package_name"] = "com.logisoft.Logi5"
    second = generate(case, app_key="logi2", package_evidence=second_package)
    text = kotlin_outputs(second)["E05.kt"].decode()
    assert text.count("// BEGIN L_OBSERVER_REGISTRY logi") == 1
    assert text.count("java.util.HashSet<java.lang.reflect.Method>()") == 1
    assert text.count('packageName != "com.logisoft.Logi4"') == 1
    assert text.count('packageName != "com.logisoft.Logi5"') == 1
    assert text.count("synchronized(LObserverRegistry_logi.installed)") == 2


def test_return_only_bridge_overloads_use_full_prototype(case):
    replace_apk(case, "Lexample/Target;", [
        ("observe", "()Ljava/lang/Object;", 0x1041),
        ("observe", "()Ljava/lang/String;", 1),
    ])
    text = kotlin_outputs(generate(case, overload_index=1))["E05.kt"].decode()
    assert "owner.declaredMethods.singleOrNull" in text
    assert "it.parameterTypes.contentEquals(parameterTypes)" in text
    assert "it.returnType == returnType" in text
    assert 'val returnType = java.lang.Class.forName("java.lang.String", false, classLoader)' in text
    assert "getDeclaredMethod(" not in text


def test_fake_anchors_in_comments_and_strings_are_ignored(case):
    original = case["module"].read_bytes()
    replacement = (b'// installLogiGpsSpoof(classLoader)\r\n'
                   b'        /* installLogiGpsSpoof(classLoader) */\r\n'
                   b'        val hint = "installLogiGpsSpoof(classLoader)"\r\n'
                   b'        val block = """installLogiGpsSpoof(classLoader)"""\r\n'
                   b'        installLogiGpsSpoof(classLoader)')
    case["module"].write_bytes(original.replace(b"installLogiGpsSpoof(classLoader)", replacement))
    text = kotlin_outputs(generate(case))["ModuleMain.kt"].decode()
    assert text.count("// BEGIN L_OBSERVER_CALL") == 1
    assert 'val hint = "installLogiGpsSpoof(classLoader)"' in text


@pytest.mark.parametrize("filename,marker", [("E05.kt", "L_OBSERVER"), ("ModuleMain.kt", "L_OBSERVER_CALL")])
def test_duplicate_generated_marker_is_rejected(case, filename, marker):
    first = generate(case)
    identifier = first["report"]["observer_id"]
    for name, content in kotlin_outputs(first).items():
        (case["module"].parent / name).write_bytes(content)
    path = case["module"].parent / filename
    path.write_bytes(path.read_bytes() + f"// BEGIN {marker} {identifier}\r\n".encode())
    with pytest.raises(ValueError):
        generate(case)


def test_cancellation_before_generation_propagates_without_output(case):
    import threading
    from l_app.processes import CancelledError, bind_cancel_event
    event = threading.Event()
    event.set()
    with bind_cancel_event(event), pytest.raises(CancelledError):
        generate(case)
    assert not (case["tmp"] / "data/generated_hooks").exists()


def test_cancellation_during_publication_removes_staging_bundle(case, monkeypatch):
    import threading
    from l_app.processes import CancelledError, bind_cancel_event
    event = threading.Event()
    actual_write = Path.write_bytes
    written = []

    def cancel_after_first_copy(path, data):
        result = actual_write(path, data)
        if path.suffix == ".kt" and any(part.startswith(".pending_") for part in path.parts):
            written.append(path)
            event.set()
        return result

    monkeypatch.setattr(Path, "write_bytes", cancel_after_first_copy)
    with bind_cancel_event(event), pytest.raises(CancelledError):
        generate(case)
    assert written  # Cancellation really happened after a copy was written.
    assert list((case["tmp"] / "data/generated_hooks").iterdir()) == []

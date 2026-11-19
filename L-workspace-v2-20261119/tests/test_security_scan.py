"""Synthetic DEX declarations prove scanner evidence belongs to instructions."""
from __future__ import annotations

import hashlib
from pathlib import Path
import re
import struct
import threading
import zipfile
import zlib

import pytest

from l_app import security_scan
from l_app.processes import CancelledError, bind_cancel_event


def _uleb(value):
    output = bytearray()
    while value > 127:
        output.append((value & 127) | 128)
        value >>= 7
    output.append(value)
    return bytes(output)


def make_security_dex(owner="Lexample/Checks;", methods=None, literals=()):
    """Build declarations and inert instruction items; no app code is executed.

    A method is (name, descriptor, access_flags, code_factory). The factory
    receives the real string-index map and returns exact 16-bit DEX code units.
    """
    methods = methods or [("probe", "()Z", 9, lambda indexes: [0x0012, 0x000f])]
    descriptors = list(dict.fromkeys([owner, "Ljava/lang/Object;"] + [
        item for _, signature, _, _ in methods
        for item in re.findall(r"\[*L[^;]+;|\[*[VZBSCIJFD]", signature)
    ]))
    strings = list(dict.fromkeys(descriptors + [method[0] for method in methods] + ["V"] + list(literals)))
    indexes = {value: index for index, value in enumerate(strings)}
    types = {value: index for index, value in enumerate(descriptors)}
    prototypes = list(dict.fromkeys(method[1] for method in methods))
    string_off = 112
    type_off = string_off + len(strings) * 4
    proto_off = type_off + len(descriptors) * 4
    method_off = proto_off + len(prototypes) * 12
    class_off = method_off + len(methods) * 8
    data_off = class_off + 32
    data = bytearray(data_off)
    data[:8] = b"dex\n035\0"
    struct.pack_into("<II", data, 36, 112, 0x12345678)
    for offset, count, address in [(56, len(strings), string_off), (64, len(descriptors), type_off),
                                   (72, len(prototypes), proto_off), (88, len(methods), method_off),
                                   (96, 1, class_off)]:
        struct.pack_into("<II", data, offset, count, address)
    for index, value in enumerate(strings):
        struct.pack_into("<I", data, string_off + index * 4, len(data))
        data.extend(_uleb(len(value)) + value.encode() + b"\0")
    for index, value in enumerate(descriptors):
        struct.pack_into("<I", data, type_off + index * 4, indexes[value])
    for index, signature in enumerate(prototypes):
        parameters, result = signature[1:].split(")")
        argument_types = re.findall(r"\[*L[^;]+;|\[*[ZBSCIJFD]", parameters)
        arguments_off = 0
        if argument_types:
            data.extend(b"\0" * (-len(data) % 4))
            arguments_off = len(data)
            data.extend(struct.pack("<I", len(argument_types)))
            data.extend(struct.pack("<" + "H" * len(argument_types), *[types[item] for item in argument_types]))
        struct.pack_into("<III", data, proto_off + index * 12, indexes["V"], types[result], arguments_off)
    for index, (name, signature, _, _) in enumerate(methods):
        struct.pack_into("<HHI", data, method_off + index * 8, types[owner], prototypes.index(signature), indexes[name])
    code_offsets = []
    for _, _, access, factory in methods:
        if access & (0x100 | 0x400):
            code_offsets.append(0)
            continue
        units = factory(indexes)
        data.extend(b"\0" * (-len(data) % 4))
        code_offsets.append(len(data))
        data.extend(struct.pack("<HHHHII", 8, 0, 0, 0, 0, len(units)))
        data.extend(struct.pack("<" + "H" * len(units), *units))
    class_data_off = len(data)
    data.extend(_uleb(0) + _uleb(0) + _uleb(len(methods)) + _uleb(0))
    previous = 0
    for index, (_, _, access, _) in enumerate(methods):
        data.extend(_uleb(index - previous) + _uleb(access) + _uleb(code_offsets[index]))
        previous = index
    struct.pack_into("<IIIIIIII", data, class_off, types[owner], 1, types["Ljava/lang/Object;"],
                     0, 0xffffffff, 0, class_data_off, 0)
    struct.pack_into("<I", data, 32, len(data))
    struct.pack_into("<II", data, 104, len(data) - data_off, data_off)
    data[12:32] = hashlib.sha1(data[32:]).digest()
    struct.pack_into("<I", data, 8, zlib.adler32(data[12:]) & 0xffffffff)
    return bytes(data)


def apk(tmp_path, *dexes):
    path = tmp_path / "test.apk"
    with zipfile.ZipFile(path, "w") as archive:
        for index, dex in enumerate(dexes):
            archive.writestr("classes.dex" if index == 0 else f"classes{index + 1}.dex", dex)
    return path


def _literal_dex(value, *, owner="Lexample/Checks;", name="probe", descriptor="()Z", access=9, jumbo=False):
    def code(indexes):
        index = indexes[value]
        instruction = [0x001b, index & 0xffff, index >> 16] if jumbo else [0x001a, index]
        if descriptor.endswith(")V"):
            return instruction + [0x000e]
        if descriptor.endswith(";") or descriptor.rsplit(")", 1)[-1].startswith("["):
            return instruction + [0x0012, 0x0011]
        return instruction + [0x0012, 0x000f]
    return make_security_dex(owner, [(name, descriptor, access, code)], [value])


@pytest.mark.parametrize("value,category", [
    ("/system/xbin/su", "root_files"),
    ("/data/adb/magisk", "root_files"),
    ("which su", "root_commands"),
    ("com.topjohnwu.magisk", "root_packages"),
    ("de.robv.android.xposed.XposedBridge", "hook_framework"),
    ("xposedmodule", "hook_framework"),
    ("test-keys", "root_files"),
    ("magisk", "root_files"),
    ("/proc/self/maps", "hook_memory"),
])
def test_security_literals_are_bound_to_declared_method(tmp_path, value, category):
    path = apk(tmp_path, _literal_dex(value))
    result = security_scan.scan_security_candidates(path)
    found = next(candidate for candidate in result["candidates"] if candidate["method_name"] == "probe")
    assert found["class_name"] == "example.Checks"
    assert found["dex_descriptor"] == "()Z"
    assert found["access_flags"] == 9
    assert category in found["categories"]
    assert "observe" in found["modes"]
    assert found["signals"]
    assert result["apk_digest"] == hashlib.sha256(path.read_bytes()).hexdigest()
    assert result["limitations"]


def test_direct_root_signal_primitive_boolean_offers_explicit_test_template(tmp_path):
    result = security_scan.scan_security_candidates(apk(tmp_path, _literal_dex("/system/xbin/su")))
    assert "boolean_false" in result["candidates"][0]["modes"]
    assert "skip_void" not in result["candidates"][0]["modes"]


def test_decoded_direct_root_signal_void_method_offers_explicit_skip_template(tmp_path):
    path = apk(tmp_path, _literal_dex("/system/xbin/su", descriptor="()V"))
    candidate = security_scan.scan_security_candidates(path)["candidates"][0]
    assert "observe" in candidate["modes"]
    assert "skip_void" in candidate["modes"]
    assert "boolean_false" not in candidate["modes"]


@pytest.mark.parametrize("name,access", [("<init>", 0x10001), ("<clinit>", 0x10009)])
def test_initializers_are_never_void_skip_targets(tmp_path, name, access):
    path = apk(tmp_path, _literal_dex("/system/xbin/su", name=name, descriptor="()V", access=access))
    candidates = security_scan.scan_security_candidates(path)["candidates"]
    assert candidates
    assert all(not candidate["modes"] for candidate in candidates)


@pytest.mark.parametrize("access", [0x101, 0x401])
def test_void_method_without_executable_code_never_offers_skip(tmp_path, access):
    path = apk(tmp_path, _literal_dex("/system/xbin/su", owner="Lexample/RootDetector;",
                                    name="checkForRoot", descriptor="()V", access=access))
    candidates = security_scan.scan_security_candidates(path)["candidates"]
    assert all("skip_void" not in candidate["modes"] for candidate in candidates)


def test_integrity_void_method_does_not_offer_skip_template(tmp_path):
    path = apk(tmp_path, _literal_dex("com.google.android.play.core.integrity", descriptor="()V"))
    candidates = security_scan.scan_security_candidates(path)["candidates"]
    assert candidates
    assert all("skip_void" not in candidate["modes"] for candidate in candidates)


def test_void_skip_requires_a_fully_decoded_method(tmp_path):
    marker = "/system/xbin/su"
    dex = make_security_dex(methods=[("probe", "()V", 9,
        lambda indexes: [0x001a, indexes[marker], 0x0073, 0x000e])], literals=[marker])
    result = security_scan.scan_security_candidates(apk(tmp_path, dex))
    assert result["coverage"]["unsupported_methods"] >= 1
    assert all("skip_void" not in candidate["modes"] for candidate in result["candidates"])


def test_jumbo_const_string_is_decoded_at_instruction_boundary(tmp_path):
    path = apk(tmp_path, _literal_dex("/system/xbin/su", jumbo=True))
    assert security_scan.scan_security_candidates(path)["candidates"]


@pytest.mark.parametrize("units", [
    lambda index: [0x0014, 0x001a, index, 0x0012, 0x000f],
    lambda index: [0x0018, 0x001a, index, 0, 0, 0x0012, 0x000f],
])
def test_instruction_operands_are_not_treated_as_const_string(tmp_path, units):
    value = "/system/xbin/su"
    dex = make_security_dex(methods=[("ordinary", "()Z", 9, lambda indexes: units(indexes[value]))], literals=[value])
    assert security_scan.scan_security_candidates(apk(tmp_path, dex))["candidates"] == []


@pytest.mark.parametrize("payload", [
    lambda index: [0x0100, 1, 0, 0, 0x001a, index],
    lambda index: [0x0200, 1, 0, 0, 0x001a, index],
    lambda index: [0x0300, 2, 2, 0, 0x001a, index],
])
def test_payload_values_are_never_scanned_as_executable_instructions(tmp_path, payload):
    value = "/system/xbin/su"
    dex = make_security_dex(methods=[("ordinary", "()Z", 9,
        lambda indexes: [0x0028, 0x0000] + payload(indexes[value]) + [0x0012, 0x000f])], literals=[value])
    assert security_scan.scan_security_candidates(apk(tmp_path, dex))["candidates"] == []


def test_only_referenced_literal_belongs_to_a_method(tmp_path):
    marker = "/system/xbin/su"
    methods = [
        ("first", "()Z", 9, lambda indexes: [0x001a, indexes[marker], 0x0012, 0x000f]),
        ("unrelated", "()Z", 9, lambda indexes: [0x0012, 0x000f]),
    ]
    result = security_scan.scan_security_candidates(apk(tmp_path, make_security_dex(methods=methods, literals=[marker])))
    assert {candidate["method_name"] for candidate in result["candidates"]} == {"first"}


def test_ordinary_root_activity_and_telemetry_names_are_not_security_evidence(tmp_path):
    dex = make_security_dex("Lfeature/home/RootActivity;", [("isVisible", "()Z", 9, lambda _: [0x0012, 0x000f])],
                            ["RootTelemetryConfiguration", "hooking an observer"])
    assert security_scan.scan_security_candidates(apk(tmp_path, dex))["candidates"] == []


def test_void_test_candidates_precede_observation_only_integrity_classes(tmp_path):
    integrity = _literal_dex("com.google.android.play.core.integrity", owner="La/IntegrityManager;")
    skip = _literal_dex("xposedmodule", owner="Lz/Checks;", descriptor="()V")
    result = security_scan.scan_security_candidates(apk(tmp_path, integrity, skip))
    assert result["candidates"][0]["class_name"] == "z.Checks"
    assert "skip_void" in result["candidates"][0]["modes"]
    assert result["candidates"][1]["modes"] == ["observe"]


def test_security_api_invoke_is_a_candidate_without_promoting_its_caller_to_test_override(tmp_path):
    methods = [
        ("isRooted", "()Z", 9, lambda _: [0x0012, 0x000f]),
        ("relay", "()Z", 9, lambda _: [0x0071, 0, 0, 0x000a, 0x000f]),
    ]
    result = security_scan.scan_security_candidates(apk(tmp_path, make_security_dex("Lexample/RootChecker;", methods)))
    relay = next(candidate for candidate in result["candidates"] if candidate["method_name"] == "relay")
    assert relay["evidence_kind"] == "method_invoke"
    assert relay["modes"] == ["observe"]


def test_empty_code_never_qualifies_a_boolean_result_template(tmp_path):
    methods = [("isRooted", "()Z", 9, lambda _: [])]
    result = security_scan.scan_security_candidates(apk(tmp_path, make_security_dex("Lexample/RootChecker;", methods)))
    assert result["coverage"]["unsupported_methods"] == 1
    assert all("boolean_false" not in candidate["modes"] for candidate in result["candidates"])


def test_integrity_candidates_never_offer_false_result_generation(tmp_path):
    path = apk(tmp_path, _literal_dex("com.google.android.play.core.integrity"))
    found = security_scan.scan_security_candidates(path)["candidates"]
    assert found
    for candidate in found:
        assert "integrity" in candidate["categories"]
        assert "boolean_false" not in candidate["modes"]


@pytest.mark.parametrize("descriptor,name,access", [
    ("()V", "<init>", 0x10001),
    ("()I", "probe", 9),
    ("()Ljava/lang/Boolean;", "probe", 9),
])
def test_only_supported_primitive_boolean_can_offer_false_template(tmp_path, descriptor, name, access):
    path = apk(tmp_path, _literal_dex("/system/xbin/su", descriptor=descriptor, name=name, access=access))
    found = security_scan.scan_security_candidates(path)["candidates"]
    assert found
    assert all("boolean_false" not in candidate["modes"] for candidate in found)
    if name == "<init>":
        assert all(not candidate["modes"] for candidate in found)


@pytest.mark.parametrize("access", [0x101, 0x401])
def test_methods_without_executable_code_cannot_offer_generation(tmp_path, access):
    dex = _literal_dex("/system/xbin/su", owner="Lexample/RootDetector;", name="isRooted", access=access)
    candidates = security_scan.scan_security_candidates(apk(tmp_path, dex))["candidates"]
    assert all(not candidate["modes"] for candidate in candidates)


def test_multidex_and_candidate_identity_are_stable(tmp_path):
    first = _literal_dex("/system/xbin/su", owner="Lfirst/Probe;")
    second = _literal_dex("de.robv.android.xposed.XposedBridge", owner="Lsecond/Probe;")
    path = apk(tmp_path, first, second)
    before = path.read_bytes()
    one = security_scan.scan_security_candidates(path)
    two = security_scan.scan_security_candidates(path)
    assert len(one["candidates"]) == 2
    assert {candidate["id"] for candidate in one["candidates"]} == {candidate["id"] for candidate in two["candidates"]}
    assert len({candidate["id"] for candidate in one["candidates"]}) == 2
    assert path.read_bytes() == before


def test_unrelated_pool_secrets_are_not_copied_into_candidate_signals(tmp_path):
    marker = "/system/xbin/su"
    secret = "unrelated-private-value-should-stay-local"
    dex = make_security_dex(methods=[("probe", "()Z", 9, lambda indexes: [0x001a, indexes[marker], 0x0012, 0x000f])],
                            literals=[marker, secret])
    assert secret not in repr(security_scan.scan_security_candidates(apk(tmp_path, dex)))


@pytest.mark.parametrize("dex", [b"not a dex", b"dex\n035\0" + bytes(104)])
def test_malformed_dex_cannot_be_reported_as_a_successful_empty_scan(tmp_path, dex):
    with pytest.raises((ValueError, RuntimeError)):
        security_scan.scan_security_candidates(apk(tmp_path, dex))


def test_cancellation_propagates(tmp_path):
    event = threading.Event()
    event.set()
    with bind_cancel_event(event), pytest.raises(CancelledError):
        security_scan.scan_security_candidates(apk(tmp_path, _literal_dex("/system/xbin/su")))


def test_reserved_opcode_does_not_leave_partial_evidence_override_eligible(tmp_path):
    marker = "/system/xbin/su"
    dex = make_security_dex(methods=[("probe", "()Z", 9,
        lambda indexes: [0x001a, indexes[marker], 0x0073, 0x0012, 0x000f])], literals=[marker])
    result = security_scan.scan_security_candidates(apk(tmp_path, dex))
    assert result["coverage"]["unsupported_methods"] >= 1
    assert all("boolean_false" not in candidate["modes"] for candidate in result["candidates"])

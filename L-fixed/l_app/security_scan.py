"""Bounded, read-only DEX indicators for an app team's security test workflow.

Indicators identify candidates, not the meaning or runtime reachability of an
entire method. Constants are associated with declared methods at valid Dalvik
instruction boundaries; unrelated string-pool entries and payload data are not
treated as instructions. Candidate IDs bind the exact APK and method prototype.
"""
from __future__ import annotations

from collections import Counter
import hashlib
from pathlib import Path
import re
import struct
import zipfile

from .generator import GenerationError, _Dex, _parse_descriptor
from .processes import CancelledError, check_cancelled


class SecurityScanError(ValueError):
    pass


class _CodeError(ValueError):
    pass


MAX_CANDIDATES = 512
MAX_METHODS = 500_000
MAX_DEX_BYTES = 256 * 1024 * 1024
MAX_TOTAL_DEX_BYTES = 512 * 1024 * 1024
_CATEGORIES = ("root_files", "root_commands", "root_packages", "hook_framework",
               "hook_stack", "hook_memory", "integrity")


def _digest(path):
    result = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            check_cancelled()
            result.update(block)
    return result.hexdigest()


def _widths():
    """Standard DEX 035-040 opcode widths, in 16-bit code units.

    Reserved/odex quickened opcodes deliberately remain unsupported. Dynamic
    payload sizes are read separately. This is not the legacy best-effort table.
    """
    widths = [0] * 256
    def fill(start, stop, width):
        for value in range(start, stop + 1):
            widths[value] = width
    fill(0x00, 0x12, 1)
    for opcode in (0x02, 0x05, 0x08):
        widths[opcode] = 2
    for opcode in (0x03, 0x06, 0x09):
        widths[opcode] = 3
    for opcode, width in {
        0x13: 2, 0x14: 3, 0x15: 2, 0x16: 2, 0x17: 3, 0x18: 5,
        0x19: 2, 0x1A: 2, 0x1B: 3, 0x1C: 2, 0x1D: 1, 0x1E: 1,
        0x1F: 2, 0x20: 2, 0x21: 1, 0x22: 2, 0x23: 2, 0x24: 3,
        0x25: 3, 0x26: 3, 0x27: 1, 0x28: 1, 0x29: 2, 0x2A: 3,
        0x2B: 3, 0x2C: 3,
    }.items():
        widths[opcode] = width
    fill(0x2D, 0x3D, 2)
    fill(0x44, 0x6D, 2)
    fill(0x6E, 0x72, 3)
    fill(0x74, 0x78, 3)
    fill(0x7B, 0x8F, 1)
    fill(0x90, 0xAF, 2)
    fill(0xB0, 0xCF, 1)
    fill(0xD0, 0xE2, 2)
    for opcode, width in {0xFA: 4, 0xFB: 4, 0xFC: 3, 0xFD: 3, 0xFE: 2, 0xFF: 2}.items():
        widths[opcode] = width
    return tuple(widths)


_WIDTHS = _widths()
_ROOT_OWNER = re.compile(
    r"(?:^|[.$])(?:rootbeer|rootchecker|rootdetector|rootdetection|rootutils|rootutil|"
    r"rootcheck|rootchecks|rootcheckutils)(?:$|[.$])", re.I,
)
_HOOK_OWNER = re.compile(
    r"(?:^|[.$])(?:hookdetector|hookchecker|hookdetection|xposeddetector|xposedchecker|"
    r"antihook|lsposeddetector)(?:$|[.$])", re.I,
)
_ROOT_METHODS = {
    "isrooted", "isdevicerooted", "checkforroot", "detectroot", "checkroot",
    "detectrootmanagementapps", "detectpotentiallydangerousapps", "checkforbinary",
    "checksuexists", "checkforsubinary", "checkformagiskbinary", "checkfordangerousprops",
    "detecttestkeys", "ismagiskinstalled", "isrootavailable", "isrootedwithbusyboxcheck",
    "checksu", "detectrootcloakingapps",
}
_HOOK_METHODS = {"isxposedactive", "isxposedpresent", "detectxposed", "detecthook",
                 "ishooked", "checkhook", "checkxposed", "islsposedactive"}
_PACKAGES = {
    "com.topjohnwu.magisk", "io.github.huskydg.magisk", "com.noshufou.android.su",
    "com.noshufou.android.su.elite", "eu.chainfire.supersu", "com.koushikdutta.superuser",
    "com.thirdparty.superuser", "com.yellowes.su", "com.kingroot.kinguser",
    "com.kingo.root", "com.smedialink.oneclickroot", "me.phh.superuser",
}
_ROOT_PATH = re.compile(
    r"(?:^|[\s\"'])/(?:system/(?:bin|xbin|sd/xbin|bin/failsafe)|sbin|"
    r"data/local(?:/bin|/xbin)?|su/bin)/(?:su|daemonsu)(?=$|[\s\"';])", re.I,
)
_INTEGRITY = (
    "com.google.android.play.core.integrity", "com.google.android.gms.safetynet",
    "meets_device_integrity", "meets_strong_integrity", "meets_basic_integrity",
    "integritytoken", "integrity_token", "play_integrity", "playintegrity",
    "attestation", "safetynet",
)


def _name_signals(owner, method):
    categories, signals = set(), set()
    folded = method.casefold()
    if _ROOT_OWNER.search(owner) and folded in _ROOT_METHODS:
        categories.add("root_files")
        signals.add("known-root-detector-name")
    if _HOOK_OWNER.search(owner) and folded in _HOOK_METHODS:
        categories.add("hook_framework")
        signals.add("known-hook-detector-name")
    combined = (owner + "." + method).casefold()
    if any(marker in combined for marker in _INTEGRITY) or "integritymanager" in combined:
        categories.add("integrity")
        signals.add("integrity-api-name")
    return categories, signals


def _literal_signals(values, invoked):
    categories, signals = set(), set()
    for original in values:
        folded = original.casefold()
        if _ROOT_PATH.search(original):
            categories.add("root_files")
            signals.add("root-su-file-path")
        if any(path in folded for path in ("/data/adb/magisk", "/sbin/.magisk", "/data/adb/ksu", "/data/adb/ap")):
            categories.add("root_files")
            signals.add("root-manager-private-path")
        if "/system/app/superuser.apk" in folded or "/system/app/supersu" in folded:
            categories.add("root_files")
            signals.add("superuser-system-app-path")
        if folded.strip() in {"test-keys", "dev-keys"}:
            categories.add("root_files")
            signals.add("android-test-build-tags")
        if folded.strip() == "magisk":
            categories.add("root_files")
            signals.add("root-manager-name")
        if folded.strip() in _PACKAGES:
            categories.add("root_packages")
            signals.add("root-manager-package")
        if re.search(r"(?:^|\s)(?:which\s+su|command\s+-v\s+su)(?:$|\s)", folded):
            categories.add("root_commands")
            signals.add("root-su-command")
        if any(marker in folded for marker in ("de.robv.android.xposed", "org.lsposed", "lsposed", "xposedbridge", "zygisk",
                                               "edxposed", "libriru_", "liblspd.so", "libxposed_art.so", "com.android.smultimain.")):
            categories.add("hook_framework")
            signals.add("hook-framework-marker")
        if folded.strip() == "xposedmodule":
            categories.add("hook_framework")
            signals.add("hook-module-manifest-key")
        if "/proc/self/maps" in folded or re.search(r"/proc/(?:\d+|%[ds])/maps", folded):
            categories.add("hook_memory")
            signals.add("process-memory-maps-path")
        if any(marker in folded for marker in _INTEGRITY):
            categories.add("integrity")
            signals.add("integrity-attestation-marker")
    stripped = {value.strip().casefold() for value in values}
    command_api = any(owner == "java.lang.Runtime" and name == "exec" or
                      owner == "java.lang.ProcessBuilder" and name in {"<init>", "start"}
                      for owner, name in invoked)
    if command_api and "su" in stripped:
        categories.add("root_commands")
        signals.add("su-with-process-execution")
    # A stack API alone is ordinary diagnostics, not evidence of hook detection.
    if "hook_framework" in categories and any(name in {"getStackTrace", "getClassName"} for _, name in invoked):
        categories.add("hook_stack")
        signals.add("hook-marker-with-stack-api")
    return categories, signals


def _method_ref(dex, index):
    offset = dex.row("methods", index, 8)
    class_index, _, name_index = struct.unpack_from("<HHI", dex.data, offset)
    owner = dex.type(class_index)
    owner = owner[1:-1].replace("/", ".") if owner.startswith("L") and owner.endswith(";") else owner
    return owner, dex.string(name_index)


def _read_code(dex, method):
    """Return only real const-string references and direct method-ID invokes."""
    offset = method["code_offset"]
    count = dex.u32(offset + 12)
    if not count:
        raise _CodeError("empty executable code_item")
    dex.span(offset + 16, count * 2)
    # Only individual instructions are unpacked, avoiding a second huge list.
    def unit(index):
        if index < 0 or index >= count:
            raise _CodeError("instruction extends beyond code_item")
        return struct.unpack_from("<H", dex.data, offset + 16 + index * 2)[0]
    values, invoked = set(), set()
    cursor = 0
    version = int(dex.data[4:7])
    while cursor < count:
        if cursor % 1024 == 0:
            check_cancelled()
        first = unit(cursor)
        opcode = first & 255
        if opcode == 0 and first:
            if cursor & 1:
                raise _CodeError("unaligned Dalvik payload")
            if first == 0x0100:  # packed-switch-payload
                width = 4 + 2 * unit(cursor + 1)
            elif first == 0x0200:  # sparse-switch-payload
                width = 2 + 4 * unit(cursor + 1)
            elif first == 0x0300:  # fill-array-data-payload
                element_width = unit(cursor + 1)
                if element_width not in {1, 2, 4, 8}:
                    raise _CodeError("invalid array payload element width")
                elements = unit(cursor + 2) | unit(cursor + 3) << 16
                width = 4 + (element_width * elements + 1) // 2
            else:
                raise _CodeError("unknown Dalvik payload")
        else:
            width = _WIDTHS[opcode]
            if not width or opcode >= 0xFA and version < 38:
                raise _CodeError("unsupported or reserved Dalvik opcode")
        if cursor + width > count:
            raise _CodeError("truncated Dalvik instruction or payload")
        if opcode == 0x1A:
            values.add(dex.string(unit(cursor + 1)))
        elif opcode == 0x1B:
            values.add(dex.string(unit(cursor + 1) | unit(cursor + 2) << 16))
        elif 0x6E <= opcode <= 0x72 or 0x74 <= opcode <= 0x78 or opcode in {0xFA, 0xFB}:
            invoked.add(_method_ref(dex, unit(cursor + 1)))
        cursor += width
    return values, invoked


def _candidate(owner, method, digest, decoded, values, invoked):
    named_categories, named_signals = _name_signals(owner, method["name"])
    literal_categories, literal_signals = _literal_signals(values, invoked)
    invoked_categories, invoked_signals = set(), set()
    for called_owner, called_name in invoked:
        cats, indicators = _name_signals(called_owner, called_name)
        invoked_categories.update(cats)
        if indicators:
            invoked_signals.add("calls-known-security-api")
    categories = named_categories | literal_categories | invoked_categories
    signals = named_signals | literal_signals | invoked_signals
    if "hook_framework" in categories and any(name in {"getStackTrace", "getClassName"} for _, name in invoked):
        categories.add("hook_stack")
        signals.add("hook-marker-with-stack-api")
    if not categories:
        return None
    supported = method["name"] not in {"<init>", "<clinit>"} and bool(method["code_offset"]) and not method["access_flags"] & (0x400 | 0x100)
    modes = ["observe"] if supported else []
    _, result = _parse_descriptor(method["dex_descriptor"])
    strong = bool(literal_categories - {"integrity"}) or bool(named_signals - {"integrity-api-name"})
    if supported and decoded and result == "Z" and strong and "integrity" not in categories:
        modes.append("boolean_false")
    if supported and decoded and result == "V" and literal_categories - {"integrity"} and "integrity" not in categories:
        modes.append("skip_void")
    identity = "\0".join(("SECURITY-CANDIDATE", digest, owner, method["name"], method["dex_descriptor"]))
    evidence = "method_literal" if literal_signals else "method_name" if named_signals else "method_invoke"
    if method["code_offset"] and not decoded:
        evidence = "partial_" + evidence
    note = "정적 보안 지표 후보입니다. 메서드 의미·실제 실행·탐지 성공은 별도 확인이 필요합니다."
    if method["code_offset"] and not decoded:
        note += " 일부 명령을 해석하지 못해 결과 변경용 생성은 보류합니다."
    if "integrity" in categories:
        note += " 무결성·증명 관련 후보는 관찰만 지원하며 결과 변경용 생성 대상이 아닙니다."
    return {"id": hashlib.sha256(identity.encode()).hexdigest()[:24],
            "class_name": owner, "method_name": method["name"],
            "dex_descriptor": method["dex_descriptor"], "access_flags": method["access_flags"],
            "categories": [category for category in _CATEGORIES if category in categories],
            "signals": sorted(signals), "evidence_kind": evidence, "modes": modes, "note": note}


def scan_security_candidates(apk_path, *, progress=None):
    """Read APK declarations/code and return bounded, APK-bound test candidates."""
    check_cancelled()
    apk = Path(apk_path).expanduser().resolve()
    if not apk.is_file() or apk.suffix.casefold() != ".apk":
        raise SecurityScanError("분석할 APK 파일을 선택하세요")
    digest = _digest(apk)
    coverage = {"dex_files": 0, "classes_scanned": 0, "methods_scanned": 0,
                "decoded_methods": 0, "unsupported_methods": 0, "duplicate_owners": 0,
                "candidates_total": 0, "candidates_returned": 0, "truncated": False,
                "method_limit_reached": False}
    collected, owners, definitions = [], Counter(), Counter()
    try:
        with zipfile.ZipFile(apk) as archive:
            files = [item for item in archive.infolist() if re.fullmatch(r"classes(?:[0-9]+)?\.dex", item.filename)]
            if not files or len({item.filename for item in files}) != len(files):
                raise SecurityScanError("고유한 classes.dex 선언 파일이 필요합니다")
            if any(item.file_size > MAX_DEX_BYTES for item in files) or sum(item.file_size for item in files) > MAX_TOTAL_DEX_BYTES:
                raise SecurityScanError("APK DEX 크기가 분석 한도를 넘습니다")
            for item in sorted(files, key=lambda entry: entry.filename):
                check_cancelled()
                if coverage["method_limit_reached"]:
                    break
                if progress:
                    progress(f"보안 후보 탐색: {item.filename}의 선언·명령 확인 중…")
                dex = _Dex(archive.read(item))
                coverage["dex_files"] += 1
                for owner, row in dex.classes():
                    check_cancelled()
                    owners[owner] += 1
                    coverage["classes_scanned"] += 1
                    for method in dex.declared_methods(row):
                        if coverage["methods_scanned"] >= MAX_METHODS:
                            coverage["method_limit_reached"] = True
                            break
                        check_cancelled()
                        coverage["methods_scanned"] += 1
                        definitions[(owner, method["name"], method["dex_descriptor"])] += 1
                        values, invoked, decoded = set(), set(), False
                        if method["code_offset"]:
                            try:
                                values, invoked = _read_code(dex, method)
                                decoded = True
                                coverage["decoded_methods"] += 1
                            except (GenerationError, _CodeError, struct.error, UnicodeError):
                                # A partial decode does not qualify a test override.
                                coverage["unsupported_methods"] += 1
                        candidate = _candidate(owner, method, digest, decoded, values, invoked)
                        if candidate is not None:
                            collected.append(candidate)
                    if coverage["method_limit_reached"]:
                        break
    except CancelledError:
        raise
    except (GenerationError, OSError, zipfile.BadZipFile, struct.error, RuntimeError) as error:
        if isinstance(error, SecurityScanError):
            raise
        raise SecurityScanError(f"APK 보안 후보의 DEX 근거를 읽을 수 없습니다: {error}") from error
    if _digest(apk) != digest:
        raise SecurityScanError("분석 중 APK가 변경되었습니다. 다시 분석하세요")
    unique = {}
    for candidate in collected:
        owner = candidate["class_name"]
        if owners[owner] != 1 or definitions[(owner, candidate["method_name"], candidate["dex_descriptor"])] != 1:
            candidate["modes"] = []
            candidate["note"] += " 클래스 또는 원형의 선언이 중복되어 코드 생성을 보류합니다."
        unique.setdefault(candidate["id"], candidate)
    candidates = sorted(unique.values(), key=lambda row: (
        not bool({"boolean_false", "skip_void"}.intersection(row["modes"])),
        "boolean_false" not in row["modes"], "method_literal" not in row["evidence_kind"],
        row["class_name"], row["method_name"], row["dex_descriptor"],
    ))
    coverage.update(duplicate_owners=sum(value > 1 for value in owners.values()),
                    candidates_total=len(candidates), candidates_returned=min(MAX_CANDIDATES, len(candidates)),
                    truncated=len(candidates) > MAX_CANDIDATES or coverage["method_limit_reached"])
    limitations = [
        "문자열·알려진 API 이름을 명령 위치와 연결한 후보 탐색이며 전체 보안 검사나 런타임 동작을 증명하지 않습니다.",
        "리플렉션·동적 문자열·네이티브 코드·별도 split APK·서버 판정은 분석 범위 밖입니다.",
        "후보의 Boolean 결과 변경은 선택한 공동 개발 테스트의 제한된 템플릿이며 의미 검토가 필요합니다.",
        "무결성 증명·서명·서버 토큰은 변경용 생성 대상에서 제외합니다.",
    ]
    if coverage["unsupported_methods"]:
        limitations.append(f"명령 형식을 완전히 읽지 못한 메서드 {coverage['unsupported_methods']}개가 있습니다.")
    if coverage["truncated"]:
        limitations.append("분석 또는 반환 후보 수의 한도에 도달했습니다. 전체 탐색으로 해석하지 마세요.")
    return {"apk_digest": digest, "candidates": candidates[:MAX_CANDIDATES],
            "coverage": coverage, "limitations": limitations}

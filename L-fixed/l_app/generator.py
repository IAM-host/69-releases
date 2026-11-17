"""Generate reviewable, read-only libxposed observers from verified REA evidence.

The original Android project is never changed. REA supplies a selection list;
declared owners, exact prototypes and access flags are checked against the APK's
DEX tables before any Kotlin is emitted. No model or remote service is involved.
"""
from __future__ import annotations

import difflib
import hashlib
import json
import re
import shutil
import struct
import tempfile
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .paths import app_dir
from .processes import CancelledError, check_cancelled


class GenerationError(ValueError):
    """The inputs do not prove a safe, exact observation target."""


def load_profiles() -> dict[str, dict[str, str]]:
    return json.loads(Path(__file__).with_name("eunora_profiles.json").read_text(encoding="utf-8"))


def resolve_project(project_path: str | Path) -> Path:
    root = Path(project_path).expanduser().resolve()
    if root.is_file() and root.name == "ModuleMain.kt":
        suffix = Path("app/src/main/java/com/example/wheelprobe/ModuleMain.kt")
        if tuple(root.parts[-len(suffix.parts):]) != suffix.parts:
            raise GenerationError("선택한 ModuleMain.kt의 EUNORA 프로젝트 경로를 확인할 수 없습니다.")
        root = root.parents[7]
    if not root.is_dir():
        raise GenerationError("EUNORA 프로젝트 폴더를 선택해 주세요.")
    if (root / "app/src/main/java/com/example/wheelprobe/ModuleMain.kt").is_file():
        return root
    candidates = [path for path in root.glob("*/app/src/main/java/com/example/wheelprobe/ModuleMain.kt")
                  if path.is_file()]
    if len(candidates) != 1:
        raise GenerationError("프로젝트에서 ModuleMain.kt의 위치를 하나로 확인할 수 없습니다.")
    return candidates[0].parents[7]


def _unwrap(value: Any, operation: str) -> dict:
    if not isinstance(value, dict):
        raise GenerationError("REA 근거는 JSON 객체여야 합니다.")
    if "ok" in value:
        if value.get("ok") is not True or not isinstance(value.get("data"), dict):
            raise GenerationError("실패한 REA 결과는 코드 생성에 사용할 수 없습니다.")
        value = value["data"]
    if value.get("operation") != operation or not isinstance(value.get("provider"), dict) or value["provider"].get("id") != "jadx":
        raise GenerationError(f"JADX {operation} 근거가 필요합니다.")
    if not isinstance(value.get("normalized_result"), dict):
        raise GenerationError("REA 정규화 결과가 없습니다.")
    return value


def _class_result(evidence: Any) -> tuple[dict, dict]:
    evidence = _unwrap(evidence, "inspect_android_class")
    result = evidence["normalized_result"]
    name = result.get("class_name")
    if not isinstance(name, str) or not name or not isinstance(evidence.get("parameters"), dict) or evidence["parameters"].get("class_name") != name:
        raise GenerationError("REA 클래스 질의와 결과의 클래스 이름이 다릅니다.")
    if not isinstance(result.get("methods"), list):
        raise GenerationError("REA 메서드 목록이 없습니다.")
    return evidence, result


def list_observer_methods(class_evidence: dict) -> list[dict]:
    """Return explicit overload choices; APK validation still occurs on generation."""
    _, result = _class_result(class_evidence)
    choices = []
    for method in result["methods"]:
        if not isinstance(method, dict) or method.get("is_constructor") or method.get("name") in {"<init>", "<clinit>"}:
            continue
        if not isinstance(method.get("name"), str) or not isinstance(method.get("overload_index"), int):
            continue
        try:
            _parse_descriptor(method.get("dex_descriptor"))
        except GenerationError:
            continue
        choice = dict(method)
        choice["label"] = f"{method.get('reported_signature') or method['name']} [{method['dex_descriptor']}]"
        choices.append(choice)
    return choices


def _sha(path: Path) -> str:
    check_cancelled()
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            check_cancelled()
            digest.update(block)
    return digest.hexdigest()


def _bind_evidence(evidence: dict, sha: str) -> None:
    subject = evidence.get("subject")
    digest = subject.get("digest") if isinstance(subject, dict) else None
    observed = digest.get("sha256") if isinstance(digest, dict) else None
    if not isinstance(observed, str) or observed.lower() != sha:
        raise GenerationError("REA 근거의 APK SHA-256이 선택한 APK와 다릅니다. 이 APK를 다시 분석해 주세요.")


def _parse_descriptor(descriptor: Any) -> tuple[list[str], str]:
    if not isinstance(descriptor, str) or not descriptor.startswith("("):
        raise GenerationError("정확한 DEX 메서드 원형이 필요합니다.")

    def one(offset: int, allow_void: bool = False) -> tuple[str, int]:
        start = offset
        while offset < len(descriptor) and descriptor[offset] == "[":
            offset += 1
        dimensions = offset - start
        if dimensions > 255 or offset >= len(descriptor):
            raise GenerationError("지원하지 않는 DEX 타입입니다.")
        symbol = descriptor[offset]
        if symbol in "ZBSCIJFD" or (symbol == "V" and allow_void and dimensions == 0):
            offset += 1
        elif symbol == "L":
            end = descriptor.find(";", offset)
            if end < 0:
                raise GenerationError("잘못된 DEX 객체 타입입니다.")
            name = descriptor[offset + 1:end]
            if not name or any(not segment for segment in name.split("/")) or any(
                character in ".;[()\\\x00" or ord(character) < 32 for character in name
            ):
                raise GenerationError("지원하지 않는 DEX 클래스 이름입니다.")
            offset = end + 1
        else:
            raise GenerationError("지원하지 않는 DEX 타입입니다.")
        return descriptor[start:offset], offset

    parameters: list[str] = []
    offset = 1
    while offset < len(descriptor) and descriptor[offset] != ")":
        item, offset = one(offset)
        parameters.append(item)
    if offset >= len(descriptor) or descriptor[offset] != ")":
        raise GenerationError("잘못된 DEX 메서드 원형입니다.")
    result, offset = one(offset + 1, True)
    if offset != len(descriptor):
        raise GenerationError("DEX 메서드 원형 뒤에 알 수 없는 데이터가 있습니다.")
    return parameters, result


class _Dex:
    """Bounded metadata reader: declarations only, never execute DEX instructions."""

    def __init__(self, data: bytes):
        self.data = data
        if len(data) < 112 or not re.fullmatch(rb"dex\n0(?:3[5-9]|40)\x00", data[:8]):
            raise GenerationError("지원하는 표준 DEX 파일이 아닙니다.")
        if self.u32(32) != len(data) or self.u32(36) != 112 or self.u32(40) != 0x12345678:
            raise GenerationError("DEX 헤더 크기 또는 바이트 순서를 확인할 수 없습니다.")
        self.tables = {}
        for name, header, width in (("strings", 56, 4), ("types", 64, 4), ("protos", 72, 12),
                                    ("methods", 88, 8), ("classes", 96, 32)):
            count, offset = self.u32(header), self.u32(header + 4)
            self.span(offset, count * width)
            self.tables[name] = (count, offset)
        self.string_cache: dict[int, str] = {}

    def span(self, offset: int, length: int) -> None:
        if offset < 0 or length < 0 or offset > len(self.data) - length:
            raise GenerationError("DEX 테이블이 파일 범위를 벗어납니다.")

    def u32(self, offset: int) -> int:
        self.span(offset, 4)
        return struct.unpack_from("<I", self.data, offset)[0]

    def uleb(self, offset: int) -> tuple[int, int]:
        value = 0
        for shift in range(0, 35, 7):
            self.span(offset, 1)
            byte = self.data[offset]
            offset += 1
            if shift == 28 and byte > 15:
                raise GenerationError("DEX ULEB128 범위가 잘못되었습니다.")
            value |= (byte & 127) << shift
            if not byte & 128:
                return value, offset
        raise GenerationError("DEX ULEB128 데이터가 잘못되었습니다.")

    def row(self, table: str, index: int, width: int) -> int:
        count, offset = self.tables[table]
        if index < 0 or index >= count:
            raise GenerationError("DEX 테이블 인덱스가 잘못되었습니다.")
        return offset + index * width

    def string(self, index: int) -> str:
        if index not in self.string_cache:
            offset = self.u32(self.row("strings", index, 4))
            _, offset = self.uleb(offset)
            end = self.data.find(b"\0", offset)
            if end < 0:
                raise GenerationError("DEX 문자열의 끝을 찾을 수 없습니다.")
            try:
                # DEX strings are modified UTF-8; combine surrogate pairs without
                # mistaking unrelated non-ASCII constants for invalid metadata.
                value = self.data[offset:end].replace(b"\xc0\x80", b"\x00").decode("utf-8", "surrogatepass")
                value = value.encode("utf-16-le", "surrogatepass").decode("utf-16-le")
            except UnicodeError as error:
                raise GenerationError("DEX 문자열 인코딩을 확인할 수 없습니다.") from error
            self.string_cache[index] = value
        return self.string_cache[index]

    def type(self, index: int) -> str:
        return self.string(self.u32(self.row("types", index, 4)))

    def proto(self, index: int) -> str:
        offset = self.row("protos", index, 12)
        result, parameters_offset = self.type(self.u32(offset + 4)), self.u32(offset + 8)
        parameters = []
        if parameters_offset:
            count = self.u32(parameters_offset)
            self.span(parameters_offset + 4, count * 2)
            parameters = [self.type(struct.unpack_from("<H", self.data, parameters_offset + 4 + i * 2)[0])
                          for i in range(count)]
        descriptor = "(" + "".join(parameters) + ")" + result
        _parse_descriptor(descriptor)
        return descriptor

    def classes(self) -> list[tuple[str, int]]:
        count, offset = self.tables["classes"]
        result = []
        for index in range(count):
            if index % 256 == 0:
                check_cancelled()
            row = offset + index * 32
            owner = self.type(self.u32(row))
            if not owner.startswith("L") or not owner.endswith(";"):
                raise GenerationError("DEX 클래스 선언이 객체 타입이 아닙니다.")
            _parse_descriptor("()" + owner)
            result.append((owner[1:-1].replace("/", "."), row))
        return result

    def declared_methods(self, row: int) -> list[dict]:
        owner = self.type(self.u32(row))
        offset = self.u32(row + 24)
        if not offset:
            return []
        counts = []
        for _ in range(4):
            count, offset = self.uleb(offset)
            counts.append(count)
        if sum(counts) > len(self.data):
            raise GenerationError("DEX 클래스 멤버 수가 잘못되었습니다.")
        for _ in range(counts[0] + counts[1]):
            check_cancelled()
            _, offset = self.uleb(offset)
            _, offset = self.uleb(offset)
        declared = []
        for count in counts[2:]:
            index = 0
            for _ in range(count):
                check_cancelled()
                difference, offset = self.uleb(offset)
                index += difference
                access, offset = self.uleb(offset)
                code, offset = self.uleb(offset)
                method = self.row("methods", index, 8)
                class_index, proto_index, name_index = struct.unpack_from("<HHI", self.data, method)
                if self.type(class_index) != owner:
                    raise GenerationError("DEX 선언과 메서드 소유 클래스가 일치하지 않습니다.")
                if code:
                    self.span(code, 16)
                    self.span(code + 16, self.u32(code + 12) * 2)
                declared.append({"name": self.string(name_index), "dex_descriptor": self.proto(proto_index),
                                 "access_flags": access, "code_offset": code})
        return declared


def _verified_target(apk: Path, reported_name: str, name: str, descriptor: str) -> dict:
    declared: dict[str, list[tuple[_Dex, int]]] = {}
    try:
        with zipfile.ZipFile(apk) as archive:
            dex_files = [item for item in archive.infolist() if re.fullmatch(r"classes(?:[0-9]+)?\.dex", item.filename)]
            if not dex_files or len({item.filename for item in dex_files}) != len(dex_files):
                raise GenerationError("APK에서 고유한 classes.dex 파일들을 확인할 수 없습니다.")
            if any(item.file_size > 256 * 1024 * 1024 for item in dex_files) or sum(item.file_size for item in dex_files) > 512 * 1024 * 1024:
                raise GenerationError("DEX 메타데이터 크기가 분석 한도를 넘습니다.")
            for item in dex_files:
                check_cancelled()
                dex = _Dex(archive.read(item))
                for binary_name, row in dex.classes():
                    declared.setdefault(binary_name, []).append((dex, row))
    except CancelledError:
        raise
    except (OSError, zipfile.BadZipFile, RuntimeError) as error:
        raise GenerationError("APK의 DEX 메타데이터를 읽을 수 없습니다.") from error
    candidates = [reported_name] if reported_name in declared else []
    if not candidates:
        # JADX's display owner is not necessarily the Class.forName binary name.
        display = reported_name.removeprefix("defpackage.")
        candidates = [binary for binary in declared if binary == display or binary.replace("$", ".") == display]
    if len(candidates) != 1 or len(declared[candidates[0]]) != 1:
        raise GenerationError("REA 클래스의 실제 DEX 소유자를 하나로 확인할 수 없습니다.")
    binary_name = candidates[0]
    dex, row = declared[binary_name][0]
    matches = [method for method in dex.declared_methods(row)
               if method["name"] == name and method["dex_descriptor"] == descriptor]
    if len(matches) != 1:
        raise GenerationError("선택한 이름·원형의 메서드가 이 DEX 클래스에 고유하게 선언되어 있지 않습니다.")
    target = matches[0]
    if name in {"<init>", "<clinit>"} or target["access_flags"] & (0x400 | 0x100) or not target["code_offset"]:
        raise GenerationError("생성자·추상·네이티브·실행 코드가 없는 메서드는 지원하지 않습니다.")
    return dict(target, class_name=binary_name)


def _kotlin(value: str) -> str:
    result = []
    for character in value:
        result.append({"\\": "\\\\", '"': '\\"', "$": "\\$", "\n": "\\n", "\r": "\\r", "\t": "\\t"}.get(
            character, f"\\u{ord(character):04x}" if ord(character) < 32 else character))
    return '"' + "".join(result) + '"'


def _class_expression(descriptor: str) -> str:
    primitive = {"V": "Void", "Z": "Boolean", "B": "Byte", "S": "Short", "C": "Character", "I": "Integer",
                 "J": "Long", "F": "Float", "D": "Double"}
    if descriptor in primitive:
        return f"java.lang.{primitive[descriptor]}.TYPE"
    name = descriptor.replace("/", ".") if descriptor.startswith("[") else descriptor[1:-1].replace("/", ".")
    return f"java.lang.Class.forName({_kotlin(name)}, false, classLoader)"


def _registry_code(family: str) -> str:
    return f'''// BEGIN L_OBSERVER_REGISTRY {family}
// Reflection members are shared across this family's package variants.
private object LObserverRegistry_{family} {{
    val installed = java.util.HashSet<java.lang.reflect.Method>()
}}
// END L_OBSERVER_REGISTRY {family}
'''


def _observer_code(identifier: str, package: str, target: dict, family: str) -> str:
    parameters, result = _parse_descriptor(target["dex_descriptor"])
    argument_types = ", ".join(_class_expression(item) for item in parameters)
    parameter_array = "arrayOf<java.lang.Class<*>>(" + argument_types + ")"
    identity = _kotlin("L_OBSERVER " + identifier + " " + target["class_name"] + "." + target["name"] + target["dex_descriptor"])
    return f'''// BEGIN L_OBSERVER {identifier}
// Generated from exact APK/DEX evidence. Observation only; no argument values are logged.
// A shared process may invoke this same member for another package after installation.
@io.github.libxposed.api.annotations.XposedHooker
class LObserverHooker_{identifier} : io.github.libxposed.api.XposedInterface.Hooker {{
    companion object {{
        @JvmStatic
        @io.github.libxposed.api.annotations.AfterInvocation
        fun after(callback: io.github.libxposed.api.XposedInterface.AfterHookCallback) {{
            try {{
                val argumentTypes = callback.args.joinToString(",") {{ it?.javaClass?.name ?: "null" }}
                val failure = callback.throwable
                val outcomeType = if (failure != null) "throw:" + failure.javaClass.name
                    else "return:" + (callback.result?.javaClass?.name ?: "null")
                ModuleMain.module?.log({identity} + " argc=" + callback.args.size +
                    " types=[" + argumentTypes + "] " + outcomeType)
            }} catch (_: Throwable) {{ /* Diagnostics must not change the observed call. */ }}
        }}
    }}
}}

internal fun ModuleMain.installLObserver_{identifier}(classLoader: ClassLoader, packageName: String) {{
    if (packageName != {_kotlin(package)}) return
    val module = ModuleMain.module ?: return
    try {{
        val owner = java.lang.Class.forName({_kotlin(target['class_name'])}, false, classLoader)
        val parameterTypes = {parameter_array}
        val returnType = {_class_expression(result)}
        val method = owner.declaredMethods.singleOrNull {{
            it.name == {_kotlin(target['name'])} && it.parameterTypes.contentEquals(parameterTypes) && it.returnType == returnType
        }} ?: throw NoSuchMethodException("Exact DEX prototype was not found")
        if (java.lang.reflect.Modifier.isAbstract(method.modifiers) || java.lang.reflect.Modifier.isNative(method.modifiers)) {{
            throw NoSuchMethodException("Unsupported method declaration")
        }}
        synchronized(LObserverRegistry_{family}.installed) {{
            if (LObserverRegistry_{family}.installed.contains(method)) return
            method.isAccessible = true
            module.hook(method, LObserverHooker_{identifier}::class.java)
            LObserverRegistry_{family}.installed.add(method)
        }}
        module.log({identity} + " installed")
    }} catch (error: Throwable) {{
        try {{ module.log({identity} + " installation failed type=" + error.javaClass.name) }}
        catch (_: Throwable) {{ }}
    }}
}}
// END L_OBSERVER {identifier}
'''


def _mask_kotlin(text: str) -> tuple[str, list[tuple[int, int]]]:
    """Keep code positions, blank comments/strings, and expose actual line comments."""
    chars = list(text)
    comments = []
    index = 0

    def blank(start: int, end: int) -> None:
        for position in range(start, end):
            if chars[position] not in "\r\n":
                chars[position] = " "

    while index < len(text):
        start = index
        if text.startswith("//", index):
            end = text.find("\n", index)
            index = len(text) if end < 0 else end
            comments.append((start, index))
        elif text.startswith("/*", index):
            depth = 1
            index += 2
            while index < len(text) and depth:
                if text.startswith("/*", index):
                    depth += 1
                    index += 2
                elif text.startswith("*/", index):
                    depth -= 1
                    index += 2
                else:
                    index += 1
            if depth:
                raise GenerationError("Kotlin 블록 주석의 끝을 확인할 수 없습니다.")
        elif text.startswith('\"\"\"', index):
            end = text.find('\"\"\"', index + 3)
            if end < 0:
                raise GenerationError("Kotlin 문자열의 끝을 확인할 수 없습니다.")
            index = end + 3
        elif text[index] in "\"'`":
            quote = text[index]
            index += 1
            while index < len(text):
                if text[index] == "\\" and quote != "`":
                    index += 2
                elif text[index] == quote:
                    index += 1
                    break
                else:
                    index += 1
            else:
                raise GenerationError("Kotlin 문자열/식별자의 끝을 확인할 수 없습니다.")
        else:
            index += 1
            continue
        blank(start, index)
    return "".join(chars), comments


def _existing_region(text: str, kind: str, identifier: str) -> tuple[int, int] | None:
    _, comments = _mask_kotlin(text)
    wanted = {f"// BEGIN {kind} {identifier}": [], f"// END {kind} {identifier}": []}
    for start, end in comments:
        token = text[start:end].rstrip("\r")
        if token in wanted:
            wanted[token].append((start, end))
    begins, ends = wanted[f"// BEGIN {kind} {identifier}"], wanted[f"// END {kind} {identifier}"]
    if not begins and not ends:
        return None
    if len(begins) != 1 or len(ends) != 1 or ends[0][0] <= begins[0][0]:
        raise GenerationError("기존 생성 블록의 경계가 중복되거나 손상되었습니다.")
    start = text.rfind("\n", 0, begins[0][0]) + 1
    if text[start:begins[0][0]].strip():
        raise GenerationError("생성 블록은 독립된 줄에 있어야 합니다.")
    end = ends[0][1]
    if end < len(text) and text[end] == "\n":
        end += 1
    return start, end


def _function_body(masked: str, name: str) -> tuple[int, int]:
    matches = list(re.finditer(r"\bfun\s+" + re.escape(name) + r"\s*\(", masked))
    if len(matches) != 1:
        raise GenerationError(f"{name} 함수의 위치를 하나로 확인할 수 없습니다.")
    opening = masked.find("{", matches[0].end())
    if opening < 0:
        raise GenerationError(f"{name} 함수 본문을 확인할 수 없습니다.")
    depth = 1
    for offset in range(opening + 1, len(masked)):
        if masked[offset] == "{":
            depth += 1
        elif masked[offset] == "}":
            depth -= 1
            if depth == 0:
                return opening + 1, offset
    raise GenerationError(f"{name} 함수의 끝을 확인할 수 없습니다.")


def _install_source(text: str, anchor: str, identifier: str, newline: str) -> str:
    region = _existing_region(text, "L_OBSERVER_CALL", identifier)
    clean = text if region is None else text[:region[0]] + text[region[1]:]
    masked, _ = _mask_kotlin(clean)
    start, end = _function_body(masked, "onPackageLoaded")
    body = masked[start:end]
    matches = list(re.finditer(r"\b" + re.escape(anchor) + r"\s*\(\s*classLoader\s*\)", body))
    if len(matches) != 1:
        raise GenerationError(f"onPackageLoaded 안의 {anchor}(classLoader) 호출이 정확히 하나여야 합니다.")
    position = start + matches[0].start()
    line = clean.rfind("\n", 0, position) + 1
    indent = clean[line:position]
    if indent.strip():
        raise GenerationError("설치 호출은 독립된 줄에 있어야 합니다.")
    prefix = masked[start:position]
    if not re.search(r"\bval\s+pkg\s*=", prefix) or not re.search(r"\bval\s+classLoader\s*=", prefix):
        raise GenerationError("설치 지점 앞에서 pkg/classLoader 지역 변수를 확인할 수 없습니다.")
    block = newline.join([indent + f"// BEGIN L_OBSERVER_CALL {identifier}",
                          indent + f"installLObserver_{identifier}(classLoader, pkg)",
                          indent + f"// END L_OBSERVER_CALL {identifier}", ""])
    return clean[:line] + block + clean[line:]


def _family_source(text: str, code: str, identifier: str, newline: str, family: str) -> str:
    masked, _ = _mask_kotlin(text)
    package = re.search(r"(?m)^\s*package\s+com\.example\.wheelprobe\s*$", masked)
    if not package:
        raise GenerationError("기존 E0 파일의 EUNORA package 선언을 확인할 수 없습니다.")
    registry = _registry_code(family).replace("\n", newline)
    existing_registry = _existing_region(text, "L_OBSERVER_REGISTRY", family)
    if existing_registry is None:
        separator = "" if text.endswith(newline + newline) else newline if text.endswith(newline) else newline + newline
        text += separator + registry
    elif text[existing_registry[0]:existing_registry[1]] != registry:
        raise GenerationError("공통 관찰 레지스트리가 변경되었습니다. 기존 생성 코드를 확인해 주세요.")
    code = code.replace("\n", newline)
    region = _existing_region(text, "L_OBSERVER", identifier)
    if region is not None:
        return text[:region[0]] + code + text[region[1]:]
    separator = "" if text.endswith(newline + newline) else newline if text.endswith(newline) else newline + newline
    return text + separator + code


def _source_text(data: bytes) -> tuple[str, bool, str]:
    bom = data.startswith(b"\xef\xbb\xbf")
    try:
        text = data.decode("utf-8-sig")
    except UnicodeError as error:
        raise GenerationError("Kotlin 파일은 UTF-8이어야 합니다.") from error
    newline = "\r\n" if "\r\n" in text else "\n"
    return text, bom, newline


def generate_observer(project_path: str | Path, app_key: str, apk_path: str | Path,
                      class_evidence: dict, method_name: str, overload_index: int | None = None,
                      package_evidence: dict | None = None) -> dict:
    """Generate full source copies and a diff, never overwrite the input project."""
    check_cancelled()
    profiles = load_profiles()
    if app_key not in profiles:
        raise GenerationError("알 수 없는 EUNORA 앱 프로필입니다.")
    profile = profiles[app_key]
    root = resolve_project(project_path)
    apk = Path(apk_path).expanduser().resolve()
    if not apk.is_file():
        raise GenerationError("분석한 APK 파일이 없습니다.")
    apk_sha = _sha(apk)
    evidence, class_result = _class_result(class_evidence)
    package = _unwrap(package_evidence, "inspect_android_package")
    _bind_evidence(evidence, apk_sha)
    _bind_evidence(package, apk_sha)
    if package["normalized_result"].get("package_name") != profile["package"]:
        raise GenerationError("선택한 앱 프로필의 패키지와 APK 패키지가 다릅니다.")
    candidates = [method for method in list_observer_methods(evidence) if method["name"] == method_name]
    if overload_index is not None:
        candidates = [method for method in candidates if method["overload_index"] == overload_index]
    if len(candidates) != 1:
        raise GenerationError("메서드의 정확한 오버로드를 하나 선택해 주세요.")
    selected = candidates[0]
    target = _verified_target(apk, class_result["class_name"], method_name, selected["dex_descriptor"])
    identity = "\0".join((profile["package"], target["class_name"], method_name, target["dex_descriptor"]))
    identifier = hashlib.sha256(identity.encode("utf-8")).hexdigest()[:16]
    source_prefix = Path("app/src/main/java/com/example/wheelprobe")
    rels = [source_prefix / "ModuleMain.kt", source_prefix / profile["source_file"]]
    originals: dict[str, str] = {}
    snapshots: dict[str, bytes] = {}
    outputs: dict[str, bytes] = {}
    diffs: list[str] = []
    for relative in rels:
        check_cancelled()
        relative_name = relative.as_posix()
        path = (root / relative).resolve()
        if not path.is_relative_to(root) or not path.is_file():
            raise GenerationError(f"원본 프로젝트 안에서 {relative_name} 파일을 찾을 수 없습니다.")
        before = path.read_bytes()
        text, bom, newline = _source_text(before)
        if relative.name == "ModuleMain.kt":
            modified = _install_source(text, profile["startup_anchor"], identifier, newline)
        else:
            modified = _family_source(text, _observer_code(identifier, profile["package"], target, profile["family"]),
                                      identifier, newline, profile["family"])
        after = (b"\xef\xbb\xbf" if bom else b"") + modified.encode("utf-8")
        originals[relative_name] = hashlib.sha256(before).hexdigest()
        snapshots[relative_name] = before
        outputs[relative_name] = after
        diffs.extend(difflib.unified_diff(text.splitlines(keepends=True), modified.splitlines(keepends=True),
                                        fromfile="a/" + relative_name, tofile="b/" + relative_name))
    # Reject stale selections or source races before publishing a review bundle.
    if _sha(apk) != apk_sha or any((root / relative).read_bytes() != data for relative, data in snapshots.items()):
        raise GenerationError("분석 중 APK 또는 원본 코드가 변경되었습니다. 다시 실행해 주세요.")
    output_root = (app_dir() / "generated_hooks").resolve()
    if output_root.is_relative_to(root):
        raise GenerationError("출력 폴더는 원본 Android 프로젝트 밖에 있어야 합니다. L_APP_DATA_DIR을 변경해 주세요.")
    check_cancelled()
    output_root.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    staging = Path(tempfile.mkdtemp(prefix=".pending_", dir=output_root))
    bundle = output_root / f"{stamp}_{app_key}_{identifier}_{staging.name.removeprefix('.pending_')}"
    files: dict[str, str] = {}
    generated: dict[str, dict[str, str]] = {}
    try:
        for relative, data in outputs.items():
            check_cancelled()
            path = staging / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
            path.with_suffix(".txt").write_bytes(data)
            published = bundle / relative
            files[relative] = str(published)
            files[Path(relative).with_suffix(".txt").as_posix()] = str(published.with_suffix(".txt"))
            generated[relative] = {"path": str(published), "sha256": hashlib.sha256(data).hexdigest()}
        diff_path = bundle / "changes.diff"
        (staging / "changes.diff").write_bytes("".join(diffs).encode("utf-8"))
        report = {
            "profile": app_key, "package_name": profile["package"], "observer_id": identifier,
            "selected_method": {key: target[key] for key in ("class_name", "name", "dex_descriptor", "access_flags")},
            "build_status": "not_run", "runtime_status": "unverified", "observation_only": True,
            "shared_process_note": "설치 시 패키지를 제한합니다. 공유 프로세스에서 같은 메서드가 호출되면 다른 패키지의 호출도 관찰될 수 있습니다.",
        }
        manifest = dict(report, schema_version=1, project_root=str(root), originals=originals, generated=generated,
                        apk_sha256=apk_sha, apk_path=str(apk), evidence_ids={
                            "class": evidence.get("evidence_id"), "package": package.get("evidence_id")},
                        diff_path=str(diff_path))
        manifest_path = bundle / "manifest.json"
        (staging / "manifest.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        # Publish a complete bundle as one directory rename. A cancelled task
        # leaves neither partial code files nor a misleading manifest behind.
        if _sha(apk) != apk_sha or any((root / relative).read_bytes() != data for relative, data in snapshots.items()):
            raise GenerationError("출력 중 APK 또는 원본 코드가 변경되었습니다. 다시 실행해 주세요.")
        check_cancelled()
        staging.rename(bundle)
    finally:
        if staging.exists():
            shutil.rmtree(staging)
    return {"path": str(bundle), "manifest": str(manifest_path), "files": files, "diff": str(diff_path),
            "report": report, "build_status": "not_run"}

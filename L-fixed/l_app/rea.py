"""Local, read-only Android analysis through the pinned REA CLI.

REA's JSON Evidence is retained verbatim as data.  This module does not execute
the selected APK, call an AI service, install tools, or substitute another engine
when REA fails.
"""
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
import math
import os
from pathlib import Path
import re
import shutil
import subprocess
from typing import Callable
import uuid
import zipfile

from .paths import app_dir, atomic_write_text
from .processes import CancelledError, check_cancelled, run_process


REA_VERSION = "6.8.0"
JADX_VERSION = "0.7.1"
JADX_SHA256 = "6e5eacf500b64292bfb73c49797c1958f6ee44646e43e868039ae7feb573ff75"
JADX_REQUIRED_CLASSES = frozenset({
    "com/atxx/jhmcp/JadxSession.class",
    "com/atxx/jhmcp/SessionHolder.class",
    "jadx/api/JadxDecompiler.class",
    "com/google/gson/Gson.class",
    "io/modelcontextprotocol/kotlin/sdk/server/Server.class",
})
_PATH_KEYS = ("node_path", "rea_entry", "jar_path", "java_home")
_OPERATIONS = {
    "package": ("inspect-android-package", "inspect_android_package", "APK 패키지 분석"),
    "class_search": ("search-android-classes", "search_android_classes", "클래스 검색"),
    "class": ("inspect-android-class", "inspect_android_class", "클래스 멤버 분석"),
    "method": ("inspect-android-method", "inspect_android_method", "메서드 분석"),
    "references": ("trace-android-references", "trace_android_references", "참조 추적"),
}


class ReaAnalysisError(RuntimeError):
    """A failed invocation, optionally with retained local diagnostic output."""

    def __init__(self, message: str, raw_path: str = ""):
        self.raw_path = raw_path
        super().__init__(message + (f"\n진단 파일: {raw_path}" if raw_path else ""))


def _first_file(candidates: list[Path]) -> str:
    return next((str(path.resolve()) for path in candidates if path.is_file()), "")


def _defaults() -> dict:
    root = app_dir() / "tools" / "rea"
    exe = ".exe" if os.name == "nt" else ""
    node = _first_file([
        root / f"node{exe}", root / "node" / f"node{exe}",
        root / "node" / "bin" / f"node{exe}",
    ]) or shutil.which("node") or ""
    entries = [root / "node_modules" / "rea-agents" / "scripts" / "rea.mjs"]
    if os.environ.get("APPDATA"):
        entries.append(Path(os.environ["APPDATA"]) / "npm" / "node_modules" /
                       "rea-agents" / "scripts" / "rea.mjs")
    entry = _first_file(entries) or str(entries[0])
    return {
        "node_path": os.environ.get("L_REA_NODE", node),
        "rea_entry": os.environ.get("L_REA_ENTRY", entry),
        "jar_path": os.environ.get("REA_JADX_MCP_JAR", str(root / f"jadx-headless-mcp-{JADX_VERSION}-all.jar")),
        "java_home": os.environ.get("JAVA_HOME", ""),
        "timeout_seconds": 300,
    }


def _clean_settings(settings: dict) -> dict:
    if not isinstance(settings, dict):
        raise ValueError("REA 설정은 JSON 객체여야 합니다")
    cleaned = {}
    for key in _PATH_KEYS:
        value = settings.get(key, "")
        if not isinstance(value, str) or "\x00" in value or "\n" in value or "\r" in value:
            raise ValueError(f"REA {key}: 올바른 경로 문자열을 입력하세요")
        cleaned[key] = value.strip()
    timeout = settings.get("timeout_seconds", 300)
    if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or not 30 <= timeout <= 7200:
        raise ValueError("REA 제한 시간은 30~7200초 사이의 숫자여야 합니다")
    cleaned["timeout_seconds"] = timeout
    return cleaned


def load_rea_settings() -> dict:
    """Read paths only; safe to call from the GUI thread without spawning tools."""
    defaults = _defaults()
    path = app_dir() / "rea_settings.json"
    try:
        saved = json.loads(path.read_text(encoding="utf-8-sig"))
        cleaned = _clean_settings(saved)
    except FileNotFoundError:
        return defaults
    except (OSError, ValueError, TypeError, RecursionError) as error:
        return {**defaults, "_load_error": f"REA 설정 파일을 읽을 수 없습니다 ({path}): {error}"}
    return {**defaults, **{key: value for key, value in cleaned.items() if value != ""}}


def save_rea_settings(settings: dict) -> None:
    """Persist only the path/timeout settings, never an environment snapshot."""
    cleaned = _clean_settings(settings)
    atomic_write_text(app_dir() / "rea_settings.json",
                      json.dumps(cleaned, ensure_ascii=False, indent=2) + "\n")


def _resolve_settings(settings: dict | None) -> dict:
    loaded = load_rea_settings()
    if settings is None:
        values = loaded
    else:
        if not isinstance(settings, dict):
            raise ValueError("REA 설정은 객체여야 합니다")
        # Explicit settings from the dialog can repair a corrupt saved file.
        values = {**{k: v for k, v in loaded.items() if not k.startswith("_")}, **settings}
    cleaned = _clean_settings(values)
    defaults = _defaults()
    cleaned = {key: (value if value != "" else defaults[key]) for key, value in cleaned.items()}
    if values.get("_load_error"):
        cleaned["_load_error"] = str(values["_load_error"])
    for key in ("rea_entry", "jar_path", "java_home"):
        if cleaned[key]:
            cleaned[key] = str(Path(cleaned[key]).expanduser().resolve())
    node = cleaned["node_path"]
    if node:
        node = shutil.which(node) or node
        cleaned["node_path"] = str(Path(node).expanduser().resolve())
    return cleaned


def _digest(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            check_cancelled()
            digest.update(chunk)
    return digest.hexdigest()


def _runtime_env(settings: dict) -> dict:
    environment = os.environ.copy()
    environment["REA_JADX_MCP_JAR"] = settings["jar_path"]
    parts = [str(Path(settings["node_path"]).parent)]
    if settings["java_home"]:
        environment["JAVA_HOME"] = settings["java_home"]
        parts.append(str(Path(settings["java_home"]) / "bin"))
    else:
        environment.pop("JAVA_HOME", None)
    parts.append(environment.get("PATH", ""))
    environment["PATH"] = os.pathsep.join(parts)
    # Leave outer deadline headroom for bridge shutdown and CLI output delivery.
    environment["REA_JADX_OPERATION_TIMEOUT_MS"] = str(max(1000, int(settings["timeout_seconds"] * 1000) - 30000))
    return environment


def _supported_node(version: tuple[int, int, int]) -> bool:
    return ((version[0] == 22 and version >= (22, 23, 4)) or
            (version[0] == 24 and version >= (24, 22, 1)) or version >= (26, 12, 1))


def rea_preflight(settings: dict | None = None) -> dict:
    """Validate local CLI, compatible Node, audited headless JAR and full JDK.

    No network request or automatic installation is performed. Tool probes use
    the same cancellable process runner as analysis.
    """
    check_cancelled()
    try:
        resolved = _resolve_settings(settings)
    except (ValueError, OSError) as error:
        return {"ready": False, "status": "missing", "errors": [str(error)],
                "missing": [str(error)], "settings": {}, "resolved": {}, "versions": {}}
    errors = [resolved["_load_error"]] if resolved.get("_load_error") else []
    versions = {"required_rea": REA_VERSION, "required_jadx": JADX_VERSION}
    for key, label in (("node_path", "Node 실행 파일"), ("rea_entry", "REA 진입 파일"),
                       ("jar_path", "JADX headless MCP JAR")):
        if not resolved[key] or not Path(resolved[key]).is_file():
            errors.append(f"{label}을 찾을 수 없습니다: {resolved[key] or '(미설정)'}")
    node_ok = False
    env = _runtime_env(resolved)
    if resolved["node_path"] and Path(resolved["node_path"]).is_file():
        try:
            node = run_process([resolved["node_path"], "--version"], timeout=10, env=env)
            match = re.fullmatch(r"v?(\d+)\.(\d+)\.(\d+)\s*", node.stdout)
            if node.returncode or not match:
                errors.append("Node 버전 확인에 실패했습니다")
            else:
                version = tuple(map(int, match.groups()))
                versions["node"] = ".".join(match.groups())
                node_ok = _supported_node(version)
                if not node_ok:
                    errors.append("REA 6.8.0은 Node 22.23.4 이상(22.x), 24.22.1 이상(24.x), 또는 26.12.1 이상이 필요합니다")
        except CancelledError:
            raise
        except (OSError, subprocess.SubprocessError) as error:
            errors.append(f"Node 실행 실패: {error}")
    if node_ok and Path(resolved["rea_entry"]).is_file():
        try:
            cli = run_process([resolved["node_path"], resolved["rea_entry"], "--version"],
                              timeout=20, env=env)
            versions["rea"] = cli.stdout.strip()
            if cli.returncode or cli.stdout.strip() != REA_VERSION:
                errors.append(f"지원하는 REA 버전은 {REA_VERSION}입니다 (현재: {cli.stdout.strip()[:100] or '확인 실패'})")
        except CancelledError:
            raise
        except (OSError, subprocess.SubprocessError) as error:
            errors.append(f"REA 실행 실패: {error}")
    jar = Path(resolved["jar_path"])
    if jar.is_file():
        try:
            versions["jar_sha256"] = _digest(jar)
            if versions["jar_sha256"] != JADX_SHA256:
                errors.append(f"JAR SHA-256이 지원 버전과 다릅니다. jadx-headless-mcp {JADX_VERSION} 공식 all.jar가 필요합니다 (일반 JADX CLI JAR은 사용할 수 없습니다)")
            with zipfile.ZipFile(jar) as archive:
                missing = sorted(JADX_REQUIRED_CLASSES - set(archive.namelist()))
            if missing:
                errors.append("JADX headless MCP 필수 클래스 누락: " + ", ".join(missing))
        except CancelledError:
            raise
        except (OSError, zipfile.BadZipFile, RuntimeError) as error:
            errors.append(f"JAR 검사 실패: {error}")
    java = (str(Path(resolved["java_home"]) / "bin" / ("java.exe" if os.name == "nt" else "java"))
            if resolved["java_home"] else shutil.which("java", path=env["PATH"]) or "")
    if not java or not Path(java).is_file():
        errors.append("Java를 찾을 수 없습니다. java_home 또는 JAVA_HOME에 전체 JDK 경로를 지정하세요")
    else:
        java = str(Path(java).resolve())
        try:
            probe = run_process([java, "--list-modules"], timeout=10, env=env)
            modules = probe.stdout.splitlines()
            base = next((line.split("@", 1)[1] for line in modules if line.startswith("java.base@")), "")
            versions["java"] = base
            major = re.match(r"(\d+)(?:[.+_-]|$)", base)
            if probe.returncode or not major or not any(re.fullmatch(r"jdk\.compiler(?:@.*)?", line) for line in modules):
                errors.append("Java에 jdk.compiler가 없습니다. JRE 대신 전체 JDK가 필요합니다 (java --list-modules 확인)")
            elif int(major.group(1)) < 17:
                errors.append("REA Android 분석에는 jdk.compiler가 포함된 JDK 17 이상이 필요합니다")
        except CancelledError:
            raise
        except (OSError, subprocess.SubprocessError) as error:
            errors.append(f"JDK 확인 실패: {error}")
    check_cancelled()
    return {"ready": not errors, "status": "ready" if not errors else "missing", "errors": errors,
            "missing": errors[:], "settings": resolved, "resolved": {**resolved, "java_path": java},
            "versions": versions}


def _arguments(apk: Path, operation: str, query: str, class_name: str,
               method_name: str, overload_index: int | None) -> tuple[list[str], dict]:
    if not isinstance(operation, str) or operation not in _OPERATIONS:
        raise ValueError(f"지원하지 않는 REA 작업: {operation}")
    for key, value in (("query", query), ("class_name", class_name), ("method_name", method_name)):
        if not isinstance(value, str) or "\x00" in value or "\n" in value or "\r" in value:
            raise ValueError(f"{key}: 올바른 문자열을 입력하세요")
    if overload_index is not None and (isinstance(overload_index, bool) or not isinstance(overload_index, int) or overload_index < 0):
        raise ValueError("오버로드 번호는 0 이상의 정수여야 합니다")
    if operation in ("class", "method", "references") and not class_name.strip():
        raise ValueError("정확한 전체 클래스 이름이 필요합니다")
    if operation == "method" and not method_name.strip():
        raise ValueError("정확한 메서드 이름이 필요합니다")
    if overload_index is not None and (operation not in ("method", "references") or not method_name.strip()):
        raise ValueError("오버로드 번호는 메서드 이름과 함께 지정하세요")
    arguments = [_OPERATIONS[operation][0], str(apk)]
    parameters = {"path": str(apk)}
    if operation == "class_search":
        arguments.append(query)
        parameters["query"] = query
    if operation in ("class", "method", "references"):
        arguments.append(class_name)
        parameters["class_name"] = class_name
    if operation == "method":
        arguments.append(method_name)
        parameters["method_name"] = method_name
    if operation == "references" and method_name:
        arguments.extend(["--methodName", method_name])
        parameters["method_name"] = method_name
    if overload_index is not None:
        arguments.extend(["--overloadIndex", str(overload_index)])
        parameters["overload_index"] = overload_index
    return arguments + ["--format", "json", "--full-output"], parameters


def _error_message(document: object) -> str:
    if not isinstance(document, dict):
        return ""
    error = document.get("error", document)
    if not isinstance(error, dict):
        return str(error)[:1500] if error else ""
    message = error.get("message")
    if not isinstance(message, str):
        return ""
    code = error.get("code")
    remediation = error.get("remediation")
    action = remediation.get("action", "") if isinstance(remediation, dict) else ""
    return f"{code + ': ' if isinstance(code, str) else ''}{message}" + (f"\n{action}" if action else "")


def _parse_cli_json(text: str) -> object:
    def pairs(items: list[tuple[str, object]]) -> dict:
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError(f"중복 JSON 키: {key}")
            result[key] = value
        return result
    def constant(value: str) -> None:
        raise ValueError(f"잘못된 JSON 상수: {value}")
    def number(value: str) -> float:
        parsed = float(value)
        if not math.isfinite(parsed):
            raise ValueError("JSON 숫자 범위를 초과했습니다")
        return parsed
    return json.loads(text, object_pairs_hook=pairs, parse_constant=constant, parse_float=number)


def _validate_evidence(document: object, operation: str, parameters: dict, digest: str) -> dict:
    if not isinstance(document, dict):
        raise ValueError("REA 결과가 JSON 객체가 아닙니다")
    if document.get("ok") is False or "error" in document:
        raise ValueError(_error_message(document) or "REA가 실패 결과를 반환했습니다")
    evidence = document.get("data") if document.get("ok") is True else document
    if not isinstance(evidence, dict) or evidence.get("predicate_type") != "rea.analysis":
        raise ValueError(_error_message(document) or "REA Evidence 형식이 아닙니다")
    if evidence.get("operation") != _OPERATIONS[operation][1]:
        raise ValueError("REA 결과의 작업 종류가 요청과 다릅니다")
    if not isinstance(evidence.get("evidence_id"), str) or not evidence["evidence_id"].startswith("ev_"):
        raise ValueError("REA Evidence 식별자가 없습니다")
    provider = evidence.get("provider")
    if (not isinstance(provider, dict) or provider.get("id") != "jadx" or
            not isinstance(provider.get("name"), str) or not provider["name"]):
        raise ValueError("REA 결과에 분석 제공자 정보가 없습니다")
    subject = evidence.get("subject")
    if (not isinstance(subject, dict) or subject.get("format") != "apk" or
            not isinstance(subject.get("digest"), dict) or subject["digest"].get("sha256") != digest):
        raise ValueError("REA 결과 APK SHA-256이 선택한 파일과 다릅니다")
    if evidence.get("parameters") != parameters:
        raise ValueError("REA 결과의 입력 조건이 요청과 다릅니다")
    result = evidence.get("normalized_result")
    if not isinstance(result, dict) or not isinstance(result.get("engine"), dict):
        raise ValueError("REA 정규화 결과 또는 엔진 정보가 없습니다")
    engine = result["engine"]
    if (engine.get("name") != "jadx-headless-mcp" or engine.get("version") != JADX_VERSION or
            engine.get("artifact_sha256") != JADX_SHA256):
        raise ValueError("REA 결과의 JADX 엔진 식별 정보가 지원 JAR과 다릅니다")
    required = {
        "package": {"package_name": (str, type(None)), "permissions": list, "manifest": dict,
                    "components": dict, "class_count": int, "resource_count": int},
        "class_search": {"query": str, "total_classes": int, "matches": list, "coverage": str},
        "class": {"class_name": str, "methods": list, "fields": list, "inner_classes": list},
        "method": {"class_name": str, "method": dict, "source": dict, "representation": str,
                   "body_status": str, "overload_count": int},
        "references": {"class_name": str, "references": list, "total": int, "coverage": str,
                       "reference_unit": str},
    }[operation]
    if any(key not in result or not isinstance(result[key], kind) or isinstance(result[key], bool)
           for key, kind in required.items()):
        raise ValueError("REA 정규화 결과의 필수 필드가 누락되었거나 잘못되었습니다")
    if not isinstance(evidence.get("limitations"), list) or not all(isinstance(item, str) for item in evidence["limitations"]):
        raise ValueError("REA Evidence의 분석 한계 필드가 잘못되었습니다")
    if evidence.get("confidence") not in ("observed", "derived", "inferred") or "raw_result" not in evidence:
        raise ValueError("REA Evidence의 신뢰도 또는 원본 결과 필드가 없습니다")
    for key in (("manifest",) if operation == "package" else ("source",) if operation == "method" else ()):
        text = result[key]
        if text.get("status") not in ("complete", "partial") or not isinstance(text.get("text"), str):
            raise ValueError(f"REA {key}의 텍스트 범위 정보가 잘못되었습니다")
    if operation == "class_search" and not all(isinstance(name, str) for name in result["matches"]):
        raise ValueError("REA 클래스 검색 결과가 잘못되었습니다")
    if operation == "package":
        components = result["components"]
        if (not all(isinstance(item, str) for item in result["permissions"]) or
                components.get("status") not in ("complete", "partial", "unavailable") or
                not isinstance(components.get("items"), list) or
                not all(isinstance(item, dict) for item in components["items"]) or
                not isinstance(components.get("limitations"), list) or
                not all(isinstance(item, str) for item in components["limitations"]) or
                result["class_count"] < 0 or result["resource_count"] < 0):
            raise ValueError("REA 패키지 권한·컴포넌트 목록 또는 개수가 잘못되었습니다")
    if operation == "class":
        if (not all(isinstance(item, dict) for item in result["methods"] + result["fields"]) or
                not all(isinstance(item, str) for item in result["inner_classes"])):
            raise ValueError("REA 클래스 멤버 목록이 잘못되었습니다")
    if operation == "class_search":
        duplicates = result.get("duplicate_names")
        if (result["query"] != parameters["query"] or result["total_classes"] < 0 or
                result["coverage"] != "complete" or not isinstance(duplicates, list) or
                not all(isinstance(item, dict) for item in duplicates)):
            raise ValueError("REA 클래스 검색 범위 정보가 잘못되었습니다")
    if operation == "method":
        if (result["representation"] not in ("java", "smali") or
                result["body_status"] not in ("available", "not_available") or
                result["overload_count"] <= 0 or not isinstance(result.get("markers"), list) or
                not all(isinstance(item, str) for item in result["markers"])):
            raise ValueError("REA 메서드 범위 정보가 잘못되었습니다")
    if operation == "references":
        if (not all(isinstance(item, dict) for item in result["references"]) or
                result["total"] != len(result["references"]) or result["coverage"] != "complete" or
                result["reference_unit"] != "using_node"):
            raise ValueError("REA 참조 범위 또는 목록이 잘못되었습니다")
    return evidence


def _result_status(result: dict) -> str:
    for key in ("manifest", "components", "source"):
        if isinstance(result.get(key), dict) and result[key].get("status") in ("partial", "unavailable"):
            return "partial"
    if result.get("body_status") == "not_available" or result.get("coverage") in ("partial", "unavailable"):
        return "partial"
    return "complete"


def _report(operation: str, evidence: dict, raw_path: Path, stderr_path: str) -> str:
    result = evidence["normalized_result"]
    status = _result_status(result)
    engine = result["engine"]
    lines = [f"REA {_OPERATIONS[operation][2]} — {'완료' if status == 'complete' else '일부 결과'}",
             f"파일: {evidence['subject'].get('name', '')}",
             f"APK SHA-256: {evidence['subject']['digest']['sha256']}",
             f"엔진: {engine['name']} {engine.get('version') or ''}".rstrip(), ""]
    def listing(title: str, rows: list, limit: int = 250) -> None:
        lines.append(f"{title} ({len(rows)}개)")
        lines.extend(f"  {row}" for row in rows[:limit])
        if len(rows) > limit:
            lines.append(f"  … 화면에는 {limit}개만 표시합니다. 전체 목록은 JSON에 저장되어 있습니다.")
    if operation == "package":
        lines.extend([f"패키지: {result.get('package_name') or '(확인 불가)'}",
                      f"버전: {result.get('version_name') or '?'} (code {result.get('version_code') or '?'})",
                      f"SDK: 최소 {result.get('min_sdk') or '?'} / 대상 {result.get('target_sdk') or '?'}",
                      f"클래스 {result['class_count']}개 / 리소스 {result['resource_count']}개", ""])
        listing("선언 권한", result["permissions"])
        components = result["components"]
        listing(f"Manifest 컴포넌트 [{components.get('status', 'unavailable')}]",
                [f"{item.get('kind', '?')}: {item.get('name', '?')} (exported={item.get('exported')})"
                 for item in components.get("items", []) if isinstance(item, dict)])
        lines.append(f"Manifest 범위: {result['manifest']['status']} / 서명 검증: 수행하지 않음")
        lines.extend(components.get("limitations", []))
    elif operation == "class_search":
        lines.extend([f"검색어: {result['query']!r} (대소문자 구분)", f"검사한 클래스: {result['total_classes']}개"])
        listing("일치한 클래스", result["matches"])
        duplicates = result.get("duplicate_names", [])
        if duplicates:
            listing("중복 클래스 이름", [f"{item.get('name')}: {item.get('occurrences')}개" for item in duplicates])
    elif operation == "class":
        lines.append(f"클래스: {result['class_name']}")
        listing("메서드", [f"[{item.get('overload_index', '?')}] {item.get('reported_signature', '?')}  DEX: {item.get('dex_descriptor', '?')}"
                           for item in result["methods"] if isinstance(item, dict)])
        listing("필드", [f"{item.get('reported_type', '?')} {item.get('name', '?')}"
                       for item in result["fields"] if isinstance(item, dict)])
        listing("내부 클래스", result["inner_classes"])
    elif operation == "method":
        method = result["method"]
        lines.extend([f"클래스: {result['class_name']}",
                      f"메서드: [{method.get('overload_index', '?')}] {method.get('reported_signature', '?')}",
                      f"DEX: {method.get('dex_descriptor', '?')} / 동일 이름 {result['overload_count']}개",
                      f"표현: {result['representation']} / 본문: {result['body_status']} / 범위: {result['source']['status']}", ""])
        text = result["source"]["text"]
        lines.append(text[:80000])
        if len(text) > 80000:
            lines.append("… 화면 표시를 줄였습니다. 전체 본문은 JSON에 저장되어 있습니다.")
        lines.extend(result.get("markers", []))
    else:
        lines.extend([f"대상: {result['class_name']}" + (f".{result['method_name']}" if result.get("method_name") else ""),
                      f"참조 using node: {result['total']}개 / 범위: {result['coverage']}"])
        listing("참조 위치", [f"{item.get('reported_full_name') or item.get('name', '?')} ({item.get('kind', '?')})"
                              for item in result["references"] if isinstance(item, dict)])
        lines.append("using node 목록은 실제 실행 순서나 동적 호출·리플렉션 전체를 보장하지 않습니다.")
    lines.extend(["", "분석 한계", "  APK를 실행하지 않은 정적 분석입니다. 실제 동작과 런타임 훅 설치 여부는 별도 확인이 필요합니다."])
    lines.extend(f"  {item}" for item in evidence["limitations"])
    lines.extend(["", f"전체 Evidence JSON: {raw_path}"])
    if stderr_path:
        lines.append(f"도구 stderr: {stderr_path}")
    return "\n".join(lines)


def _retain(operation: str, digest: str, document: object, *, failed: bool = False,
            stderr: str = "") -> tuple[Path, str]:
    check_cancelled()
    folder = app_dir() / "rea_results"
    folder.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")
    stem = f"{operation}_{digest[:16]}_{stamp}_{uuid.uuid4().hex[:8]}" + ("_failed" if failed else "")
    path = folder / (stem + ".json")
    stderr_path = ""
    if stderr:
        output = folder / (stem + ".stderr.txt")
        atomic_write_text(output, stderr)
        stderr_path = str(output)
    atomic_write_text(path, json.dumps(document, ensure_ascii=False, indent=2, allow_nan=False) + "\n")
    return path, stderr_path


def run_rea_analysis(apk_path: Path, *, settings: dict | None = None, operation: str = "package",
                     query: str = "", class_name: str = "", method_name: str = "",
                     overload_index: int | None = None,
                     progress: Callable[[str], None] | None = None) -> dict:
    """Run exactly one REA operation and retain the complete CLI JSON locally."""
    check_cancelled()
    apk = Path(apk_path).expanduser().resolve()
    arguments, parameters = _arguments(apk, operation, query, class_name, method_name, overload_index)
    if not apk.is_file() or apk.suffix.lower() != ".apk":
        raise ValueError("분석할 로컬 .apk 파일을 선택하세요")
    try:
        with zipfile.ZipFile(apk) as archive:
            archive.getinfo("AndroidManifest.xml")
    except (OSError, KeyError, zipfile.BadZipFile) as error:
        raise ValueError("AndroidManifest.xml을 포함한 정상 APK ZIP 파일이 필요합니다") from error
    if progress:
        progress("REA 도구 및 Java 환경 확인 중…")
    preflight = rea_preflight(settings)
    if not preflight["ready"]:
        raise ReaAnalysisError("REA 환경 설정을 확인하세요:\n" + "\n".join(preflight["errors"]))
    resolved = preflight["settings"]
    digest = _digest(apk)
    command = [resolved["node_path"], resolved["rea_entry"], *arguments]
    if progress:
        progress(f"REA {_OPERATIONS[operation][2]} 실행 중…")
    stdout = stderr = ""
    returncode = None
    document = None
    try:
        completed = run_process(command, timeout=resolved["timeout_seconds"], cwd=str(apk.parent),
                                env=_runtime_env(resolved))
        check_cancelled()
        stdout, stderr, returncode = completed.stdout, completed.stderr, completed.returncode
        try:
            document = _parse_cli_json(stdout)
        except (ValueError, RecursionError) as error:
            raise ValueError("REA stdout가 완전한 JSON 문서가 아닙니다") from error
        if returncode:
            raise ValueError(f"REA 종료 코드 {returncode}: " + (_error_message(document) or "도구 stderr를 확인하세요"))
        evidence = _validate_evidence(document, operation, parameters, digest)
        if _digest(apk) != digest:
            raise ValueError("분석 중 원본 APK가 변경되었습니다. 파일을 다시 선택해 분석하세요")
        raw_path, stderr_path = _retain(operation, digest, document, stderr=stderr)
        check_cancelled()
        report = _report(operation, evidence, raw_path, stderr_path)
    except CancelledError:
        raise
    except (OSError, ValueError, TypeError, KeyError, subprocess.SubprocessError, RecursionError) as error:
        diagnostic = {"status": "failed", "operation": operation, "apk_sha256": digest,
                      "reason": str(error), "returncode": returncode, "stdout": stdout,
                      "parsed_document": document}
        if isinstance(error, subprocess.TimeoutExpired):
            diagnostic["reason"] = f"REA 제한 시간 {resolved['timeout_seconds']}초를 초과했습니다"
        try:
            diagnostic_path, _ = _retain(operation, digest, diagnostic, failed=True, stderr=stderr)
        except OSError as storage_error:
            raise ReaAnalysisError(f"{diagnostic['reason']}\n진단 파일 저장 실패: {storage_error}") from error
        raise ReaAnalysisError(diagnostic["reason"], str(diagnostic_path)) from error
    if progress:
        progress("REA 분석 결과와 전체 Evidence JSON을 저장했습니다")
    return {"operation": operation, "status": _result_status(evidence["normalized_result"]),
            "report": report, "evidence": evidence, "raw_path": str(raw_path),
            "stderr_path": stderr_path, "settings_status": preflight}

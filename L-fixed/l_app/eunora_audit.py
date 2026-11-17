"""Read-only EUNORA-oriented orchestration over the existing REA adapter."""
from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path, PurePosixPath, PureWindowsPath
import re
import uuid
import zipfile

from .generator import GenerationError, _Dex, load_profiles
from .paths import app_dir, atomic_write_text
from .processes import CancelledError, check_cancelled
from .rea import run_rea_analysis
from .source_catalog import collect_source_catalog


MAX_DETAIL_CLASSES = 24


class EunoraAuditError(RuntimeError):
    """The inputs cannot support a stable EUNORA comparison."""


class _StaleAuditInput(EunoraAuditError):
    pass


def _digest(path: Path) -> str:
    check_cancelled()
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            check_cancelled()
            value.update(block)
    return value.hexdigest()


def _bound_result(result: dict, digest: str, operation: str) -> dict:
    if not isinstance(result, dict) or result.get("status") not in {"complete", "partial"} or result.get("operation") != operation:
        raise EunoraAuditError("REA가 유효한 분석 결과를 반환하지 않았습니다")
    evidence = result.get("evidence")
    if not isinstance(evidence, dict) or evidence.get("subject", {}).get("digest", {}).get("sha256") != digest:
        raise _StaleAuditInput("점검 중 APK가 바뀌었거나 다른 APK의 분석 결과가 반환되었습니다")
    normalized = evidence.get("normalized_result")
    if not isinstance(normalized, dict):
        raise EunoraAuditError("REA 정규화 결과가 없습니다")
    return normalized


def _source_path(root: Path, name: str) -> Path:
    if not isinstance(name, str) or not name or "\\" in name:
        raise EunoraAuditError("원본 코드 기록의 상대 경로를 확인할 수 없습니다")
    relative = PurePosixPath(name)
    if relative.is_absolute() or PureWindowsPath(name).drive or any(part in {"", ".", ".."} for part in name.split("/")):
        raise EunoraAuditError("원본 코드 기록이 프로젝트 밖을 가리킵니다")
    source = (root / Path(*relative.parts)).resolve()
    if not source.is_relative_to(root) or not source.is_file():
        raise EunoraAuditError(f"원본 프로젝트 안에서 파일을 찾을 수 없습니다: {name}")
    return source


def _check_sources(root: Path, sources: dict) -> None:
    if not isinstance(sources, dict) or not sources:
        raise EunoraAuditError("EUNORA 원본 코드 기록이 없습니다")
    for name, expected in sources.items():
        if _digest(_source_path(root, name)) != expected:
            raise EunoraAuditError(f"점검 중 원본 코드가 변경되었습니다. 다시 점검하세요: {name}")


def _declared_classes(apk: Path) -> Counter:
    """Resolve display aliases against real declarations, never DEX string hits."""
    result = Counter()
    try:
        with zipfile.ZipFile(apk) as archive:
            files = [item for item in archive.infolist() if re.fullmatch(r"classes(?:[0-9]+)?\.dex", item.filename)]
            if not files or len({item.filename for item in files}) != len(files):
                raise EunoraAuditError("APK에서 고유한 DEX 선언 파일을 확인할 수 없습니다")
            if any(item.file_size > 256 * 1024 * 1024 for item in files) or sum(item.file_size for item in files) > 512 * 1024 * 1024:
                raise EunoraAuditError("DEX 선언 크기가 분석 한도를 넘습니다")
            for item in files:
                check_cancelled()
                for binary, _ in _Dex(archive.read(item)).classes():
                    result[binary] += 1
    except CancelledError:
        raise
    except (GenerationError, OSError, zipfile.BadZipFile, RuntimeError) as error:
        if isinstance(error, EunoraAuditError):
            raise
        raise EunoraAuditError(f"APK의 실제 클래스 선언을 읽을 수 없습니다: {error}") from error
    return result


def _display_matches(binary: str, display: str) -> bool:
    if binary == display:
        return True
    shown = display.removeprefix("defpackage.")
    return binary == shown or binary.replace("$", ".") == shown


def _resolve_class(name: str, inventory: list[str], duplicates: set[str], declared: Counter) -> tuple[str | None, str]:
    if declared[name] != 1:
        if declared[name] > 1:
            return None, "실제 DEX에 같은 이름의 클래스가 여러 개 선언돼 있습니다"
        return None, "선택 APK의 실제 DEX 선언에서 원본 클래스 이름을 찾지 못했습니다"
    candidates = [item for item in inventory if _display_matches(name, item)]
    if len(candidates) != 1 or candidates[0] in duplicates:
        return None, "REA 표시 이름을 실제 클래스에 하나로 연결할 수 없습니다"
    # The selected display name must not also describe another declared owner.
    display = candidates[0]
    owners = [binary for binary in declared if _display_matches(binary, display)]
    if len(owners) != 1 or owners[0] != name:
        return None, "REA 클래스 별칭이 여러 실제 클래스와 겹칩니다"
    return display, "" if display == name else f"실제 DEX 선언에 연결된 표시 별칭: {display}"


_LABELS = {
    "class_found": "클래스 확인", "method_name_found": "메서드 이름 확인",
    "not_found": "선택 APK에서 미발견", "needs_review": "추가 확인 필요",
    "error": "분석 실패", "deferred": "상세 검사 보류",
}


def _report(profile: dict, root: Path, apk: Path, catalog: dict, rows: list, counts: dict,
            notes: list[str], status: str) -> str:
    lines = [f"EUNORA 자동 점검 — {'완료' if status == 'complete' else '일부 결과·확인 필요'}",
             f"앱: {profile['label']} ({profile['package']})", f"APK: {apk}", f"프로젝트: {root}",
             f"선택 E파일: {profile['source_file']}", "",
             f"원본에서 읽은 클래스 대상 {len(rows)}개 / 상세 분석 {counts['detail_completed']}개",
             "정확한 원형·인자 타입·필드 구조·실제 훅 등록/실행은 이 점검으로 확인되지 않습니다.",
             "미발견은 선택 APK의 선언 목록 기준이며 split APK·플랫폼·동적 로딩 전체를 뜻하지 않습니다.", ""]
    for row in rows:
        check_cancelled()
        lines.append(f"[{_LABELS[row['status']]}] {row['class_name']}")
        if row.get("resolved_class") and row["resolved_class"] != row["class_name"]:
            lines.append(f"  REA 표시: {row['resolved_class']}")
        for item in row.get("method_checks", []):
            count = item["matching_overloads"]
            lines.append(f"  {item['name']}: " + (f"이름 일치 {count}개 (원형 미검증)" if count else "직접 선언 목록에서 미발견 (상속 여부 별도 확인)"))
        if row.get("note"):
            lines.append("  " + row["note"])
        locations = row.get("locations", [])
        if locations:
            lines.append("  원본: " + ", ".join(f"{loc['file']}:{loc['line']}" for loc in locations[:4]))
    unresolved = catalog.get("unresolved", [])
    lines.extend(["", f"동적 표현·불명확한 원본 대상 {len(unresolved)}개는 자동 판정하지 않았습니다."])
    for item in unresolved[:30]:
        lines.append(f"  {item.get('file', '?')}:{item.get('line', '?')} — {item.get('reason', '확인 필요')}")
    if len(unresolved) > 30:
        lines.append("  나머지 원본 대상은 점검 JSON에 저장했습니다.")
    lines.extend(["", "점검 범위"])
    lines.extend("  " + str(note) for note in catalog.get("report_notes", []))
    lines.extend("  " + note for note in notes)
    return "\n".join(lines)


def run_eunora_audit(apk_path, project_path, *, settings=None, progress=None) -> dict:
    """Discover the app and compare its existing source targets in one worker."""
    check_cancelled()
    apk = Path(apk_path).expanduser().resolve()
    if not apk.is_file() or apk.suffix.lower() != ".apk":
        raise EunoraAuditError("분석할 APK 파일을 선택하세요")
    digest = _digest(apk)
    if progress:
        progress("EUNORA 점검: APK 앱 종류 확인 중…")
    package_result = run_rea_analysis(apk, settings=settings, operation="package", progress=progress)
    package = _bound_result(package_result, digest, "package")
    profiles = load_profiles()
    app_keys = [key for key, value in profiles.items() if value["package"] == package.get("package_name")]
    if len(app_keys) != 1:
        raise EunoraAuditError("현재 7개 EUNORA 앱 프로필에 해당하는 APK가 아닙니다")
    app_key = app_keys[0]
    profile = profiles[app_key]
    if progress:
        progress(f"EUNORA 점검: {profile['label']} · {profile['source_file']} 원본 읽는 중…")
    catalog = collect_source_catalog(project_path, app_key)
    root = Path(catalog["project_root"]).resolve()
    sources = dict(catalog["source_files"])
    _check_sources(root, sources)
    inventory_result = run_rea_analysis(apk, settings=settings, operation="class_search", query="", progress=progress)
    inventory = _bound_result(inventory_result, digest, "class_search")
    names = inventory.get("matches")
    duplicate_items = inventory.get("duplicate_names", [])
    if inventory.get("coverage") != "complete" or not isinstance(names, list) or not all(isinstance(name, str) for name in names):
        raise EunoraAuditError("완전한 APK 클래스 목록이 없어 자동 대조를 진행할 수 없습니다")
    duplicates = {item.get("name") for item in duplicate_items if isinstance(item, dict)}
    names = list(dict.fromkeys(names))
    declared = _declared_classes(apk)
    rows, class_results, notes = [], [], []
    attempts = 0
    for target in catalog.get("targets", []):
        check_cancelled()
        name = target["class_name"]
        row = {"class_name": name, "resolved_class": None, "status": "needs_review",
               "methods": list(target.get("methods", [])), "method_checks": [],
               "locations": target.get("locations", []), "note": ""}
        resolved, note = _resolve_class(name, names, duplicates, declared)
        row["resolved_class"], row["note"] = resolved, note
        if resolved is None:
            row["status"] = "not_found" if not declared[name] else "needs_review"
        elif attempts >= MAX_DETAIL_CLASSES:
            row["status"] = "deferred"
            row["note"] = f"한 번에 상세 분석하는 클래스는 {MAX_DETAIL_CLASSES}개입니다. 클래스 선언 존재만 확인했습니다."
        else:
            attempts += 1
            if progress:
                progress(f"EUNORA 점검: 기존 대상 상세 확인 {attempts}/{min(MAX_DETAIL_CLASSES, len(catalog['targets']))} — {name}")
            try:
                result = run_rea_analysis(apk, settings=settings, operation="class", class_name=resolved, progress=progress)
                normalized = _bound_result(result, digest, "class")
                if normalized.get("class_name") != resolved or not isinstance(normalized.get("methods"), list):
                    raise EunoraAuditError("REA 클래스 상세 결과가 요청과 다릅니다")
                methods = Counter(item.get("name") for item in normalized["methods"] if isinstance(item, dict))
                row["method_checks"] = [{"name": method, "matching_overloads": methods[method]} for method in row["methods"]]
                row["status"] = "method_name_found" if row["methods"] else "class_found"
                if any(not item["matching_overloads"] for item in row["method_checks"]):
                    row["status"] = "needs_review"
                    row["note"] += (" / " if row["note"] else "") + "일부 메서드 이름이 직접 선언 목록에 없습니다. 상속·업데이트 여부를 확인하세요."
                class_results.append({**result, "target": target})
                if result.get("status") == "partial":
                    row["status"] = "needs_review"
                    row["note"] += " REA 상세 결과가 일부 범위입니다."
            except CancelledError:
                raise
            except _StaleAuditInput:
                # A different APK or malformed result cannot be aggregated as
                # a merely unavailable class and used for code generation.
                raise
            except Exception as error:
                row["status"] = "error"
                row["note"] = str(error)
        rows.append(row)
    check_cancelled()
    if _digest(apk) != digest:
        raise EunoraAuditError("점검 중 APK가 변경되었습니다. 다시 점검하세요")
    _check_sources(root, sources)
    counts = dict(Counter(row["status"] for row in rows))
    counts.update(total=len(rows), detail_attempted=attempts, detail_completed=len(class_results),
                  unresolved=len(catalog.get("unresolved", [])))
    status = "partial" if (not rows or counts["unresolved"] or any(row["status"] in {"not_found", "needs_review", "error", "deferred"} for row in rows)
                           or package_result.get("status") == "partial") else "complete"
    notes.append(f"상세 분석은 최대 {MAX_DETAIL_CLASSES}개이며 나머지는 보류로 표시합니다.")
    notes.append("클래스·메서드 이름 확인은 원형 호환성이나 수락 로직의 정확성을 보장하지 않습니다.")
    report = _report(profile, root, apk, catalog, rows, counts, notes, status)
    folder = app_dir() / "eunora_audits"
    folder.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")
    output = folder / f"audit_{app_key}_{digest[:16]}_{stamp}_{uuid.uuid4().hex[:8]}.json"
    report_path = output.with_suffix(".txt")
    result = {"status": status, "report": report, "app_key": app_key, "apk_path": str(apk),
              "project_root": str(root), "apk_digest": digest, "source_files": sources,
              "package_result": package_result, "inventory_result": inventory_result,
              "class_results": class_results, "rows": rows, "counts": counts,
              "catalog": catalog, "report_path": str(report_path), "json_path": str(output)}
    atomic_write_text(output, json.dumps(result, ensure_ascii=False, indent=2, allow_nan=False) + "\n")
    check_cancelled()
    atomic_write_text(report_path, report + "\n")
    return result

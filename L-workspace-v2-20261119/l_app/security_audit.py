"""Bind APK security-test candidates to exact REA/DEX targets for EUNORA.

Finding a marker is a candidate, not proof of a check's meaning or coverage.
This worker only reads inputs and creates local reports. Code generation is a
separate operation over the saved, verified evidence.
"""
from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
import json
from pathlib import Path
import uuid

from .eunora_audit import (
    EunoraAuditError, _StaleAuditInput, _bound_result, _check_sources,
    _declared_classes, _digest, _resolve_class,
)
from .generator import GenerationError, _parse_descriptor, _verified_target, load_profiles
from .paths import app_dir, atomic_write_text
from .processes import CancelledError, check_cancelled
from .rea import run_rea_analysis
from .source_catalog import collect_source_catalog


MAX_DETAIL_CLASSES = 12
MAX_CANDIDATE_ROWS = 512
MAX_CHOICES = 120
_MODES = {"observe", "boolean_false", "skip_void"}
_INTEGRITY = {"integrity", "attestation", "play_integrity"}
_CATEGORY_LABELS = {
    "root_files": "root·su·Magisk 파일", "root_commands": "root 관련 명령",
    "root_packages": "root 관련 설치 앱", "hook_framework": "후킹 프레임워크",
    "hook_stack": "실행 스택", "hook_memory": "메모리·매핑", "integrity": "무결성·증명",
}
_STATUS_LABELS = {
    "ready": "정확한 대상 확인", "needs_review": "추가 확인",
    "unsupported": "현재 생성 범위 밖", "error": "분석 오류", "deferred": "상세 분석 보류",
}


class SecurityAuditError(EunoraAuditError):
    pass


def scan_security_candidates(apk_path, *, progress=None):
    # Keep the orchestration importable while optional UI code loads. A missing
    # scanner is an explicit ImportError at execution, never an empty success.
    from .security_scan import scan_security_candidates as scan
    return scan(apk_path, progress=progress)


def _candidate(value):
    if not isinstance(value, dict):
        raise SecurityAuditError("보안 후보 기록이 JSON 객체가 아닙니다")
    for name in ("id", "class_name", "method_name", "dex_descriptor"):
        if not isinstance(value.get(name), str) or not value[name]:
            raise SecurityAuditError(f"보안 후보의 {name} 정보가 없습니다")
    _parse_descriptor(value["dex_descriptor"])
    flags = value.get("access_flags")
    if not isinstance(flags, int) or isinstance(flags, bool) or flags < 0:
        raise SecurityAuditError("보안 후보의 DEX 접근 플래그가 잘못되었습니다")
    for name in ("categories", "signals", "modes"):
        if not isinstance(value.get(name), list) or not all(isinstance(item, str) for item in value[name]):
            raise SecurityAuditError(f"보안 후보의 {name} 목록이 잘못되었습니다")
    return value


def _allowed_modes(candidate, target):
    _, result = _parse_descriptor(target["dex_descriptor"])
    modes = [mode for mode in ("observe", "boolean_false", "skip_void") if mode in candidate["modes"]]
    no_changes = (_INTEGRITY.intersection(candidate["categories"]) or
                  target["name"] in {"<init>", "<clinit>"} or target["access_flags"] & (0x100 | 0x400))
    if result != "Z" or no_changes:
        modes = [mode for mode in modes if mode != "boolean_false"]
    if result != "V" or no_changes:
        modes = [mode for mode in modes if mode != "skip_void"]
    return modes


def _priority(candidate):
    metadata = {"name": candidate["method_name"], "dex_descriptor": candidate["dex_descriptor"],
                "access_flags": candidate["access_flags"]}
    changes = {"boolean_false", "skip_void"}.intersection(_allowed_modes(candidate, metadata))
    return (not changes, bool(_INTEGRITY.intersection(candidate["categories"])))


def _class_detail(apk, digest, display, settings, progress):
    result = run_rea_analysis(apk, settings=settings, operation="class", class_name=display, progress=progress)
    normalized = _bound_result(result, digest, "class")
    if normalized.get("class_name") != display or not isinstance(normalized.get("methods"), list):
        raise SecurityAuditError("REA 클래스 상세 정보가 요청한 보안 대상과 다릅니다")
    return result, normalized


def _make_report(profile, apk, root, rows, choices, scan, counts, status):
    lines = [f"EUNORA 보안 자동 점검 — {'완료' if status == 'complete' else '일부 결과·확인 필요'}",
             f"앱: {profile['label']} ({profile['package']})", f"APK: {apk}",
             f"프로젝트: {root}", f"생성 대상 E파일: {profile['source_file']}", "",
             f"스캔 후보 {counts['scan_candidates_total']}개 중 반환 {counts['scan_candidates']}개 / 상세 클래스 {counts['detail_completed']}개 / 선택 가능한 메서드 {len(choices)}개",
             "보안 문자열·이름은 후보의 근거이며 검사 의미·전체 탐지 경로·실기기 동작을 증명하지 않습니다.",
             "코드 생성은 별도로 선택합니다. 관찰과 Boolean 판정 변경·void 실행 생략 테스트는 서로 다른 모드입니다.",
             "Boolean=false는 primitive boolean, 실행 생략은 지원되는 void 메서드만 대상으로 하며 무결성 증명·서명·서버 응답은 생성하지 않습니다.", ""]
    for row in rows[:80]:
        candidate = row["candidate"]
        categories = ", ".join(_CATEGORY_LABELS.get(item, item) for item in candidate["categories"]) or "분류 미확정"
        lines.append(f"[{_STATUS_LABELS[row['status']]}] {candidate['class_name']}.{candidate['method_name']}{candidate['dex_descriptor']}")
        lines.append(f"  분류: {categories}")
        if candidate["signals"]:
            lines.append("  근거: " + ", ".join(candidate["signals"][:8]))
        if row.get("modes"):
            labels = {"observe": "호출 관찰", "boolean_false": "Boolean=false 테스트", "skip_void": "void 실행 생략 테스트"}
            lines.append("  생성: " + ", ".join(labels[item] for item in row["modes"]))
        if row.get("note"):
            lines.append("  " + row["note"])
    if len(rows) > 80:
        lines.append(f"나머지 {len(rows) - 80}개 후보는 점검 JSON에서 확인할 수 있습니다.")
    if not rows:
        lines.append("현재 규칙으로 후보를 찾지 못했습니다. 보안 검사가 없다는 뜻은 아닙니다.")
    if counts["rows_omitted"]:
        lines.append(f"후보 기록 한도로 {counts['rows_omitted']}개를 보류했습니다.")
    lines.extend(["", "점검 범위", f"  상세 REA 조회는 최대 {MAX_DETAIL_CLASSES}개 클래스입니다.",
                  "  정적으로 해석 가능한 Java/DEX 범위이며 native·split·동적 로딩과 서버 판정은 별도 확인이 필요합니다.",
                  "  기존 EUNORA 보안 처리 코드와 APK를 변경하지 않았습니다."])
    lines.extend("  " + str(note) for note in scan.get("limitations", []))
    coverage = scan.get("coverage", {})
    if coverage.get("truncated"):
        lines.append("  스캐너 후보 한도에 도달해 전체 후보가 포함되지 않았습니다.")
    if coverage.get("unsupported_methods", 0):
        lines.append(f"  스캐너가 해석하지 못한 메서드 {coverage['unsupported_methods']}개가 있습니다.")
    return "\n".join(lines)


def _run_security_audit(apk_path, project_path, *, settings=None, progress=None):
    check_cancelled()
    apk = Path(apk_path).expanduser().resolve()
    if not apk.is_file() or apk.suffix.lower() != ".apk":
        raise SecurityAuditError("보안 점검에 사용할 APK 파일을 선택하세요")
    digest = _digest(apk)
    if progress:
        progress("보안 점검: APK 앱 종류 확인 중…")
    package_result = run_rea_analysis(apk, settings=settings, operation="package", progress=progress)
    package = _bound_result(package_result, digest, "package")
    profiles = load_profiles()
    keys = [key for key, item in profiles.items() if item["package"] == package.get("package_name")]
    if len(keys) != 1:
        raise SecurityAuditError("현재 등록된 7개 EUNORA 패키지 프로필에 해당하는 APK가 아닙니다")
    app_key, profile = keys[0], profiles[keys[0]]
    catalog = collect_source_catalog(project_path, app_key)
    root = Path(catalog["project_root"]).resolve()
    sources = dict(catalog["source_files"])
    _check_sources(root, sources)
    if progress:
        progress(f"보안 점검: {profile['label']} APK에서 후보를 찾는 중…")
    scan = scan_security_candidates(apk, progress=progress)
    if not isinstance(scan, dict) or scan.get("apk_digest") != digest:
        raise SecurityAuditError("선택한 APK와 보안 스캔 결과의 SHA-256이 다릅니다")
    candidates = scan.get("candidates")
    if not isinstance(candidates, list) or not isinstance(scan.get("coverage"), dict):
        raise SecurityAuditError("보안 스캔 후보 목록 또는 범위 정보가 잘못되었습니다")
    for candidate in candidates:
        _candidate(candidate)
    if len({item["id"] for item in candidates}) != len(candidates):
        raise SecurityAuditError("보안 스캔 후보 식별자가 중복되어 대상을 확정할 수 없습니다")
    total = len(candidates)
    # Local test targets must not be crowded out by large SDK integrity API
    # inventories. Keep stable scanner order within each priority group.
    candidates = sorted(candidates, key=_priority)[:MAX_CANDIDATE_ROWS]
    names, duplicates, declared = [], set(), Counter()
    inventory_result = None
    if candidates:
        inventory_result = run_rea_analysis(apk, settings=settings, operation="class_search", query="", progress=progress)
        inventory = _bound_result(inventory_result, digest, "class_search")
        names = inventory.get("matches")
        if inventory.get("coverage") != "complete" or not isinstance(names, list) or not all(isinstance(name, str) for name in names):
            raise SecurityAuditError("완전한 REA 클래스 목록이 없어 보안 대상을 연결할 수 없습니다")
        duplicates = {item.get("name") for item in inventory.get("duplicate_names", []) if isinstance(item, dict)}
        names = list(dict.fromkeys(names))
        declared = _declared_classes(apk)
    cache, rows, choices = {}, [], []
    attempts = 0
    for candidate in candidates:
        check_cancelled()
        row = {"candidate": candidate, "resolved_class": None, "status": "needs_review", "modes": [], "note": ""}
        requested_modes = _MODES.intersection(candidate["modes"])
        if not requested_modes:
            row.update(status="unsupported", note=candidate.get("note") or "이 후보는 현재 코드 생성 원형을 지원하지 않습니다.")
            rows.append(row)
            continue
        display, reason = _resolve_class(candidate["class_name"], names, duplicates, declared)
        row["resolved_class"], row["note"] = display, reason
        if display is None:
            rows.append(row)
            continue
        if display not in cache:
            if attempts >= MAX_DETAIL_CLASSES:
                row.update(status="deferred", note=f"상세 조회 클래스 한도 {MAX_DETAIL_CLASSES}개에 도달했습니다.")
                rows.append(row)
                continue
            attempts += 1
            if progress:
                progress(f"보안 점검: 정확한 클래스 원형 확인 {attempts}/{MAX_DETAIL_CLASSES} — {display}")
            try:
                cache[display] = _class_detail(apk, digest, display, settings, progress)
            except (CancelledError, _StaleAuditInput):
                raise
            except Exception as error:
                cache[display] = error
        detail = cache[display]
        if isinstance(detail, Exception):
            row.update(status="error", note=str(detail))
            rows.append(row)
            continue
        class_result, normalized = detail
        if class_result.get("status") != "complete":
            row.update(note="REA 클래스 결과가 일부 범위여서 생성 대상으로 확정하지 않았습니다.")
            rows.append(row)
            continue
        matches = [method for method in normalized["methods"] if isinstance(method, dict) and
                   method.get("name") == candidate["method_name"] and method.get("dex_descriptor") == candidate["dex_descriptor"]]
        if (len(matches) != 1 or not isinstance(matches[0].get("overload_index"), int) or
                isinstance(matches[0]["overload_index"], bool) or matches[0]["overload_index"] < 0):
            row.update(note="REA 메서드의 이름·원형·오버로드를 하나로 확정할 수 없습니다.")
            rows.append(row)
            continue
        method = matches[0]
        try:
            target = _verified_target(apk, display, candidate["method_name"], candidate["dex_descriptor"])
            if target["class_name"] != candidate["class_name"] or target["access_flags"] != candidate["access_flags"]:
                raise GenerationError("스캐너와 실제 DEX 선언의 소유자·접근 플래그가 다릅니다")
        except CancelledError:
            raise
        except (GenerationError, OSError, RuntimeError) as error:
            row.update(note=str(error))
            rows.append(row)
            continue
        modes = _allowed_modes(candidate, target)
        if not modes:
            row.update(status="unsupported", note="정확한 메서드는 확인했지만 요청한 생성 모드를 지원하지 않습니다.")
        elif len(choices) >= MAX_CHOICES:
            row.update(status="deferred", note=f"선택 목록 한도 {MAX_CHOICES}개에 도달했습니다.")
        else:
            row.update(status="ready", modes=modes)
            if not {"boolean_false", "skip_void"}.intersection(modes):
                row["note"] += (" / " if row["note"] else "") + "호출 관찰만 지원합니다."
            label = f"{candidate['class_name']}.{candidate['method_name']}{candidate['dex_descriptor']} — " + ", ".join(candidate["categories"])
            choices.append({"candidate": candidate, "class_result": class_result,
                            "class_evidence": class_result["evidence"], "method_name": candidate["method_name"],
                            "overload_index": method["overload_index"], "dex_descriptor": candidate["dex_descriptor"],
                            "modes": modes, "label": label})
        rows.append(row)
    check_cancelled()
    if _digest(apk) != digest:
        raise SecurityAuditError("보안 점검 중 APK가 변경되었습니다. 다시 점검하세요")
    _check_sources(root, sources)
    counts = dict(Counter(row["status"] for row in rows))
    coverage = scan["coverage"]
    reported_total = coverage.get("candidates_total", total)
    if not isinstance(reported_total, int) or isinstance(reported_total, bool) or reported_total < total:
        raise SecurityAuditError("보안 스캐너의 전체 후보 개수와 반환 개수가 맞지 않습니다")
    counts.update(scan_candidates=total, scan_candidates_total=reported_total, total=len(rows), detail_attempted=attempts,
                  detail_completed=sum(not isinstance(item, Exception) for item in cache.values()),
                  choices=len(choices), boolean_false=sum("boolean_false" in item["modes"] for item in choices),
                  skip_void=sum("skip_void" in item["modes"] for item in choices),
                  rows_omitted=total - len(rows))
    partial = (not rows or counts["rows_omitted"] or any(row["status"] != "ready" for row in rows) or
               coverage.get("truncated") or coverage.get("unsupported_methods", 0) or coverage.get("duplicate_owners", 0) or
               package_result.get("status") != "complete")
    status = "partial" if partial else "complete"
    report = _make_report(profile, apk, root, rows, choices, scan, counts, status)
    folder = app_dir() / "security_audits"
    folder.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")
    output = folder / f"security_{app_key}_{digest[:16]}_{stamp}_{uuid.uuid4().hex[:8]}.json"
    report_path = output.with_suffix(".txt")
    result = {"status": status, "report": report, "report_path": str(report_path), "json_path": str(output),
              "app_key": app_key, "apk_path": str(apk), "apk_digest": digest, "project_root": str(root),
              "source_files": sources, "package_result": package_result, "inventory_result": inventory_result,
              "rows": rows, "choices": choices, "scan": scan, "counts": counts}
    try:
        atomic_write_text(output, json.dumps(result, ensure_ascii=False, indent=2, allow_nan=False) + "\n")
        check_cancelled()
        atomic_write_text(report_path, report + "\n")
        check_cancelled()
    except BaseException:
        output.unlink(missing_ok=True)
        report_path.unlink(missing_ok=True)
        raise
    return result


def run_security_audit(apk_path, project_path, *, settings=None, progress=None) -> dict:
    """Automatically bind supported security candidates for one EUNORA profile."""
    try:
        return _run_security_audit(apk_path, project_path, settings=settings, progress=progress)
    except SecurityAuditError:
        raise
    except (EunoraAuditError, GenerationError) as error:
        raise SecurityAuditError(str(error)) from error

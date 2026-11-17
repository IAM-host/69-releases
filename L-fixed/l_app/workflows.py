"""Long-running non-UI operations. Inputs and results contain no Qt widgets."""
from __future__ import annotations

import hashlib
from pathlib import Path

from .config import APP_LABELS
from .paths import app_dir, atomic_write_text
from .processes import check_cancelled
from .state import (
    apk_has_symbols, apply_symbol_replacements, collect_log_text_from_sessions,
    log_symbol_hits, modulemain_symbol_counts,
)


def file_digest(path: Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            check_cancelled()
            digest.update(chunk)
    return digest.hexdigest()


def build_hook_map(app_key, spec, module_path, apk_path, session_dir, live_log=""):
    check_cancelled()
    module_path, apk_path = Path(module_path), Path(apk_path)
    module_bytes = module_path.read_bytes() if module_path.is_file() else b""
    module_text = module_bytes.decode("utf-8-sig", errors="strict")
    apk_ok = apk_path.is_file()
    log_text = collect_log_text_from_sessions(Path(session_dir), app_key)
    if live_log:
        log_text = live_log + "\n" + log_text
    notes = [
        f"앱={APP_LABELS.get(app_key, app_key)}",
        f"ModuleMain={'있음' if module_text else '없음'}  APK={'있음' if apk_ok else '없음'}",
        f"로그 글자 수={len(log_text)}",
        "APK 문자열 대조 결과이며 훅 등록·실행을 확인한 결과가 아닙니다.",
    ]
    rows, pending = [], []
    sites = spec.get("sites") or []
    for site in sites:
        check_cancelled()
        if not isinstance(site, dict):
            continue
        symbols = [s for s in site.get("symbols", []) if isinstance(s, str) and s]
        counts = modulemain_symbol_counts(module_text, symbols) if module_text else {}
        flags = apk_has_symbols(apk_path, symbols) if apk_ok else {}
        hits, extras = log_symbol_hits(log_text, list(site.get("log_needles") or []) + symbols)
        missing = [s for s in symbols if apk_ok and not flags.get(s, False)]
        for old in missing:
            if counts.get(old, 0) <= 0:
                continue
            # Keep all candidates. The copy operation refuses ambiguous mappings.
            for candidate in extras:
                if candidate != old and candidate not in symbols:
                    pending.append((old, candidate))
                    notes.append(f"미검증 후보 {site.get('id')}: {old} → {candidate}")
        rows.append([
            str(site.get("id", "")), str(site.get("role", "")),
            ", ".join(symbols) or "(없음)",
            ", ".join(f"{s}:{counts.get(s, 0)}" for s in symbols) or "-",
            ", ".join("문자열 있음" if flags.get(s) else "미발견" for s in symbols)
            if symbols and apk_ok else "-",
            f"hits={hits}" + ("  " + ", ".join(extras[:4]) if extras else ""),
        ])
    if not sites:
        notes.append("지식 파일에 이 앱 정보가 없습니다. eunora_hooks.json을 확인하세요.")
    if pending:
        notes.append("치환 후보는 정적·로그 기반 추정입니다. 복사본 생성은 동작 검증을 뜻하지 않습니다.")
    else:
        notes.append("자동 치환 후보 없음")
    return {
        "rows": rows, "pending": pending, "notes": notes,
        "source_path": str(module_path.resolve()),
        "source_digest": hashlib.sha256(module_bytes).hexdigest(),
        "apk_path": str(apk_path.resolve()),
        "apk_digest": file_digest(apk_path) if apk_ok else None,
    }


def create_source_copy(module_path, pairs, expected_source_digest, apk_path, expected_apk_digest):
    check_cancelled()
    module_path = Path(module_path)
    raw = module_path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != expected_source_digest:
        raise RuntimeError("대조 후 원본 코드가 바뀌었습니다. 지도 대조를 다시 실행하세요.")
    if expected_apk_digest is not None and file_digest(Path(apk_path)) != expected_apk_digest:
        raise RuntimeError("대조 후 APK가 바뀌었습니다. 지도 대조를 다시 실행하세요.")
    patched, applied = apply_symbol_replacements(raw.decode("utf-8-sig"), pairs)
    check_cancelled()
    output = None
    if applied:
        output = app_dir() / "ModuleMain_patched.kt"
        if output.resolve() == module_path.resolve():
            output = app_dir() / "ModuleMain_patched_copy.kt"
        if output.resolve() == module_path.resolve():
            raise RuntimeError("원본과 복사본 경로가 같습니다. 출력 경로를 바꿔 주세요.")
        atomic_write_text(output, patched)
    return {"text": patched, "applied": applied, "path": output}

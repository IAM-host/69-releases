"""ADB process execution and APK transfer services."""
from __future__ import annotations
from pathlib import Path, PurePosixPath
from typing import Callable
import json
import re
import subprocess
import zipfile

from .config import APP_LABELS, DRIVER_APPS
from .paths import apk_dir
from .processes import CancelledError, check_cancelled, run_process

def find_adb() -> str | None:
    from shutil import which

    found = which("adb")
    if found:
        return found
    candidates = [
        Path.home() / "AppData/Local/Android/Sdk/platform-tools/adb.exe",
        Path("C:/Android/platform-tools/adb.exe"),
        Path("C:/platform-tools/adb.exe"),
    ]
    for p in candidates:
        if p.exists():
            return str(p)
    return None

def parse_pm_paths(stdout: str) -> list[str]:
    """Read paths without interpreting shell syntax or accepting relative names."""
    paths: list[str] = []
    for ln in stdout.splitlines():
        line = ln.strip()
        if line.startswith("package:"):
            line = line[8:].strip()
        if not _valid_remote_apk_path(line):
            continue
        if line not in paths:
            paths.append(line)
    return paths


def _valid_remote_apk_path(path: str) -> bool:
    return (
        path.startswith("/")
        and not path.startswith("//")
        and path.endswith(".apk")
        and "\\" not in path
        and not any(ord(ch) < 32 for ch in path)
        and all(part not in (".", "..") for part in path.split("/")[1:])
        and bool(PurePosixPath(path).name)
    )


def run_adb_command(
    adb_path: str | None, args: list[str], timeout: float = 8.0
) -> tuple[int, str, str]:
    """Execute an argument vector. Cancellation remains visible to the job runner."""
    check_cancelled()
    if not adb_path:
        return 1, "", "adb not found"
    try:
        result = run_process([str(adb_path), *map(str, args)], timeout=timeout)
        return result.returncode, result.stdout or "", result.stderr or ""
    except CancelledError:
        raise
    except (OSError, subprocess.SubprocessError) as error:
        return 1, "", str(error)


def _snapshot_directory(app_key: str, stamp: str) -> Path:
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,80}", stamp):
        raise ValueError("잘못된 APK 스냅샷 이름입니다")
    parent = apk_dir() / app_key
    parent.mkdir(parents=True, exist_ok=True)
    for index in range(10000):
        name = stamp if index == 0 else f"{stamp}_{index:02d}"
        result = parent / name
        try:
            result.mkdir()
            (result / ".incomplete").write_text("추출 진행 중\n", encoding="utf-8")
            return result
        except FileExistsError:
            continue
    raise RuntimeError("같은 시각의 APK 스냅샷이 너무 많습니다")


def _is_apk(path: Path) -> bool:
    """A successful transfer must contain an actual APK manifest, not a renamed split."""
    if not path.is_file() or path.stat().st_size == 0:
        return False
    try:
        with zipfile.ZipFile(path) as archive:
            return "AndroidManifest.xml" in archive.namelist()
    except (OSError, zipfile.BadZipFile):
        return False


def pull_package(
    adb_path: str | None,
    serial: str,
    app_key: str,
    stamp: str,
    *,
    progress: Callable[[str], None] | None = None,
) -> dict:
    """Pull all package APKs into a new snapshot without touching any Qt widget.

    A split APK is never renamed to base.apk. Incomplete snapshots have a marker
    that excludes them from subsequent history comparisons.
    """
    if app_key not in DRIVER_APPS:
        raise ValueError(f"알 수 없는 앱: {app_key}")
    if not serial.strip() or any(ord(ch) < 32 for ch in serial):
        raise ValueError("기기 번호를 확인하세요")
    check_cancelled()
    info = DRIVER_APPS[app_key]
    package = info["package"]
    label = APP_LABELS[app_key]
    destination = _snapshot_directory(app_key, stamp)
    result = {
        "app_key": app_key,
        "package": package,
        "stamp": destination.name,
        "directory": destination,
        "base_path": None,
        "metadata": None,
        "files": [],
        "report": "",
    }
    lines = [f"[{label}] {package}"]

    def report(message: str) -> None:
        if progress:
            progress(message)

    report(f"추출 중 {label}")
    code, stdout, stderr = run_adb_command(
        adb_path, ["-s", serial, "shell", "pm", "path", package], timeout=20
    )
    paths = parse_pm_paths(stdout)
    if code != 0 or not paths:
        lines.append(f"  미설치 또는 APK 경로 조회 실패 ({code})")
        if (stdout + stderr).strip():
            lines.append((stdout + stderr).strip())
        result["report"] = "\n".join(lines)
        return result

    names = [PurePosixPath(path).name for path in paths]
    if len(names) != len(set(names)):
        lines.append("  서로 다른 원격 APK의 파일명이 겹쳐 추출을 중단했습니다")
        result["report"] = "\n".join(lines)
        return result

    for remote, name in zip(paths, names):
        check_cancelled()
        report(f"추출 중 {label}: {name}")
        local = destination / name
        temporary = destination / (name + ".part")
        pcode, pout, perr = run_adb_command(
            adb_path, ["-s", serial, "pull", remote, str(temporary)], timeout=180
        )
        successful = pcode == 0 and _is_apk(temporary)
        size = temporary.stat().st_size if temporary.is_file() else 0
        if successful:
            temporary.replace(local)
        detail = (perr.strip() or pout.strip())
        if pcode == 0 and not successful:
            detail = "APK 파일이 비어 있거나 올바른 APK가 아닙니다"
        lines.append(f"  {'OK' if successful else 'FAIL'} {name}  {size / 1024 / 1024:.1f}MB  {detail}")
        result["files"].append({
            "remote": remote,
            "name": name,
            "path": local if successful else None,
            "success": successful,
            "bytes": size,
            "error": "" if successful else detail,
        })
        if name == "base.apk" and successful:
            result["base_path"] = local

    base = result["base_path"]
    if base is None:
        lines.append("  base.apk 추출 실패: 분할 APK를 base로 대체하지 않았습니다")
        result["report"] = "\n".join(lines)
        return result

    # Imports are local so the transfer runner can be imported without loading
    # the larger analysis module, and tests can supply a small analysis fixture.
    from .analysis import apk_meta, check_needles, diff_apk
    from .state import previous_snapshot

    check_cancelled()
    metadata = {
        "app": app_key,
        "package": package,
        "stamp": destination.name,
        "device": serial,
        "size": base.stat().st_size,
        "base_valid": True,
        "all_parts_ok": all(item["success"] for item in result["files"]),
        "static_evidence_only": True,
    }
    try:
        metadata["apk_meta"] = apk_meta(base)
        for needle, present in check_needles(base, info["needles"]):
            lines.append(f"  정적 문자열 {'발견' if present else '미발견'}: {needle}")
        lines.append("  문자열 발견 여부는 훅 등록·실행 확인을 뜻하지 않습니다")
        previous = previous_snapshot(app_key, destination.name)
        if previous:
            difference = diff_apk(previous, base)
            lines.append(
                f"  이전 대비 문자열 +{len(difference['added'])} / -{len(difference['removed'])}"
                f"  ({previous.parent.name})"
            )
        else:
            lines.append("  이전 스냅샷 없음 (이번이 첫 추출)")
    except CancelledError:
        raise
    except Exception as error:
        metadata["analysis_error"] = str(error)
        lines.append(f"  APK는 추출했지만 정적 분석은 실패했습니다: {error}")
    if not metadata["all_parts_ok"]:
        lines.append("  일부 분할 APK 추출 실패: 전체 설치 세트는 불완전합니다")
    check_cancelled()
    meta_temporary = destination / "meta.json.part"
    meta_temporary.write_text(json.dumps(metadata, ensure_ascii=False, indent=2), encoding="utf-8")
    meta_temporary.replace(destination / "meta.json")
    (destination / ".incomplete").unlink()
    result["metadata"] = metadata
    result["report"] = "\n".join(lines)
    return result

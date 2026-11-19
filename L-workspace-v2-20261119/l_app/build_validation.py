"""Compile generated Kotlin copies in an isolated Android project."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path, PurePosixPath, PureWindowsPath
import re
import shutil
import subprocess
import tempfile

from .paths import atomic_write_text
from .processes import CancelledError, check_cancelled, run_process


class BuildValidationError(RuntimeError):
    pass


_IGNORED = {".git", ".gradle", ".idea", ".venv", "__pycache__", "build", "dist", ".pytest_cache"}
_MAX_WINDOWS_ROOT_LENGTH = 100


def _is_windows():
    # Keep this separate from pathlib's platform selection so path behaviour can
    # be exercised on another host without changing the process-wide os.name.
    return os.name == "nt"


def _create_windows_workspace(project):
    """Allocate a short ASCII path; Gradle must never run under a Unicode bundle."""
    explicit = os.environ.get("L_BUILD_DIR")
    if explicit is not None:
        candidates = [(explicit, "L_BUILD_DIR")]
    else:
        candidates = [
            (str(Path(value) / "L-build"), name)
            for name in ("LOCALAPPDATA", "PUBLIC", "TEMP")
            if (value := os.environ.get(name))
        ]
        candidates.append((str(Path(tempfile.gettempdir()) / "L-build"), "TEMP"))
    failures, seen = [], set()
    for value, label in candidates:
        check_cancelled()
        try:
            candidate = Path(value).expanduser()
            if not value or not candidate.is_absolute():
                raise ValueError("절대 경로가 필요합니다")
            # resolve follows junctions/symlinks before the same path is passed
            # as Gradle's cwd, avoiding a nominally ASCII alias to a Unicode path.
            candidate = candidate.resolve()
            key = str(candidate).casefold()
            if key in seen:
                continue
            seen.add(key)
            if not str(candidate).isascii():
                raise ValueError("한글 등 비 ASCII 문자가 포함되어 있습니다")
            if len(str(candidate)) > _MAX_WINDOWS_ROOT_LENGTH:
                raise ValueError("경로가 너무 깁니다")
            if candidate.is_relative_to(project):
                raise ValueError("원본 Android 프로젝트 밖의 경로가 필요합니다")
            candidate.mkdir(parents=True, exist_ok=True)
            return Path(tempfile.mkdtemp(prefix="b_", dir=candidate))
        except (OSError, ValueError) as error:
            failures.append(f"{label}: {error}")
    detail = " / ".join(failures)
    raise BuildValidationError(
        "짧은 영문 빌드 검사 폴더를 만들 수 없습니다. "
        "L_BUILD_DIR에 원본 프로젝트 밖의 쓰기 가능한 영문 절대 경로를 지정하세요 "
        "(예: C:\\L-build)." + (f" {detail}" if detail else "")
    )


def _failure_excerpt(log, limit=3200):
    """Surface Gradle's cause and Kotlin errors without hiding the full log."""
    clean = re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", "", log)
    lines = clean.splitlines()
    chosen = set()
    for index, line in enumerate(lines):
        stripped = line.strip()
        if stripped in {"* Where:", "* What went wrong:"}:
            end = index + 1
            while end < len(lines) and not lines[end].strip().startswith("* "):
                end += 1
            chosen.update(range(index, min(end, index + 35)))
        elif stripped.startswith(("e:", "error:", "Caused by:")):
            chosen.add(index)
    if chosen:
        excerpt = "\n".join(lines[index] for index in sorted(chosen)).strip()
    else:
        excerpt = "\n".join(lines[-30:]).strip()
    if not excerpt:
        excerpt = "빌드 도구가 오류 내용을 출력하지 않았습니다. 전체 로그를 확인하세요."
    return excerpt if len(excerpt) <= limit else excerpt[:limit] + "\n… 나머지는 전체 빌드 로그에서 확인하세요."


def _digest(path):
    check_cancelled()
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            check_cancelled()
            digest.update(block)
    return digest.hexdigest()


def _relative(value):
    if not isinstance(value, str) or not value or "\\" in value:
        raise BuildValidationError("생성 기록에 잘못된 상대 경로가 있습니다")
    path = PurePosixPath(value)
    if path.is_absolute() or PureWindowsPath(value).drive or any(p in {".", ".."} for p in value.split("/")):
        raise BuildValidationError("생성 기록의 상대 경로가 프로젝트 밖을 가리킵니다")
    if path.suffix != ".kt" or any(p in _IGNORED for p in path.parts):
        raise BuildValidationError("빌드 검사에는 프로젝트의 Kotlin 소스만 적용할 수 있습니다")
    return Path(*path.parts)


def _verify_files(project, bundle, originals, generated):
    if not isinstance(originals, dict) or not isinstance(generated, dict) or not originals or set(originals) != set(generated):
        raise BuildValidationError("생성 기록의 원본·생성본 파일 목록이 일치하지 않습니다")
    overlay = {}
    for name, expected in originals.items():
        relative = _relative(name)
        source = project / relative
        if not source.resolve().is_relative_to(project) or source.is_symlink() or not source.is_file():
            raise BuildValidationError(f"원본 소스를 찾을 수 없습니다: {name}")
        if _digest(source) != expected:
            raise BuildValidationError(f"생성 후 원본 코드가 바뀌었습니다. 다시 생성하세요: {name}")
        record = generated[name]
        if not isinstance(record, dict) or not isinstance(record.get("path"), str):
            raise BuildValidationError(f"생성본 기록이 잘못되었습니다: {name}")
        copy = Path(record["path"]).expanduser()
        if not copy.is_absolute() or copy.is_symlink() or not copy.is_file() or not copy.resolve().is_relative_to(bundle):
            raise BuildValidationError(f"생성 폴더 안의 소스만 검사할 수 있습니다: {name}")
        if _digest(copy) != record.get("sha256"):
            raise BuildValidationError(f"생성한 코드가 바뀌었습니다. 다시 생성하세요: {name}")
        overlay[relative] = copy
    return overlay


def _copy_project(source, target):
    def ignore(directory, names):
        check_cancelled()
        ignored = set(names) & _IGNORED
        for name in names:
            if name not in ignored and (Path(directory) / name).is_symlink():
                raise BuildValidationError("심볼릭 링크가 포함된 프로젝트는 별도의 일반 폴더 사본으로 검사하세요")
        return ignored

    def copy_file(source_file, target_file):
        check_cancelled()
        return shutil.copy2(source_file, target_file)

    shutil.copytree(source, target, ignore=ignore, copy_function=copy_file)


def validate_generated_project(manifest_path, java_home=None, *, progress=None,
                               gradle_command=None, extra_args=(), timeout=1800):
    """Validate hashes, copy the project, overlay copies and compile Debug Kotlin.

    gradle_command/extra_args allow an already installed Gradle in local CI. The
    UI uses the project's Java wrapper directly, including on Windows.
    """
    check_cancelled()
    manifest_path = Path(manifest_path).expanduser().resolve()
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        project = Path(manifest["project_root"]).expanduser().resolve()
    except (OSError, ValueError, TypeError, KeyError) as error:
        raise BuildValidationError("생성 기록을 읽을 수 없습니다. 훅 코드를 다시 생성하세요") from error
    if not project.is_dir() or not (project / "app").is_dir():
        raise BuildValidationError("원본 Android 프로젝트의 app 폴더를 찾을 수 없습니다")
    bundle = manifest_path.parent
    if bundle.is_relative_to(project):
        raise BuildValidationError("생성 폴더는 원본 Android 프로젝트 밖에 있어야 합니다")
    overlay = _verify_files(project, bundle, manifest.get("originals"), manifest.get("generated"))
    env = os.environ.copy()
    home = java_home or env.get("JAVA_HOME")
    java = None
    if home:
        home = str(Path(home).expanduser().resolve())
        java = Path(home) / "bin" / ("java.exe" if os.name == "nt" else "java")
        if not java.is_file():
            raise BuildValidationError("JDK 경로의 bin/java 실행 파일을 찾을 수 없습니다")
        env["JAVA_HOME"] = home
        env["PATH"] = str(java.parent) + os.pathsep + env.get("PATH", "")
    elif gradle_command is None:
        found = shutil.which("java")
        if found:
            java = Path(found).resolve()
    wrapper = project / "gradle" / "wrapper" / "gradle-wrapper.jar"
    if gradle_command is None and (java is None or not wrapper.is_file()):
        raise BuildValidationError("JDK와 gradle/wrapper/gradle-wrapper.jar가 필요합니다. REA 설정의 JDK 경로를 확인하세요")
    if gradle_command is not None and (isinstance(gradle_command, (str, bytes)) or not gradle_command):
        raise BuildValidationError("Gradle 명령은 비어 있지 않은 인자 목록이어야 합니다")
    checks = bundle / "build_checks"
    checks.mkdir(exist_ok=True)
    check_dir = Path(tempfile.mkdtemp(prefix="check_", dir=checks))
    if _is_windows():
        copied_project = _create_windows_workspace(project) / "p"
    else:
        copied_project = check_dir / "project"
    if progress:
        progress("원본을 보존하고 빌드용 프로젝트 사본을 만드는 중…")
    try:
        _copy_project(project, copied_project)
        for relative, generated_file in overlay.items():
            shutil.copy2(generated_file, copied_project / relative)
        # Catch edits during the copy as well as changes before it started.
        _verify_files(project, bundle, manifest["originals"], manifest["generated"])
        for relative, generated_file in overlay.items():
            if _digest(copied_project / relative) != _digest(generated_file):
                raise BuildValidationError("빌드 사본의 코드가 생성본과 일치하지 않습니다")
        command = list(gradle_command) if gradle_command is not None else [
            str(java), "-cp", str(copied_project / "gradle/wrapper/gradle-wrapper.jar"),
            "org.gradle.wrapper.GradleWrapperMain",
        ]
        command += [":app:compileDebugKotlin", "--no-daemon", "--no-configuration-cache", "--console=plain", "--max-workers=2"]
        command += list(extra_args)
        if progress:
            progress("생성본의 Debug Kotlin 빌드를 검사하는 중…")
        log_path = check_dir / "build.log"
        try:
            result = run_process(command, cwd=copied_project, env=env, timeout=timeout)
            status = "passed" if result.returncode == 0 else "failed"
            log = result.stdout + ("\n" + result.stderr if result.stderr else "")
        except (OSError, subprocess.TimeoutExpired) as error:
            status = "failed"
            log = f"빌드 실행 실패: {error}\n"
        atomic_write_text(log_path, log)
        excerpt = _failure_excerpt(log) if status == "failed" else ""
        failure_kind = None
        report = ("생성본 Kotlin 빌드 통과" if status == "passed" else "생성본 Kotlin 빌드 실패")
        if status == "failed":
            failure_kind = "build_failure"
            if "your project path contains non-ascii characters" in log.casefold():
                failure_kind = "non_ascii_project_path"
                report += "\n원인: Windows 빌드 프로젝트 경로에 한글 등 비 ASCII 문자가 포함되어 있습니다."
                report += "\nL_BUILD_DIR에 짧은 영문 검사 폴더를 지정한 뒤 다시 검사하세요."
            report += "\n\n실패 원인 발췌:\n" + excerpt
        report += f"\n프로젝트 사본: {copied_project}\n빌드 로그: {log_path}\n기기에서의 동작은 별도 확인이 필요합니다."
        validation = dict(status=status, report=report, log_path=str(log_path),
                          project_path=str(copied_project), manifest_path=str(manifest_path),
                          log_excerpt=excerpt, failure_kind=failure_kind)
        atomic_write_text(check_dir / "validation.json", json.dumps(validation, ensure_ascii=False, indent=2))
        manifest["build_status"] = status
        manifest["build_validation"] = validation
        atomic_write_text(manifest_path, json.dumps(manifest, ensure_ascii=False, indent=2))
        return validation
    except CancelledError:
        atomic_write_text(check_dir / "build.log", "사용자가 빌드 검사를 취소했습니다.\n")
        raise

"""Install the pinned REA tools locally; never install Node or Java globally."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import urllib.error
import urllib.request


REA_VERSION = "6.8.0"
JAR_VERSION = "0.7.1"
JAR_NAME = f"jadx-headless-mcp-{JAR_VERSION}-all.jar"
JAR_URL = (
    "https://github.com/1013503897/jadx-headless-mcp/releases/download/"
    f"v{JAR_VERSION}/{JAR_NAME}"
)
JAR_SHA256 = "6e5eacf500b64292bfb73c49797c1958f6ee44646e43e868039ae7feb573ff75"


class SetupError(RuntimeError):
    pass


def run_command(arguments: list[str], *, timeout: float = 30) -> subprocess.CompletedProcess:
    options = {}
    if os.name == "nt":
        options["creationflags"] = subprocess.CREATE_NO_WINDOW
    try:
        result = subprocess.run(
            arguments, capture_output=True, text=True, encoding="utf-8",
            errors="replace", timeout=timeout, shell=False, **options,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise SetupError(f"도구 실행 실패: {error}") from error
    if result.returncode:
        detail = (result.stderr or result.stdout or "알 수 없는 오류")[-4000:]
        raise SetupError(f"도구가 오류를 반환했습니다 ({result.returncode}):\n{detail}")
    return result


def parse_node_version(value: str) -> tuple[int, int, int]:
    match = re.fullmatch(r"v?(\d+)\.(\d+)\.(\d+)\s*", value.strip())
    if not match:
        raise SetupError("Node 버전을 확인하지 못했습니다. 공식 Node.js 설치를 확인하세요.")
    return tuple(map(int, match.groups()))


def node_version_supported(version: tuple[int, int, int]) -> bool:
    return (
        version[0] == 22 and version >= (22, 23, 4)
        or version[0] == 24 and version >= (24, 22, 1)
        or version >= (26, 12, 1)
    )


def _existing_file(value) -> Path | None:
    if not isinstance(value, str) or not value.strip():
        return None
    candidate = Path(value).expanduser()
    return candidate.resolve() if candidate.is_file() else None


def select_node(explicit: str | None, settings: dict) -> Path:
    choices = [explicit] if explicit else [settings.get("node_path"), shutil.which("node")]
    for value in choices:
        node = _existing_file(value)
        if node is None:
            continue
        version = parse_node_version(run_command([str(node), "--version"]).stdout)
        if not node_version_supported(version):
            raise SetupError(
                "지원되는 Node.js가 필요합니다: 22.23.4 이상인 22.x, "
                "24.22.1 이상인 24.x 또는 26.12.1 이상. Node.js 24 LTS 설치를 권장합니다."
            )
        return node
    raise SetupError("Node.js를 찾을 수 없습니다. Node.js 24 LTS를 설치한 뒤 setup_rea.bat를 다시 실행하세요.")


def find_npm_cli(node: Path, explicit: str | None = None) -> Path:
    if explicit:
        selected = _existing_file(explicit)
        if selected:
            return selected
        raise SetupError("--npm-cli 경로에 npm-cli.js가 없습니다.")
    directories = [node.parent, node.parent.parent, node.parent.parent / "lib"]
    for directory in directories:
        candidate = directory / "node_modules" / "npm" / "bin" / "npm-cli.js"
        if candidate.is_file():
            return candidate.resolve()
    launcher = shutil.which("npm")
    if launcher:
        launcher_path = Path(launcher)
        resolved = launcher_path.resolve()
        if resolved.name == "npm-cli.js" and resolved.is_file():
            return resolved
        for directory in [launcher_path.parent, resolved.parent, resolved.parent.parent]:
            candidate = directory / "node_modules" / "npm" / "bin" / "npm-cli.js"
            if candidate.is_file():
                return candidate.resolve()
    raise SetupError(
        "npm-cli.js를 찾을 수 없습니다. npm이 포함된 공식 Node.js 설치를 확인하세요. "
        "필요하면 install_rea.py --npm-cli 경로로 직접 지정할 수 있습니다."
    )


def _jdk_candidates(explicit: str | None, settings: dict) -> list[Path]:
    if explicit:
        return [Path(explicit).expanduser()]
    paths = []
    for value in [settings.get("java_home"), os.environ.get("JAVA_HOME")]:
        if isinstance(value, str) and value.strip():
            paths.append(Path(value).expanduser())
    java = shutil.which("java")
    if java:
        paths.append(Path(java).resolve().parent.parent)
    for base in [os.environ.get("ProgramFiles"), os.environ.get("LOCALAPPDATA")]:
        if base:
            paths += [Path(base) / "Android" / "Android Studio" / "jbr",
                      Path(base) / "Programs" / "Android Studio" / "jbr"]
    return list(dict.fromkeys(paths))


def select_java_home(explicit: str | None, settings: dict) -> Path:
    failures = []
    for home in _jdk_candidates(explicit, settings):
        java = home / "bin" / ("java.exe" if os.name == "nt" else "java")
        if not java.is_file():
            continue
        try:
            modules = run_command([str(java), "--list-modules"], timeout=20).stdout
            version = re.search(r"(?m)^java\.base@(\d+)(?:[.\s+-]|$)", modules)
            if not version or int(version.group(1)) < 17 or not re.search(r"(?m)^jdk\.compiler(?:@|$)", modules):
                failures.append(str(home))
                continue
            return home.resolve()
        except SetupError:
            failures.append(str(home))
    suffix = f" 확인한 경로: {', '.join(failures)}" if failures else ""
    raise SetupError(
        "jdk.compiler가 포함된 JDK 17 이상이 필요합니다(JDK 21 권장). "
        "JAVA_HOME 또는 --java-home으로 JDK/Android Studio의 jbr 폴더를 지정하세요." + suffix
    )


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        while data := stream.read(1024 * 1024):
            digest.update(data)
    return digest.hexdigest()


def _download_once(url: str, destination: Path, expected_sha256: str) -> None:
    """Keep an existing file intact until a complete download passes its digest."""
    destination = Path(destination)
    destination.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(
        prefix=destination.name + ".", suffix=".part", dir=destination.parent,
    )
    temporary = Path(temporary)
    digest = hashlib.sha256()
    total = 0
    try:
        request = urllib.request.Request(url, headers={"User-Agent": "L-REA-Setup/1"})
        with os.fdopen(descriptor, "wb") as output:
            with urllib.request.urlopen(request, timeout=60) as response:
                expected_length = response.headers.get("Content-Length")
                while data := response.read(1024 * 1024):
                    output.write(data)
                    digest.update(data)
                    total += len(data)
                if expected_length is not None and total != int(expected_length):
                    raise SetupError("JAR 다운로드가 끝나지 않았습니다. 다시 실행하세요.")
            output.flush()
            os.fsync(output.fileno())
        if digest.hexdigest().lower() != expected_sha256.lower():
            raise SetupError("JAR SHA-256이 일치하지 않습니다. 기존 파일과 설정은 유지했습니다.")
        os.replace(temporary, destination)
    finally:
        temporary.unlink(missing_ok=True)


def download_verified(url: str, destination: Path, expected_sha256: str) -> None:
    """Retry failed transfers without publishing a partial or unverified file."""
    for attempt in range(3):
        try:
            _download_once(url, destination, expected_sha256)
            return
        except (OSError, urllib.error.URLError, SetupError, ValueError):
            if attempt == 2:
                raise


def read_settings(path: Path) -> dict:
    if not path.exists():
        return {}
    try:
        value = json.loads(path.read_text(encoding="utf-8-sig"))
        if not isinstance(value, dict):
            raise ValueError("JSON 객체가 필요합니다")
        for key in ("node_path", "rea_entry", "jar_path", "java_home"):
            if key in value and not isinstance(value[key], (str, type(None))):
                raise ValueError(f"{key}는 경로 문자열이어야 합니다")
        return value
    except (ValueError, UnicodeError) as error:
        raise SetupError(f"{path.name} 형식을 확인하세요. 기존 파일은 바꾸지 않았습니다: {error}") from error


def write_settings(path: Path, settings: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=".rea-settings-", suffix=".tmp", dir=path.parent)
    temporary = Path(temporary)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="") as stream:
            json.dump(settings, stream, ensure_ascii=False, indent=2)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def rea_entry_is_pinned(entry: Path) -> bool:
    try:
        info = json.loads((entry.parent.parent / "package.json").read_text(encoding="utf-8"))
        return entry.is_file() and info.get("name") == "rea-agents" and info.get("version") == REA_VERSION
    except (OSError, ValueError):
        return False


def install(directory: Path, *, node_path=None, npm_cli=None, java_home=None, progress=print) -> dict:
    directory = Path(directory).expanduser().resolve()
    directory.mkdir(parents=True, exist_ok=True)
    settings_path = directory / "rea_settings.json"
    settings = read_settings(settings_path)
    lock = directory / ".l-rea-setup.lock"
    try:
        lock_fd = os.open(lock, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError as error:
        raise SetupError("REA 설치가 이미 진행 중입니다. 이전 작업이 끝난 뒤 다시 실행하세요.") from error
    try:
        os.close(lock_fd)
        node = select_node(node_path, settings)
        npm = find_npm_cli(node, npm_cli)
        jdk = select_java_home(java_home, settings)
        prefix = directory / "tools" / "rea"
        progress(f"REA {REA_VERSION} 로컬 설치 중…")
        run_command([
            str(node), str(npm), "install", "--omit=optional", "--no-audit", "--no-fund",
            "--prefix", str(prefix), f"rea-agents@{REA_VERSION}",
        ], timeout=900)
        local_entry = prefix / "node_modules" / "rea-agents" / "scripts" / "rea.mjs"
        if not rea_entry_is_pinned(local_entry):
            raise SetupError("npm 설치 결과에 REA 6.8.0 실행 파일이 없습니다. 설정을 저장하지 않았습니다.")
        prior_entry = _existing_file(settings.get("rea_entry"))
        entry = prior_entry if prior_entry and rea_entry_is_pinned(prior_entry) else local_entry.resolve()
        prior_jar = _existing_file(settings.get("jar_path"))
        jar = prior_jar if prior_jar and file_sha256(prior_jar) == JAR_SHA256 else prefix / JAR_NAME
        if not jar.is_file() or file_sha256(jar) != JAR_SHA256:
            progress(f"REA 전용 JADX {JAR_VERSION} 다운로드·해시 확인 중…")
            download_verified(JAR_URL, jar, JAR_SHA256)
        merged = dict(settings)
        merged.update(node_path=str(node), rea_entry=str(entry), jar_path=str(jar.resolve()), java_home=str(jdk))
        write_settings(settings_path, merged)
        progress("REA 설치와 설정 저장 완료. L의 REA 설정에서 경로를 확인할 수 있습니다.")
        return merged
    finally:
        lock.unlink(missing_ok=True)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="L용 REA와 headless JADX를 로컬 폴더에 설치합니다")
    parser.add_argument("--directory", type=Path, default=Path(os.environ.get("L_APP_DATA_DIR", Path(__file__).resolve().parent)))
    parser.add_argument("--node", help="기존 node.exe 또는 node 경로")
    parser.add_argument("--npm-cli", help="기존 npm-cli.js 경로")
    parser.add_argument("--java-home", help="기존 JDK 또는 Android Studio jbr 폴더")
    args = parser.parse_args(argv)
    try:
        install(args.directory, node_path=args.node, npm_cli=args.npm_cli, java_home=args.java_home)
    except (SetupError, OSError, urllib.error.URLError, ValueError) as error:
        print(f"REA 설치 실패: {error}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("REA 설치를 취소했습니다. 완료되지 않은 설정은 저장하지 않았습니다.", file=sys.stderr)
        return 130
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

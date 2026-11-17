"""Keep portable app data beside the launcher/executable; allow an explicit override."""
import os
import sys
import tempfile
import re
from pathlib import Path


def app_dir() -> Path:
    override = os.environ.get("L_APP_DATA_DIR")
    if override:
        result = Path(override).expanduser().resolve()
        result.mkdir(parents=True, exist_ok=True)
        return result
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parent.parent

def apk_dir() -> Path:
    d = app_dir() / "apks"
    d.mkdir(exist_ok=True)
    return d

def knowledge_path() -> Path:
    return app_dir() / "eunora_hooks.json"


def atomic_write_text(path: Path, text: str) -> None:
    """Publish a complete file, keeping the previous file if the write fails."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", newline="", dir=path.parent,
            prefix=f".{path.name}.", suffix=".tmp", delete=False,
        ) as stream:
            temporary = Path(stream.name)
            stream.write(text)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def session_path(directory: Path, stamp: str, app_tag: str, device: str) -> Path:
    """Keep serial numbers filename-safe and preserve captures from the same second."""
    safe_tag = re.sub(r"[^A-Za-z0-9_.-]", "_", app_tag)
    safe_device = re.sub(r"[^A-Za-z0-9_.-]", "_", device) or "unknown"
    tag = f"_{safe_tag}" if safe_tag else ""
    stem = f"session_{stamp}{tag}_{safe_device}"
    for number in range(10000):
        suffix = "" if number == 0 else f"_{number:02d}"
        candidate = Path(directory) / f"{stem}{suffix}.json"
        if not candidate.exists() and not candidate.with_suffix(".txt").exists():
            return candidate
    raise RuntimeError("같은 시각의 세션 파일이 너무 많습니다")


"""Find the selected EUNORA project and completed APK snapshots."""
from __future__ import annotations

from pathlib import Path

from .paths import app_dir, apk_dir

def previous_snapshot(app_key: str, current_stamp: str | None = None) -> Path | None:
    root = apk_dir() / app_key
    if not root.is_dir():
        return None
    stamps = sorted([p for p in root.iterdir() if p.is_dir()], key=lambda p: p.name)
    if current_stamp:
        stamps = [p for p in stamps if p.name < current_stamp]
    for folder in reversed(stamps):
        if (folder / ".incomplete").exists():
            continue
        base = folder / "base.apk"
        if base.is_file():
            return base
    return None


def find_modulemain() -> Path | None:
    home = Path.home()
    candidates = [
        home / "AndroidStudioProjects/WheelProbe/app/src/main/java/com/example/wheelprobe/ModuleMain.kt",
        home / "OneDrive" / "바탕 화면" / "안드스튜" / "WheelProbe" / "app" / "src" / "main" / "java" / "com" / "example" / "wheelprobe" / "ModuleMain.kt",
        app_dir() / "ModuleMain.kt",
        app_dir().parent / "ModuleMain.kt",
    ]
    for p in candidates:
        try:
            if p.is_file():
                return p
        except Exception:
            continue
    roots = [
        home / "AndroidStudioProjects",
        home / "OneDrive" / "바탕 화면" / "안드스튜",
    ]
    for root in roots:
        try:
            if not root.is_dir():
                continue
            hits = list(root.rglob("ModuleMain.kt"))
        except Exception:
            hits = []
        wheel = [h for h in hits if "wheelprobe" in str(h).lower()]
        pick = wheel[0] if wheel else (hits[0] if hits else None)
        if pick and pick.is_file():
            return pick
    return None

"""Shared streaming digest for source and APK evidence checks."""
from __future__ import annotations

import hashlib
from pathlib import Path

from .processes import check_cancelled


def file_digest(path: Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            check_cancelled()
            digest.update(chunk)
    return digest.hexdigest()

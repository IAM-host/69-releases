"""Session lookup, hook profiles, and source-copy operations."""
from __future__ import annotations
import json
import re
from pathlib import Path
from .paths import app_dir, apk_dir, knowledge_path
from .config import DRIVER_APPS, CLASS_LIKE
from .analysis import check_needles

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

def parse_modulemain_needles(path: Path) -> dict[str, list[str]]:
    """Collect declared class-name hints; these are static references, not live hooks."""
    text = path.read_text(encoding="utf-8", errors="replace")
    found = re.findall(
        r'(?:Class\.forName|findClass|loadClass|XposedHelpers\.findClass)\(\s*"([^"]+)"',
        text,
    )
    found += re.findall(r'"(?:[a-z][a-z0-9]{0,3}\.)+[A-Za-z0-9_$]+"', text)
    found = [s.strip('"') for s in found]
    out: dict[str, list[str]] = {k: [] for k in DRIVER_APPS}
    for s in found:
        low = s.lower()
        bucket = None
        if "kakao" in low or s.startswith("yi.") or s.startswith("gj."):
            bucket = "kakao"
        elif "callmanerdriver2sharp2" in low:
            bucket = "callmaner2"
        elif "callmaner" in low or "com.aintegration" in low:
            bucket = "callmaner"
        elif "tmap" in low or s.startswith("me.") or s.startswith("te."):
            bucket = "tmap"
        elif "com.logisoft.logi5" in low:
            bucket = "logi2"
        elif "logi" in low:
            bucket = "logi"
        elif "idriver" in low or "idrive" in low:
            bucket = "idrive"
        if bucket and s not in out[bucket]:
            out[bucket].append(s)
    return out

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

def load_hook_knowledge() -> dict:
    path = knowledge_path()
    if not path.exists():
        return {"version": 1, "apps": {}}
    try:
        data = json.loads(path.read_text(encoding="utf-8-sig"))
        if not isinstance(data, dict) or not isinstance(data.get("apps", {}), dict):
            raise ValueError("최상위 객체와 apps 객체를 확인하세요")
        return data
    except (OSError, UnicodeError, ValueError) as error:
        # The UI can display this diagnostic. Never silently overwrite a broken
        # user profile with a newly generated empty profile.
        return {"version": 1, "apps": {}, "_load_error": f"{path.name} 읽기 실패: {error}"}

def modulemain_symbol_counts(text: str, symbols: list[str]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for sym in symbols:
        if not sym:
            continue
        counts[sym] = text.count(sym)
    return counts

def apk_has_symbols(apk_path: Path, symbols: list[str]) -> dict[str, bool]:
    return dict(check_needles(apk_path, symbols))

def collect_log_text_from_sessions(session_dir: Path, app_key: str = "") -> str:
    chunks: list[str] = []
    for f in sorted(session_dir.glob("session_*.json"), reverse=True)[:40]:
        try:
            data = json.loads(f.read_text(encoding="utf-8"))
        except Exception:
            continue
        if app_key and data.get("app") and data.get("app") != app_key:
            continue
        lines = data.get("lines") or []
        chunks.extend(str(x) for x in lines)
    return "\n".join(chunks)

CLASS_FROM_LOG = re.compile(
    r"(?:class|source|host|repo)=([A-Za-z][\w.$]*)",
    re.IGNORECASE,
)

def log_symbol_hits(log_text: str, needles: list[str]) -> tuple[int, list[str]]:
    if not log_text:
        return 0, []
    upper = log_text.upper()
    hit_n = 0
    extras: list[str] = []
    for n in needles:
        if n and n.upper() in upper:
            hit_n += 1
    for m in CLASS_FROM_LOG.finditer(log_text):
        name = m.group(1)
        if name not in extras and len(name) >= 3:
            extras.append(name)
    return hit_n, extras[:12]

def _skip_comment(text: str, start: int) -> int:
    if text.startswith("//", start):
        end = text.find("\n", start + 2)
        return len(text) if end < 0 else end
    depth = 1
    index = start + 2
    while index < len(text):
        if text.startswith("/*", index):
            depth += 1
            index += 2
        elif text.startswith("*/", index):
            depth -= 1
            index += 2
            if depth == 0:
                return index
        else:
            index += 1
    raise ValueError("닫히지 않은 Kotlin 주석이 있어 치환하지 않았습니다")


def _skip_character(text: str, start: int) -> int:
    index = start + 1
    while index < len(text):
        if text[index] == "\\":
            index += 2
        elif text[index] == "'":
            return index + 1
        elif text[index] in "\r\n":
            break
        else:
            index += 1
    raise ValueError("닫히지 않은 Kotlin 문자 리터럴이 있어 치환하지 않았습니다")


def _skip_identifier(text: str, start: int) -> int:
    end = text.find("`", start + 1)
    if end < 0:
        raise ValueError("닫히지 않은 Kotlin 식별자가 있어 치환하지 않았습니다")
    return end + 1


def _skip_template_expression(text: str, start: int) -> int:
    """Skip ${ ... } including nested comments and quoted expressions."""
    depth = 1
    index = start
    while index < len(text):
        if text.startswith(("//", "/*"), index):
            index = _skip_comment(text, index)
        elif text[index] == '"':
            index, _, _ = _read_kotlin_string(text, index)
        elif text[index] == "'":
            index = _skip_character(text, index)
        elif text[index] == "`":
            index = _skip_identifier(text, index)
        elif text[index] == "{":
            depth += 1
            index += 1
        elif text[index] == "}":
            depth -= 1
            index += 1
            if depth == 0:
                return index
        else:
            index += 1
    raise ValueError("닫히지 않은 Kotlin 문자열 보간식이 있어 치환하지 않았습니다")


def _read_kotlin_string(text: str, start: int) -> tuple[int, str, bool]:
    raw = text.startswith('"""', start)
    delimiter = '"""' if raw else '"'
    index = start + len(delimiter)
    value: list[str] = []
    interpolated = False
    escapes = {"t": "\t", "b": "\b", "n": "\n", "r": "\r", '"': '"', "'": "'", "\\": "\\", "$": "$"}
    while index < len(text):
        if text.startswith(delimiter, index):
            return index + len(delimiter), "".join(value), interpolated
        char = text[index]
        if not raw and char in "\r\n":
            raise ValueError("Kotlin 문자열의 줄바꿈을 확인하세요")
        if not raw and char == "\\":
            if index + 1 >= len(text):
                break
            escaped = text[index + 1]
            if escaped == "u":
                digits = text[index + 2:index + 6]
                if len(digits) != 4 or not all(c in "0123456789abcdefABCDEF" for c in digits):
                    raise ValueError("잘못된 Kotlin Unicode escape가 있어 치환하지 않았습니다")
                value.append(chr(int(digits, 16)))
                index += 6
            elif escaped in escapes:
                value.append(escapes[escaped])
                index += 2
            else:
                raise ValueError("잘못된 Kotlin 문자열 escape가 있어 치환하지 않았습니다")
            continue
        if char == "$" and index + 1 < len(text):
            next_char = text[index + 1]
            if next_char == "{":
                interpolated = True
                index = _skip_template_expression(text, index + 2)
                continue
            if next_char == "_" or next_char.isalpha():
                interpolated = True
        value.append(char)
        index += 1
    raise ValueError("닫히지 않은 Kotlin 문자열이 있어 치환하지 않았습니다")


def _kotlin_string(value: str) -> str:
    escapes = {"\\": "\\\\", '"': '\\"', "$": "\\$", "\t": "\\t", "\b": "\\b", "\n": "\\n", "\r": "\\r"}
    encoded = []
    for char in value:
        if char in escapes:
            encoded.append(escapes[char])
        elif ord(char) < 32:
            encoded.append(f"\\u{ord(char):04x}")
        else:
            encoded.append(char)
    return '"' + "".join(encoded) + '"'


def apply_symbol_replacements(text: str, pairs: list[tuple[str, str]]) -> tuple[str, list[str]]:
    """Replace exact, non-interpolated Kotlin string literals in a source copy.

    Comments, identifiers, substrings, and template expressions are not edited.
    All edits refer to the original text, so A→B and B→C do not cascade.
    """
    mapping: dict[str, str] = {}
    for old, new in pairs:
        if not isinstance(old, str) or not isinstance(new, str):
            raise TypeError("치환 대상과 결과는 문자열이어야 합니다")
        if not old or not new:
            continue
        if old in mapping and mapping[old] != new:
            raise ValueError(f"치환 후보가 여러 개입니다: {old}")
        mapping[old] = new
    mapping = {old: new for old, new in mapping.items() if old != new}
    if not mapping:
        return text, []
    edits: list[tuple[int, int, str]] = []
    applied: set[str] = set()
    index = 0
    while index < len(text):
        if text.startswith(("//", "/*"), index):
            index = _skip_comment(text, index)
        elif text[index] == "'":
            index = _skip_character(text, index)
        elif text[index] == "`":
            index = _skip_identifier(text, index)
        elif text[index] == '"':
            end, value, interpolated = _read_kotlin_string(text, index)
            if not interpolated and value in mapping:
                edits.append((index, end, _kotlin_string(mapping[value])))
                applied.add(value)
            index = end
        else:
            index += 1
    if not edits:
        return text, []
    parts: list[str] = []
    cursor = 0
    for start, end, replacement in edits:
        parts.extend((text[cursor:start], replacement))
        cursor = end
    parts.append(text[cursor:])
    return "".join(parts), [f"{old} → {new}" for old, new in mapping.items() if old in applied]

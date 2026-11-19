"""APK/DEX inspection and JADX reporting, independent of the Qt UI."""
from __future__ import annotations
import hashlib
import json
import os
import shutil
import re
import struct
import subprocess
import sys
import zipfile
from datetime import datetime
from pathlib import Path
from .paths import app_dir
from .processes import CancelledError, check_cancelled, run_process
from .config import SKIP_PREFIX, CLASS_LIKE, DRIVER_APPS, APP_LABELS

def _uleb128(data: bytes, off: int) -> tuple[int, int]:
    """Decode one bounded DEX uleb128 value; invalid input raises ValueError."""
    if off < 0:
        raise ValueError("Negative DEX offset")
    result = 0
    for index in range(5):
        if off >= len(data):
            raise ValueError("Truncated DEX uleb128")
        value = data[off]
        off += 1
        if index == 4 and value > 0x0F:
            raise ValueError("DEX uleb128 overflow")
        result |= (value & 0x7F) << (index * 7)
        if not value & 0x80:
            return result, off
    raise ValueError("Oversized DEX uleb128")


def _dex_table(dex: bytes, size_at: int, offset_at: int, width: int) -> tuple[int, int]:
    if len(dex) < 0x70 or dex[:4] != b"dex\n":
        raise ValueError("Invalid DEX header")
    count = struct.unpack_from("<I", dex, size_at)[0]
    offset = struct.unpack_from("<I", dex, offset_at)[0]
    if count == 0:
        return 0, offset
    if offset < 0x70 or offset > len(dex) or count > (len(dex) - offset) // width:
        raise ValueError("DEX table extends beyond the file")
    return count, offset

def dex_string_set(dex: bytes) -> set[str]:
    """Display-sized DEX strings; malformed input has no reliable string evidence."""
    return {value for value in _dex_string_list(dex) if 3 <= len(value) <= 120}


def _checked_apk_dex_strings(data: bytes, entry_name: str) -> list[str]:
    """Do not turn a damaged DEX into a trustworthy all-missing result."""
    try:
        count, _ = _dex_table(data, 56, 60, 4)
        for size_at, offset_at, width in ((64, 68, 4), (72, 76, 12),
                                         (80, 84, 8), (88, 92, 8), (96, 100, 32)):
            _dex_table(data, size_at, offset_at, width)
        values = _dex_string_list(data)
        if len(values) != count:
            raise ValueError("Unreadable DEX string data")
        return values
    except CancelledError:
        raise
    except (ValueError, IndexError, struct.error) as error:
        raise RuntimeError(f"{entry_name}: DEX 구조가 손상됐거나 지원되지 않습니다") from error


def apk_interesting_strings(apk_path: Path) -> set[str]:
    check_cancelled()
    found: set[str] = set()
    try:
        with zipfile.ZipFile(apk_path, "r") as zf:
            names = zf.namelist()
            dex_names = [n for n in names if n == "classes.dex" or re.match(r"classes\d+\.dex$", n)]
            for dn in dex_names:
                check_cancelled()
                data = zf.read(dn)
                for s in _checked_apk_dex_strings(data, dn):
                    if 3 <= len(s) <= 120 and _keep_string(s):
                        found.add(s)
    except CancelledError:
        raise
    except Exception as e:
        raise RuntimeError(f"APK 읽기 실패: {e}") from e
    return found

def _keep_string(s: str) -> bool:
    if " " in s or "\n" in s or "\t" in s:
        return False
    low = s.lower()
    for p in SKIP_PREFIX:
        if low.startswith(p):
            return False
    # 패키지형 or 짧은 난독화 식별자
    if "." in s:
        if s.count(".") >= 1 and re.match(r"^[A-Za-z][\w.$]*$", s):
            return True
        return False
    # yi.i, gj.z0 같은 난독화
    if re.match(r"^[a-z][a-z0-9_]{0,3}(?:\.[a-z][a-z0-9_]{0,6})+$", s):
        return True
    if re.match(r"^[A-Za-z][\w$]{2,40}$", s) and not s.isupper():
        return True
    return False

SECURITY_PATTERNS = {
    "root_detect": [
        "isrooted", "is_rooted", "rootbeer", "rootcloak", "magisk", "supersu",
        "superuser", "/system/bin/su", "/system/xbin/su", "checkroot",
        "detectroot", "isdevicerooted", "rootcheck", "root_check", "bin/su",
    ],
    # 짧은 "exposed" 등 제거 — Material Design 오탐 방지
    "xposed_frida": [
        "xposedbridge", "lsposed", "edxposed", "de.robv.android.xposed",
        "xposedhelpers", "xposed_init", "libfrida", "frida-agent", "frida-gadget",
        "fridaserver", "substrate", "cydiasubstrate",
    ],
    "integrity": [
        "safetynet", "playintegrity", "play_integrity", "safetynetclient",
        "integritytoken", "appattest", "hardware_backed", "attestation",
    ],
    "debugger_emu": [
        "isdebuggerconnected", "android_sdk_built_for_x86", "genymotion",
        "goldfish", "ranchu", "nox_player", "bluestacks",
    ],
    "mock_gps": [
        "mocklocation", "mock_location", "allowmocklocation", "isfrommockprovider",
        "frommockprovider", "addtestprovider", "setmock", "fakegps", "mockprovider",
        "ismocklocation",
    ],
    "gps_location": [
        "fusedlocationproviderclient", "requestlocationupdates",
        "getlastknownlocation", "locationmanager", "locationservices",
    ],
    "ssl_pinning": [
        "certificatepinner", "certificate_pinner", "network_security_config",
        "publickeypin", "ssl_pinning", "okhttp3.certificatepinner",
    ],
}

API_HINTS = [
    "call-list", "calllist", "call_list", "call/accept", "/accept",
    "retrofit2", "okhttp3", "interceptor", "authorization", "bearer ",
    "websocket", "wss://",
]

LOGI_API_KEYWORDS = [
    "order", "alloc", "accept", "dispatch", "assign", "bidding",
    "callstate", "call_state", "orderno", "order_no", "orderid", "order_id",
    "receipt", "matching", "passenger", "dest", "pickup",
    "nfast", "bfast", "fastfilter", "strkeyword", "charge",
    "bFastFilterCheck", "strKeywordIncludingStart", "nFastChargeMax",
]

SYMBOL_NOISE_PREFIXES = (
    "androidx.",
    "android.",
    "com.google.",
    "com.android.",
    "kotlin.",
    "kotlinx.",
    "java.",
    "javax.",
    "okhttp3.",
    "okio.",
    "retrofit2.",
    "com.squareup.",
    "org.apache.",
    "com.facebook.",
    "com.bumptech.",
)

def _is_noise_symbol(name: str) -> bool:
    low = name.lower()
    if low.startswith(SYMBOL_NOISE_PREFIXES):
        return True
    if "mtrl_" in low or "material." in low:
        return True
    if "nestedscroll" in low or "jsonformatvisitor" in low:
        return True
    if "accessibility" in low or "autofill" in low:
        return True
    return False

def _dex_string_list(dex: bytes) -> list[str]:
    """Read the DEX string table while preserving symbol indexes."""
    check_cancelled()
    try:
        count, offset = _dex_table(dex, 56, 60, 4)
        out = []
        for index in range(count):
            if index % 1024 == 0:
                check_cancelled()
            string_offset = struct.unpack_from("<I", dex, offset + index * 4)[0]
            if string_offset < 0x70 or string_offset >= len(dex):
                raise ValueError("Invalid DEX string offset")
            _, start = _uleb128(dex, string_offset)
            end = dex.find(b"\0", start)
            if end < 0:
                raise ValueError("Unterminated DEX string")
            # DEX uses modified UTF-8. Preserve encoded NUL and surrogate pairs.
            raw = dex[start:end].replace(b"\xc0\x80", b"\0")
            value = raw.decode("utf-8", errors="surrogatepass")
            value = value.encode("utf-16-le", errors="surrogatepass").decode(
                "utf-16-le", errors="surrogatepass")
            out.append(value)
        return out
    except CancelledError:
        raise
    except (ValueError, IndexError, struct.error, UnicodeError):
        return []

def _dex_type_names(dex: bytes, strings: list[str]) -> list[str]:
    if len(dex) < 0x70:
        return []
    try:
        type_ids_size, type_ids_off = _dex_table(dex, 64, 68, 4)
        out = []
        for i in range(type_ids_size):
            if i % 1024 == 0:
                check_cancelled()
            idx = struct.unpack_from("<I", dex, type_ids_off + i * 4)[0]
            if 0 <= idx < len(strings):
                out.append(strings[idx])
            else:
                out.append("")
        return out
    except CancelledError:
        raise
    except Exception:
        return []

def _dex_method_symbols(dex: bytes) -> list[str]:
    """Lcom/foo/Bar;->methodName 형태 심볼 목록"""
    strings = _dex_string_list(dex)
    if not strings:
        return []
    types = _dex_type_names(dex, strings)
    if not types:
        return []
    try:
        method_ids_size, method_ids_off = _dex_table(dex, 88, 92, 8)
        out = []
        for i in range(method_ids_size):
            if i % 1024 == 0:
                check_cancelled()
            off = method_ids_off + i * 8
            class_idx = struct.unpack_from("<H", dex, off)[0]
            name_idx = struct.unpack_from("<I", dex, off + 4)[0]
            cls = types[class_idx] if class_idx < len(types) else "?"
            name = strings[name_idx] if name_idx < len(strings) else "?"
            # descriptor Lcom/foo; -> com.foo
            if cls.startswith("L") and cls.endswith(";"):
                pretty = cls[1:-1].replace("/", ".")
            else:
                pretty = cls
            out.append(f"{pretty}.{name}")
        return out
    except CancelledError:
        raise
    except Exception:
        return []

def _dex_field_symbols(dex: bytes) -> list[str]:
    strings = _dex_string_list(dex)
    if not strings:
        return []
    types = _dex_type_names(dex, strings)
    try:
        field_ids_size, field_ids_off = _dex_table(dex, 80, 84, 8)
        out = []
        for i in range(field_ids_size):
            if i % 1024 == 0:
                check_cancelled()
            off = field_ids_off + i * 8
            class_idx = struct.unpack_from("<H", dex, off)[0]
            name_idx = struct.unpack_from("<I", dex, off + 4)[0]
            cls = types[class_idx] if class_idx < len(types) else "?"
            name = strings[name_idx] if name_idx < len(strings) else "?"
            if cls.startswith("L") and cls.endswith(";"):
                pretty = cls[1:-1].replace("/", ".")
            else:
                pretty = cls
            out.append(f"{pretty}.{name}")
        return out
    except CancelledError:
        raise
    except Exception:
        return []

def apk_dex_symbols(apk_path: Path) -> dict:
    check_cancelled()
    methods: list[str] = []
    fields: list[str] = []
    types: list[str] = []
    with zipfile.ZipFile(apk_path, "r") as zf:
        for n in zf.namelist():
            check_cancelled()
            if n == "classes.dex" or re.match(r"classes\d+\.dex$", n):
                data = zf.read(n)
                _checked_apk_dex_strings(data, n)
                methods.extend(_dex_method_symbols(data))
                fields.extend(_dex_field_symbols(data))
                sl = _dex_string_list(data)
                types.extend(_dex_type_names(data, sl))
    return {
        "methods": methods,
        "fields": fields,
        "types": types,
    }

def _dex_method_id_names(dex: bytes) -> list[str]:
    """method_ids 인덱스 → 'com.foo.Bar.method' 목록"""
    strings = _dex_string_list(dex)
    if not strings:
        return []
    types = _dex_type_names(dex, strings)
    try:
        method_ids_size, method_ids_off = _dex_table(dex, 88, 92, 8)
        out = []
        for i in range(method_ids_size):
            if i % 1024 == 0:
                check_cancelled()
            off = method_ids_off + i * 8
            class_idx = struct.unpack_from("<H", dex, off)[0]
            name_idx = struct.unpack_from("<I", dex, off + 4)[0]
            cls = types[class_idx] if class_idx < len(types) else "?"
            name = strings[name_idx] if name_idx < len(strings) else "?"
            if cls.startswith("L") and cls.endswith(";"):
                pretty = cls[1:-1].replace("/", ".")
            else:
                pretty = cls
            out.append(f"{pretty}.{name}")
        return out
    except CancelledError:
        raise
    except Exception:
        return []

def _dex_invoke_edges(dex: bytes) -> list[tuple[str, str]]:
    """DEX invoke-* → (caller, callee) 목록. 부분 호출 그래프용."""
    strings = _dex_string_list(dex)
    if not strings:
        return []
    types = _dex_type_names(dex, strings)
    method_names = _dex_method_id_names(dex)
    if not method_names:
        return []
    try:
        class_defs_size, class_defs_off = _dex_table(dex, 96, 100, 32)
    except CancelledError:
        raise
    except Exception:
        return []

    edges: list[tuple[str, str]] = []
    seen: set[tuple[str, str]] = set()

    def add_edge(caller: str, callee: str) -> None:
        if not caller or not callee or caller == callee:
            return
        if _is_noise_symbol(caller) and _is_noise_symbol(callee):
            return
        key = (caller, callee)
        if key in seen:
            return
        seen.add(key)
        edges.append(key)

    def scan_code(code_off: int, caller: str) -> None:
        if not code_off or code_off + 16 > len(dex):
            return
        try:
            insns_size = struct.unpack_from("<I", dex, code_off + 12)[0]
            p = code_off + 16
            end = min(p + insns_size * 2, len(dex))
            while p + 2 <= end:
                if p % 1024 == 0:
                    check_cancelled()
                op = dex[p]
                if op in (0x6E, 0x6F, 0x70, 0x71, 0x72) and p + 6 <= end:
                    method_idx = struct.unpack_from("<H", dex, p + 2)[0]
                    if 0 <= method_idx < len(method_names):
                        add_edge(caller, method_names[method_idx])
                    p += 6
                    continue
                if op in (0x74, 0x75, 0x76, 0x77, 0x78) and p + 6 <= end:
                    method_idx = struct.unpack_from("<H", dex, p + 2)[0]
                    if 0 <= method_idx < len(method_names):
                        add_edge(caller, method_names[method_idx])
                    p += 6
                    continue
                p += _dalvik_width_bytes(op)
        except CancelledError:
            raise
        except Exception:
            return

    for ci in range(class_defs_size):

        if ci % 64 == 0:

            check_cancelled()
        try:
            cdef = class_defs_off + ci * 32
            class_idx = struct.unpack_from("<I", dex, cdef)[0]
            class_data_off = struct.unpack_from("<I", dex, cdef + 24)[0]
            if not class_data_off:
                continue
            owner = types[class_idx] if class_idx < len(types) else "?"
            if owner.startswith("L") and owner.endswith(";"):
                owner = owner[1:-1].replace("/", ".")
            if _is_noise_symbol(owner):
                continue
            off = class_data_off
            sf, off = _uleb128(dex, off)
            inf, off = _uleb128(dex, off)
            dm, off = _uleb128(dex, off)
            vm, off = _uleb128(dex, off)
            for _ in range(sf + inf):
                _, off = _uleb128(dex, off)
                _, off = _uleb128(dex, off)
            method_idx = 0
            for _ in range(dm):
                diff, off = _uleb128(dex, off)
                method_idx += diff
                _, off = _uleb128(dex, off)
                code_off, off = _uleb128(dex, off)
                caller = method_names[method_idx] if method_idx < len(method_names) else f"{owner}.?"
                scan_code(code_off, caller)
            method_idx = 0
            for _ in range(vm):
                diff, off = _uleb128(dex, off)
                method_idx += diff
                _, off = _uleb128(dex, off)
                code_off, off = _uleb128(dex, off)
                caller = method_names[method_idx] if method_idx < len(method_names) else f"{owner}.?"
                scan_code(code_off, caller)
        except CancelledError:
            raise
        except Exception:
            continue
    return edges

def apk_invoke_edges(apk_path: Path, package_filter: str = "") -> list[tuple[str, str]]:
    check_cancelled()
    edges: list[tuple[str, str]] = []
    seen: set[tuple[str, str]] = set()
    pf = package_filter.strip().lower()
    with zipfile.ZipFile(apk_path, "r") as zf:
        for n in zf.namelist():
            check_cancelled()
            if n == "classes.dex" or re.match(r"classes\d+\.dex$", n):
                for a, b in _dex_invoke_edges(zf.read(n)):
                    if pf and pf not in a.lower() and pf not in b.lower():
                        continue
                    key = (a, b)
                    if key in seen:
                        continue
                    seen.add(key)
                    edges.append(key)
    return edges

CALL_GRAPH_SEED_KEYWORDS = [
    "accept", "alloc", "order", "matching", "calllist", "call_list", "call-list",
    "dispatch", "pickup", "destination", "bfast", "nfast", "filter",
    "request", "socket", "notify", "refresh", "reload",
    "getorders", "makedaeri", "serviceallocate",
]

def build_partial_call_graph(
    edges: list[tuple[str, str]],
    seeds: list[str] | None = None,
    depth: int = 2,
    max_edges: int = 120,
) -> dict:
    """시드 심볼 주변 depth단계 호출 관계."""
    empty = {
        "seeds": [], "edges": [], "forward": [], "backward": [],
        "edge_count_total": 0, "edge_count_selected": 0,
    }
    if not edges:
        return empty

    seed_set: set[str] = set()
    for s in seeds or []:
        s = (s or "").strip()
        if s:
            seed_set.add(s)

    all_syms = set()
    for a, b in edges:
        all_syms.add(a)
        all_syms.add(b)

    for sym in all_syms:
        low = sym.lower()
        if _is_noise_symbol(sym):
            continue
        if any(k in low for k in CALL_GRAPH_SEED_KEYWORDS):
            if "accept" in low and not any(
                x in low for x in ("order", "call", "alloc", "daeri", "match", "list", "service")
            ):
                if not (low.endswith(".accept") or "acceptorder" in low or "doaccept" in low):
                    continue
            seed_set.add(sym)
            if len(seed_set) >= 40:
                break

    if not seed_set:
        empty["edge_count_total"] = len(edges)
        return empty

    fwd: dict[str, list[str]] = {}
    bwd: dict[str, list[str]] = {}
    for a, b in edges:
        fwd.setdefault(a, []).append(b)
        bwd.setdefault(b, []).append(a)

    selected: list[tuple[str, str]] = []
    selected_set: set[tuple[str, str]] = set()

    def walk(start_nodes: set[str], adj: dict[str, list[str]], out_list: list[str], forward: bool) -> None:
        frontier = set(start_nodes)
        visited = set(start_nodes)
        for _ in range(max(1, depth)):
            nxt = set()
            for node in frontier:
                for nei in adj.get(node, []):
                    e = (node, nei) if forward else (nei, node)
                    if e not in selected_set:
                        selected_set.add(e)
                        selected.append(e)
                        out_list.append(f"{e[0]}  →  {e[1]}")
                    if nei not in visited:
                        visited.add(nei)
                        nxt.add(nei)
                    if len(selected) >= max_edges:
                        return
            frontier = nxt
            if not frontier:
                break

    forward_lines: list[str] = []
    backward_lines: list[str] = []
    walk(set(seed_set), fwd, forward_lines, True)
    walk(set(seed_set), bwd, backward_lines, False)

    return {
        "seeds": sorted(seed_set)[:40],
        "edges": selected[:max_edges],
        "forward": forward_lines[:80],
        "backward": backward_lines[:80],
        "edge_count_total": len(edges),
        "edge_count_selected": len(selected),
    }

def _match_keywords(items: list[str], keywords: list[str], limit: int = 60) -> list[str]:
    hits = []
    seen = set()
    for item in items:
        low = item.lower()
        for kw in keywords:
            if kw in low:
                k = item.lower()
                if k not in seen:
                    seen.add(k)
                    hits.append(item)
                break
        if len(hits) >= limit:
            break
    return hits

def _all_apk_strings(apk_path: Path, max_len: int = 200) -> set[str]:
    check_cancelled()
    found: set[str] = set()
    try:
        with zipfile.ZipFile(apk_path, "r") as zf:
            for name in zf.namelist():
                check_cancelled()
                low = name.lower()
                if low.endswith(".dex") or name == "AndroidManifest.xml" or low.endswith(".so"):
                    try:
                        data = zf.read(name)
                    except CancelledError:
                        raise
                    except Exception:
                        continue
                    if low.endswith(".dex"):
                        for s in _checked_apk_dex_strings(data, name):
                            if 2 <= len(s) <= max_len:
                                found.add(s)
                    else:
                        cur = []
                        for b in data:
                            if 32 <= b < 127:
                                cur.append(chr(b))
                            else:
                                if len(cur) >= 4:
                                    found.add("".join(cur))
                                cur = []
                        if len(cur) >= 4:
                            found.add("".join(cur))
    except CancelledError:
        raise
    except Exception as e:
        raise RuntimeError(f"APK 읽기 실패: {e}") from e
    return found

def apk_meta(apk_path: Path) -> dict:
    check_cancelled()
    meta = {
        "file": str(apk_path),
        "size_mb": round(apk_path.stat().st_size / (1024 * 1024), 2),
        "dex_count": 0,
        "package_hints": [],
        "version_hints": [],
    }
    try:
        with zipfile.ZipFile(apk_path, "r") as zf:
            names = zf.namelist()
            meta["dex_count"] = sum(
                1 for n in names if n == "classes.dex" or re.match(r"classes\d+\.dex$", n)
            )
            strings: set[str] = set()
            for n in names:
                if n.endswith(".dex"):
                    strings |= dex_string_set(zf.read(n))
            pkgs = []
            vers = []
            for s in strings:
                if re.match(r"^com\.[a-zA-Z0-9_.]+$", s) and 8 <= len(s) <= 80:
                    pkgs.append(s)
                if re.match(r"^\d+\.\d+\.\d+", s) and len(s) <= 24:
                    vers.append(s)
            meta["package_hints"] = sorted(set(pkgs), key=len)[:30]
            meta["version_hints"] = sorted(set(vers))[:20]
    except CancelledError:
        raise
    except Exception as e:
        meta["error"] = str(e)
    return meta

def _dalvik_width_bytes(op: int) -> int:
    """code units * 2 — best-effort skip table"""
    # most common sizes; unknown defaults to 2 bytes
    u = {
        0x00: 1, 0x01: 1, 0x02: 2, 0x03: 3, 0x04: 1, 0x05: 2, 0x06: 3, 0x07: 1, 0x08: 2, 0x09: 3,
        0x0A: 1, 0x0B: 1, 0x0C: 1, 0x0D: 1, 0x0E: 1, 0x0F: 1, 0x10: 1, 0x11: 1, 0x12: 1, 0x13: 2,
        0x14: 3, 0x15: 2, 0x16: 2, 0x17: 3, 0x18: 5, 0x19: 2, 0x1A: 2, 0x1B: 3, 0x1C: 2, 0x1D: 1,
        0x1E: 1, 0x1F: 2, 0x20: 2, 0x21: 1, 0x22: 2, 0x23: 2, 0x24: 3, 0x25: 3, 0x26: 3, 0x27: 1,
        0x28: 1, 0x29: 2, 0x2A: 3, 0x2B: 3, 0x2C: 3, 0x32: 2, 0x33: 2, 0x34: 2, 0x35: 2, 0x36: 2,
        0x37: 2, 0x38: 2, 0x39: 2, 0x3A: 2, 0x3B: 2, 0x3C: 2, 0x3D: 2,
        0x44: 2, 0x45: 2, 0x46: 2, 0x47: 2, 0x48: 2, 0x49: 2, 0x4A: 2, 0x4B: 2, 0x4C: 2, 0x4D: 2,
        0x4E: 2, 0x4F: 2, 0x50: 2, 0x51: 2, 0x52: 2, 0x53: 2, 0x54: 2, 0x55: 2, 0x56: 2, 0x57: 2,
        0x58: 2, 0x59: 2, 0x5A: 2, 0x5B: 2, 0x5C: 2, 0x5D: 2, 0x5E: 2, 0x5F: 2, 0x60: 2, 0x61: 2,
        0x62: 2, 0x63: 2, 0x64: 2, 0x65: 2, 0x66: 2, 0x67: 2, 0x68: 2, 0x69: 2, 0x6A: 2, 0x6B: 2,
        0x6C: 2, 0x6D: 2, 0x6E: 3, 0x6F: 3, 0x70: 3, 0x71: 3, 0x72: 3, 0x74: 3, 0x75: 3, 0x76: 3,
        0x77: 3, 0x78: 3, 0x7B: 1, 0x90: 2, 0xB0: 1, 0xD0: 2, 0xD8: 2,
    }.get(op, 1)
    return u * 2

def _parse_dex_code_pref_keys(dex: bytes) -> list[dict]:
    """const-string -> SharedPreferences get/put 키 추출."""
    PREF_APIS = {
        "getSharedPreferences", "getDefaultSharedPreferences",
        "getString", "getInt", "getLong", "getBoolean", "getFloat", "getStringSet", "contains",
        "putString", "putInt", "putLong", "putBoolean", "putFloat", "putStringSet", "remove",
    }
    strings = _dex_string_list(dex)
    if not strings:
        return []
    types = _dex_type_names(dex, strings)
    try:
        method_ids_size, method_ids_off = _dex_table(dex, 88, 92, 8)
        method_names = []
        for i in range(method_ids_size):
            if i % 1024 == 0:
                check_cancelled()
            off = method_ids_off + i * 8
            name_idx = struct.unpack_from("<I", dex, off + 4)[0]
            method_names.append(strings[name_idx] if name_idx < len(strings) else "")
        class_defs_size, class_defs_off = _dex_table(dex, 96, 100, 32)
    except CancelledError:
        raise
    except Exception:
        return []

    results: list[dict] = []

    def maybe_add(key: str, api: str, owner: str, mname: str) -> None:
        if not key or not (2 <= len(key) <= 80) or " " in key or "\n" in key:
            return
        low = key.lower()
        if low.startswith("android.") or "accessibility" in low or low.startswith("com.google"):
            return
        if key.startswith("http://") or key.startswith("https://"):
            return
        results.append({"key": key, "api": api, "caller": f"{owner}.{mname}"})

    def handle_invoke(mn: str, regs: list, reg_str: dict, recent: list, owner: str, mname: str) -> None:
        if mn not in PREF_APIS:
            return
        key = None
        if len(regs) >= 2 and regs[1] in reg_str:
            si = reg_str[regs[1]]
            if 0 <= si < len(strings):
                key = strings[si]
        if not key:
            for si in reversed(recent[-5:]):
                if 0 <= si < len(strings):
                    cand = strings[si]
                    if cand and re.match(r"^[A-Za-z][A-Za-z0-9_.]{1,60}$", cand):
                        key = cand
                        break
        if key:
            maybe_add(key, mn, owner, mname)

    def scan_code(code_off: int, owner: str, mname: str) -> None:
        if not code_off or code_off >= len(dex):
            return
        try:
            insns_size = struct.unpack_from("<I", dex, code_off + 12)[0]
            p = code_off + 16
            end = min(p + insns_size * 2, len(dex))
            reg_str: dict[int, int] = {}
            recent: list[int] = []
            while p + 2 <= end:
                if p % 1024 == 0:
                    check_cancelled()
                op = dex[p]
                if op == 0x1A and p + 4 <= end:
                    va = dex[p + 1]
                    si = struct.unpack_from("<H", dex, p + 2)[0]
                    reg_str[va] = si
                    recent.append(si)
                    if len(recent) > 16:
                        recent.pop(0)
                    p += 4
                    continue
                if op == 0x1B and p + 6 <= end:
                    va = dex[p + 1]
                    si = struct.unpack_from("<I", dex, p + 2)[0]
                    reg_str[va] = si
                    recent.append(si)
                    if len(recent) > 16:
                        recent.pop(0)
                    p += 6
                    continue
                if op in (0x6E, 0x6F, 0x70, 0x71, 0x72) and p + 6 <= end:
                    ag = dex[p + 1]
                    argc = (ag >> 4) & 0xF
                    method_idx = struct.unpack_from("<H", dex, p + 2)[0]
                    packed = struct.unpack_from("<H", dex, p + 4)[0]
                    regs = [
                        packed & 0xF, (packed >> 4) & 0xF, (packed >> 8) & 0xF,
                        (packed >> 12) & 0xF, ag & 0xF,
                    ][:argc]
                    if method_idx < len(method_names):
                        handle_invoke(method_names[method_idx], regs, reg_str, recent, owner, mname)
                    p += 6
                    continue
                if op in (0x74, 0x75, 0x76, 0x77, 0x78) and p + 6 <= end:
                    count = dex[p + 1]
                    method_idx = struct.unpack_from("<H", dex, p + 2)[0]
                    start_reg = struct.unpack_from("<H", dex, p + 4)[0]
                    regs = list(range(start_reg, start_reg + count))
                    if method_idx < len(method_names):
                        handle_invoke(method_names[method_idx], regs, reg_str, recent, owner, mname)
                    p += 6
                    continue
                p += _dalvik_width_bytes(op)
        except CancelledError:
            raise
        except Exception:
            return

    for ci in range(class_defs_size):

        if ci % 64 == 0:

            check_cancelled()
        try:
            cdef = class_defs_off + ci * 32
            class_idx = struct.unpack_from("<I", dex, cdef)[0]
            class_data_off = struct.unpack_from("<I", dex, cdef + 24)[0]
            if not class_data_off:
                continue
            owner = types[class_idx] if class_idx < len(types) else "?"
            if owner.startswith("L") and owner.endswith(";"):
                owner = owner[1:-1].replace("/", ".")
            off = class_data_off
            sf, off = _uleb128(dex, off)
            inf, off = _uleb128(dex, off)
            dm, off = _uleb128(dex, off)
            vm, off = _uleb128(dex, off)
            for _ in range(sf + inf):
                _, off = _uleb128(dex, off)
                _, off = _uleb128(dex, off)
            method_idx = 0
            for _ in range(dm):
                diff, off = _uleb128(dex, off)
                method_idx += diff
                _, off = _uleb128(dex, off)
                code_off, off = _uleb128(dex, off)
                mn = method_names[method_idx] if method_idx < len(method_names) else "?"
                scan_code(code_off, owner, mn)
            method_idx = 0
            for _ in range(vm):
                diff, off = _uleb128(dex, off)
                method_idx += diff
                _, off = _uleb128(dex, off)
                code_off, off = _uleb128(dex, off)
                mn = method_names[method_idx] if method_idx < len(method_names) else "?"
                scan_code(code_off, owner, mn)
        except CancelledError:
            raise
        except Exception:
            continue

    out = []
    seen = set()
    for r in results:
        if r["key"] in seen:
            continue
        seen.add(r["key"])
        out.append(r)
    return out

def apk_pref_keys_from_bytecode(apk_path: Path, package_filter: str = "") -> list[dict]:
    check_cancelled()
    hits: list[dict] = []
    with zipfile.ZipFile(apk_path, "r") as zf:
        for n in zf.namelist():
            check_cancelled()
            if n == "classes.dex" or re.match(r"classes\d+\.dex$", n):
                hits.extend(_parse_dex_code_pref_keys(zf.read(n)))
    pf = package_filter.strip().lower()
    if pf:
        hits = [h for h in hits if pf in h.get("caller", "").lower()]
    priority = ("bfast", "nfast", "strkeyword", "order", "filter", "charge", "alloc", "accept")
    def score(h: dict) -> tuple:
        low = h["key"].lower()
        return (0 if any(p in low for p in priority) else 1, low)
    seen = set()
    out = []
    for h in sorted(hits, key=score):
        if h["key"] in seen:
            continue
        seen.add(h["key"])
        out.append(h)
    return out

def find_jadx(explicit: str | None = None) -> str | None:
    """Resolve an explicit path, saved selection, PATH, then portable/legacy locations."""
    def valid(candidate: str | Path) -> str | None:
        candidate = str(candidate).strip().strip('"')
        is_jar = candidate.startswith("JAR:")
        path = Path(candidate[4:] if is_jar else candidate).expanduser()
        if not path.is_file():
            return None
        if is_jar or path.suffix.lower() == ".jar":
            return "JAR:" + str(path.resolve())
        if path.suffix.lower() in (".bat", ".cmd") or path.name in ("jadx", "jadx-cli"):
            # Run Java directly instead of passing untrusted APK names through cmd.exe.
            lib = path.parent.parent / "lib"
            jars = sorted(lib.glob("jadx-*-all.jar")) + sorted(lib.glob("jadx-cli*.jar"))
            if jars:
                return "JAR:" + str(jars[0].resolve())
        return str(path.resolve())

    check_cancelled()
    if explicit and str(explicit).strip():
        return valid(explicit)
    saved = app_dir() / "jadx_path.txt"
    try:
        result = valid(saved.read_text(encoding="utf-8").strip())
        if result:
            return result
    except (OSError, ValueError):
        pass
    configured = os.environ.get("JADX_PATH")
    if configured:
        result = valid(configured)
        if result:
            return result
    for name in ("jadx", "jadx.bat", "jadx-cli", "jadx-cli.bat"):
        found = shutil.which(name)
        if found:
            result = valid(found)
            if result:
                return result
    for directory in (
        app_dir() / "tools/jadx/bin", app_dir() / "jadx/bin",
        Path("C:/Users/hjk01/OneDrive/바탕 화면/EUNORA/jadx/bin"),
    ):
        for name in ("jadx.bat", "jadx-cli.bat", "jadx", "jadx-cli"):
            result = valid(directory / name)
            if result:
                return result
        for jar in sorted(directory.glob("jadx*.jar")):
            result = valid(jar)
            if result:
                return result
    return None


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while block := source.read(1024 * 1024):
            check_cancelled()
            digest.update(block)
    return digest.hexdigest()


def _jadx_base_command(jadx: str) -> list[str]:
    if jadx.startswith("JAR:"):
        java_home = os.environ.get("JAVA_HOME")
        home_java = Path(java_home) / "bin" / ("java.exe" if os.name == "nt" else "java") if java_home else None
        java = str(home_java) if home_java and home_java.is_file() else shutil.which("java") or "java"
        jar = Path(jadx[4:])
        jars = sorted(jar.parent.glob("*.jar")) if "jadx-cli" in jar.name else [jar]
        classpath = os.pathsep.join(str(item.resolve()) for item in jars)
        return [java, "-cp", classpath, "jadx.cli.JadxCLI"]
    if Path(jadx).suffix.lower() in (".bat", ".cmd"):
        raise ValueError("JADX 배포본의 lib/jadx-*-all.jar를 함께 설치하거나 JAR 경로를 지정하세요")
    return [jadx]



def _java_inventory(directory: Path) -> dict[str, int]:
    result = {}
    for source in sorted(directory.rglob("*.java")):
        check_cancelled()
        result[source.relative_to(directory).as_posix()] = source.stat().st_size
    return result


def _prepare_jadx_cache(apk_path: Path, jadx: str, timeout: float) -> tuple[Path, dict]:
    apk_digest = _file_sha256(apk_path)
    tool_path = Path(jadx[4:] if jadx.startswith("JAR:") else jadx).resolve()
    base_command = _jadx_base_command(jadx)
    dependencies = []
    if jadx.startswith("JAR:") and "jadx-cli" in tool_path.name:
        dependencies = [
            {"path": str(item.resolve()), "sha256": _file_sha256(item)}
            for item in sorted(tool_path.parent.glob("*.jar"))
        ]
    identity = {
        "schema": 1, "apk_sha256": apk_digest, "dependencies": dependencies,
        "tool_path": str(tool_path), "tool_sha256": _file_sha256(tool_path),
        "command": base_command, "options": ["-j", "2", "--show-bad-code"],
    }
    fingerprint = hashlib.sha256(json.dumps(identity, sort_keys=True).encode()).hexdigest()
    out_dir = app_dir() / "jadx_out" / fingerprint[:24]
    manifest_path = out_dir / ".l-jadx-cache.json"
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        status_valid = isinstance(manifest, dict) and type(manifest.get("returncode")) is int and (
            (manifest.get("status") == "complete" and manifest["returncode"] == 0)
            or (manifest.get("status") == "partial" and manifest["returncode"] != 0)
        )
        if (status_valid and manifest.get("identity") == identity
                and manifest.get("fingerprint") == fingerprint
                and manifest.get("java_files")
                and manifest["java_files"] == _java_inventory(out_dir)):
            check_cancelled()
            return out_dir, manifest
    except (OSError, ValueError, TypeError):
        pass
    check_cancelled()
    if out_dir.is_symlink():
        raise ValueError("JADX 캐시 폴더가 심볼릭 링크입니다")
    if out_dir.exists():
        shutil.rmtree(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    command = base_command + ["-d", str(out_dir)] + identity["options"] + [str(apk_path)]
    process = run_process(command, timeout=timeout, encoding="utf-8", errors="replace")
    check_cancelled()
    java_files = _java_inventory(out_dir)
    if not java_files:
        detail = (process.stderr or process.stdout or "")[:800]
        raise RuntimeError(f"복원된 Java 소스가 없습니다 (exit={process.returncode})\n{detail}")
    manifest = {
        "fingerprint": fingerprint, "identity": identity, "apk_sha256": apk_digest,
        "status": "complete" if process.returncode == 0 else "partial",
        "returncode": process.returncode,
        "diagnostic": (process.stderr or process.stdout or "")[-2000:],
        "java_files": java_files,
    }
    check_cancelled()
    temporary = manifest_path.with_suffix(".tmp")
    temporary.write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")
    temporary.replace(manifest_path)
    return out_dir, manifest

def jadx_xref(
    apk_path: Path,
    symbols: list[str],
    timeout: float = 300.0,
    jadx_path: str | None = None,
) -> str:
    check_cancelled()
    jadx = find_jadx(jadx_path)
    if not jadx:
        return "[jadx 없음] JADX 경로를 jadx_path.txt 또는 JADX_PATH/PATH에 설정하세요. JDK도 필요합니다."
    try:
        (app_dir() / "jadx_path.txt").write_text(jadx, encoding="utf-8")
    except OSError:
        pass
    try:
        out_dir, cache_manifest = _prepare_jadx_cache(apk_path, jadx, timeout)
        cache_id = cache_manifest["fingerprint"]
        java_files = list(out_dir.rglob("*.java"))

        def read_java(jp: Path) -> list[str]:
            try:
                return jp.read_text(encoding="utf-8", errors="ignore").splitlines()
            except CancelledError:
                raise
            except Exception:
                return []

        def type_hints(chunk: str) -> str:
            cl = re.sub(r"\s+", "", chunk.lower())
            hints = []
            for api, label in (
                ("putboolean", "Boolean(put)"),
                ("getboolean", "Boolean(get)"),
                ("putint", "Int(put)"),
                ("getint", "Int(get)"),
                ("putlong", "Long(put)"),
                ("getlong", "Long(get)"),
                ("putstring", "String(put)"),
                ("getstring", "String(get)"),
                ("putfloat", "Float(put)"),
                ("getfloat", "Float(get)"),
                ("contains(", "contains"),
                ("sharedpreferences", "SharedPreferences"),
            ):
                if api in cl:
                    hints.append(label)
            if re.search(r"\btrue\b", chunk, re.I):
                hints.append("literal:true")
            if re.search(r"\bfalse\b", chunk, re.I):
                hints.append("literal:false")
            m = re.search(
                r"get(?:Boolean|Int|Long|String|Float)\s*\(\s*[^,]+,\s*([^)]+)\)",
                chunk,
            )
            if m:
                hints.append(f"default:{m.group(1).strip()[:40]}")
            return ", ".join(dict.fromkeys(hints)) if hints else "타입미상"

        def extract_string_literals(chunk: str) -> list[str]:
            return re.findall(r'"([^"\\]{1,80})"', chunk)

        def find_method_def(simple_name: str, max_hits: int = 2) -> list[str]:
            if not simple_name or len(simple_name) < 2:
                return []
            if simple_name in ("a", "b", "c", "d", "e", "f", "k", "l", "run", "get", "set"):
                return []
            out = []
            pat = re.compile(
                rf"(public|private|protected|static).*\b{re.escape(simple_name)}\s*\(",
            )
            for jp in java_files:
                check_cancelled()
                lines = read_java(jp)
                if not lines:
                    continue
                rel = str(jp.relative_to(out_dir))
                for i, line in enumerate(lines):
                    if not pat.search(line):
                        continue
                    out.append(f"  [정의후보] {rel}:{i+1}: {line.strip()[:140]}")
                    if len(out) >= max_hits:
                        return out
            return out

        def dump_match(rel: str, lines: list[str], idx: int) -> str:
            # 매칭 줄만 (위아래 없음)
            line = lines[idx].rstrip()[:200]
            hints = type_hints(line)
            lits = extract_string_literals(line)
            lit_s = ", ".join(f'"{x}"' for x in dict.fromkeys(lits) if len(x) > 1)[:300]
            parts = [f"  {rel}:{idx+1}  [{hints}]", f"  >> {line}"]
            if lit_s:
                parts.append(f"  리터럴: {lit_s}")
            return "\n".join(parts)

        lines_out = [
            f"jadx XREF — {apk_path.name}",
            f"jadx: {jadx}",
            f"출력: {out_dir}",
            f"캐시: {cache_id}  (APK·JADX 도구·옵션 확인)",
            f"복원 상태: {cache_manifest['status']} (exit={cache_manifest['returncode']})",
            "범위: 정적 문자열·정의 후보. 실제 훅 실행 여부는 포함하지 않습니다.",
            "※ 매칭 줄만 표시 (위아래 컨텍스트 없음)",
            "",
        ]

        for sym in symbols:
            if not sym or len(sym) < 2:
                continue
            needle = sym.split(".")[-1] if "." in sym else sym
            if len(needle) < 2:
                needle = sym
            blocks = []
            method_follow: list[str] = []
            for jp in java_files:
                check_cancelled()
                src_lines = read_java(jp)
                if not src_lines or not any(needle in ln for ln in src_lines):
                    continue
                rel = str(jp.relative_to(out_dir))
                for i, line in enumerate(src_lines):
                    if needle not in line:
                        continue
                    blocks.append(dump_match(rel, src_lines, i))
                    for a, b in re.findall(
                        r"\b([A-Za-z_][\w]*)\s*\.\s*([A-Za-z_][\w]*)\s*\(",
                        line,
                    ):
                        if b not in ("toString", "equals", "valueOf", "append", "value"):
                            method_follow.append(b)
                    if len(blocks) >= 8:
                        break
                if len(blocks) >= 8:
                    break
            lines_out.append(f"### {sym}")
            if blocks:
                lines_out.extend(blocks)
                followed = []
                seen_m = set()
                for mname in method_follow:
                    if mname in seen_m:
                        continue
                    seen_m.add(mname)
                    followed.extend(find_method_def(mname, max_hits=1))
                    if len(followed) >= 3:
                        break
                if followed:
                    lines_out.append("  --- 근처 메서드 정의 후보 ---")
                    lines_out.extend(followed)
            else:
                lines_out.append("  (이 APK 디컴파일 결과에 없음)")
            lines_out.append("")

        # 요청 심볼에 관련 키워드가 있을 때만 추가 스캔
        want_auto = any(
            any(k in (s or "").lower() for k in ("auto_matching", "calllist", "matching_filter"))
            for s in symbols
        )
        if want_auto:
            lines_out.append("======== 자동배차/필터 키 모음 (요청 심볼 관련) ========")
            key_pat = re.compile(
                r'"(auto_matching_filters[^"]*|matching[^"]*filter[^"]*|callList[^"]*)"',
                re.I,
            )
            key_hits: list[str] = []
            for jp in java_files:
                check_cancelled()
                src = read_java(jp)
                if not src:
                    continue
                rel = str(jp.relative_to(out_dir))
                text_j = "\n".join(src)
                if "auto_matching" not in text_j and "CallList" not in text_j and "callList" not in text_j:
                    continue
                for i, line in enumerate(src):
                    for m in key_pat.finditer(line):
                        key_hits.append(f"  {rel}:{i+1}: {m.group(0)}")
            seen_k = set()
            n = 0
            for k in key_hits:
                if k in seen_k:
                    continue
                seen_k.add(k)
                lines_out.append(k)
                n += 1
                if n >= 40:
                    break
            if not key_hits:
                lines_out.append("  (이 APK에 해당 키 문자열 없음)")
            lines_out.append("")

        report = "\n".join(lines_out)
        return ("[jadx 부분 복원]\n" + report) if cache_manifest["status"] == "partial" else report
    except subprocess.TimeoutExpired:
        return "[jadx 시간 초과]"
    except CancelledError:
        raise
    except Exception as e:
        return f"[jadx 오류] {e}"

def analyze_apk_structure(apk_path: Path, package_filter: str = "") -> dict:
    """
    단일 APK 정적 구조 분석.
    - 문자열만 있는 것 = 흔적(string)
    - 클래스/메서드/필드 심볼에 있으면 = 실제 심볼(symbol) → 호출 가능성 높음
    """
    check_cancelled()
    strings = _all_apk_strings(apk_path)
    symbols = apk_dex_symbols(apk_path)
    methods = symbols["methods"]
    fields = symbols["fields"]
    types = symbols["types"]

    # 패키지 필터 (예: com.logisoft) — 심볼 쪽만
    pf = package_filter.strip().lower()
    if pf:
        methods_f = [m for m in methods if pf in m.lower()]
        fields_f = [f for f in fields if pf in f.lower()]
        types_f = [t for t in types if pf in t.lower()]
    else:
        methods_f, fields_f, types_f = methods, fields, types

    def classify_group(keywords: list[str], drop_noise: bool = True) -> dict:
        str_hits = []
        seen_s = set()
        for s in strings:
            low = s.lower()
            if drop_noise and _is_noise_symbol(s):
                continue
            for kw in keywords:
                kl = kw.lower()
                if kl in low:
                    # 너무 짧은 키워드는 단어 경계에 가깝게
                    if len(kl) <= 4 and not (
                        low == kl or low.startswith(kl + ".") or low.endswith("." + kl)
                        or ("." + kl + ".") in low or low.endswith("/" + kl)
                    ):
                        continue
                    if low not in seen_s:
                        seen_s.add(low)
                        str_hits.append(s)
                    break
            if len(str_hits) >= 50:
                break

        sym_hits = []
        seen_m = set()
        for pool in (methods_f, fields_f, types_f):
            for item in pool:
                if drop_noise and _is_noise_symbol(item):
                    continue
                low = item.lower()
                for kw in keywords:
                    kl = kw.lower()
                    if kl in low:
                        if len(kl) <= 4 and kl not in low.replace("android", ""):
                            # accept 등: 메서드명 조각으로만 허용
                            if not any(
                                x in low
                                for x in (
                                    ".accept",
                                    "acceptorder",
                                    "orderaccept",
                                    "doaccept",
                                    "onaccept",
                                    "alloc",
                                    "order",
                                )
                            ) and kl == "accept":
                                continue
                        if low not in seen_m:
                            seen_m.add(low)
                            sym_hits.append(item)
                        break
                if len(sym_hits) >= 50:
                    break
            if len(sym_hits) >= 50:
                break

        return {
            "string_hits": str_hits[:40],
            "symbol_hits": sym_hits[:40],
            "likely_real": len(sym_hits) > 0,
        }

    security = {}
    for group, kws in SECURITY_PATTERNS.items():
        security[group] = classify_group(kws)

    # 로지/주문 수락 쪽 API (패키지 필터 적용된 methods_f 기준)
    logi_api = classify_group(LOGI_API_KEYWORDS, drop_noise=True)
    # 메서드만 한 번 더 좁히기
    logi_methods = []
    seen_lm = set()
    for m in methods_f:
        if _is_noise_symbol(m):
            continue
        low = m.lower()
        if any(k.lower() in low for k in LOGI_API_KEYWORDS):
            # Material/JSON visitor 제거
            if _is_noise_symbol(m):
                continue
            if low not in seen_lm:
                seen_lm.add(low)
                logi_methods.append(m)
            if len(logi_methods) >= 80:
                break
    logi_api["symbol_hits"] = logi_methods[:60]
    logi_api["likely_real"] = len(logi_methods) > 0

    urls = []
    for s in strings:
        low = s.lower()
        if low.startswith("http://") or low.startswith("https://") or low.startswith("wss://"):
            if len(s) <= 180:
                urls.append(s)
        elif s.startswith("/v") and len(s) < 100 and re.search(r"/v\d+/", s):
            urls.append(s)
        elif any(h in low for h in ("call-list", "calllist", "/accept", "/drive/")):
            if 4 <= len(s) <= 120:
                urls.append(s)
    urls = sorted(set(urls), key=str.lower)[:100]

    api_related = _match_keywords(list(strings), API_HINTS, 60)
    api_symbols = _match_keywords(methods_f, API_HINTS, 40)

    obfuscated = sorted(
        {
            s
            for s in strings
            if re.match(r"^[a-z][a-z0-9]{0,2}(?:\.[a-z][a-z0-9]{0,4}){1,3}$", s)
        }
    )[:80]

    # SharedPreferences: 메서드 심볼 + 앱 패키지 쪽 문자열 키 후보
    pref_methods = [
        m
        for m in methods_f
        if "sharedprefer" in m.lower()
        or "getsharedprefer" in m.lower()
        or m.lower().endswith(".getstring")
        or m.lower().endswith(".getlong")
        or m.lower().endswith(".getint")
        or "preference" in m.lower()
    ][:40]

    pref_name_candidates = []
    for s in strings:
        low = s.lower()
        if any(
            x in low
            for x in (
                "pref",
                "setting",
                "config",
                "token",
                "driver",
                "user",
                "session",
                "login",
                "device",
                "radius",
                "app_",
            )
        ):
            if re.match(r"^[A-Za-z][A-Za-z0-9_\.]{2,48}$", s) and " " not in s:
                # accessibility 노이즈 제외
                if "accessibility" in low or "autofill" in low:
                    continue
                pref_name_candidates.append(s)
    pref_name_candidates = sorted(set(pref_name_candidates), key=str.lower)[:60]

    pref_from_code = apk_pref_keys_from_bytecode(apk_path, package_filter)

    flags = []
    for group, title in [
        ("root_detect", "루트 탐지"),
        ("xposed_frida", "Xposed/Frida"),
        ("integrity", "무결성"),
        ("mock_gps", "Mock GPS"),
        ("ssl_pinning", "SSL 피닝"),
        ("debugger_emu", "디버거/에뮬"),
        ("gps_location", "GPS/위치"),
    ]:
        g = security.get(group) or {}
        if g.get("symbol_hits"):
            flags.append(f"{title}: DEX 참조 심볼 (실제 실행 여부 미확인)")
        elif g.get("string_hits"):
            flags.append(f"{title}: 문자열 후보 (정의·호출 여부 미확정)")

    call_graph = {
        "seeds": [], "edges": [], "forward": [], "backward": [],
        "edge_count_total": 0, "edge_count_selected": 0,
    }
    try:
        inv_edges = apk_invoke_edges(apk_path, package_filter=package_filter)
        seed_syms: list[str] = []
        for s in (logi_api.get("symbol_hits") or [])[:25]:
            seed_syms.append(s)
        for s in (api_symbols or [])[:15]:
            seed_syms.append(s)
        for g in security.values():
            for s in (g.get("symbol_hits") or [])[:5]:
                seed_syms.append(s)
        call_graph = build_partial_call_graph(
            inv_edges, seeds=seed_syms, depth=2, max_edges=120
        )
        call_graph["edge_count_total"] = len(inv_edges)
    except CancelledError:
        raise
    except Exception as e:
        call_graph["error"] = str(e)

    return {
        "meta": apk_meta(apk_path),
        "package_filter": package_filter,
        "flags": flags,
        "security": security,
        "urls": urls,
        "api_related": api_related,
        "api_symbols": api_symbols,
        "logi_api": logi_api,
        "obfuscated_classes": obfuscated,
        "pref_methods": pref_methods,
        "pref_name_candidates": pref_name_candidates,
        "pref_from_code": pref_from_code,
        "call_graph": call_graph,
        "string_count": len(strings),
        "method_count": len(methods),
        "note": "정적 후보 분석입니다. DEX 참조·문자열 발견은 함수 정의·훅 등록·실행 성공의 증명이 아닙니다.",
    }

def pick_deep_xref_symbols(result: dict, limit: int = 30) -> list[str]:
    """구조 분석 결과에서 XREF 가치가 높은 심볼 자동 선정."""
    scored = []

    def add(sym, score):
        s = (sym or "").strip()
        if not s or len(s) < 3 or len(s) > 120:
            return
        if _is_noise_symbol(s):
            return
        low = s.lower()
        noise = (
            "dispatchtouch", "dispatchkey", "dispatchdraw", "ondestroy",
            "nestedscroll", "jsonformat", ".jpg", ".png", ".jpeg",
            "accept-language", "audience_filter", "appsflyer",
            "allocateinstance", "removeeldest",
        )
        if any(x in low for x in noise):
            return
        scored.append((score, s))

    HIGH = (
        "auto_matching", "matching_filter", "calllist", "call_list", "call-list",
        "playintegrity", "integritytoken", "isrooted", "mocklocation", "frommock",
        "wheellocation", "acceptcall", "callaccept", "bfastfilter", "nfastcharge",
        "strkeyword", "fastfilter",
    )

    sec = result.get("security") or {}
    for g in sec.values():
        for s in g.get("symbol_hits") or []:
            add(s, 80)
        for s in g.get("string_hits") or []:
            low = s.lower()
            if any(h in low for h in HIGH):
                add(s, 90)
            elif any(m in low for m in ("calllist", "integrity", "rooted", "mock", "filter")):
                add(s, 55)

    for s in result.get("api_symbols") or []:
        low = s.lower()
        if "calllist" in low:
            add(s, 70)

    la = result.get("logi_api") or {}
    for s in la.get("symbol_hits") or []:
        low = s.lower()
        if any(h in low for h in ("calllist", "order", "accept", "alloc", "filter", "matching")):
            add(s, 75)
    for s in la.get("string_hits") or []:
        if any(h in s.lower() for h in HIGH) or "calllist" in s.lower():
            add(s, 85)

    for u in result.get("urls") or []:
        low = u.lower()
        if any(x in low for x in ("calllist", "call-list", "/accept", "matching")):
            if "schemas.android" not in low and "adobe" not in low:
                add(u, 60)

    for h in result.get("pref_from_code") or []:
        k = h.get("key") or ""
        low = k.lower()
        if any(x in low for x in (
            "filter", "matching", "integrity", "token", "rooted", "mock",
            "bfast", "nfast", "keyword", "charge", "call",
        )):
            add(k, 65)

    # 강제 심볼 없음 (카카오 전용 이름을 콜마너 분석에 넣지 않음)
    # 이 APK 구조 분석에서 실제로 나온 심볼/문자열만 선정

    scored.sort(key=lambda x: (-x[0], x[1].lower()))
    out = []
    seen = set()
    for sc, s in scored:
        key = s.lower()
        if key in seen:
            continue
        seen.add(key)
        out.append(s)
        if len(out) >= limit:
            break
    return out

def format_analysis_report(result: dict) -> str:
    lines = []
    m = result.get("meta") or {}
    lines.append("======== EUNORA L — APK 정적 구조 분석 ========")
    lines.append(f"파일: {m.get('file', '')}")
    lines.append(
        f"크기: {m.get('size_mb', '?')} MB  |  DEX: {m.get('dex_count', '?')}개  |  "
        f"문자열: {result.get('string_count', 0)}  |  메서드심볼: {result.get('method_count', 0)}"
    )
    if result.get("package_filter"):
        lines.append(f"패키지 필터: {result.get('package_filter')}")
    lines.append("")
    lines.append("[패키지 힌트]")
    for p in (m.get("package_hints") or [])[:15]:
        lines.append(f"  {p}")
    lines.append("")
    lines.append("[버전 힌트]")
    for v in (m.get("version_hints") or [])[:10]:
        lines.append(f"  {v}")
    lines.append("")
    lines.append("[보안·환경 정적 후보 요약]")
    lines.append("  문자열/참조 발견과 실제 실행·탐지는 별도입니다.")
    flags = result.get("flags") or []
    if flags:
        for f in flags:
            lines.append(f"  ! {f}")
    else:
        lines.append("  (해당 키워드 약함)")
    lines.append("")

    labels = {
        "root_detect": "루트 탐지",
        "xposed_frida": "Xposed / Frida",
        "integrity": "무결성 (SafetyNet 등)",
        "debugger_emu": "디버거 / 에뮬레이터",
        "mock_gps": "Mock GPS / 가짜 위치",
        "gps_location": "GPS / 위치",
        "ssl_pinning": "SSL 피닝",
    }
    sec = result.get("security") or {}
    for key, title in labels.items():
        g = sec.get(key) or {}
        sym = g.get("symbol_hits") or []
        st = g.get("string_hits") or []
        lines.append(f"--- {title} ---")
        lines.append(f"  [DEX 참조 class/method/field] {len(sym)}개")
        if sym:
            for it in sym[:25]:
                lines.append(f"    SYM  {it}")
        else:
            lines.append("    (없음)")
        lines.append(f"  [문자열만] {len(st)}개")
        if st:
            for it in st[:20]:
                lines.append(f"    STR  {it}")
        else:
            lines.append("    (없음)")
        lines.append("")

    lines.append(f"--- URL / API 경로 ({len(result.get('urls') or [])}) ---")
    for u in (result.get("urls") or [])[:50]:
        lines.append(f"  {u}")
    lines.append("")
    lines.append(f"--- API 관련 메서드 심볼 (범용, 참고) ({len(result.get('api_symbols') or [])}) ---")
    for a in (result.get("api_symbols") or [])[:20]:
        lines.append(f"  SYM  {a}")
    lines.append("")
    la = result.get("logi_api") or {}
    lines.append(
        f"--- 주문/수락 API 후보 (로지 등, 패키지 필터 권장) "
        f"심볼 {len(la.get('symbol_hits') or [])} / 문자열 {len(la.get('string_hits') or [])} ---"
    )
    lines.append("  키워드: order, alloc, accept, dispatch, bFastFilterCheck 등")
    for a in (la.get("symbol_hits") or [])[:50]:
        lines.append(f"  SYM  {a}")
    for a in (la.get("string_hits") or [])[:30]:
        lines.append(f"  STR  {a}")
    if not (la.get("symbol_hits") or la.get("string_hits")):
        lines.append("  (없음 — 패키지 필터를 com.logisoft 등으로 넣어보세요)")
    lines.append("")
    lines.append(f"--- SharedPreferences 관련 메서드 ({len(result.get('pref_methods') or [])}) ---")
    for p in (result.get("pref_methods") or [])[:30]:
        lines.append(f"  SYM  {p}")
    lines.append("")
    lines.append(
        f"--- SharedPreferences 키 (바이트코드 const-string 추적) ({len(result.get('pref_from_code') or [])}) ---"
    )
    lines.append("  getSharedPreferences(\"키\") 호출에 연결된 상수 — 로지 전용 키는 여기 우선")
    for h in (result.get("pref_from_code") or [])[:50]:
        lines.append(f"  KEY  {h.get('key')}  <= {h.get('api')}  @ {h.get('caller')}")
    if not (result.get("pref_from_code") or []):
        lines.append("  (없음 — 난독화/동적 키일 수 있음)")
    lines.append("")
    lines.append(
        f"--- Pref/설정 키 후보 문자열 (참고) ({len(result.get('pref_name_candidates') or [])}) ---"
    )
    for p in (result.get("pref_name_candidates") or [])[:30]:
        lines.append(f"  {p}")
    lines.append("")
    lines.append(f"--- 난독화 클래스형 ({len(result.get('obfuscated_classes') or [])}) ---")
    for o in (result.get("obfuscated_classes") or [])[:40]:
        lines.append(f"  {o}")
    lines.append("")

    cg = result.get("call_graph") or {}
    lines.append(
        f"--- 부분 호출 그래프 (DEX invoke) "
        f"전체간선 {cg.get('edge_count_total', 0)} / 선택 {cg.get('edge_count_selected', 0)} ---"
    )
    lines.append("  시드(수락/리스트/매칭 등) 주변 depth=2. 완벽한 전체 그래프는 아님.")
    if cg.get("error"):
        lines.append(f"  [오류] {cg.get('error')}")
    seeds = cg.get("seeds") or []
    lines.append(f"  [시드 {len(seeds)}개]")
    for s in seeds[:25]:
        lines.append(f"    SEED  {s}")
    fwd = cg.get("forward") or []
    lines.append(f"  [호출 방향 → 시드에서 나가는 쪽 {len(fwd)}]")
    for line in fwd[:50]:
        lines.append(f"    {line}")
    if not fwd:
        lines.append("    (없음)")
    bwd = cg.get("backward") or []
    lines.append(f"  [역방향 → 시드로 들어오는 쪽 {len(bwd)}]")
    for line in bwd[:50]:
        lines.append(f"    {line}")
    if not bwd:
        lines.append("    (없음)")
    lines.append("")
    lines.append("======== 끝 ========")
    return "\n".join(lines)

def diff_apk(old_path: Path, new_path: Path) -> dict:
    check_cancelled()
    old_s = apk_interesting_strings(old_path)
    new_s = apk_interesting_strings(new_path)
    added = sorted(new_s - old_s)
    removed = sorted(old_s - new_s)
    return {
        "old_count": len(old_s),
        "new_count": len(new_s),
        "added": added,
        "removed": removed,
    }

def apk_has_needle(apk_path: Path, needle: str) -> bool:
    """Find static text evidence in decompressed DEX strings, never ZIP carrier bytes."""
    result = check_needles(apk_path, [needle])
    return result[0][1] if result else False

def check_needles(apk_path: Path, needles: list[str]) -> list[tuple[str, bool]]:
    """Read each DEX table once for a batch of static string checks."""
    requested = [needle for needle in needles if needle]
    if not requested:
        return []
    check_cancelled()
    if not apk_path.is_file():
        return [(needle, False) for needle in requested]
    strings = set()
    with zipfile.ZipFile(apk_path) as archive:
        for name in archive.namelist():
            check_cancelled()
            if re.fullmatch(r"classes(?:[0-9]+)?\.dex", name):
                strings.update(value.lower() for value in _checked_apk_dex_strings(archive.read(name), name))
    return [(needle, any(needle.lower() in value for value in strings)) for needle in requested]

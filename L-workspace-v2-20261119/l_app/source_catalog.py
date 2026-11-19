"""Conservative Kotlin reflection inventory for EUNORA's selected app file.

This is a bounded lexical scan, not a Kotlin evaluator. Only literal class names
and unambiguously bound method names are returned as targets. No source is run
or modified, and unresolved expressions remain visible in the report.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
from pathlib import Path
import re

from .generator import load_profiles, resolve_project
from .processes import check_cancelled


@dataclass(frozen=True)
class _Token:
    text: str
    kind: str
    line: int
    scope: tuple[int, ...]
    value: str | None = None


_PLATFORM = ("java.", "javax.", "android.", "dalvik.", "kotlin.")
_METHODS = {"getMethod", "getDeclaredMethod"}


def _template_end(source, opening):
    """Skip ${...}, including nested strings, without interpreting its code."""
    depth = 1
    offset = opening + 1
    while offset < len(source):
        if offset % 1024 == 0:
            check_cancelled()
        if source.startswith("//", offset):
            end = source.find("\n", offset + 2)
            offset = len(source) if end < 0 else end
            continue
        if source.startswith("/*", offset):
            comments = 1
            offset += 2
            while offset < len(source) and comments:
                if source.startswith("/*", offset):
                    comments += 1
                    offset += 2
                elif source.startswith("*/", offset):
                    comments -= 1
                    offset += 2
                else:
                    offset += 1
            continue
        if source[offset] in {'"', "'"}:
            offset = _quoted_end(source, offset)
            continue
        if source[offset] == "{":
            depth += 1
        elif source[offset] == "}":
            depth -= 1
            if not depth:
                return offset + 1
        offset += 1
    raise ValueError("Kotlin 문자열 보간식의 끝을 확인할 수 없습니다")


def _quoted_end(source, start):
    quote = source[start]
    raw = source.startswith('"""', start)
    marker = '"""' if raw else quote
    offset = start + len(marker)
    while offset < len(source):
        if source.startswith(marker, offset):
            return offset + len(marker)
        if not raw and source[offset] == "\\":
            offset += 2
            continue
        if quote == '"' and source.startswith("${", offset):
            offset = _template_end(source, offset + 1)
            continue
        offset += 1
    raise ValueError("Kotlin 문자열의 끝을 확인할 수 없습니다")


def _lex(source: str) -> list[_Token]:
    tokens: list[_Token] = []
    offset = 0
    line = 1
    scope: list[int] = []
    block = 0
    while offset < len(source):
        if offset % 1024 == 0:
            check_cancelled()
        char = source[offset]
        if char.isspace():
            line += char == "\n"
            offset += 1
            continue
        if source.startswith("//", offset):
            end = source.find("\n", offset + 2)
            offset = len(source) if end < 0 else end
            continue
        if source.startswith("/*", offset):
            depth = 1
            offset += 2
            while offset < len(source) and depth:
                if source.startswith("/*", offset):
                    depth += 1
                    offset += 2
                elif source.startswith("*/", offset):
                    depth -= 1
                    offset += 2
                else:
                    line += source[offset] == "\n"
                    offset += 1
            if depth:
                raise ValueError("Kotlin 블록 주석의 끝을 확인할 수 없습니다")
            continue
        start_line = line
        if source.startswith('"""', offset):
            end = _quoted_end(source, offset)
            value = source[offset + 3:end - 3]
            dynamic = "$" in value
            line += value.count("\n")
            tokens.append(_Token("", "dynamic" if dynamic else "string", start_line,
                                 tuple(scope), None if dynamic else value))
            offset = end
            continue
        if char in {'"', "'"}:
            quote = char
            offset += 1
            value: list[str] = []
            dynamic = False
            closed = False
            while offset < len(source):
                char = source[offset]
                if char == quote:
                    offset += 1
                    closed = True
                    break
                if char == "\\":
                    offset += 1
                    if offset >= len(source):
                        break
                    escaped = source[offset]
                    if escaped == "u" and re.fullmatch(r"[0-9a-fA-F]{4}", source[offset + 1:offset + 5]):
                        value.append(chr(int(source[offset + 1:offset + 5], 16)))
                        offset += 5
                        continue
                    known = {"t": "\t", "b": "\b", "n": "\n", "r": "\r", "'": "'", '"': '"', "\\": "\\", "$": "$"}
                    if escaped not in known:
                        dynamic = True
                    value.append(known.get(escaped, escaped))
                    offset += 1
                    continue
                if char == "$" and quote == '"':
                    dynamic = True
                    if source.startswith("${", offset):
                        end = _template_end(source, offset + 1)
                        line += source[offset:end].count("\n")
                        offset = end
                        continue
                if char == "\n":
                    line += 1
                value.append(char)
                offset += 1
            if not closed:
                raise ValueError("Kotlin 문자열/문자 리터럴의 끝을 확인할 수 없습니다")
            kind = "char" if quote == "'" else "dynamic" if dynamic else "string"
            tokens.append(_Token("", kind, start_line, tuple(scope), "".join(value) if kind == "string" else None))
            continue
        if char == "`":
            end = source.find("`", offset + 1)
            if end < 0 or "\n" in source[offset:end]:
                raise ValueError("Kotlin 식별자의 끝을 확인할 수 없습니다")
            tokens.append(_Token(source[offset + 1:end], "id", line, tuple(scope)))
            offset = end + 1
            continue
        if char.isalpha() or char == "_":
            end = offset + 1
            while end < len(source) and (source[end].isalnum() or source[end] == "_"):
                end += 1
            tokens.append(_Token(source[offset:end], "id", line, tuple(scope)))
            offset = end
            continue
        if char == "}":
            if not scope:
                raise ValueError("Kotlin 블록의 괄호가 일치하지 않습니다")
            scope.pop()
        tokens.append(_Token(char, "punct", line, tuple(scope)))
        if char == "{":
            block += 1
            scope.append(block)
        offset += 1
    if scope:
        raise ValueError("Kotlin 블록의 끝을 확인할 수 없습니다")
    check_cancelled()
    return tokens


def _pairs(tokens):
    stacks = {"(": [], "[": [], "{": []}
    reverse = {")": "(", "]": "[", "}": "{"}
    pairs = {}
    for i, token in enumerate(tokens):
        if i % 1024 == 0:
            check_cancelled()
        if token.text in stacks:
            stacks[token.text].append(i)
        elif token.text in reverse:
            stack = stacks[reverse[token.text]]
            if not stack:
                raise ValueError("Kotlin 식의 괄호가 일치하지 않습니다")
            opening = stack.pop()
            pairs[opening] = i
            pairs[i] = opening
    if any(stacks.values()):
        raise ValueError("Kotlin 식의 끝을 확인할 수 없습니다")
    return pairs


def _ancestor(parent, child):
    return child[:len(parent)] == parent


def _first_literal(tokens, opening, pairs):
    end = pairs.get(opening)
    if end is None or opening + 1 >= end:
        return None
    first = tokens[opening + 1]
    following = tokens[opening + 2].text if opening + 2 <= end else ""
    return first.value if first.kind == "string" and following in {",", ")"} else None


def _class_name(value):
    if not value or any(not part for part in value.split(".")):
        return False
    return all(c.isalnum() or c in "._$" for c in value)


def _functions(tokens, pairs):
    """Prove only one-parameter expression helpers that directly call Class.forName."""
    functions = []
    body_calls = set()
    for i in range(len(tokens) - 5):
        if tokens[i].text != "fun" or tokens[i + 1].kind != "id" or tokens[i + 2].text != "(":
            continue
        close = pairs.get(i + 2)
        if close is None:
            continue
        name = tokens[i + 1].text
        signature = [t.text for t in tokens[i + 3:close]]
        cursor = close + 1
        # An optional explicit return type must fit on this declaration line.
        if cursor < len(tokens) and tokens[cursor].text == ":":
            while cursor < len(tokens) and tokens[cursor].text not in {"=", "{"} and tokens[cursor].line == tokens[close].line:
                cursor += 1
        proven = False
        if cursor + 6 < len(tokens) and tokens[cursor].text == "=" and len(signature) == 3 and signature[1:] == [":", "String"]:
            body = [t.text for t in tokens[cursor + 1:cursor + 7]]
            proven = body == ["Class", ".", "forName", "(", signature[0], ","] or body[:5] == ["Class", ".", "forName", "(", signature[0]] and body[5] == ")"
            call_end = pairs.get(cursor + 4)
            if proven and call_end is not None and call_end + 1 < len(tokens):
                following = tokens[call_end + 1]
                # The entire helper expression must return the reflected Class.
                # A chain, Elvis expression or another operator can change it.
                proven = following.text in {";", "}"} or (
                    following.line > tokens[call_end].line and
                    following.text not in {".", "?", "+", "-", "*", "/", "[", "!", "=", "&", "|", ":"}
                )
            if proven:
                body_calls.add(cursor + 1)
        functions.append(dict(name=name, scope=tokens[i].scope, pos=i, proven=proven))
    return functions, body_calls


def _declarations(tokens):
    declarations = []
    declaration_names = set()
    for i, token in enumerate(tokens[:-1]):
        if token.text not in {"val", "var"} or tokens[i + 1].kind != "id":
            continue
        name = tokens[i + 1].text
        equals = None
        for cursor in range(i + 2, min(len(tokens), i + 40)):
            current = tokens[cursor]
            if current.line != token.line or current.text in {";", "{", "}", ",", ")"}:
                break
            if current.text == "=":
                equals = cursor
                break
        declarations.append(dict(name=name, scope=token.scope, pos=i, equals=equals, class_name=None))
        declaration_names.add(i + 1)
    assignments = [(i, token.text) for i, token in enumerate(tokens[:-1])
                   if token.kind == "id" and i not in declaration_names and tokens[i + 1].text == "="
                   and (i + 2 >= len(tokens) or tokens[i + 2].text != "=")
                   and (i == 0 or tokens[i - 1].text not in {".", "="})]
    return declarations, assignments


def _nearest(records, name, pos, scope):
    visible = [r for r in records if r["name"] == name and r["pos"] < pos and _ancestor(r["scope"], scope)]
    return max(visible, key=lambda r: (len(r["scope"]), r["pos"])) if visible else None


def _parameter_shadows(tokens, pairs):
    """Parameter/lambda names hide outer vals but don't prove any Class value."""
    ranges = []
    for i, token in enumerate(tokens):
        if token.text in {"fun", "catch", "for", "class"}:
            opening = next((j for j in range(i + 1, min(len(tokens), i + 30))
                            if tokens[j].text in {"(", "{", "="}), None)
            if opening is None or tokens[opening].text != "(":
                continue
            close = pairs.get(opening)
            if close is None:
                continue
            body = close + 1
            while body < len(tokens) and tokens[body].text not in {"{", "=", ";", "}"}:
                if tokens[body].text in {"fun", "val", "var", "class"}:
                    break
                body += 1
            if body >= len(tokens) or tokens[body].text not in {"{", "="}:
                continue
            if tokens[body].text == "{":
                end = pairs[body]
            else:
                end = next((j for j in range(body + 1, len(tokens))
                            if tokens[j].line > tokens[body].line or tokens[j].text in {";", "}"}), len(tokens))
            names = [tokens[j].text for j in range(opening + 1, close - 1)
                     if tokens[j].kind == "id" and tokens[j + 1].text == ":"]
            if token.text == "for":
                before_in = next((j for j in range(opening + 1, close) if tokens[j].text == "in"), close)
                names.extend(t.text for t in tokens[opening + 1:before_in] if t.kind == "id")
            ranges.extend((name, body, end) for name in names)
        if token.text == "{":
            close = pairs[i]
            arrow = None
            for j in range(i + 1, min(close, i + 45)):
                if tokens[j].text in {"{", "}", "=", ";"}:
                    break
                if tokens[j].text == "-" and j + 1 < close and tokens[j + 1].text == ">":
                    arrow = j
                    break
            if arrow is not None:
                names = [t.text for t in tokens[i + 1:arrow] if t.kind == "id"]
                ranges.extend((name, arrow, close) for name in names)
    return ranges


def _scan(source: str, filename: str):
    tokens = _lex(source)
    pairs = _pairs(tokens)
    functions, body_calls = _functions(tokens, pairs)
    declarations, assignments = _declarations(tokens)
    shadows = _parameter_shadows(tokens, pairs)
    calls = {}
    unresolved = []
    found = {}
    excluded = set()

    def unclear(index, reason):
        unresolved.append(dict(file=filename, line=tokens[index].line, reason=reason))

    def record(owner, index, method=None, lookup=None):
        if owner.startswith(_PLATFORM):
            excluded.add(owner)
            return
        row = found.setdefault(owner, dict(class_name=owner, methods=set(), locations=set(), confidence="literal", method_refs=[]))
        row["locations"].add((filename, tokens[index].line))
        if method:
            row["methods"].add(method)
            reference = dict(name=method, lookup=lookup, file=filename, line=tokens[index].line)
            if reference not in row["method_refs"]:
                row["method_refs"].append(reference)

    for i, token in enumerate(tokens):
        if i % 256 == 0:
            check_cancelled()
        opening = None
        if i + 3 < len(tokens) and [t.text for t in tokens[i:i + 4]] == ["Class", ".", "forName", "("]:
            if i in body_calls:
                continue
            opening = i + 3
        elif token.text == "loadClass" and i > 0 and tokens[i - 1].text == "." and i + 1 < len(tokens) and tokens[i + 1].text == "(":
            opening = i + 1
        elif token.kind == "id" and i + 1 < len(tokens) and tokens[i + 1].text == "(" and (i == 0 or tokens[i - 1].text not in {".", "fun"}):
            helper = _nearest(functions, token.text, i, token.scope)
            shadow = _nearest(declarations, token.text, i, token.scope)
            parameter_shadow = any(name == token.text and start < i < end for name, start, end in shadows)
            if helper and helper["proven"] and not parameter_shadow and not (shadow and len(shadow["scope"]) >= len(helper["scope"]) and shadow["pos"] > helper["pos"]):
                opening = i + 1
        if opening is None:
            continue
        value = _first_literal(tokens, opening, pairs)
        if value is None or not _class_name(value):
            unclear(i, "동적·보간식·복합 클래스 이름은 정적으로 확정하지 않았습니다")
            continue
        calls[i] = dict(class_name=value, end=pairs[opening])
        record(value, i)

    for declaration in declarations:
        eq = declaration["equals"]
        if eq is None:
            continue
        start = eq + 1
        call = calls.get(start)
        # Qualified Class and loader.loadClass expressions can start before the
        # recognizer's final identifier. A plain identifier/dot prefix is safe;
        # a preceding invocation or operator can produce an unrelated receiver.
        if not call:
            for position, candidate in calls.items():
                if position <= start:
                    continue
                prefix = tokens[start:position]
                if prefix and len(prefix) % 2 == 0 and all(
                    t.kind == "id" if index % 2 == 0 else t.text == "."
                    for index, t in enumerate(prefix)
                ):
                    call = candidate
                    break
        if not call:
            continue
        after = call["end"] + 1
        # A following member access can turn a Class into a different object.
        if after < len(tokens):
            following = tokens[after]
            if following.text in {".", "?", "[", "+", "-", "*", "/", "%", "!", "&", "|", "^", "=", "<", ">", ":"}:
                continue
            if following.line == tokens[call["end"]].line and following.text not in {";", "}", ")", ","}:
                continue
        declaration["class_name"] = call["class_name"]

    call_ends = {call["end"]: call["class_name"] for call in calls.values()}
    for i, token in enumerate(tokens):
        if i % 256 == 0:
            check_cancelled()
        if token.text not in _METHODS or i < 2 or tokens[i - 1].text != "." or i + 1 >= len(tokens) or tokens[i + 1].text != "(":
            continue
        owner = None
        receiver = tokens[i - 2]
        if receiver.kind == "id" and (i < 3 or tokens[i - 3].text != "."):
            declaration = _nearest(declarations, receiver.text, i, token.scope)
            # Nested blocks can introduce implicit lambda receivers, destructured
            # vals and other Kotlin scopes this lexer does not fully evaluate.
            # Bind only a declaration in this exact brace scope; outer owners
            # remain unresolved rather than silently selecting a wrong class.
            if declaration and declaration["class_name"] and declaration["scope"] == token.scope:
                changed = any(declaration["pos"] < pos < i and name == receiver.text for pos, name in assignments)
                hidden = any(name == receiver.text and start < i < end for name, start, end in shadows)
                if not changed and not hidden:
                    owner = declaration["class_name"]
        elif receiver.text == ")":
            owner = call_ends.get(i - 2)
        method = _first_literal(tokens, i + 1, pairs)
        if not owner or method is None:
            unclear(i, "메서드 소유 클래스 또는 메서드 이름을 리터럴 근거로 확정하지 못했습니다")
            continue
        record(owner, i, method, token.text)

    for i in range(2, len(tokens)):
        if tokens[i - 1].text == "." and tokens[i].text in {"declaredMethods", "methods", "declaredConstructors", "getDeclaredConstructor", "getConstructor"}:
            unclear(i, "동적 메서드·생성자 선택은 이름 목록 대조에 포함하지 않았습니다")
    targets = []
    for owner in sorted(found):
        row = found[owner]
        row["methods"] = sorted(row["methods"])
        row["locations"] = [dict(file=file, line=line) for file, line in sorted(row["locations"])]
        targets.append(row)
    # Repeated expressions on one source line need only one explanation.
    unresolved = [dict(file=f, line=n, reason=r) for f, n, r in sorted({(r["file"], r["line"], r["reason"]) for r in unresolved})]
    return targets, unresolved, excluded


def collect_source_catalog(project_path, app_key) -> dict:
    """Read selected E file and snapshot hashes, preserving both original files."""
    check_cancelled()
    profiles = load_profiles()
    if app_key not in profiles:
        raise ValueError("지원하는 EUNORA 앱 프로필을 선택해 주세요")
    root = resolve_project(project_path)
    prefix = Path("app/src/main/java/com/example/wheelprobe")
    snapshots = {}
    for name in ("ModuleMain.kt", profiles[app_key]["source_file"]):
        relative = (prefix / name).as_posix()
        path = root / relative
        if not path.is_file() or not path.resolve().is_relative_to(root):
            raise ValueError(f"프로젝트 안의 소스를 찾을 수 없습니다: {relative}")
        snapshots[relative] = path.read_bytes()
        check_cancelled()
    selected = (prefix / profiles[app_key]["source_file"]).as_posix()
    try:
        source = snapshots[selected].decode("utf-8-sig", errors="strict")
    except UnicodeError as error:
        raise ValueError("EUNORA Kotlin 소스는 UTF-8이어야 합니다") from error
    targets, unresolved, excluded = _scan(source, selected)
    hashes = {name: hashlib.sha256(raw).hexdigest() for name, raw in snapshots.items()}
    for name, raw in snapshots.items():
        check_cancelled()
        if (root / name).read_bytes() != raw:
            raise ValueError("수집 중 EUNORA 원본 코드가 바뀌었습니다. 다시 점검해 주세요")
    return dict(project_root=str(root), app_key=app_key, source_files=hashes,
                targets=targets, unresolved=unresolved, report_notes=[
                    f"{profiles[app_key]['source_file']}의 실제 코드에 있는 리터럴 클래스와 결합 가능한 메서드 이름을 수집했습니다.",
                    "ModuleMain.kt는 파일 존재와 SHA-256을 기록했습니다. 패키지 분기와 설치 실행 여부까지 검증한 결과는 아닙니다.",
                    "동일 블록에서 직접 선언한 클래스 변수의 메서드 이름만 결합합니다. 외부 블록·동적 표현은 추가 확인이 필요합니다.",
                    "메서드 이름 발견은 인자·반환형·필드·실행 순서·수락 동작 검증과 구분됩니다. getMethod는 상속 메서드일 수 있습니다.",
                    f"플랫폼 클래스 {len(excluded)}개는 APK 내부 대상에서 제외했습니다. 동적 표현은 추가 확인 항목에 남깁니다.",
                ])

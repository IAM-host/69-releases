"""Generate exact, debug-module-only security test hooks from bound APK evidence.

The observation mode uses the existing observer generator. Boolean tests change
one successful primitive Boolean return after original execution; void tests
skip one exact method body. Test hooks require the loaded EUNORA debug module.
Neither mode alters request bodies, attestation tokens, platform APIs, arguments,
or input project files. Skipped void bodies do not execute or throw.
"""
from __future__ import annotations

import difflib
import hashlib
import json
from pathlib import Path, PurePosixPath, PureWindowsPath
import re
import shutil
import tempfile
from datetime import datetime, timezone

from . import generator as _g
from .paths import app_dir, atomic_write_text
from .processes import check_cancelled


class SecurityGenerationError(_g.GenerationError):
    pass


_SUPPORTED_TEST_CATEGORIES = {
    "root_files", "root_commands", "root_packages", "hook_framework",
    "hook_stack", "hook_memory",
}
_PLATFORM = ("java.", "javax.", "android.", "dalvik.", "kotlin.")
_MODULE_PACKAGE = "com.example.wheelprobe"


def scan_security_candidates(apk_path):
    # Lazy import permits the independently tested scanner to remain a separate
    # service and keeps observation-only code generation importable on its own.
    from .security_scan import scan_security_candidates as scan
    return scan(apk_path)


def _source_checks(root: Path, source_hashes) -> None:
    check_cancelled()
    if source_hashes is None:
        return
    if not isinstance(source_hashes, dict) or not source_hashes:
        raise SecurityGenerationError("점검한 원본 코드의 해시 기록이 없습니다")
    for name, expected in source_hashes.items():
        check_cancelled()
        if not isinstance(name, str) or not name or "\\" in name:
            raise SecurityGenerationError("원본 코드의 상대 경로가 잘못되었습니다")
        relative = PurePosixPath(name)
        if relative.is_absolute() or PureWindowsPath(name).drive or any(p in {"", ".", ".."} for p in name.split("/")):
            raise SecurityGenerationError("원본 코드의 경로가 프로젝트 밖을 가리킵니다")
        path = root / Path(*relative.parts)
        if not path.is_file() or not path.resolve().is_relative_to(root):
            raise SecurityGenerationError(f"점검한 원본 파일을 찾을 수 없습니다: {name}")
        if not isinstance(expected, str) or _g._sha(path) != expected:
            raise SecurityGenerationError(f"점검 후 원본 코드가 변경되었습니다. 다시 점검하세요: {name}")


def _selected_target(apk: Path, class_evidence, method_name, overload_index, package_evidence, profile):
    digest = _g._sha(apk)
    evidence, result = _g._class_result(class_evidence)
    package = _g._unwrap(package_evidence, "inspect_android_package")
    _g._bind_evidence(evidence, digest)
    _g._bind_evidence(package, digest)
    if package["normalized_result"].get("package_name") != profile["package"]:
        raise SecurityGenerationError("선택한 앱 프로필과 APK 패키지가 다릅니다")
    choices = [entry for entry in _g.list_observer_methods(evidence) if entry["name"] == method_name]
    if overload_index is not None:
        choices = [entry for entry in choices if entry["overload_index"] == overload_index]
    if len(choices) != 1:
        raise SecurityGenerationError("정확한 메서드 오버로드를 하나 선택하세요")
    selected = choices[0]
    target = _g._verified_target(apk, result["class_name"], method_name, selected["dex_descriptor"])
    if target["class_name"].startswith(_PLATFORM):
        raise SecurityGenerationError("앱 APK에 선언된 개별 메서드만 생성할 수 있습니다")
    return digest, evidence, package, target, selected


def _verify_method_evidence(method_evidence, digest, display_class, selected):
    if method_evidence is None:
        return None
    evidence = _g._unwrap(method_evidence, "inspect_android_method")
    _g._bind_evidence(evidence, digest)
    normalized = evidence["normalized_result"]
    actual = normalized.get("method")
    if (normalized.get("class_name") != display_class or not isinstance(actual, dict)
            or actual.get("name") != selected["name"]
            or actual.get("dex_descriptor") != selected["dex_descriptor"]
            or actual.get("overload_index") != selected["overload_index"]):
        raise SecurityGenerationError("메서드 분석 근거가 선택한 정확한 대상과 다릅니다")
    return evidence


def _rescan_candidate(apk: Path, digest: str, candidate, target: dict, mode: str) -> dict:
    if not isinstance(candidate, dict) or not isinstance(candidate.get("id"), str):
        raise SecurityGenerationError("보안 자동 점검에서 확인한 후보가 필요합니다")
    expected = {"class_name": target["class_name"], "method_name": target["name"],
                "dex_descriptor": target["dex_descriptor"]}
    if any(candidate.get(key) != value for key, value in expected.items()):
        raise SecurityGenerationError("선택한 보안 후보와 DEX 메서드 대상이 다릅니다")
    if candidate.get("apk_digest", digest) != digest:
        raise SecurityGenerationError("보안 후보의 APK 해시가 다릅니다")
    scan = scan_security_candidates(apk)
    if not isinstance(scan, dict) or scan.get("apk_digest") != digest or not isinstance(scan.get("candidates"), list):
        raise SecurityGenerationError("보안 후보 재검사 결과의 APK 해시를 확인할 수 없습니다")
    matches = [entry for entry in scan["candidates"] if isinstance(entry, dict) and entry.get("id") == candidate["id"]]
    if len(matches) != 1:
        raise SecurityGenerationError("선택한 보안 후보를 현재 APK에서 고유하게 다시 확인할 수 없습니다")
    current = matches[0]
    if any(current.get(key) != value for key, value in expected.items()):
        raise SecurityGenerationError("재검사한 보안 후보가 선택한 메서드와 다릅니다")
    if current.get("access_flags") != target["access_flags"]:
        raise SecurityGenerationError("보안 후보의 실제 DEX 접근 플래그가 다릅니다")
    categories, modes = current.get("categories"), current.get("modes")
    if (not isinstance(categories, list) or not categories or
            not all(isinstance(category, str) and category in _SUPPORTED_TEST_CATEGORIES for category in categories)
            or not isinstance(modes, list) or mode not in modes):
        raise SecurityGenerationError("이 후보는 선택한 보안 테스트 모드를 지원하지 않습니다. 무결성·인증 대상은 제외됩니다")
    if not isinstance(current.get("signals"), list) or not current["signals"]:
        raise SecurityGenerationError("보안 후보에 탐색 근거가 없습니다")
    return current


def _registry(family: str) -> str:
    return f'''// BEGIN L_SECURITY_TEST_REGISTRY {family}
private object LSecurityTestRegistry_{family} {{
    val installed = java.util.HashSet<java.lang.reflect.Method>()
}}
// END L_SECURITY_TEST_REGISTRY {family}
'''


def _test_code(identifier: str, package: str, target: dict, family: str, mode: str) -> str:
    parameters, _ = _g._parse_descriptor(target["dex_descriptor"])
    argument_types = ", ".join(_g._class_expression(parameter) for parameter in parameters)
    label = _g._kotlin("L_SECURITY_TEST " + identifier + " " + target["class_name"] + "." + target["name"] + target["dex_descriptor"])
    guard = f'''                val module = ModuleMain.module ?: return
                val moduleInfo = module.applicationInfo
                if (moduleInfo.packageName != {_g._kotlin(_MODULE_PACKAGE)} ||
                    (moduleInfo.flags and android.content.pm.ApplicationInfo.FLAG_DEBUGGABLE) == 0) return'''
    if mode == "boolean_false":
        hook = f'''        @JvmStatic
        @io.github.libxposed.api.annotations.AfterInvocation
        fun after(callback: io.github.libxposed.api.XposedInterface.AfterHookCallback) {{
            try {{
{guard}
                if (callback.throwable != null) return
                val original = callback.result as? Boolean ?: return
                if (original) {{
                    callback.result = false
                    module.log({label} + " original=true test_result=false")
                }}
            }} catch (_: Throwable) {{ /* Keep the observed exception and arguments intact. */ }}
        }}'''
        description = "Only a successful primitive Boolean result is changed; exceptions are preserved."
        return_type = "java.lang.Boolean.TYPE"
    else:
        hook = f'''        @JvmStatic
        @io.github.libxposed.api.annotations.BeforeInvocation
        fun before(callback: io.github.libxposed.api.XposedInterface.BeforeHookCallback) {{
            try {{
{guard}
                callback.returnAndSkip(null)
                module.log({label} + " skipped: debug void-method test")
            }} catch (_: Throwable) {{ /* Do not propagate instrumentation failures. */ }}
        }}'''
        description = "The selected void method is skipped for a debug test; its body does not execute."
        return_type = "java.lang.Void.TYPE"
    return f'''// BEGIN L_SECURITY_TEST {identifier}
// Local debug-module test: {mode}.
// {description}
@io.github.libxposed.api.annotations.XposedHooker
class LSecurityTestHooker_{identifier} : io.github.libxposed.api.XposedInterface.Hooker {{
    companion object {{
{hook}
    }}
}}

internal fun ModuleMain.installLSecurityTest_{identifier}(classLoader: ClassLoader, packageName: String) {{
    if (packageName != {_g._kotlin(package)}) return
    val module = ModuleMain.module ?: return
    try {{
        val moduleInfo = module.applicationInfo
        if (moduleInfo.packageName != {_g._kotlin(_MODULE_PACKAGE)} ||
            (moduleInfo.flags and android.content.pm.ApplicationInfo.FLAG_DEBUGGABLE) == 0) {{
            module.log({label} + " skipped: module is not the EUNORA debug package")
            return
        }}
        val owner = java.lang.Class.forName({_g._kotlin(target['class_name'])}, false, classLoader)
        val parameterTypes = arrayOf<java.lang.Class<*>>({argument_types})
        val method = owner.declaredMethods.singleOrNull {{
            it.name == {_g._kotlin(target['name'])} && it.parameterTypes.contentEquals(parameterTypes) &&
                it.returnType == {return_type}
        }} ?: throw NoSuchMethodException("Exact security-test DEX prototype was not found")
        if (java.lang.reflect.Modifier.isAbstract(method.modifiers) || java.lang.reflect.Modifier.isNative(method.modifiers)) {{
            throw NoSuchMethodException("Unsupported method declaration")
        }}
        synchronized(LSecurityTestRegistry_{family}.installed) {{
            if (LSecurityTestRegistry_{family}.installed.contains(method)) return
            method.isAccessible = true
            module.hook(method, LSecurityTestHooker_{identifier}::class.java)
            LSecurityTestRegistry_{family}.installed.add(method)
        }}
        module.log({label} + " installed: debug security test {mode}")
    }} catch (error: Throwable) {{
        try {{ module.log({label} + " installation failed type=" + error.javaClass.name) }}
        catch (_: Throwable) {{ }}
    }}
}}
// END L_SECURITY_TEST {identifier}
'''


def _install(text: str, anchor: str, identifier: str, newline: str) -> str:
    existing = _g._existing_region(text, "L_SECURITY_TEST_CALL", identifier)
    clean = text if existing is None else text[:existing[0]] + text[existing[1]:]
    if _g._existing_region(clean, "L_OBSERVER_CALL", identifier) is not None:
        raise SecurityGenerationError("동일한 식별자의 관찰 생성 블록이 있어 자동 삽입할 수 없습니다")
    modified = _g._install_source(clean, anchor, identifier, newline)
    region = _g._existing_region(modified, "L_OBSERVER_CALL", identifier)
    if region is None:
        raise SecurityGenerationError("보안 테스트 설치 지점을 확인할 수 없습니다")
    block = modified[region[0]:region[1]]
    block = block.replace(f"L_OBSERVER_CALL {identifier}", f"L_SECURITY_TEST_CALL {identifier}")
    block = block.replace(f"installLObserver_{identifier}", f"installLSecurityTest_{identifier}")
    return modified[:region[0]] + block + modified[region[1]:]


def _family(text: str, code: str, identifier: str, newline: str, family: str) -> str:
    masked, _ = _g._mask_kotlin(text)
    if not re.search(r"(?m)^\s*package\s+com\.example\.wheelprobe\s*$", masked):
        raise SecurityGenerationError("E파일의 EUNORA 패키지 선언을 확인할 수 없습니다")
    registry = _registry(family).replace("\n", newline)
    region = _g._existing_region(text, "L_SECURITY_TEST_REGISTRY", family)
    if region is not None:
        if text[region[0]:region[1]] != registry:
            raise SecurityGenerationError("공통 보안 테스트 레지스트리가 변경되었습니다")
    else:
        separator = "" if text.endswith(newline + newline) else newline if text.endswith(newline) else newline + newline
        text += separator + registry
    code = code.replace("\n", newline)
    region = _g._existing_region(text, "L_SECURITY_TEST", identifier)
    if region is not None:
        return text[:region[0]] + code + text[region[1]:]
    separator = "" if text.endswith(newline + newline) else newline if text.endswith(newline) else newline + newline
    return text + separator + code


def generate_security_hook(project_path, app_key, apk_path, class_evidence,
                           method_name, overload_index=None, *, mode="observe",
                           package_evidence=None, method_evidence=None,
                           source_hashes=None, candidate=None) -> dict:
    """Create full Kotlin/TXT copies for an exact observation or debug test."""
    check_cancelled()
    if not isinstance(mode, str) or mode not in {"observe", "boolean_false", "skip_void"}:
        raise SecurityGenerationError("지원하지 않는 보안 코드 생성 모드입니다")
    profiles = _g.load_profiles()
    if app_key not in profiles:
        raise SecurityGenerationError("알 수 없는 EUNORA 앱 프로필입니다")
    profile = profiles[app_key]
    root = _g.resolve_project(project_path)
    _source_checks(root, source_hashes)
    apk = Path(apk_path).expanduser().resolve()
    if not apk.is_file():
        raise SecurityGenerationError("분석한 APK 파일이 없습니다")
    digest, evidence, package, target, selected = _selected_target(
        apk, class_evidence, method_name, overload_index, package_evidence, profile)
    method = _verify_method_evidence(method_evidence, digest, evidence["normalized_result"]["class_name"], selected)
    if mode == "observe":
        result = _g.generate_observer(root, app_key, apk, evidence, method_name,
                                      selected["overload_index"], package_evidence=package)
        try:
            _source_checks(root, source_hashes)
            metadata = {"mode": "observe", "debug_only": False,
                        "original_execution_preserved": True, "throwable_preserved": True,
                        "audit_source_hashes": source_hashes}
            manifest_path = Path(result["manifest"])
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            manifest.update(metadata)
            check_cancelled()
            atomic_write_text(manifest_path, json.dumps(manifest, ensure_ascii=False, indent=2) + "\n")
            result["report"].update(metadata)
            _source_checks(root, source_hashes)
        except BaseException:
            published = Path(result["path"])
            if published.parent.resolve() == (app_dir() / "generated_hooks").resolve():
                shutil.rmtree(published)
            raise
        return result
    _, return_type = _g._parse_descriptor(target["dex_descriptor"])
    required_return = "Z" if mode == "boolean_false" else "V"
    if return_type != required_return:
        raise SecurityGenerationError("선택한 테스트 모드와 실제 DEX 반환형이 다릅니다")
    verified = _rescan_candidate(apk, digest, candidate, target, mode)
    _source_checks(root, source_hashes)
    identity = "\0".join(("L_SECURITY_TEST_" + mode.upper(), profile["package"], target["class_name"],
                            target["name"], target["dex_descriptor"]))
    identifier = hashlib.sha256(identity.encode()).hexdigest()[:16]
    prefix = Path("app/src/main/java/com/example/wheelprobe")
    snapshots, outputs, originals, differences = {}, {}, {}, []
    for relative in (prefix / "ModuleMain.kt", prefix / profile["source_file"]):
        check_cancelled()
        path = root / relative
        if not path.is_file() or not path.resolve().is_relative_to(root):
            raise SecurityGenerationError(f"프로젝트 안에서 원본 파일을 찾을 수 없습니다: {relative}")
        before = path.read_bytes()
        text, bom, newline = _g._source_text(before)
        changed = (_install(text, profile["startup_anchor"], identifier, newline) if relative.name == "ModuleMain.kt"
                   else _family(text, _test_code(identifier, profile["package"], target, profile["family"], mode),
                                identifier, newline, profile["family"]))
        name = relative.as_posix()
        snapshots[name] = before
        originals[name] = hashlib.sha256(before).hexdigest()
        outputs[name] = (b"\xef\xbb\xbf" if bom else b"") + changed.encode("utf-8")
        differences.extend(difflib.unified_diff(text.splitlines(keepends=True), changed.splitlines(keepends=True),
                                               fromfile="a/" + name, tofile="b/" + name))
    def check_inputs():
        check_cancelled()
        _source_checks(root, source_hashes)
        if _g._sha(apk) != digest or any((root / name).read_bytes() != value for name, value in snapshots.items()):
            raise SecurityGenerationError("생성 중 APK 또는 원본 코드가 변경되었습니다. 다시 점검하세요")
    check_inputs()
    output_root = (app_dir() / "generated_hooks").resolve()
    if output_root.is_relative_to(root):
        raise SecurityGenerationError("출력 폴더는 원본 Android 프로젝트 밖에 있어야 합니다")
    output_root.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    staging = Path(tempfile.mkdtemp(prefix=".pending_security_", dir=output_root))
    bundle = output_root / f"security_{stamp}_{app_key}_{identifier}_{staging.name.removeprefix('.pending_security_')}"
    generated, files = {}, {}
    report = {
        "profile": app_key, "package_name": profile["package"], "security_test_id": identifier,
        "mode": mode, "observation_only": False, "debug_only": True,
        "debug_guard": "libxposed module ApplicationInfo package and FLAG_DEBUGGABLE",
        "original_execution_preserved": mode == "boolean_false", "throwable_preserved": mode == "boolean_false",
        "selected_method": {key: target[key] for key in ("class_name", "name", "dex_descriptor", "access_flags")},
        "candidate_id": verified["id"], "categories": list(verified["categories"]),
        "candidate_evidence_kind": verified.get("evidence_kind"), "static_candidate_only": True,
        "candidate_note": "정적 단서로 찾은 후보입니다. 정확한 메서드 원형을 검증했지만 업무 의미·실기기 동작은 별도 확인이 필요합니다.",
        "build_status": "not_run", "runtime_status": "unverified",
        "shared_process_note": "설치 시 패키지를 제한하지만 공유 프로세스의 같은 메서드 호출에는 테스트 결과가 적용될 수 있습니다.",
    }
    try:
        for name, contents in outputs.items():
            check_cancelled()
            path = staging / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(contents)
            path.with_suffix(".txt").write_bytes(contents)
            published = bundle / name
            files[name] = str(published)
            files[Path(name).with_suffix(".txt").as_posix()] = str(published.with_suffix(".txt"))
            generated[name] = {"path": str(published), "sha256": hashlib.sha256(contents).hexdigest()}
        diff = bundle / "changes.diff"
        (staging / "changes.diff").write_text("".join(differences), encoding="utf-8", newline="")
        manifest = dict(report, schema_version=1, project_root=str(root), originals=originals,
                        generated=generated, apk_sha256=digest, apk_path=str(apk),
                        audit_source_hashes=source_hashes, evidence_ids={
                            "class": evidence.get("evidence_id"), "package": package.get("evidence_id"),
                            "method": method.get("evidence_id") if method else None}, diff_path=str(diff))
        manifest_path = bundle / "manifest.json"
        (staging / "manifest.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        check_inputs()
        staging.rename(bundle)
    finally:
        if staging.exists():
            shutil.rmtree(staging)
    return {"path": str(bundle), "manifest": str(manifest_path), "files": files,
            "diff": str(diff), "report": report, "build_status": "not_run"}

"""Static Kotlin target collection preserves sources and refuses guessed bindings."""
from __future__ import annotations

import hashlib
from pathlib import Path
import threading

import pytest

from l_app import source_catalog
from l_app.processes import CancelledError, bind_cancel_event


@pytest.fixture
def make_project(tmp_path):
    def make(text: str, filename="E05.kt", newline="\n"):
        root = tmp_path / "EUNORA source"
        directory = root / "app/src/main/java/com/example/wheelprobe"
        directory.mkdir(parents=True, exist_ok=True)
        module = directory / "ModuleMain.kt"
        module.write_text('package com.example.wheelprobe\nclass ModuleMain\n', encoding="utf-8")
        source = directory / filename
        content = "package com.example.wheelprobe\n" + text
        source.write_bytes(content.replace("\n", newline).encode("utf-8"))
        return root, module, source
    return make


def _targets(result):
    return {item["class_name"]: item for item in result["targets"]}


def test_selected_family_sources_are_hashed_without_writes(make_project):
    root, module, source = make_project('fun install(loader: ClassLoader) {\n val owner = Class.forName("example.Order", false, loader)\n owner.getDeclaredMethod("make")\n}\n', newline="\r\n")
    before = {path: path.read_bytes() for path in (module, source)}
    result = source_catalog.collect_source_catalog(module, "logi")
    assert Path(result["project_root"]) == root
    assert result["app_key"] == "logi"
    assert result["source_files"] == {
        path.relative_to(root).as_posix(): hashlib.sha256(data).hexdigest()
        for path, data in before.items()
    }
    assert all(path.read_bytes() == data for path, data in before.items())
    target = _targets(result)["example.Order"]
    assert target["confidence"] == "literal"
    assert set(target["methods"]) == {"make"}
    assert {"file": source.relative_to(root).as_posix(), "line": 3} in target["locations"]
    assert all(item["file"] == source.relative_to(root).as_posix() for item in target["locations"])
    assert result["report_notes"]


def test_direct_class_and_loader_literal_targets_are_collected(make_project):
    root, _, _ = make_project('''
fun install(loader: ClassLoader) {
    val first = Class.forName("sample.First", false, loader)
    val second = loader.loadClass("sample.Second")
    first.getDeclaredMethod("decode")
    second.getMethod("publish")
}
''')
    targets = _targets(source_catalog.collect_source_catalog(root, "logi"))
    assert set(targets) == {"sample.First", "sample.Second"}
    assert targets["sample.First"]["methods"] == ["decode"]
    assert targets["sample.Second"]["methods"] == ["publish"]


def test_comments_nested_comments_and_strings_do_not_supply_targets(make_project):
    root, _, _ = make_project(r'''
// val fake = Class.forName("fake.Line")
/* outside /* val fake = Class.forName("fake.Nested") */ still comment */
val text = "Class.forName(\"fake.String\")"
val raw = """loader.loadClass("fake.Raw")"""
fun install(loader: ClassLoader) {
    val real = Class.forName("sample.Real", false, loader)
    // real.getDeclaredMethod("fakeMethod")
    val fakeMethod = "real.getMethod(\"notCode\")"
    real.getDeclaredMethod("actual")
}
''')
    targets = _targets(source_catalog.collect_source_catalog(root, "logi"))
    assert set(targets) == {"sample.Real"}
    assert targets["sample.Real"]["methods"] == ["actual"]


def test_interpolated_class_names_are_unresolved(make_project):
    root, _, _ = make_project('''
fun install(loader: ClassLoader) {
    Class.forName("sample.$name", false, loader)
    loader.loadClass("sample.${suffix}")
}
''')
    result = source_catalog.collect_source_catalog(root, "logi")
    assert not result["targets"]
    assert result["unresolved"]
    assert all(isinstance(item["line"], int) and item["reason"] for item in result["unresolved"])


def test_nested_quotes_and_templates_never_expose_fake_string_code(make_project):
    root, _, _ = make_project(r'''
fun install(loader: ClassLoader, values: List<String>) {
    val message = "items ${values.joinToString(",") { "${it}: Class.forName(\"fake.Template\")" }} done"
    val owner = Class.forName("sample.AfterTemplate", false, loader)
    owner.getDeclaredMethod("actual")
}
''')
    targets = _targets(source_catalog.collect_source_catalog(root, "logi"))
    assert set(targets) == {"sample.AfterTemplate"}
    assert targets["sample.AfterTemplate"]["methods"] == ["actual"]


def test_escaped_dollar_preserves_inner_class_binary_name(make_project):
    root, _, _ = make_project(r'''
fun install(loader: ClassLoader) {
    val owner = Class.forName("sample.Outer\$Inner", false, loader)
    owner.getDeclaredMethod("run")
}
''')
    targets = _targets(source_catalog.collect_source_catalog(root, "logi"))
    assert set(targets) == {"sample.Outer$Inner"}
    assert targets["sample.Outer$Inner"]["methods"] == ["run"]


def test_scoped_helper_is_proven_from_its_implementation(make_project):
    root, _, _ = make_project('''
fun install(loader: ClassLoader) {
    fun type(name: String) = Class.forName(name, false, loader)
    val owner = type("sample.HelperOwner")
    owner.getDeclaredMethod("make")
    type("sample.InlineOwner").getDeclaredMethod("publish")
}
''')
    targets = _targets(source_catalog.collect_source_catalog(root, "logi"))
    assert set(targets) == {"sample.HelperOwner", "sample.InlineOwner"}
    assert targets["sample.HelperOwner"]["methods"] == ["make"]
    assert targets["sample.InlineOwner"]["methods"] == ["publish"]


def test_unproven_helper_and_helper_outside_scope_do_not_create_targets(make_project):
    root, _, _ = make_project('''
fun first(loader: ClassLoader) {
    fun type(name: String) = Class.forName(name, false, loader)
    type("sample.InScope")
}
fun second() {
    type("fake.OutOfScope")
}
fun third() {
    fun type(name: String) = otherFunction(name)
    type("fake.Unproven")
}
''')
    targets = _targets(source_catalog.collect_source_catalog(root, "logi"))
    assert set(targets) == {"sample.InScope"}


def test_helper_that_transforms_forname_result_is_not_proven(make_project):
    root, _, _ = make_project('''
fun install(loader: ClassLoader) {
    fun type(name: String) = Class.forName(name, false, loader).let { Class.forName("sample.Actual", false, loader) }
    val owner = type("fake.NotReturned")
    owner.getDeclaredMethod("wrongOwner")
}
''')
    targets = _targets(source_catalog.collect_source_catalog(root, "logi"))
    assert "fake.NotReturned" not in targets
    assert all("wrongOwner" not in row["methods"] for row in targets.values())


def test_later_loadclass_expression_does_not_bind_previous_unknown_value(make_project):
    root, _, _ = make_project('''
fun install(loader: ClassLoader, unknown: Class<*>) {
    val owner = unknown
    loader.loadClass("sample.Standalone")
    owner.getDeclaredMethod("wrongOwner")
}
''')
    targets = _targets(source_catalog.collect_source_catalog(root, "logi"))
    assert set(targets) == {"sample.Standalone"}
    assert not targets["sample.Standalone"]["methods"]


@pytest.mark.parametrize("owner", ["java.lang.String", "javax.net.SocketFactory", "android.location.Location", "dalvik.system.DexFile", "kotlin.Unit"])
def test_platform_class_is_not_reported_as_missing_apk_target(make_project, owner):
    root, _, _ = make_project(f'fun install(loader: ClassLoader) {{ val owner = Class.forName("{owner}", false, loader) }}')
    result = source_catalog.collect_source_catalog(root, "logi")
    assert not result["targets"]
    assert result["report_notes"]


def test_library_class_is_retained_as_a_packaged_candidate(make_project):
    root, _, _ = make_project('fun install(loader: ClassLoader) { val owner = Class.forName("okhttp3.RealCall", false, loader) }')
    assert set(_targets(source_catalog.collect_source_catalog(root, "logi"))) == {"okhttp3.RealCall"}


def test_dynamic_class_and_method_names_remain_unresolved(make_project):
    root, _, _ = make_project('''
fun install(loader: ClassLoader, className: String, methodName: String) {
    Class.forName(className, false, loader)
    val owner = Class.forName("sample.Owner", false, loader)
    owner.getDeclaredMethod(methodName)
}
''')
    result = source_catalog.collect_source_catalog(root, "logi")
    assert _targets(result)["sample.Owner"]["methods"] == []
    assert result["unresolved"]


def test_same_variable_name_in_separate_functions_does_not_cross_bind(make_project):
    root, _, _ = make_project('''
fun first(loader: ClassLoader) {
    val owner = Class.forName("sample.First", false, loader)
    owner.getDeclaredMethod("firstMethod")
}
fun second(loader: ClassLoader) {
    val owner = Class.forName("sample.Second", false, loader)
    owner.getDeclaredMethod("secondMethod")
}
''')
    targets = _targets(source_catalog.collect_source_catalog(root, "logi"))
    assert targets["sample.First"]["methods"] == ["firstMethod"]
    assert targets["sample.Second"]["methods"] == ["secondMethod"]


def test_unknown_shadow_never_binds_to_outer_owner(make_project):
    root, _, _ = make_project('''
fun install(loader: ClassLoader, dynamic: String) {
    val owner = Class.forName("sample.Outer", false, loader)
    owner.getDeclaredMethod("outerMethod")
    run {
        val owner = Class.forName(dynamic, false, loader)
        owner.getDeclaredMethod("wrongInnerMethod")
    }
}
''')
    result = source_catalog.collect_source_catalog(root, "logi")
    assert _targets(result)["sample.Outer"]["methods"] == ["outerMethod"]
    assert result["unresolved"]


def test_unknown_reassignment_invalidates_old_binding(make_project):
    root, _, _ = make_project('''
fun install(loader: ClassLoader, unknown: Class<*>) {
    var owner = Class.forName("sample.Original", false, loader)
    owner.getDeclaredMethod("before")
    owner = unknown
    owner.getDeclaredMethod("wrongAfter")
}
''')
    targets = _targets(source_catalog.collect_source_catalog(root, "logi"))
    assert "wrongAfter" not in targets["sample.Original"]["methods"]


def test_function_parameter_shadow_never_uses_same_named_property(make_project):
    root, _, _ = make_project('''
val owner = Class.forName("sample.Property")
fun inspect(owner: Class<*>) {
    owner.getDeclaredMethod("wrongParameterMethod")
}
''')
    targets = _targets(source_catalog.collect_source_catalog(root, "logi"))
    assert "wrongParameterMethod" not in targets["sample.Property"]["methods"]


def test_lambda_parameter_shadow_never_uses_outer_owner(make_project):
    root, _, _ = make_project('''
fun inspect(values: List<Class<*>>) {
    val owner = Class.forName("sample.Outer")
    values.forEach { owner ->
        owner.getDeclaredMethod("wrongLambdaMethod")
    }
}
''')
    targets = _targets(source_catalog.collect_source_catalog(root, "logi"))
    assert "wrongLambdaMethod" not in targets["sample.Outer"]["methods"]


def test_qualified_property_does_not_bind_to_lexical_variable(make_project):
    root, _, _ = make_project('''
fun inspect(other: Holder) {
    val owner = Class.forName("sample.Lexical")
    owner.getDeclaredMethod("correct")
    other.owner.getDeclaredMethod("wrongQualified")
}
''')
    targets = _targets(source_catalog.collect_source_catalog(root, "logi"))
    assert targets["sample.Lexical"]["methods"] == ["correct"]


def test_duplicate_class_uses_one_target_with_all_locations(make_project):
    root, _, source = make_project('''
fun first(loader: ClassLoader) { Class.forName("sample.Owner", false, loader) }
fun second(loader: ClassLoader) { Class.forName("sample.Owner", false, loader) }
''')
    result = source_catalog.collect_source_catalog(root, "logi")
    assert len(result["targets"]) == 1
    target = result["targets"][0]
    assert len(target["locations"]) == 2
    assert all(location["file"] == source.relative_to(root).as_posix() for location in target["locations"])


def test_selected_profile_does_not_read_other_families(make_project):
    root, _, source = make_project('fun install(loader: ClassLoader) { Class.forName("sample.Logi", false, loader) }')
    other = source.with_name("E02.kt")
    other.write_text('fun install() { Class.forName("fake.Kakao") }')
    result = source_catalog.collect_source_catalog(root, "logi2")
    assert set(_targets(result)) == {"sample.Logi"}
    assert not any(name.endswith("E02.kt") for name in result["source_files"])


def test_cancellation_propagates_and_preserves_sources(make_project):
    root, module, source = make_project('fun install() { Class.forName("sample.Owner") }')
    before = (module.read_bytes(), source.read_bytes())
    event = threading.Event()
    event.set()
    with bind_cancel_event(event), pytest.raises(CancelledError):
        source_catalog.collect_source_catalog(root, "logi")
    assert before == (module.read_bytes(), source.read_bytes())


def test_destructured_loop_parameter_hides_outer_owner(make_project):
    root, _, _ = make_project('''
fun inspect(loader: ClassLoader, pairs: List<Pair<Class<*>, Int>>) {
    val owner = Class.forName("sample.Outer", false, loader)
    for ((owner, index) in pairs) {
        owner.getDeclaredMethod("wrong")
    }
}
''')
    result = source_catalog.collect_source_catalog(root, "logi")
    assert _targets(result)["sample.Outer"]["methods"] == []
    assert result["unresolved"]


def test_constructor_parameter_hides_top_level_owner(make_project):
    root, _, _ = make_project('''
val owner = Class.forName("sample.Outer")
class Example(owner: Class<*>) {
    init { owner.getDeclaredMethod("wrong") }
}
''')
    result = source_catalog.collect_source_catalog(root, "logi")
    assert _targets(result)["sample.Outer"]["methods"] == []
    assert result["unresolved"]


def test_operator_after_class_call_does_not_prove_receiver(make_project):
    root, _, _ = make_project('''
fun inspect(loader: ClassLoader, another: Class<*>) {
    val owner = Class.forName("sample.Operand", false, loader) + another
    owner.getDeclaredMethod("notProved")
}
''')
    result = source_catalog.collect_source_catalog(root, "logi")
    assert _targets(result)["sample.Operand"]["methods"] == []
    assert result["unresolved"]


def test_method_lookup_kind_is_retained_for_inheritance_caveat(make_project):
    root, _, _ = make_project('''
fun inspect(loader: ClassLoader) {
    val owner = Class.forName("sample.Owner", false, loader)
    owner.getMethod("inherited")
    owner.getDeclaredMethod("declared")
}
''')
    target = _targets(source_catalog.collect_source_catalog(root, "logi"))["sample.Owner"]
    assert {(ref["name"], ref["lookup"]) for ref in target["method_refs"]} == {
        ("inherited", "getMethod"), ("declared", "getDeclaredMethod"),
    }


def test_implicit_lambda_it_is_not_bound_to_outer_literal(make_project):
    root, _, _ = make_project('''
fun inspect(loader: ClassLoader, values: List<Class<*>>) {
    val it = Class.forName("sample.Outer", false, loader)
    values.forEach { it.getDeclaredMethod("wrong") }
}
''')
    result = source_catalog.collect_source_catalog(root, "logi")
    assert _targets(result)["sample.Outer"]["methods"] == []
    assert result["unresolved"]


def test_nested_destructured_val_never_uses_outer_literal(make_project):
    root, _, _ = make_project('''
fun inspect(loader: ClassLoader, pair: Pair<Class<*>, Int>) {
    val owner = Class.forName("sample.Outer", false, loader)
    run {
        val (owner, index) = pair
        owner.getDeclaredMethod("wrong")
    }
}
''')
    result = source_catalog.collect_source_catalog(root, "logi")
    assert _targets(result)["sample.Outer"]["methods"] == []
    assert result["unresolved"]

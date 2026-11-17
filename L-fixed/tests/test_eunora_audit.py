"""Orchestration preserves APK/source binding and never guesses a repair."""
from collections import Counter
import hashlib
import json
from pathlib import Path
import struct
import zipfile

import pytest

from l_app import eunora_audit as audit
from l_app.processes import CancelledError


def _sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


@pytest.fixture
def case(tmp_path, monkeypatch):
    monkeypatch.setenv("L_APP_DATA_DIR", str(tmp_path / "L data"))
    project = tmp_path / "EUNORA original"
    source = project / "app/src/main/java/com/example/wheelprobe/E05.kt"
    source.parent.mkdir(parents=True)
    source.write_text("// original source\n")
    main = source.with_name("ModuleMain.kt")
    main.write_text("// original module\n")
    apk = tmp_path / "test.apk"
    with zipfile.ZipFile(apk, "w") as archive:
        archive.writestr("AndroidManifest.xml", "synthetic")
    files = {str(path.relative_to(project).as_posix()): _sha(path) for path in (main, source)}
    targets = [{"class_name": "example.Orders", "methods": ["load"],
                "locations": [{"file": source.relative_to(project).as_posix(), "line": 5}], "confidence": "literal"}]
    catalog = {"project_root": str(project), "app_key": "logi", "source_files": files,
               "targets": targets, "unresolved": [], "report_notes": ["Synthetic source catalog"]}
    monkeypatch.setattr(audit, "collect_source_catalog", lambda root, key: catalog)
    monkeypatch.setattr(audit, "_declared_classes", lambda path: Counter({item["class_name"]: 1 for item in targets}))
    calls = []
    package_name = ["com.logisoft.Logi4"]
    inventory = {"matches": ["example.Orders"], "duplicate_names": [], "coverage": "complete", "total_classes": 1}
    methods = [{"name": "load", "overload_index": 0, "dex_descriptor": "()V", "is_constructor": False}]

    def result(operation, normalized):
        return {"operation": operation, "status": "complete", "report": "synthetic report",
                "raw_path": "local-only.json", "evidence": {"subject": {"digest": {"sha256": _sha(apk)}},
                "normalized_result": normalized}}

    def run(path, *, operation, **options):
        calls.append((operation, options))
        if operation == "package":
            return result(operation, {"package_name": package_name[0]})
        if operation == "class_search":
            assert options["query"] == ""
            return result(operation, inventory)
        assert operation == "class"
        return result(operation, {"class_name": options["class_name"], "methods": methods})

    monkeypatch.setattr(audit, "run_rea_analysis", run)
    return dict(apk=apk, project=project, source=source, catalog=catalog, targets=targets, calls=calls,
                inventory=inventory, methods=methods, package_name=package_name, run=run, result=result)


def test_identifies_profile_and_collects_all_results_without_original_writes(case):
    before = case["source"].read_bytes()
    result = audit.run_eunora_audit(case["apk"], case["project"])
    assert result["app_key"] == "logi"
    assert result["rows"][0]["status"] == "method_name_found"
    assert result["rows"][0]["method_checks"] == [{"name": "load", "matching_overloads": 1}]
    assert result["status"] == "complete"
    assert [item[0] for item in case["calls"]] == ["package", "class_search", "class"]
    assert result["class_results"][0]["target"] == case["targets"][0]
    assert result["class_results"][0]["evidence"]["normalized_result"]["class_name"] == "example.Orders"
    assert result["apk_digest"] == _sha(case["apk"])
    assert case["source"].read_bytes() == before
    assert "원형 미검증" in result["report"]
    assert json.loads(Path(result["json_path"]).read_text())["counts"]["detail_completed"] == 1
    assert Path(result["report_path"]).read_text().startswith("EUNORA 자동 점검")


def test_unknown_package_stops_before_reading_sources_or_inventory(case):
    case["package_name"][0] = "unknown.application"
    with pytest.raises(audit.EunoraAuditError, match="7개"):
        audit.run_eunora_audit(case["apk"], case["project"])
    assert len(case["calls"]) == 1


def test_unfound_class_is_explicit_and_not_sent_for_detail(case, monkeypatch):
    monkeypatch.setattr(audit, "_declared_classes", lambda path: Counter())
    case["inventory"]["matches"] = []
    result = audit.run_eunora_audit(case["apk"], case["project"])
    assert result["status"] == "partial"
    assert result["rows"][0]["status"] == "not_found"
    assert len(case["calls"]) == 2
    assert "split APK" in result["report"]


def test_inventory_duplicate_forces_review_without_detail(case):
    case["inventory"]["duplicate_names"] = [{"name": "example.Orders", "occurrences": 2}]
    result = audit.run_eunora_audit(case["apk"], case["project"])
    assert result["rows"][0]["status"] == "needs_review"
    assert not result["class_results"]


def test_actual_dex_duplicate_also_forces_review(case, monkeypatch):
    monkeypatch.setattr(audit, "_declared_classes", lambda path: Counter({"example.Orders": 2}))
    result = audit.run_eunora_audit(case["apk"], case["project"])
    assert result["rows"][0]["status"] == "needs_review"


def test_missing_method_is_review_and_inherited_lookup_not_declared_broken(case):
    case["methods"].clear()
    result = audit.run_eunora_audit(case["apk"], case["project"])
    assert result["rows"][0]["status"] == "needs_review"
    assert "상속" in result["rows"][0]["note"]
    assert len(result["class_results"]) == 1


def test_multiple_overloads_are_reported_as_name_only(case):
    case["methods"].append({"name": "load", "overload_index": 1, "dex_descriptor": "(I)V"})
    result = audit.run_eunora_audit(case["apk"], case["project"])
    assert result["rows"][0]["method_checks"][0]["matching_overloads"] == 2
    assert "원형 미검증" in result["report"]


def test_unique_defpackage_alias_requires_real_declaration(case):
    case["targets"][0]["class_name"] = "obfuscated"
    case["inventory"]["matches"] = ["defpackage.obfuscated"]
    result = audit.run_eunora_audit(case["apk"], case["project"])
    assert result["rows"][0]["resolved_class"] == "defpackage.obfuscated"
    assert result["rows"][0]["status"] == "method_name_found"


def test_alias_ambiguous_against_another_real_owner_is_not_selected(case, monkeypatch):
    case["targets"][0]["class_name"] = "example.Outer$Inner"
    case["inventory"]["matches"] = ["example.Outer.Inner"]
    monkeypatch.setattr(audit, "_declared_classes", lambda path: Counter({"example.Outer$Inner": 1, "example.Outer.Inner": 1}))
    result = audit.run_eunora_audit(case["apk"], case["project"])
    assert result["rows"][0]["status"] == "needs_review"
    assert result["class_results"] == []


def test_detail_is_bounded_and_deferred_not_silently_skipped(case, monkeypatch):
    monkeypatch.setattr(audit, "MAX_DETAIL_CLASSES", 1)
    case["targets"].append({**case["targets"][0], "class_name": "example.Second"})
    case["inventory"]["matches"].append("example.Second")
    result = audit.run_eunora_audit(case["apk"], case["project"])
    assert [item["status"] for item in result["rows"]] == ["method_name_found", "deferred"]
    assert result["counts"]["detail_attempted"] == 1
    assert result["status"] == "partial"


def test_detail_failure_does_not_discard_other_classes(case, monkeypatch):
    case["targets"].append({**case["targets"][0], "class_name": "example.Second"})
    case["inventory"]["matches"].append("example.Second")
    def run(path, *, operation, **options):
        if operation == "class" and options["class_name"] == "example.Orders":
            raise RuntimeError("synthetic unavailable class")
        return case["run"](path, operation=operation, **options)
    monkeypatch.setattr(audit, "run_rea_analysis", run)
    result = audit.run_eunora_audit(case["apk"], case["project"])
    assert [item["status"] for item in result["rows"]] == ["error", "method_name_found"]
    assert result["status"] == "partial"
    assert len(result["class_results"]) == 1


@pytest.mark.parametrize("changed", ["apk", "source"])
def test_edits_during_detail_never_publish_a_report(case, monkeypatch, changed):
    def run(path, *, operation, **options):
        result = case["run"](path, operation=operation, **options)
        if operation == "class":
            case[changed].write_bytes(case[changed].read_bytes() + b"changed")
        return result
    monkeypatch.setattr(audit, "run_rea_analysis", run)
    with pytest.raises(audit.EunoraAuditError, match="変更|변경"):
        audit.run_eunora_audit(case["apk"], case["project"])
    assert not list(audit.app_dir().glob("eunora_audits/*"))


def test_wrong_apk_evidence_aborts_instead_of_marking_class_error(case, monkeypatch):
    def run(path, *, operation, **options):
        result = case["run"](path, operation=operation, **options)
        if operation == "class":
            result["evidence"]["subject"]["digest"]["sha256"] = "0" * 64
        return result
    monkeypatch.setattr(audit, "run_rea_analysis", run)
    with pytest.raises(audit.EunoraAuditError, match="다른 APK"):
        audit.run_eunora_audit(case["apk"], case["project"])


def test_cancellation_propagates_without_audit_output(case, monkeypatch):
    def run(path, *, operation, **options):
        if operation == "class":
            raise CancelledError("cancel")
        return case["run"](path, operation=operation, **options)
    monkeypatch.setattr(audit, "run_rea_analysis", run)
    with pytest.raises(CancelledError):
        audit.run_eunora_audit(case["apk"], case["project"])
    assert not list(audit.app_dir().glob("eunora_audits/*"))


def test_unresolved_source_and_empty_targets_remain_partial(case):
    case["targets"].clear()
    case["catalog"]["unresolved"] = [{"file": "E05.kt", "line": 12, "reason": "dynamic owner"}]
    result = audit.run_eunora_audit(case["apk"], case["project"])
    assert result["status"] == "partial"
    assert result["counts"]["unresolved"] == 1
    assert "dynamic owner" in result["report"]


def test_partial_inventory_cannot_be_used_to_claim_targets_missing(case):
    case["inventory"]["coverage"] = "partial"
    with pytest.raises(audit.EunoraAuditError, match="완전한"):
        audit.run_eunora_audit(case["apk"], case["project"])


def test_source_path_escape_is_rejected_before_inventory(case):
    case["catalog"]["source_files"] = {"../outside.kt": "0" * 64}
    with pytest.raises(audit.EunoraAuditError, match="밖"):
        audit.run_eunora_audit(case["apk"], case["project"])


def _declared_dex(owner):
    """Minimal inert class_def fixture, containing no methods or instructions."""
    descriptor = ("L" + owner.replace(".", "/") + ";").encode()
    value = bytearray(152)
    value[:8] = b"dex\n035\0"
    struct.pack_into("<II", value, 36, 112, 0x12345678)
    struct.pack_into("<II", value, 56, 1, 112)
    struct.pack_into("<II", value, 64, 1, 116)
    struct.pack_into("<II", value, 96, 1, 120)
    struct.pack_into("<I", value, 112, 152)
    value.extend(bytes([len(descriptor)]) + descriptor + b"\0")
    struct.pack_into("<I", value, 32, len(value))
    return bytes(value)


def test_raw_class_inventory_counts_declarations_across_dex_files(tmp_path):
    apk = tmp_path / "multidex.apk"
    with zipfile.ZipFile(apk, "w") as archive:
        archive.writestr("classes.dex", _declared_dex("example.Orders"))
        archive.writestr("classes2.dex", _declared_dex("example.Orders"))
        archive.writestr("assets/not-a-class.txt", "example.Decoy")
    assert audit._declared_classes(apk) == Counter({"example.Orders": 2})


def test_unsupported_raw_dex_declaration_fails_actionably(tmp_path):
    apk = tmp_path / "broken.apk"
    with zipfile.ZipFile(apk, "w") as archive:
        archive.writestr("classes.dex", b"not a dex declaration")
    with pytest.raises(audit.EunoraAuditError, match="클래스 선언"):
        audit._declared_classes(apk)


def test_class_detail_malformed_result_is_reported_as_partial(case, monkeypatch):
    def run(path, *, operation, **options):
        result = case["run"](path, operation=operation, **options)
        if operation == "class":
            result["evidence"]["normalized_result"]["class_name"] = "wrong.Class"
        return result
    monkeypatch.setattr(audit, "run_rea_analysis", run)
    result = audit.run_eunora_audit(case["apk"], case["project"])
    assert result["status"] == "partial"
    assert result["rows"][0]["status"] == "error"
    assert result["class_results"] == []

"""Security candidates require matching APK, source, REA and DEX declarations."""
from collections import Counter
import copy
import hashlib
import json
from pathlib import Path
import zipfile

import pytest

from l_app import security_audit as audit
from l_app.processes import CancelledError


def _sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


@pytest.fixture
def case(tmp_path, monkeypatch):
    monkeypatch.setenv("L_APP_DATA_DIR", str(tmp_path / "L data"))
    project = tmp_path / "EUNORA original"
    source = project / "app/src/main/java/com/example/wheelprobe/E05.kt"
    source.parent.mkdir(parents=True)
    source.write_text("// original E05\n")
    main = source.with_name("ModuleMain.kt")
    main.write_text("// original ModuleMain\n")
    apk = tmp_path / "test.apk"
    with zipfile.ZipFile(apk, "w") as archive:
        archive.writestr("AndroidManifest.xml", "inert synthetic fixture")
    files = {path.relative_to(project).as_posix(): _sha(path) for path in (main, source)}
    catalog = {"project_root": str(project), "app_key": "logi", "source_files": files}
    candidate = {"id": "test-one", "class_name": "example.RootChecks", "method_name": "isRooted",
                 "dex_descriptor": "()Z", "access_flags": 9, "categories": ["root_files"],
                 "signals": ["root:su_path"], "evidence_kind": "method_literal",
                 "modes": ["observe", "boolean_false"], "note": "heuristic candidate"}
    scan = {"apk_digest": _sha(apk), "candidates": [candidate],
            "coverage": {"truncated": False, "unsupported_methods": 0}, "limitations": ["static candidates only"]}
    inventory = {"matches": ["example.RootChecks"], "coverage": "complete", "duplicate_names": []}
    methods = [{"name": "isRooted", "dex_descriptor": "()Z", "overload_index": 0, "is_constructor": False}]
    package = ["com.logisoft.Logi4"]
    calls = []

    def result(operation, normalized):
        return {"operation": operation, "status": "complete", "report": "synthetic REA report",
                "evidence": {"subject": {"digest": {"sha256": _sha(apk)}}, "normalized_result": normalized}}

    def run(path, *, operation, **options):
        calls.append((operation, options))
        if operation == "package":
            return result(operation, {"package_name": package[0]})
        if operation == "class_search":
            assert options["query"] == ""
            return result(operation, inventory)
        assert operation == "class"
        return result(operation, {"class_name": options["class_name"], "methods": methods})

    def target(path, class_name, method_name, descriptor):
        return {"class_name": class_name.removeprefix("defpackage."), "name": method_name,
                "dex_descriptor": descriptor, "access_flags": 9, "code_offset": 128}

    monkeypatch.setattr(audit, "collect_source_catalog", lambda path, key: catalog)
    monkeypatch.setattr(audit, "scan_security_candidates", lambda path, **options: scan)
    monkeypatch.setattr(audit, "_declared_classes", lambda path: Counter({item["class_name"]: 1 for item in scan["candidates"]}))
    monkeypatch.setattr(audit, "_verified_target", target)
    monkeypatch.setattr(audit, "run_rea_analysis", run)
    return dict(apk=apk, project=project, source=source, main=main, files=files, catalog=catalog,
                scan=scan, candidate=candidate, inventory=inventory, methods=methods, package=package,
                calls=calls, run=run, result=result, target=target)


def test_automatic_profile_and_exact_choice_preserve_originals(case):
    originals = {path: path.read_bytes() for path in (case["source"], case["main"], case["apk"])}
    result = audit.run_security_audit(case["apk"], case["project"])
    assert result["app_key"] == "logi"
    assert result["status"] == "complete"
    assert result["rows"][0]["status"] == "ready"
    choice = result["choices"][0]
    assert choice["modes"] == ["observe", "boolean_false"]
    assert choice["dex_descriptor"] == "()Z"
    assert choice["overload_index"] == 0
    assert choice["class_evidence"] == choice["class_result"]["evidence"]
    assert choice["candidate"] == case["candidate"]
    assert result["source_files"] == case["files"]
    assert [operation for operation, _ in case["calls"]] == ["package", "class_search", "class"]
    assert "후보의 근거" in result["report"]
    assert "실기기 동작을 증명하지 않습니다" in result["report"]
    assert json.loads(Path(result["json_path"]).read_text())["counts"]["boolean_false"] == 1
    assert Path(result["report_path"]).read_text().startswith("EUNORA 보안 자동 점검")
    assert all(path.read_bytes() == before for path, before in originals.items())


def test_unknown_package_stops_before_scanner(case, monkeypatch):
    case["package"][0] = "unregistered.application"
    monkeypatch.setattr(audit, "scan_security_candidates", lambda *a, **k: pytest.fail("must not scan"))
    with pytest.raises(audit.SecurityAuditError, match="7개"):
        audit.run_security_audit(case["apk"], case["project"])


def test_wrong_scan_apk_is_fatal(case):
    case["scan"]["apk_digest"] = "0" * 64
    with pytest.raises(audit.SecurityAuditError, match="SHA-256"):
        audit.run_security_audit(case["apk"], case["project"])


@pytest.mark.parametrize("field,value", [("modes", "boolean_false"), ("access_flags", True), ("id", "")])
def test_malformed_candidates_do_not_become_success(case, field, value):
    case["candidate"][field] = value
    with pytest.raises(audit.SecurityAuditError):
        audit.run_security_audit(case["apk"], case["project"])


def test_duplicate_candidate_ids_are_rejected(case):
    case["scan"]["candidates"].append(copy.deepcopy(case["candidate"]))
    with pytest.raises(audit.SecurityAuditError, match="식별자"):
        audit.run_security_audit(case["apk"], case["project"])


def test_same_method_name_with_other_signature_is_not_selected(case):
    case["methods"][0]["dex_descriptor"] = "(I)Z"
    result = audit.run_security_audit(case["apk"], case["project"])
    assert result["choices"] == []
    assert result["rows"][0]["status"] == "needs_review"


def test_duplicate_exact_rea_descriptors_remain_ambiguous(case):
    case["methods"].append({**case["methods"][0], "overload_index": 1})
    result = audit.run_security_audit(case["apk"], case["project"])
    assert not result["choices"]
    assert result["status"] == "partial"


def test_unique_defpackage_alias_bound_to_actual_owner(case):
    case["candidate"]["class_name"] = "obfuscated"
    case["inventory"]["matches"] = ["defpackage.obfuscated"]
    result = audit.run_security_audit(case["apk"], case["project"])
    assert result["rows"][0]["resolved_class"] == "defpackage.obfuscated"
    assert len(result["choices"]) == 1


def test_actual_owner_alias_collision_never_generates(case, monkeypatch):
    case["candidate"]["class_name"] = "example.Outer$Inner"
    case["inventory"]["matches"] = ["example.Outer.Inner"]
    monkeypatch.setattr(audit, "_declared_classes", lambda path: Counter({"example.Outer$Inner": 1, "example.Outer.Inner": 1}))
    result = audit.run_security_audit(case["apk"], case["project"])
    assert not result["choices"]
    assert result["rows"][0]["status"] == "needs_review"


def test_scanner_flags_must_match_actual_dex(case, monkeypatch):
    def target(*args):
        return {**case["target"](*args), "access_flags": 1}
    monkeypatch.setattr(audit, "_verified_target", target)
    result = audit.run_security_audit(case["apk"], case["project"])
    assert not result["choices"]
    assert "접근 플래그" in result["rows"][0]["note"]


@pytest.mark.parametrize("descriptor,categories,allowed", [
    ("()Z", ["integrity"], ["observe"]),
    ("()Ljava/lang/Boolean;", ["root_files"], ["observe"]),
    ("()V", ["hook_stack"], ["observe", "skip_void"]),
    ("()V", ["integrity"], ["observe"]),
    ("()Z", ["root_files"], ["observe", "boolean_false"]),
])
def test_modes_require_exact_primitive_return_and_local_category(case, descriptor, categories, allowed):
    case["candidate"].update(dex_descriptor=descriptor, categories=categories, modes=["observe", "boolean_false", "skip_void"])
    case["methods"][0]["dex_descriptor"] = descriptor
    result = audit.run_security_audit(case["apk"], case["project"])
    assert result["choices"][0]["modes"] == allowed


def test_unsupported_candidate_is_visible_without_class_detail(case):
    case["candidate"]["modes"] = []
    case["candidate"]["note"] = "native implementation"
    result = audit.run_security_audit(case["apk"], case["project"])
    assert result["rows"][0]["status"] == "unsupported"
    assert not result["choices"]
    assert [op for op, _ in case["calls"]] == ["package", "class_search"]


def test_partial_class_results_do_not_generate(case, monkeypatch):
    def run(path, *, operation, **options):
        result = case["run"](path, operation=operation, **options)
        if operation == "class":
            result["status"] = "partial"
        return result
    monkeypatch.setattr(audit, "run_rea_analysis", run)
    result = audit.run_security_audit(case["apk"], case["project"])
    assert result["status"] == "partial"
    assert not result["choices"]


def test_class_failures_are_cached_and_other_classes_continue(case, monkeypatch):
    second = {**case["candidate"], "id": "test-two", "method_name": "check"}
    third = {**case["candidate"], "id": "test-three", "class_name": "example.Other"}
    case["scan"]["candidates"].extend([second, third])
    case["inventory"]["matches"].append("example.Other")
    failed = []
    def run(path, *, operation, **options):
        if operation == "class" and options["class_name"] == "example.RootChecks":
            failed.append(options["class_name"])
            raise RuntimeError("synthetic unavailable class")
        return case["run"](path, operation=operation, **options)
    monkeypatch.setattr(audit, "run_rea_analysis", run)
    result = audit.run_security_audit(case["apk"], case["project"])
    assert [item["status"] for item in result["rows"]] == ["error", "error", "ready"]
    assert len(failed) == 1
    assert result["counts"]["detail_attempted"] == 2


def test_unique_class_limit_is_explicit(case, monkeypatch):
    monkeypatch.setattr(audit, "MAX_DETAIL_CLASSES", 1)
    case["scan"]["candidates"].append({**case["candidate"], "id": "test-two", "class_name": "example.Other"})
    case["inventory"]["matches"].append("example.Other")
    result = audit.run_security_audit(case["apk"], case["project"])
    assert [item["status"] for item in result["rows"]] == ["ready", "deferred"]
    assert result["counts"]["detail_attempted"] == 1


def test_void_test_target_precedes_observation_only_integrity_under_detail_limit(case, monkeypatch):
    monkeypatch.setattr(audit, "MAX_DETAIL_CLASSES", 1)
    case["candidate"].update(categories=["integrity"], modes=["observe"])
    local = {**case["candidate"], "id": "local-void", "class_name": "example.LocalHookCheck",
             "dex_descriptor": "()V", "categories": ["hook_stack"], "modes": ["observe", "skip_void"]}
    case["scan"]["candidates"].append(local)
    case["inventory"]["matches"].append(local["class_name"])
    case["methods"][0]["dex_descriptor"] = "()V"
    result = audit.run_security_audit(case["apk"], case["project"])
    assert result["rows"][0]["candidate"]["id"] == "local-void"
    assert result["rows"][0]["status"] == "ready"
    assert result["choices"][0]["modes"] == ["observe", "skip_void"]
    assert result["rows"][1]["status"] == "deferred"
    assert result["counts"]["skip_void"] == 1


def test_empty_scan_does_not_claim_no_security_or_query_inventory(case):
    case["scan"]["candidates"].clear()
    result = audit.run_security_audit(case["apk"], case["project"])
    assert result["status"] == "partial"
    assert result["choices"] == []
    assert "보안 검사가 없다는 뜻은 아닙니다" in result["report"]
    assert [op for op, _ in case["calls"]] == ["package"]


@pytest.mark.parametrize("changed", ["apk", "source"])
def test_inputs_changed_during_analysis_never_publish_report(case, monkeypatch, changed):
    def run(path, *, operation, **options):
        result = case["run"](path, operation=operation, **options)
        if operation == "class":
            case[changed].write_bytes(case[changed].read_bytes() + b"changed")
        return result
    monkeypatch.setattr(audit, "run_rea_analysis", run)
    with pytest.raises(audit.SecurityAuditError, match="변경"):
        audit.run_security_audit(case["apk"], case["project"])
    assert not list(audit.app_dir().glob("security_audits/*"))


def test_other_apk_class_evidence_is_fatal_not_partial(case, monkeypatch):
    def run(path, *, operation, **options):
        result = case["run"](path, operation=operation, **options)
        if operation == "class":
            result["evidence"]["subject"]["digest"]["sha256"] = "0" * 64
        return result
    monkeypatch.setattr(audit, "run_rea_analysis", run)
    with pytest.raises(audit.SecurityAuditError, match="다른 APK"):
        audit.run_security_audit(case["apk"], case["project"])


def test_cancellation_propagates_without_report(case, monkeypatch):
    def run(path, *, operation, **options):
        if operation == "class":
            raise CancelledError("cancelled")
        return case["run"](path, operation=operation, **options)
    monkeypatch.setattr(audit, "run_rea_analysis", run)
    with pytest.raises(CancelledError):
        audit.run_security_audit(case["apk"], case["project"])
    assert not list(audit.app_dir().glob("security_audits/*"))


def test_failed_second_report_write_removes_our_first_file(case, monkeypatch):
    original = audit.atomic_write_text
    def write(path, text):
        if Path(path).suffix == ".txt":
            raise OSError("synthetic disk failure")
        original(path, text)
    monkeypatch.setattr(audit, "atomic_write_text", write)
    with pytest.raises(OSError, match="disk failure"):
        audit.run_security_audit(case["apk"], case["project"])
    assert not list(audit.app_dir().glob("security_audits/*"))


def test_scanner_unknown_coverage_is_not_silently_complete(case):
    case["scan"]["coverage"]["unsupported_methods"] = 4
    result = audit.run_security_audit(case["apk"], case["project"])
    assert result["status"] == "partial"
    assert "해석하지 못한 메서드 4개" in result["report"]


def test_row_limit_reports_omitted_candidates(case, monkeypatch):
    monkeypatch.setattr(audit, "MAX_CANDIDATE_ROWS", 1)
    case["scan"]["candidates"].append({**case["candidate"], "id": "test-two"})
    result = audit.run_security_audit(case["apk"], case["project"])
    assert result["counts"]["rows_omitted"] == 1
    assert result["status"] == "partial"
    assert "1개를 보류" in result["report"]

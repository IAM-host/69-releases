"""APK evidence and JADX cache lifecycle tests; no ADB or real decompiler needed."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import struct
import subprocess
import tempfile
import unittest
from unittest import mock
import zipfile

from l_app import analysis


def _uleb(value: int) -> bytes:
    result = bytearray()
    while value >= 128:
        result.append((value & 127) | 128)
        value >>= 7
    result.append(value)
    return bytes(result)


def make_dex(strings: list[str]) -> bytes:
    """Minimal DEX string table, deliberately independent of app code fixtures."""
    header = bytearray(0x70)
    header[:8] = b"dex\n035\0"
    struct.pack_into("<I", header, 36, 0x70)
    struct.pack_into("<I", header, 40, 0x12345678)
    struct.pack_into("<II", header, 56, len(strings), 0x70)
    table = bytearray(4 * len(strings))
    payload = bytearray()
    for index, text in enumerate(strings):
        offset = 0x70 + len(table) + len(payload)
        struct.pack_into("<I", table, index * 4, offset)
        utf16_length = len(text.encode("utf-16-le")) // 2
        payload.extend(_uleb(utf16_length))
        payload.extend(text.encode("utf-8"))
        payload.append(0)
    content = header + table + payload
    struct.pack_into("<I", content, 32, len(content))
    return bytes(content)


def make_apk(path: Path, strings: list[str], **assets: str) -> Path:
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("classes.dex", make_dex(strings))
        for name, value in assets.items():
            archive.writestr(name, value)
    return path


class DexEvidenceTests(unittest.TestCase):
    def test_compressed_dex_needles_include_short_and_descriptor_strings(self):
        with tempfile.TemporaryDirectory() as folder:
            apk = make_apk(Path(folder) / "base.apk", ["di", "Lcom/example/Target;", "후불20K"])
            result = dict(analysis.check_needles(apk, ["di", "Target", "후불20K", "absent"]))
            self.assertEqual(result, {"di": True, "Target": True, "후불20K": True, "absent": False})

    def test_archive_filename_and_asset_text_are_not_dex_evidence(self):
        with tempfile.TemporaryDirectory() as folder:
            apk = make_apk(Path(folder) / "base.apk", ["ordinary"], **{
                "assets/asset_only_marker.txt": "asset_only_marker",
            })
            self.assertFalse(analysis.apk_has_needle(apk, "asset_only_marker"))

    def test_all_dex_entries_are_inspected(self):
        with tempfile.TemporaryDirectory() as folder:
            apk = make_apk(Path(folder) / "base.apk", ["first"])
            with zipfile.ZipFile(apk, "a", compression=zipfile.ZIP_DEFLATED) as archive:
                archive.writestr("classes2.dex", make_dex(["second_dex_marker"]))
            self.assertTrue(analysis.apk_has_needle(apk, "second_dex_marker"))

    def test_empty_needle_and_missing_apk_have_no_evidence(self):
        self.assertFalse(analysis.apk_has_needle(Path("does-not-exist.apk"), ""))
        self.assertFalse(analysis.apk_has_needle(Path("does-not-exist.apk"), "target"))

    def test_needles_preserve_order_and_ignore_empty_input(self):
        with tempfile.TemporaryDirectory() as folder:
            apk = make_apk(Path(folder) / "base.apk", ["marker"])
            self.assertEqual(analysis.check_needles(apk, ["missing", "", "marker"]),
                             [("missing", False), ("marker", True)])

    def test_invalid_dex_does_not_fabricate_strings(self):
        for data in [b"", b"not dex" * 20, make_dex(["valid"])[:0x71]]:
            with self.subTest(size=len(data)):
                self.assertEqual(analysis._dex_string_list(data), [])

    def test_invalid_string_table_counts_and_offsets_are_rejected(self):
        for field, value in [(56, 0xFFFFFFFF), (60, 0xFFFFFFFE)]:
            damaged = bytearray(make_dex(["valid"]))
            struct.pack_into("<I", damaged, field, value)
            self.assertEqual(analysis._dex_string_list(bytes(damaged)), [])

    def test_corrupt_apk_dex_is_an_error_instead_of_all_missing_evidence(self):
        with tempfile.TemporaryDirectory() as folder:
            apk = Path(folder) / "damaged.apk"
            with zipfile.ZipFile(apk, "w") as archive:
                archive.writestr("classes.dex", b"not a valid DEX")
            with self.assertRaisesRegex(RuntimeError, "classes.dex"):
                analysis.check_needles(apk, ["target"])
            with self.assertRaises(RuntimeError):
                analysis.analyze_apk_structure(apk)

    def test_cancelled_parser_does_not_silently_report_empty_strings(self):
        import threading
        from l_app.processes import bind_cancel_event, CancelledError
        event = threading.Event()
        event.set()
        with bind_cancel_event(event):
            with self.assertRaises(CancelledError):
                analysis._dex_string_list(make_dex(["target"]))

    def test_truncated_and_overlong_uleb_values_are_rejected(self):
        for data in [b"", b"\x80", b"\x80" * 6, b"\xff" * 5]:
            with self.subTest(data=data):
                with self.assertRaises((ValueError, IndexError)):
                    analysis._uleb128(data, 0)

    def test_valid_uleb_and_unicode_string_table_survive(self):
        self.assertEqual(analysis._uleb128(b"\xe5\x8e\x26", 0), (624485, 3))
        self.assertEqual(analysis._dex_string_list(make_dex(["a", "도착지", "Example.method"])),
                         ["a", "도착지", "Example.method"])


class JadxDiscoveryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.app = self.root / "app"
        self.app.mkdir()
        self.explicit = self.root / "explicit-jadx"
        self.saved = self.root / "saved-jadx"
        self.bin = self.root / "bin"
        self.bin.mkdir()
        self.path_tool = self.bin / ("jadx.bat" if os.name == "nt" else "jadx")
        for tool in [self.explicit, self.saved, self.path_tool]:
            tool.write_text("placeholder", encoding="utf-8")
            tool.chmod(0o755)
        self.patcher = mock.patch.object(analysis, "app_dir", return_value=self.app)
        self.patcher.start()

    def tearDown(self):
        self.patcher.stop()
        self.temp.cleanup()

    def test_explicit_configuration_wins_saved_and_path(self):
        (self.app / "jadx_path.txt").write_text(str(self.saved), encoding="utf-8")
        with mock.patch.dict(os.environ, {"PATH": str(self.bin)}):
            self.assertEqual(analysis.find_jadx(str(self.explicit)), str(self.explicit))

    def test_invalid_explicit_path_is_not_silently_replaced(self):
        (self.app / "jadx_path.txt").write_text(str(self.saved), encoding="utf-8")
        with mock.patch.dict(os.environ, {"PATH": str(self.bin)}):
            self.assertIsNone(analysis.find_jadx(str(self.root / "missing")))

    def test_saved_configuration_wins_path_when_no_explicit_path_is_set(self):
        (self.app / "jadx_path.txt").write_text(str(self.saved), encoding="utf-8")
        with mock.patch.dict(os.environ, {"PATH": str(self.bin)}):
            self.assertEqual(analysis.find_jadx(), str(self.saved))

    def test_path_discovery_works_without_a_personal_fixed_directory(self):
        with mock.patch.dict(os.environ, {"PATH": str(self.bin)}):
            self.assertEqual(analysis.find_jadx(), str(self.path_tool))


class JadxCacheTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.app = self.root / "app"
        self.app.mkdir()
        self.apk = make_apk(self.root / "base.apk", ["needle"])
        self.tool = self.root / "jadx-tool"
        self.tool.write_text("tool-version-one", encoding="utf-8")
        self.calls = []
        self.patchers = [
            mock.patch.object(analysis, "app_dir", return_value=self.app),
            mock.patch.object(analysis, "find_jadx", side_effect=lambda *_: str(self.tool)),
        ]
        for patcher in self.patchers:
            patcher.start()

    def tearDown(self):
        for patcher in reversed(self.patchers):
            patcher.stop()
        self.temp.cleanup()

    def manifest_files(self):
        return list(self.app.rglob(".l-jadx-cache.json"))

    def decompiler(self, returncode=0, write_java=True, fail_after_write=None):
        def invoke(args, **kwargs):
            self.calls.append((list(args), dict(kwargs)))
            if write_java:
                output = Path(args[args.index("-d") + 1]) / "sources" / "com" / "example"
                output.mkdir(parents=True, exist_ok=True)
                (output / "Sample.java").write_text(
                    'package com.example; public class Sample { public void execute() { String value = "needle"; } }',
                    encoding="utf-8",
                )
            if fail_after_write is not None:
                raise fail_after_write
            return subprocess.CompletedProcess(args, returncode, "decompiler output", "decompiler diagnostics")
        return invoke

    def test_complete_cache_reused_with_full_apk_identity(self):
        with mock.patch.object(analysis, "run_process", side_effect=self.decompiler()):
            first = analysis.jadx_xref(self.apk, ["needle"])
            second = analysis.jadx_xref(self.apk, ["needle"])
        self.assertEqual(len(self.calls), 1)
        self.assertIn("Sample.java", first)
        self.assertIn("Sample.java", second)
        self.assertEqual(len(self.manifest_files()), 1)
        record = json.loads(self.manifest_files()[0].read_text())
        self.assertEqual(record["status"], "complete")
        self.assertEqual(record["apk_sha256"], hashlib.sha256(self.apk.read_bytes()).hexdigest())

    def test_orphaned_java_from_interrupted_run_does_not_become_cache_success(self):
        with mock.patch.object(analysis, "run_process", side_effect=self.decompiler(fail_after_write=RuntimeError("interrupted fixture"))):
            failed = analysis.jadx_xref(self.apk, ["needle"])
        self.assertTrue(failed.startswith("[jadx 오류]"), failed)
        with mock.patch.object(analysis, "run_process", side_effect=self.decompiler()):
            recovered = analysis.jadx_xref(self.apk, ["needle"])
        self.assertEqual(len(self.calls), 2)
        self.assertIn("Sample.java", recovered)
        self.assertEqual(json.loads(self.manifest_files()[0].read_text())["status"], "complete")

    def test_tool_content_change_invalidates_reusable_cache(self):
        with mock.patch.object(analysis, "run_process", side_effect=self.decompiler()):
            analysis.jadx_xref(self.apk, ["needle"])
            self.tool.write_text("tool-version-two-different", encoding="utf-8")
            analysis.jadx_xref(self.apk, ["needle"])
        self.assertEqual(len(self.calls), 2)
        self.assertEqual(len(self.manifest_files()), 2)

    def test_different_tool_path_does_not_reuse_same_apk_cache(self):
        with mock.patch.object(analysis, "run_process", side_effect=self.decompiler()):
            analysis.jadx_xref(self.apk, ["needle"])
            self.tool = self.root / "another-jadx-tool"
            self.tool.write_text("tool-version-one", encoding="utf-8")
            analysis.jadx_xref(self.apk, ["needle"])
        self.assertEqual(len(self.calls), 2)

    def test_same_apk_filename_with_new_content_gets_a_new_cache(self):
        with mock.patch.object(analysis, "run_process", side_effect=self.decompiler()):
            analysis.jadx_xref(self.apk, ["needle"])
            make_apk(self.apk, ["updated_apk_content"])
            analysis.jadx_xref(self.apk, ["needle"])
        self.assertEqual(len(self.calls), 2)
        self.assertEqual(len(self.manifest_files()), 2)

    def test_damaged_cache_manifest_does_not_reuse_sources(self):
        with mock.patch.object(analysis, "run_process", side_effect=self.decompiler()):
            analysis.jadx_xref(self.apk, ["needle"])
            self.manifest_files()[0].write_text("{interrupted JSON", encoding="utf-8")
            analysis.jadx_xref(self.apk, ["needle"])
        self.assertEqual(len(self.calls), 2)
        self.assertEqual(json.loads(self.manifest_files()[0].read_text())["status"], "complete")

    def test_wrong_manifest_shape_is_rebuilt(self):
        with mock.patch.object(analysis, "run_process", side_effect=self.decompiler()):
            analysis.jadx_xref(self.apk, ["needle"])
            self.manifest_files()[0].write_text("[]", encoding="utf-8")
            analysis.jadx_xref(self.apk, ["needle"])
        self.assertEqual(len(self.calls), 2)

    def test_deleted_one_of_several_sources_invalidates_cache(self):
        original = self.decompiler()
        def several(args, **kwargs):
            result = original(args, **kwargs)
            output = Path(args[args.index("-d") + 1]) / "sources"
            (output / "Second.java").write_text("class Second {}", encoding="utf-8")
            return result
        with mock.patch.object(analysis, "run_process", side_effect=several):
            analysis.jadx_xref(self.apk, ["needle"])
            next(self.app.rglob("Second.java")).unlink()
            analysis.jadx_xref(self.apk, ["needle"])
        self.assertEqual(len(self.calls), 2)

    def test_manifest_without_java_sources_is_not_a_cache_hit(self):
        with mock.patch.object(analysis, "run_process", side_effect=self.decompiler()):
            analysis.jadx_xref(self.apk, ["needle"])
            for source in self.app.rglob("*.java"):
                source.unlink()
            analysis.jadx_xref(self.apk, ["needle"])
        self.assertEqual(len(self.calls), 2)

    def test_nonzero_result_with_java_is_reported_as_partial(self):
        with mock.patch.object(analysis, "run_process", side_effect=self.decompiler(returncode=1)):
            report = analysis.jadx_xref(self.apk, ["needle"])
        self.assertTrue(report.startswith("[jadx"), report)
        self.assertIn("부분", report.splitlines()[0])
        self.assertIn("Sample.java", report)
        self.assertEqual(json.loads(self.manifest_files()[0].read_text())["status"], "partial")

    def test_no_java_failure_is_not_recorded_as_complete(self):
        with mock.patch.object(analysis, "run_process", side_effect=self.decompiler(returncode=1, write_java=False)):
            report = analysis.jadx_xref(self.apk, ["needle"])
        self.assertTrue(report.startswith("[jadx"), report)
        self.assertIn("Java 소스", report)
        for manifest in self.manifest_files():
            self.assertNotEqual(json.loads(manifest.read_text())["status"], "complete")

    def test_cancellation_propagates_and_does_not_commit_cache(self):
        from l_app.processes import CancelledError
        with mock.patch.object(analysis, "run_process", side_effect=self.decompiler(fail_after_write=CancelledError("cancel fixture"))):
            with self.assertRaises(CancelledError):
                analysis.jadx_xref(self.apk, ["needle"])
        self.assertFalse(self.manifest_files())


if __name__ == "__main__":
    unittest.main()

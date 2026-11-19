"""Service regressions use temporary data and a fake ADB transport, never a phone."""
from __future__ import annotations

import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch
import zipfile

from l_app import adb, config, state
from l_app.paths import apk_dir
from l_app.processes import CancelledError


class ProfileTests(unittest.TestCase):
    def test_seven_distinct_apps_keep_existing_history_keys(self):
        self.assertEqual(len(config.DRIVER_APPS), 7)
        for key in ("kakao", "callmaner", "tmap", "logi", "idrive"):
            self.assertIn(key, config.DRIVER_APPS)
        self.assertEqual(config.DRIVER_APPS["callmaner2"]["package"], "com.callmanerdriver2sharp2")
        self.assertEqual(config.DRIVER_APPS["logi2"]["package"], "com.logisoft.Logi5")
        self.assertEqual(len({item["package"] for item in config.DRIVER_APPS.values()}), 7)

    def test_variant_rules_can_fall_back_without_merging_storage_keys(self):
        self.assertEqual(config.family_for("callmaner2"), "callmaner")
        self.assertEqual(config.family_for("logi2"), "logi")
        self.assertEqual(config.family_for("custom"), "custom")
        self.assertNotIn("GetOrders", config.DRIVER_APPS["idrive"]["needles"])
        self.assertIn("overlayAction", config.DRIVER_APPS["idrive"]["needles"])
        self.assertNotIn("wh", config.DRIVER_APPS["callmaner"]["needles"])


class AppDataCase(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.environment = patch.dict(os.environ, {"L_APP_DATA_DIR": str(self.root)})
        self.environment.start()

    def tearDown(self):
        self.environment.stop()
        self.temporary.cleanup()


class TemporaryAppDataTests(AppDataCase):
    def test_history_keeps_variants_separate_and_skips_incomplete(self):
        for app, stamp in [("callmaner", "20261116_010000"), ("callmaner2", "20261116_020000")]:
            folder = apk_dir() / app / stamp
            folder.mkdir(parents=True)
            (folder / "base.apk").write_bytes(b"existing historical snapshot")
        incomplete = apk_dir() / "callmaner" / "20261116_030000"
        incomplete.mkdir()
        (incomplete / "base.apk").write_bytes(b"unfinished")
        (incomplete / ".incomplete").touch()
        self.assertEqual(state.previous_snapshot("callmaner").parent.name, "20261116_010000")
        self.assertEqual(state.previous_snapshot("callmaner2").parent.name, "20261116_020000")
        self.assertIsNone(state.previous_snapshot("logi2"))


def _write_apk(path: Path) -> None:
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("AndroidManifest.xml", b"fake manifest for transport testing")
        archive.writestr("classes.dex", b"test dex placeholder")


class AdbTransferTests(AppDataCase):
    def _transport(self, *, base_failure=False, split_failure=False, only_split=False):
        def run(adb_path, args, timeout=8):
            self.assertEqual(adb_path, "fake-adb")
            if args[2:5] == ["shell", "pm", "path"]:
                paths = ([] if only_split else ["package:/data/app/a/base.apk"]) + ["package:/data/app/a/split_config.en.apk"]
                return 0, "\r\n".join(paths), ""
            self.assertEqual(args[2], "pull")
            remote, local = args[3:5]
            if (base_failure and remote.endswith("base.apk")) or (split_failure and "split_" in remote):
                Path(local).write_bytes(b"truncated")
                return 1, "", "transport failed"
            _write_apk(Path(local))
            return 0, "1 file pulled", ""
        return run

    def _pull(self, **transport_options):
        with patch.object(adb, "run_adb_command", side_effect=self._transport(**transport_options)), \
             patch("l_app.analysis.apk_meta", return_value={"packages": ["sample"]}), \
             patch("l_app.analysis.check_needles", return_value=[("ls0", True)]):
            return adb.pull_package("fake-adb", "device", "callmaner2", "20261116_123456")

    def test_pull_keeps_base_and_splits_and_marks_static_evidence(self):
        result = self._pull()
        self.assertTrue(result["base_path"].is_file())
        self.assertTrue((result["directory"] / "split_config.en.apk").is_file())
        self.assertEqual(result["metadata"]["package"], "com.callmanerdriver2sharp2")
        self.assertTrue(result["metadata"]["all_parts_ok"])
        self.assertTrue(result["metadata"]["static_evidence_only"])
        self.assertIn("정적 문자열 발견", result["report"])
        self.assertNotIn("훅 생존", result["report"])
        self.assertFalse((result["directory"] / ".incomplete").exists())

    def test_failed_base_never_uses_a_split_as_base(self):
        result = self._pull(base_failure=True)
        self.assertIsNone(result["base_path"])
        self.assertIsNone(result["metadata"])
        self.assertFalse((result["directory"] / "base.apk").exists())
        self.assertTrue((result["directory"] / "split_config.en.apk").exists())
        self.assertTrue((result["directory"] / ".incomplete").exists())
        self.assertIsNone(state.previous_snapshot("callmaner2"))

    def test_split_only_never_creates_base(self):
        result = self._pull(only_split=True)
        self.assertIsNone(result["base_path"])
        self.assertFalse((result["directory"] / "base.apk").exists())

    def test_split_failure_keeps_explicit_base_only_metadata(self):
        result = self._pull(split_failure=True)
        self.assertIsNotNone(result["base_path"])
        self.assertFalse(result["metadata"]["all_parts_ok"])
        self.assertIn("전체 설치 세트는 불완전", result["report"])

    def test_repeated_timestamp_does_not_overwrite_previous_snapshot(self):
        first = self._pull()
        before = first["base_path"].read_bytes()
        with patch("l_app.analysis.diff_apk", return_value={"added": [], "removed": []}):
            second = self._pull()
        self.assertNotEqual(first["directory"], second["directory"])
        self.assertEqual(second["stamp"], "20261116_123456_01")
        self.assertEqual(first["base_path"].read_bytes(), before)

    def test_repeated_remote_basename_is_rejected_before_any_pull(self):
        with patch.object(adb, "run_adb_command", return_value=(0, "package:/data/a/base.apk\npackage:/data/b/base.apk", "")) as runner:
            result = adb.pull_package("fake-adb", "device", "logi2", "20261116_010000")
        self.assertEqual(runner.call_count, 1)
        self.assertIsNone(result["base_path"])
        self.assertIn("파일명이 겹쳐", result["report"])

    def test_cancelled_pull_propagates_and_is_not_recorded_as_success(self):
        with patch.object(adb, "run_adb_command", side_effect=CancelledError("cancelled")):
            with self.assertRaises(CancelledError):
                adb.pull_package("fake-adb", "device", "logi", "20261116_010000")
        self.assertIsNone(state.previous_snapshot("logi"))

    def test_path_parser_ignores_invalid_paths_and_deduplicates(self):
        text = "\n".join([
            "package:/data/app/a/base.apk",
            "package:/data/app/a/base.apk",
            "package:../../escape.apk",
            "package:/data/app/../escape.apk",
            "package:/data/app\\escape.apk",
            "package:/data/app/split.apk;echo bad",
            "daemon started successfully",
        ])
        self.assertEqual(adb.parse_pm_paths(text), ["/data/app/a/base.apk"])

    def test_stamp_cannot_escape_destination(self):
        with self.assertRaises(ValueError):
            adb.pull_package("fake-adb", "device", "logi2", "../escape")

    def test_adb_uses_an_argument_vector_and_propagates_cancellation(self):
        completed = subprocess.CompletedProcess([], 0, "out", "err")
        with patch.object(adb, "run_process", return_value=completed) as runner:
            self.assertEqual(adb.run_adb_command("adb path", ["-s", "serial&literal", "devices"]), (0, "out", "err"))
        self.assertEqual(runner.call_args.args[0], ["adb path", "-s", "serial&literal", "devices"])
        with patch.object(adb, "run_process", side_effect=CancelledError("cancelled")):
            with self.assertRaises(CancelledError):
                adb.run_adb_command("fake-adb", ["devices"])

    def test_missing_adb_and_timeout_are_failures(self):
        self.assertEqual(adb.run_adb_command(None, ["devices"])[0], 1)
        with patch.object(adb, "run_process", side_effect=subprocess.TimeoutExpired(["adb"], 1)):
            self.assertEqual(adb.run_adb_command("fake-adb", ["devices"])[0], 1)


if __name__ == "__main__":
    unittest.main()

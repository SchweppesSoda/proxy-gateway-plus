#!/usr/bin/env python3
"""Offline rule freshness tests using real refresh functions and fake I/O edges."""
import ast
import contextlib
import copy
import importlib.util
import io
import json
import os
from pathlib import Path
import posixpath
import shutil
import sys
import tempfile
import types
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]


def functions(relative, names, namespace):
    tree = ast.parse((ROOT / relative).read_text(encoding="utf-8"))
    selected = [node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name in names]
    assert len(selected) == len(names)
    exec(compile(ast.Module(body=selected, type_ignores=[]), relative, "exec"), namespace)
    return namespace


class RuleStatus(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="pdg-rule-status-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.directory = str(self.root / "rule-status")
        spec = importlib.util.spec_from_file_location("rule_status", ROOT / "deploy/bot/rule_status.py")
        self.status = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.status)
        # Use the existing transaction engine's actual atomic writer. On Windows
        # only directory fsync and flock are unavailable, and are explicit mocks.
        ns = functions("deploy/bot/pdgtx.py", {"atomic_write", "_fsync_dir"},
                       {"os": os, "tempfile": tempfile})
        if os.name != "posix":
            ns["_fsync_dir"] = lambda path: None
        modules = {"rule_status": self.status,
                   "pdgtx": types.SimpleNamespace(atomic_write=ns["atomic_write"])}
        if os.name != "posix":
            modules["fcntl"] = types.SimpleNamespace(LOCK_EX=1, LOCK_NB=2, flock=lambda *args: None)
        patcher = mock.patch.dict(sys.modules, modules)
        patcher.start()
        self.addCleanup(patcher.stop)
        patcher = mock.patch.object(self.status.time, "time", return_value=10000)
        self.clock = patcher.start()
        self.addCleanup(patcher.stop)
        for target in ("socket.create_connection", "socket.socket.connect", "subprocess.run"):
            patcher = mock.patch(target, side_effect=AssertionError("unexpected external operation"))
            patcher.start()
            self.addCleanup(patcher.stop)
        self.version = self.status.content_version({"sample": b"synthetic rules"})

    def update(self, component="geosite"):
        return self.status.Update(component, self.directory)

    def row(self, component="geosite"):
        return self.status.read(component, self.directory)

    def success(self, component="geosite"):
        with self.update(component) as update:
            update.finish(True, self.version)

    def test_missing_receipt_is_unknown_not_fresh(self):
        self.assertEqual(self.status.assessment("geosite", self.directory)[:2], ("warn", "unknown"))
        self.assertFalse(Path(self.directory).exists())

    def test_attempt_does_not_advance_success_until_full_commit(self):
        self.success()
        self.clock.return_value = 20000
        with self.update() as update:
            row = self.row()
            self.assertEqual(row["lastAttempt"], 20000)
            self.assertEqual(row["lastSuccess"], 10000)
            self.assertTrue(row["running"])
            update.finish(False, partial=True)
        row = self.row()
        self.assertEqual((row["lastSuccess"], row["sourceVersion"]), (10000, self.version))
        self.assertEqual((row["failure"], row["failureCount"]), ("partial", 1))
        self.assertEqual(self.status.assessment("geosite", self.directory)[:2], ("warn", "partial"))

    def test_failure_and_exception_are_redacted_and_success_recovers(self):
        self.success()
        with self.assertRaisesRegex(RuntimeError, "synthetic"):
            with self.update():
                raise RuntimeError("synthetic SECRET_URL")
        self.assertNotIn("SECRET_URL", Path(self.directory, "geosite.json").read_text())
        self.assertEqual(self.row()["failure"], "exception")
        self.clock.return_value = 30000
        self.success()
        self.assertEqual(self.row()["lastSuccess"], 30000)
        self.assertIsNone(self.row()["failure"])
        self.assertEqual(self.row()["failureCount"], 0)

    def test_age_uses_last_success_not_file_mtime_or_failed_attempt(self):
        self.success()
        self.clock.return_value = 10000 + 49 * 3600
        with self.update() as update:
            update.finish(False)
        level, status, detail = self.status.assessment("geosite", self.directory)
        self.assertEqual((level, status), ("warn", "refresh_failed"))
        self.assertEqual(detail["ageSeconds"], 49 * 3600)
        self.clock.return_value = 10000 + 8 * 86400
        self.assertEqual(self.status.assessment("geosite", self.directory)[:2], ("fail", "stale-7d"))

    def test_stale_threshold_clock_and_interrupted_run(self):
        self.success()
        self.assertEqual(self.status.assessment("geosite", self.directory, now=10000+48*3600)[:2],
                         ("warn", "stale-48h"))
        self.assertEqual(self.status.assessment("geosite", self.directory, now=100)[:2], ("warn", "clock"))
        with self.update() as update:
            self.assertEqual(self.status.assessment("geosite", self.directory, now=14000)[:2],
                             ("warn", "interrupted"))
            update.finish(True, self.version)

    def test_invalid_state_and_replace_failure_keep_previous_receipt(self):
        self.success()
        path = Path(self.directory, "geosite.json")
        before = path.read_bytes()
        with mock.patch.object(os, "replace", side_effect=OSError("synthetic full disk")):
            with self.assertRaises(OSError):
                with self.update():
                    self.fail("must fail before changing rules")
        self.assertEqual(path.read_bytes(), before)
        path.write_text('{"schema":1}', encoding="utf-8")
        self.assertEqual(self.status.assessment("geosite", self.directory)[:2], ("warn", "invalid"))
        with self.assertRaises(ValueError):
            with self.update():
                self.fail("must not reset corrupt state")

    def test_source_version_deterministic_and_content_sensitive(self):
        version = self.status.content_version({"b": b"2", "a": b"1"})
        self.assertEqual(version, self.status.content_version({"a": b"1", "b": b"2"}))
        self.assertNotEqual(version, self.status.content_version({"a": b"new", "b": b"2"}))

    @unittest.skipUnless(os.name == "posix", "real flock/owner/mode checks require Linux")
    def test_posix_lock_and_restricted_receipt(self):
        with self.update() as first:
            with self.assertRaises(BlockingIOError):
                with self.update():
                    self.fail("concurrent writer")
            first.finish(True, self.version)
        self.assertEqual(Path(self.directory, "geosite.json").stat().st_mode & 0o777, 0o600)

    def bot(self):
        metadata = {
            "good": {"path": str(self.root / "good.mrs"), "format": "mrs", "behavior": "domain", "url": "good"},
            "other": {"path": str(self.root / "other.mrs"), "format": "mrs", "behavior": "domain", "url": "other"},
        }
        namespace = {"os": os, "posixpath": posixpath, "tempfile": tempfile, "shutil": shutil, "json": json,
                     "RS_META": str(self.root / "rulesets.json"), "RS_DIR": str(self.root),
                     "MRS_BEHAVIORS": {"domain"}, "_rs_meta_snapshot": lambda: (copy.deepcopy(metadata), "old"),
                     "_fetch_bytes": mock.Mock(return_value=b"synthetic candidate"),
                     "tx_apply": mock.Mock(return_value=(True, "committed"))}
        return functions("deploy/bot/pdg-bot.py", {"refresh_rulesets", "_refresh_rulesets"}, namespace)

    def test_real_ruleset_refresh_full_partial_total_failure_and_recovery(self):
        bot = self.bot()
        self.assertEqual(bot["refresh_rulesets"](), (2, []))
        first = self.row("rulesets")
        self.clock.return_value = 20000
        bot["_fetch_bytes"].side_effect = [b"new candidate", OSError("synthetic failure")]
        count, failed = bot["refresh_rulesets"]()
        self.assertEqual((count, len(failed)), (1, 1))
        self.assertEqual(self.row("rulesets")["lastSuccess"], first["lastSuccess"])
        self.assertEqual(self.row("rulesets")["sourceVersion"], first["sourceVersion"])
        self.assertEqual(self.row("rulesets")["failure"], "partial")
        bot["_fetch_bytes"].side_effect = OSError("synthetic failure")
        bot["tx_apply"].reset_mock()
        count, failed = bot["refresh_rulesets"]()
        self.assertEqual((count, len(failed)), (0, 2))
        bot["tx_apply"].assert_not_called()
        bot["_fetch_bytes"].side_effect = None
        self.assertEqual(bot["refresh_rulesets"](), (2, []))
        self.assertEqual(self.row("rulesets")["lastSuccess"], 20000)

    def test_transaction_failure_and_state_failure_are_not_success(self):
        bot = self.bot()
        bot["tx_apply"].return_value = (False, "synthetic rollback")
        count, failed = bot["refresh_rulesets"]()
        self.assertEqual((count, len(failed)), (0, 1))
        self.assertIsNone(self.row("rulesets")["lastSuccess"])
        with mock.patch.object(self.status.Update, "_write", side_effect=OSError("synthetic")):
            bot["tx_apply"].reset_mock()
            count, failed = bot["refresh_rulesets"]()
            self.assertEqual((count, len(failed)), (0, 1))
            bot["tx_apply"].assert_not_called()

    def test_alert_text_stable_while_doctor_age_advances(self):
        Path(self.root, "rulesets.json").write_text('{}', encoding="utf-8")
        self.success()
        checks = functions("deploy/bot/checks.py", {"check_rule_updates", "check_rule_update_alerts"},
                           {"os": os, "json": json, "RS_META": str(self.root / "rulesets.json")})
        self.clock.return_value = 10000 + 49 * 3600
        first_alert = checks["check_rule_update_alerts"]()
        first_doctor = checks["check_rule_updates"]()
        self.clock.return_value += 600
        self.assertEqual(first_alert, checks["check_rule_update_alerts"]())
        self.assertNotEqual(first_doctor, checks["check_rule_updates"]())
        self.assertNotIn("rulesets:", first_alert[2])
        Path(self.root, "rulesets.json").write_text('{"synthetic": {}}', encoding="utf-8")
        self.assertIn("rulesets: unknown", checks["check_rule_update_alerts"]()[2])

    def test_geosite_wrapper_records_only_after_worker_success(self):
        update_class = self.status.Update
        with mock.patch.object(self.status, "Update", side_effect=lambda component: update_class(component, self.directory)), \
                mock.patch.object(sys, "argv", ["rule_status.py", "run-geosite", "synthetic-script"]), \
                mock.patch.object(self.status.subprocess, "run", return_value=types.SimpleNamespace(returncode=0)) as run, \
                mock.patch("builtins.open", side_effect=lambda path, mode: io.BytesIO(b"synthetic rule")):
            self.assertEqual(self.status.main(), 0)
        self.assertEqual(run.call_args.args[0], ["/bin/bash", "synthetic-script", "--recorded-live"])
        self.assertEqual(self.row()["sourceVersion"], self.status.content_version(
            {name: b"synthetic rule" for name in self.status.GEOSITE_FILES}))

    def test_geosite_worker_failure_preserves_previous_success(self):
        self.success()
        update_class = self.status.Update
        self.clock.return_value = 20000
        with mock.patch.object(self.status, "Update", side_effect=lambda component: update_class(component, self.directory)), \
                mock.patch.object(sys, "argv", ["rule_status.py", "run-geosite", "synthetic-script"]), \
                mock.patch.object(self.status.subprocess, "run", return_value=types.SimpleNamespace(returncode=7)):
            self.assertEqual(self.status.main(), 7)
        self.assertEqual(self.row()["lastSuccess"], 10000)
        self.assertEqual(self.row()["failure"], "refresh_failed")


if __name__ == "__main__":
    unittest.main(verbosity=2)

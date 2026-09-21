#!/usr/bin/env python3
"""Offline health notification delivery/state regressions; no checks or API calls.

Only the healthcheck module executes. bot/checks are stubs, time is explicit and
all state lives in TemporaryDirectory. POSIX lock/mode tests run in Linux CI;
the state machine and atomic-file failure tests also run on Windows.
"""
import ast
import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import socket
import stat
import subprocess
import sys
import tempfile
import types
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
FAULT = ["❌ DNS: synthetic unavailable"]
OTHER = ["⚠️ certificate: synthetic expiry"]


def load_health():
    bot = types.SimpleNamespace(post=mock.Mock(return_value={"ok": True}))
    checks = types.SimpleNamespace(ALERT=(), run=mock.Mock(return_value=[]),
                                   bot_credentials=mock.Mock(return_value="ready"))
    spec = importlib.util.spec_from_file_location("health_test", ROOT / "deploy/bot/healthcheck.py")
    module = importlib.util.module_from_spec(spec)
    with mock.patch.dict(sys.modules, {"bot": bot, "checks": checks}), \
            mock.patch.dict(os.environ, {"PDG_BOT_TOKEN": "synthetic", "PDG_CERT": "synthetic",
                                         "PDG_BOT_ALLOWED": "101,202"}), \
            mock.patch.object(sys, "path", list(sys.path)):
        spec.loader.exec_module(module)
    return module


class Notifications(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="pdg-health-test-")
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "health-state.json"
        self.h = load_health()
        self.h.STATE = str(self.path)
        self.h.ALLOWED = [101, 202]
        self.now = 10000
        self.errors = io.StringIO()
        # A missing mock must fail locally, never contact a service or shell.
        for target in ("socket.create_connection", "socket.socket.connect", "subprocess.run"):
            patcher = mock.patch(target, side_effect=AssertionError("unexpected external operation"))
            patcher.start()
            self.addCleanup(patcher.stop)

    def run_health(self, problems=FAULT, *, ids=(101,), now=None):
        self.h.ALLOWED = list(ids)
        with mock.patch.object(self.h, "_problems", return_value=problems), \
                mock.patch.object(self.h.time, "time", return_value=self.now if now is None else now), \
                contextlib.redirect_stderr(self.errors):
            if os.name == "posix":
                return self.h.main()
            with mock.patch.object(self.h, "_state_lock", contextlib.nullcontext):
                return self.h.main()

    def state(self):
        return json.loads(self.path.read_text(encoding="utf-8"))

    def row(self, uid=101):
        return self.state()["recipients"][str(uid)]

    def write_state(self, value):
        self.path.write_text(json.dumps(value), encoding="utf-8")

    def restart(self):
        self.h = load_health()
        self.h.STATE = str(self.path)

    def test_normal_fault_recovery_each_delivered_once(self):
        self.assertEqual(self.run_health([]), 0)
        self.assertEqual(self.run_health([]), 0)
        self.h.bot.post.assert_not_called()
        self.assertEqual(self.run_health(), 0)
        self.assertEqual(self.run_health(), 0)
        self.assertEqual(self.row()["delivered"], FAULT)
        self.assertEqual(self.state()["problems"], FAULT)
        self.assertEqual(self.h.bot.post.call_count, 1)
        self.assertEqual(self.run_health([]), 0)
        self.assertEqual(self.run_health([]), 0)
        self.assertEqual(self.h.bot.post.call_count, 2)
        self.assertEqual(self.row()["delivered"], [])
        self.assertIsNone(self.row()["pending"])

    def test_only_explicit_telegram_success_confirms_delivery(self):
        for response in ({}, {"ok": False, "description": "synthetic private response"},
                         None, True, [], {"ok": 1}, {"ok": "true"}):
            with self.subTest(response=response):
                self.path.unlink(missing_ok=True)
                self.h.bot.post.return_value = response
                self.assertEqual(self.run_health(), 1)
                self.assertEqual(self.row()["observed"], FAULT)
                self.assertEqual(self.row()["delivered"], [])
                self.assertEqual(self.row()["pending"]["attempts"], 1)
                self.assertEqual(self.state()["problems"], [])
        self.assertNotIn("synthetic private response", self.errors.getvalue())

    def test_exception_is_redacted_and_keeps_pending(self):
        self.h.bot.post.side_effect = RuntimeError("SYNTHETIC_TOKEN_DO_NOT_LOG")
        self.assertEqual(self.run_health(), 1)
        self.assertIsNotNone(self.row()["pending"])
        self.assertNotIn("SYNTHETIC_TOKEN_DO_NOT_LOG", self.errors.getvalue())

    def test_bounded_backoff_survives_restart_and_continues(self):
        now = self.now
        for attempt, delay in enumerate((600, 1200, 2400, 3600, 3600, 3600), 1):
            self.restart()
            self.h.bot.post.return_value = {"ok": False}
            self.assertEqual(self.run_health(now=now), 1)
            pending = self.row()["pending"]
            self.assertEqual(pending["attempts"], min(attempt, 4))
            self.assertEqual(pending["next_attempt"], now + delay)
            self.assertEqual(self.run_health(now=now + delay - 1), 0)
            self.assertEqual(self.h.bot.post.call_count, 1)
            now += delay
        self.restart()
        self.assertEqual(self.run_health(now=now), 0)
        self.assertIsNone(self.row()["pending"])
        self.assertEqual(self.run_health(now=now + 7200), 0)
        self.assertEqual(self.h.bot.post.call_count, 1)

    def test_clock_rollback_bounds_future_retry(self):
        self.h.bot.post.return_value = {}
        self.run_health()
        self.run_health(now=100)
        self.assertEqual(self.row()["pending"]["next_attempt"], 3700)
        self.assertEqual(self.h.bot.post.call_count, 1)
        self.run_health(now=3700)
        self.assertEqual(self.h.bot.post.call_count, 2)

    def test_partial_success_is_per_recipient_and_restart_safe(self):
        self.h.bot.post.side_effect = lambda _, params: {"ok": params["chat_id"] == 101}
        self.assertEqual(self.run_health(ids=(101, 202)), 1)
        self.assertEqual(self.row(101)["delivered"], FAULT)
        self.assertIsNone(self.row(101)["pending"])
        self.assertEqual(self.row(202)["delivered"], [])
        self.assertEqual(self.state()["problems"], [])
        self.restart()
        self.assertEqual(self.run_health(ids=(101, 202), now=self.now + 600), 0)
        self.assertEqual(self.h.bot.post.call_count, 1)
        self.assertEqual(self.h.bot.post.call_args.args[1]["chat_id"], 202)
        self.assertEqual(self.state()["problems"], FAULT)

    def test_recovery_before_fault_receipt_coalesces_and_retries(self):
        self.h.bot.post.return_value = {}
        self.run_health()
        self.run_health([], now=self.now + 10)
        self.assertEqual(self.row()["pending"]["kind"], "resolved")
        self.assertEqual(self.row()["pending"]["problems"], FAULT)
        self.assertEqual(self.h.bot.post.call_count, 2)
        self.restart()
        self.assertEqual(self.run_health([], now=self.now + 610), 0)
        text = self.h.bot.post.call_args.args[1]["text"]
        self.assertIn("期间异常已恢复", text)
        self.assertIn("未确认送达", text)
        self.assertIn(FAULT[0], text)
        self.assertEqual(self.run_health([], now=self.now + 1210), 0)
        self.assertEqual(self.h.bot.post.call_count, 1)

    def test_recovery_message_matches_each_recipient_history(self):
        self.h.bot.post.side_effect = lambda _, params: {"ok": params["chat_id"] == 101}
        self.run_health(ids=(101, 202))
        self.h.bot.post.reset_mock(side_effect=True)
        self.h.bot.post.return_value = {"ok": True}
        self.run_health([], ids=(101, 202))
        texts = {call.args[1]["chat_id"]: call.args[1]["text"]
                 for call in self.h.bot.post.call_args_list}
        self.assertIn("已恢复正常", texts[101])
        self.assertNotIn("未确认送达", texts[101])
        self.assertIn("未确认送达", texts[202])

    def test_recovery_failure_retries_without_repeating_fault(self):
        self.run_health()
        self.h.bot.post.return_value = {}
        self.assertEqual(self.run_health([]), 1)
        self.assertEqual(self.row()["pending"]["kind"], "recovery")
        self.assertEqual(self.row()["delivered"], FAULT)
        self.restart()
        self.run_health([], now=self.now + 600)
        self.assertEqual(self.h.bot.post.call_count, 1)
        self.assertIn("已恢复正常", self.h.bot.post.call_args.args[1]["text"])

    def test_repeated_fault_cancels_undelivered_recovery(self):
        self.run_health()
        self.h.bot.post.return_value = {}
        self.run_health([])
        self.run_health(now=self.now + 10)
        self.assertEqual(self.h.bot.post.call_count, 2)
        self.assertIsNone(self.row()["pending"])
        self.assertEqual(self.row()["delivered"], FAULT)

    def test_changed_fault_supersedes_old_pending(self):
        self.h.bot.post.return_value = {}
        self.run_health()
        self.h.bot.post.return_value = {"ok": True}
        self.run_health(OTHER, now=self.now + 1)
        self.assertEqual(self.row()["delivered"], OTHER)
        self.assertEqual(self.h.bot.post.call_count, 2)
        self.assertNotIn(FAULT[0], self.h.bot.post.call_args.args[1]["text"])

    def test_recipients_added_removed_and_duplicates(self):
        self.run_health(ids=(101, 101))
        self.assertEqual(self.h.bot.post.call_count, 1)
        self.h.bot.post.reset_mock()
        self.run_health(ids=(101, 202))
        self.assertEqual(self.h.bot.post.call_count, 1)
        self.assertEqual(self.h.bot.post.call_args.args[1]["chat_id"], 202)
        self.h.bot.post.reset_mock()
        self.run_health(ids=(202,))
        self.h.bot.post.assert_not_called()
        self.assertEqual(set(self.state()["recipients"]), {"202"})

    def test_legacy_empty_is_quiet_and_nonempty_is_not_a_receipt(self):
        self.write_state({"problems": []})
        self.run_health([])
        self.h.bot.post.assert_not_called()
        self.write_state({"problems": FAULT})
        self.h.bot.post.return_value = {}
        self.run_health()
        self.assertIsNone(self.row()["delivered"])
        self.restart()
        self.run_health(now=self.now + 600)
        self.run_health(now=self.now + 1200)
        self.assertEqual(self.h.bot.post.call_count, 1)
        self.assertEqual(self.row()["delivered"], FAULT)

    def test_legacy_fault_already_recovered_gets_combined_notice(self):
        self.write_state({"problems": FAULT})
        self.run_health([])
        self.assertIn("未确认送达", self.h.bot.post.call_args.args[1]["text"])
        self.run_health([])
        self.assertEqual(self.h.bot.post.call_count, 1)

    def test_crash_after_pending_save_resumes(self):
        self.h.bot.post.side_effect = SystemExit("synthetic crash before acceptance")
        with self.assertRaises(SystemExit):
            self.run_health()
        self.assertEqual(self.row()["pending"]["attempts"], 0)
        self.restart()
        self.run_health()
        self.assertEqual(self.h.bot.post.call_count, 1)
        self.assertEqual(self.row()["delivered"], FAULT)

    def test_crash_after_acceptance_before_receipt_can_duplicate(self):
        original = self.h._save_state
        writes = 0

        def save(value):
            nonlocal writes
            writes += 1
            if writes == 2:
                raise OSError("synthetic disk failure")
            return original(value)

        with mock.patch.object(self.h, "_save_state", side_effect=save):
            self.assertEqual(self.run_health(), 1)
        self.assertEqual(self.h.bot.post.call_count, 1)
        self.assertEqual(self.row()["delivered"], [])
        self.restart()
        self.run_health()
        self.assertEqual(self.h.bot.post.call_count, 1)  # at least once, not exactly once

    def test_receipt_saved_before_later_recipient_crash(self):
        def post(_, params):
            if params["chat_id"] == 202:
                raise SystemExit("synthetic crash")
            return {"ok": True}

        self.h.bot.post.side_effect = post
        with self.assertRaises(SystemExit):
            self.run_health(ids=(101, 202))
        self.restart()
        self.run_health(ids=(101, 202))
        self.assertEqual(self.h.bot.post.call_count, 1)
        self.assertEqual(self.h.bot.post.call_args.args[1]["chat_id"], 202)

    def test_invalid_or_oversized_state_is_preserved_without_send(self):
        for raw in ("{broken", '[]', '{"schema":99}', '{"problems":"bad"}',
                    '{"problems":[],"unexpected":true}', " " * (self.h.MAX_STATE_BYTES + 1)):
            with self.subTest(raw=raw[:40]):
                self.path.write_text(raw, encoding="utf-8")
                self.assertEqual(self.run_health(), 1)
                self.assertEqual(self.path.read_text(encoding="utf-8"), raw)
        self.h.bot.post.assert_not_called()

    def test_pending_validation_rejects_invalid_backoff(self):
        self.h.bot.post.return_value = {}
        self.run_health()
        for field, invalid in (("attempts", -1), ("attempts", True), ("attempts", 1000),
                               ("next_attempt", float("nan")), ("next_attempt", -1),
                               ("kind", "unknown"), ("problems", "not a list")):
            value = self.state()
            value["recipients"]["101"]["pending"][field] = invalid
            self.write_state(value)
            self.h.bot.post.reset_mock()
            self.assertEqual(self.run_health(), 1)
            self.h.bot.post.assert_not_called()
            self.path.unlink()
            self.run_health()

    def test_inconsistent_state_cannot_confirm_a_different_message(self):
        self.h.bot.post.return_value = {}
        self.run_health()
        baseline = self.state()
        invalid_rows = [None, {"observed": FAULT, "delivered": []},
                        {"observed": FAULT, "delivered": [], "pending": None}]
        wrong_message = json.loads(json.dumps(baseline["recipients"]["101"]))
        wrong_message["pending"]["problems"] = OTHER
        invalid_rows.append(wrong_message)
        for row in invalid_rows:
            baseline["recipients"]["101"] = row
            self.write_state(baseline)
            before = self.path.read_bytes()
            self.h.bot.post.reset_mock()
            self.assertEqual(self.run_health(), 1)
            self.assertEqual(self.path.read_bytes(), before)
            self.h.bot.post.assert_not_called()

    def test_atomic_failures_preserve_old_bytes_and_remove_temp(self):
        self.run_health([])
        before = self.path.read_bytes()
        for function in ("replace", "fsync"):
            with self.subTest(function=function), \
                    mock.patch.object(self.h.os, function, side_effect=OSError("synthetic private data")):
                self.assertEqual(self.run_health(), 1)
            self.assertEqual(self.path.read_bytes(), before)
            self.assertEqual(list(self.path.parent.glob(".health-state.*")), [])
        self.h.bot.post.assert_not_called()
        self.assertNotIn("synthetic private data", self.errors.getvalue())

    def test_hardlinked_state_is_refused(self):
        self.write_state({"problems": []})
        linked = self.path.with_suffix(".hardlink")
        try:
            os.link(self.path, linked)
        except OSError as error:
            self.skipTest("hard links unavailable: " + type(error).__name__)
        self.assertEqual(self.run_health(), 1)
        self.assertEqual(linked.read_text(encoding="utf-8"), '{"problems": []}')
        self.h.bot.post.assert_not_called()

    @unittest.skipUnless(os.name == "posix", "POSIX symlinks, permissions and flock run in Linux CI")
    def test_symlink_state_and_parent_are_refused(self):
        target = self.path.with_suffix(".target")
        target.write_text('{"problems":[]}', encoding="utf-8")
        self.path.symlink_to(target)
        self.assertEqual(self.run_health(), 1)
        self.path.unlink()
        linked_dir = self.path.parent / "alias"
        linked_dir.symlink_to(self.path.parent, target_is_directory=True)
        self.h.STATE = str(linked_dir / "health-state.json")
        self.assertEqual(self.run_health(), 1)
        self.h.bot.post.assert_not_called()

    @unittest.skipUnless(os.name == "posix", "POSIX file permissions run in Linux CI")
    def test_atomic_mode_and_parent_mode_not_migrated(self):
        self.path.parent.chmod(0o755)
        self.write_state({"problems": []})
        self.path.chmod(0o644)
        self.assertEqual(self.run_health([]), 0)
        self.assertEqual(stat.S_IMODE(self.path.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(self.path.parent.stat().st_mode), 0o755)
        self.path.parent.chmod(0o777)
        self.assertEqual(self.run_health(), 1)
        self.assertEqual(stat.S_IMODE(self.path.parent.stat().st_mode), 0o777)
        self.path.parent.chmod(0o700)
        self.path.chmod(0o666)
        self.assertEqual(self.run_health(), 1)
        self.h.bot.post.assert_not_called()

    @unittest.skipUnless(os.name == "posix", "POSIX flock runs in Linux CI")
    def test_lock_conflict_refuses_send_then_releases(self):
        with self.h._state_lock():
            self.assertEqual(self.run_health(), 1)
        self.h.bot.post.assert_not_called()
        self.assertEqual(self.run_health(), 0)
        self.assertEqual(self.h.bot.post.call_count, 1)

    def test_unconfigured_or_no_recipients_creates_no_state(self):
        self.h.checks.bot_credentials.return_value = "unset"
        self.assertEqual(self.run_health(), 0)
        self.h.checks.bot_credentials.return_value = "partial"
        self.assertEqual(self.run_health(), 0)
        self.h.checks.bot_credentials.return_value = "ready"
        self.assertEqual(self.run_health(ids=()), 0)
        self.assertFalse(self.path.exists())
        self.h.bot.post.assert_not_called()

    def test_plain_text_and_bounded_message(self):
        self.run_health(["<synthetic & detail> " + "🚨" * 6000])
        params = self.h.bot.post.call_args.args[1]
        self.assertNotIn("parse_mode", params)
        self.assertIn("<synthetic & detail>", params["text"])
        self.assertLessEqual(len(params["text"].encode("utf-16-le")) // 2, 4096)


class BotPostContract(unittest.TestCase):
    def test_actual_post_returns_raw_api_json_and_empty_on_transport_failure(self):
        # Execute only the real post function, with fake HTTPS, no Bot startup.
        tree = ast.parse((ROOT / "deploy/bot/pdg-bot.py").read_text(encoding="utf-8"))
        function = next(node for node in tree.body if isinstance(node, ast.FunctionDef)
                        and node.name == "post")
        connection = mock.Mock()
        https = mock.Mock(return_value=connection)
        namespace = {"json": json, "TOKEN": "synthetic", "_tls": types.SimpleNamespace(),
                     "http": types.SimpleNamespace(client=types.SimpleNamespace(HTTPSConnection=https))}
        exec(compile(ast.Module(body=[function], type_ignores=[]), "bot.post", "exec"), namespace)
        for response in ({"ok": True, "result": {"message_id": 1}}, {"ok": False}, {}):
            connection.getresponse.return_value.read.return_value = json.dumps(response).encode()
            self.assertEqual(namespace["post"]("sendMessage", {"chat_id": 101}), response)
        connection.request.side_effect = OSError("SYNTHETIC_TOKEN_DO_NOT_LOG")
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            self.assertEqual(namespace["post"]("sendMessage", {"chat_id": 101}), {})
        self.assertNotIn("SYNTHETIC_TOKEN_DO_NOT_LOG", output.getvalue())
        self.assertEqual(https.call_count, 2)


if __name__ == "__main__":
    unittest.main(verbosity=2)

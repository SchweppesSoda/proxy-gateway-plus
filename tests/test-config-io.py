#!/usr/bin/env python3
"""Security and conversion regressions for PDG configuration import/export."""
from __future__ import annotations

import copy
import base64
import hashlib
import importlib.util
import io
import json
import os
import pathlib
import struct
import sys
import tarfile
import tempfile
import threading
import time
import types
import unittest
import zipfile
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "deploy" / "web"))
sys.path.insert(0, str(ROOT / "deploy" / "bot"))

import pdgconfigio as cio  # noqa: E402
import sb2mihomo  # noqa: E402
if os.name == "nt":
    # Validator-only tests do not exercise file locking.  Supply Windows'
    # absent module long enough to load the production validator so its pure
    # candidate/live namespace checks run on every development host.
    _previous_fcntl = sys.modules.get("fcntl")
    sys.modules["fcntl"] = types.SimpleNamespace(
        flock=lambda *_args: None, LOCK_EX=1, LOCK_UN=8)
    try:
        import pdgtx  # noqa: E402
    finally:
        if _previous_fcntl is None:
            sys.modules.pop("fcntl", None)
        else:
            sys.modules["fcntl"] = _previous_fcntl
else:
    import pdgtx  # noqa: E402


def model(*outbounds):
    return cio.normalize_model({
        "outbounds": list(outbounds) or [{"type": "direct", "tag": "JP"}],
        "route": {"rules": [], "final": "JP"},
    })


def tar_bytes(entries, *, symlink=None):
    out = io.BytesIO()
    with tarfile.open(fileobj=out, mode="w:gz") as archive:
        for name, data in entries.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            archive.addfile(info, io.BytesIO(data))
        if symlink:
            info = tarfile.TarInfo(symlink)
            info.type = tarfile.SYMTYPE
            info.linkname = "target"
            archive.addfile(info)
    return out.getvalue()


def v2_pdg_bytes(entries):
    entries = dict(entries)
    manifest = {
        "version": 2,
        "createdAt": "2026-08-11T00:00:00Z",
        "files": [
            {"path": name, "size": len(data), "sha256": cio._sha(data)}
            for name, data in sorted(entries.items())
        ],
    }
    entries["manifest.json"] = json.dumps(
        manifest, ensure_ascii=True, sort_keys=True).encode("utf-8")
    return tar_bytes(entries)


_MOSDNS_GFW_GATES = [
    {"matches": "!qname $hijack_set", "exec": "$ecs_neutral"},
    {"matches": "!qname $hijack_set", "exec": "$remote_upstream"},
]


def mosdns_plugin(document, tag):
    return next(item for item in document["plugins"] if item.get("tag") == tag)


def mosdns_all_mode(document):
    """Apply the exact all-mode shape used by lib/mosdns.sh."""
    candidate = copy.deepcopy(document)
    sequence = mosdns_plugin(candidate, "internal_sequence")["args"]
    if sequence[8:10] != _MOSDNS_GFW_GATES:
        raise AssertionError("test fixture is not the managed gfw MosDNS shape")
    del sequence[8:10]
    return candidate


def load_bot_module():
    """Load the production backup parser; provide only Windows' absent fcntl."""
    previous = sys.modules.get("fcntl")
    if os.name == "nt":
        sys.modules["fcntl"] = types.SimpleNamespace(
            flock=lambda *_args: None, LOCK_EX=1, LOCK_NB=2, LOCK_UN=8)
    try:
        path = ROOT / "deploy" / "bot" / "pdg-bot.py"
        spec = importlib.util.spec_from_file_location("pdgbot_config_io_test", path)
        module = importlib.util.module_from_spec(spec)
        assert spec is not None and spec.loader is not None
        spec.loader.exec_module(module)
        return module
    finally:
        if os.name == "nt":
            if previous is None:
                sys.modules.pop("fcntl", None)
            else:
                sys.modules["fcntl"] = previous


class FakeBot:
    def __init__(self, current=None):
        self.current = current or model()
        self.calls = []

    def load(self):
        return copy.deepcopy(self.current)

    def tx_apply(self, *args, **kwargs):
        self.calls.append((args, kwargs))
        modifier = kwargs.get("model_mod")
        if modifier:
            modifier(self.current)
        return True, "ok"

    def restore_from(self, payload, **kwargs):
        self.calls.append(((payload,), kwargs))
        members = cio._archive_files(payload, total_limit=cio.MAX_LEGACY_PDG_TOTAL)
        _name, candidate = cio._choose_config(members or {}, "pdg")
        self.current = cio.normalize_model(cio._strict_json(candidate))
        return True, "ok"


class StrictYamlTests(unittest.TestCase):
    def assert_rejected(self, text):
        with self.assertRaises(cio.ImportInvalid):
            cio._safe_yaml_load(text.encode())

    def test_rejects_duplicate_multidoc_alias_tag_and_complex_key(self):
        for text in (
            "a: 1\na: 2\n",
            "a: 1\n---\nb: 2\n",
            "a: &x [1]\nb: *x\n",
            "a: !!python/object:builtins.str {}\n",
            "? [a, b]\n: value\n",
            "a: .nan\n",
            "a: .inf\n",
        ):
            with self.subTest(text=text):
                self.assert_rejected(text)

    def test_rejects_excessive_depth(self):
        self.assert_rejected("a: " + "[" * 80 + "1" + "]" * 80)


class ArchiveTests(unittest.TestCase):
    def test_bot_default_restore_keeps_legacy_64_mib_envelope(self):
        bot = load_bot_module()
        self.assertEqual(bot.RESTORE_MAX_TOTAL_BYTES, 64 * 1024 * 1024)
        payload = tar_bytes({
            f"etc/sing-box/rs/legacy-{index}.json": b"x" * (7 * 1024 * 1024)
            for index in range(5)
        })
        with tempfile.TemporaryDirectory() as tmp:
            with tarfile.open(fileobj=io.BytesIO(payload), mode="r:gz") as archive:
                bot._safe_extract(archive, tmp)
            self.assertEqual(sum(path.stat().st_size for path in Path(tmp).rglob("*.json")),
                             35 * 1024 * 1024)

    def test_tar_rejects_traversal_and_link(self):
        with self.assertRaises(cio.ImportInvalid):
            cio._archive_files(tar_bytes({"../escape": b"x"}))
        with self.assertRaises(cio.ImportInvalid):
            cio._archive_files(tar_bytes({"config.yaml": b"x"}, symlink="link"))

    def test_zip_rejects_member_table_before_zipfile(self):
        out = io.BytesIO()
        with zipfile.ZipFile(out, "w") as archive:
            archive.writestr("config.yaml", "a: b")
        payload = bytearray(out.getvalue())
        eocd = payload.rfind(b"PK\x05\x06")
        struct.pack_into("<HH", payload, eocd + 8, 513, 513)
        with self.assertRaisesRegex(cio.ImportInvalid, "member table"):
            cio._archive_files(bytes(payload))

    def test_zip_rejects_compression_bomb(self):
        out = io.BytesIO()
        with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("config.yaml", b"0" * 200_000)
        with self.assertRaisesRegex(cio.ImportInvalid, "compression ratio"):
            cio._archive_files(out.getvalue())

    def test_manifest_requires_exact_archive_closure(self):
        files = {"model.json": b"{}", "extra.txt": b"x"}
        manifest = {"version": 2, "createdAt": "2026-08-11T00:00:00Z", "files": [{
            "path": "model.json", "size": 2,
            "sha256": cio._sha(b"{}"),
        }]}
        files["manifest.json"] = json.dumps(manifest).encode()
        with self.assertRaisesRegex(cio.ImportInvalid, "complete archive"):
            cio._verify_manifest(files)

    def test_manifest_requires_a_real_rfc3339_utc_timestamp(self):
        for value in ("soon", "2026-02-30T00:00:00Z", "2026-08-11T00:00:00+00:00"):
            files = {"model.json": b"{}"}
            files["manifest.json"] = json.dumps({
                "version": 2, "createdAt": value,
                "files": [{"path": "model.json", "size": 2,
                           "sha256": cio._sha(b"{}")}],
            }).encode()
            with self.subTest(value=value), self.assertRaises(cio.ImportInvalid):
                cio._verify_manifest(files)

    def test_duplicate_and_device_members_are_rejected(self):
        out = io.BytesIO()
        with tarfile.open(fileobj=out, mode="w:gz") as archive:
            for data in (b"one", b"two"):
                info = tarfile.TarInfo("config.yaml")
                info.size = len(data)
                archive.addfile(info, io.BytesIO(data))
        with self.assertRaisesRegex(cio.ImportInvalid, "invalid|duplicate"):
            cio._archive_files(out.getvalue())
        out = io.BytesIO()
        with tarfile.open(fileobj=out, mode="w:gz") as archive:
            info = tarfile.TarInfo("device")
            info.type = tarfile.CHRTYPE
            archive.addfile(info)
        with self.assertRaisesRegex(cio.ImportInvalid, "non-regular"):
            cio._archive_files(out.getvalue())
        out = io.BytesIO()
        with zipfile.ZipFile(out, "w") as archive:
            archive.writestr("config.yaml", "one")
            archive.writestr("config.yaml", "two")
        with self.assertRaisesRegex(cio.ImportInvalid, "duplicate"):
            cio._archive_files(out.getvalue())

    def test_v2_manifest_round_trip(self):
        entries = {"model.json": b"{}", "etc/mosdns/config.yaml": b"log: {}\n"}
        manifest = {"version": 2, "createdAt": "2026-08-11T00:00:00Z", "files": [
            {"path": name, "size": len(data), "sha256": cio._sha(data)}
            for name, data in sorted(entries.items())
        ]}
        payload = tar_bytes({**entries, "manifest.json": json.dumps(manifest).encode()})
        parsed = cio._archive_files(payload)
        cio._verify_manifest(parsed)
        self.assertEqual(parsed["etc/mosdns/config.yaml"], b"log: {}\n")

    def test_pdg_member_whitelist_and_strict_manifest_shape(self):
        with self.assertRaisesRegex(cio.ImportInvalid, "restore whitelist"):
            cio._verify_pdg_members({
                "etc/sing-box/config.json": b"{}", "foo.txt": b"x"})
        with self.assertRaisesRegex(cio.ImportInvalid, "canonical model"):
            cio._verify_pdg_members({"manifest.json": b"{}"})
        files = {"etc/sing-box/config.json": b"{}"}
        files["manifest.json"] = json.dumps({
            "version": 2, "createdAt": "2026-08-11T00:00:00Z", "extra": True,
            "files": [{"path": "etc/sing-box/config.json", "size": 2,
                       "sha256": cio._sha(b"{}")}],
        }).encode()
        with self.assertRaises(cio.ImportInvalid):
            cio._verify_manifest(files)

    def test_bot_v2_backup_is_web_previewable_and_restore_parser_compatible(self):
        bot = load_bot_module()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            sb = root / "etc" / "sing-box" / "config.json"
            mosdns = root / "etc" / "mosdns" / "config.yaml"
            rules = root / "etc" / "mosdns" / "rules"
            rs_dir = root / "etc" / "sing-box" / "rs"
            provider_dir = root / "etc" / "mihomo" / "providers"
            for directory in (sb.parent, rules, rs_dir, provider_dir):
                directory.mkdir(parents=True, exist_ok=True)

            provider = b"proxies:\n  - {name: local, type: ss}\n"
            leaf = cio._sha(provider) + ".yaml"
            current = model()
            current["_pdg"]["mihomo"]["managed-files"] = {
                leaf: base64.b64encode(provider).decode("ascii")}
            current["_pdg"]["mihomo"]["proxy-providers"] = {
                "local": {"type": "file", "path": "/etc/mihomo/providers/" + leaf}}
            current = cio.normalize_model(current)
            sb.write_bytes(cio._model_bytes(current))
            (provider_dir / leaf).write_bytes(provider)

            mosdns_text = (ROOT / "deploy" / "mosdns" / "config.yaml").read_text(
                encoding="utf-8")
            for old, new in {
                    "__SERVER_IP__": "203.0.113.10",
                    "__INTERNAL_CIDR__": "192.0.2.0/24",
                    "__CERT_DIR__": "/etc/mosdns/certs",
                    "__HIJACK_SET_FILE__": "ruleset_hijack.txt",
                    "__MOSDNS_CACHE__": "1024",
            }.items():
                mosdns_text = mosdns_text.replace(old, new)
            # Production's ``all`` profile removes exactly the two managed
            # negative-hijack gates.  Back up that legitimate runtime shape
            # so this round trip covers the Web import regression from CI.
            mosdns_document = mosdns_all_mode(
                cio._safe_yaml_load(mosdns_text.encode("utf-8")))
            mosdns.write_bytes(cio._safe_yaml_dump(mosdns_document))
            fixed_rules = {
                "custom_direct.txt": "direct.example\n",
                "ruleset_direct.txt": "cn.example\n",
                "ruleset_hijack.txt": "hijack.example\n",
                "custom_hijack.txt": "custom.example\n",
            }
            for name, data in fixed_rules.items():
                (rules / name).write_text(data, encoding="utf-8")
            rs_meta = root / "opt" / "pdg-bot" / "rulesets.json"
            rs_meta.parent.mkdir(parents=True)
            rs_meta.write_text(json.dumps({
                "sample": {"path": "/etc/sing-box/rs/sample.json",
                           "format": "source", "outbound": "JP"},
            }), encoding="utf-8")
            (rs_dir / "sample.json").write_text(
                '{"version":1,"rules":[]}\n', encoding="utf-8")

            bot.SB = str(sb)
            bot.MOSDNS_CONF = str(mosdns)
            bot.MOSDNS_DIRECT = str(rules / "custom_direct.txt")
            bot.MOSDNS_RULESET_DIRECT = str(rules / "ruleset_direct.txt")
            bot.MOSDNS_RULESET_HIJACK = str(rules / "ruleset_hijack.txt")
            bot.MOSDNS_HIJACK = str(rules / "custom_hijack.txt")
            bot.RS_META = str(rs_meta)
            bot.RS_DIR = str(rs_dir)
            bot.MIHOMO_DIR = str(provider_dir.parent)
            bot.BACKUP_FILES = [
                bot.SB, bot.MOSDNS_CONF, bot.MOSDNS_DIRECT,
                bot.MOSDNS_RULESET_DIRECT, bot.MOSDNS_RULESET_HIJACK,
                bot.MOSDNS_HIJACK, bot.RS_META,
            ]
            payload = bot.backup_blob()
            parsed = cio._archive_files(payload)
            self.assertIsNotNone(parsed)
            cio._verify_manifest(parsed)
            cio._verify_pdg_members(parsed)
            self.assertIn("etc/sing-box/rs/sample.json", parsed)
            self.assertIn("etc/mihomo/providers/" + leaf, parsed)

            old_paths = (cio.MODEL_PATH, cio.MOSDNS_PATH,
                         cio.MIHOMO_PROVIDER_DIR, cio.RULESET_META_PATH)
            cio.MODEL_PATH = str(sb)
            cio.MOSDNS_PATH = str(mosdns)
            cio.MIHOMO_PROVIDER_DIR = str(provider_dir)
            cio.RULESET_META_PATH = str(root / "current-rulesets.json")
            staging = root / "staging"
            try:
                manager = cio.ConfigIO(
                    bot=FakeBot(current), staging_dir=str(staging),
                    enforce_root_owner=False)
                preview = manager.preview("pdg", payload, "application/gzip")
                self.assertTrue(preview["summary"]["bundleMosdns"])
                record = manager._record(preview["importId"])
                staged = cio._safe_yaml_load(base64.b64decode(
                    record["candidate"]["mosdns"]))
                self.assertEqual(
                    mosdns_plugin(staged, "internal_sequence")["args"],
                    mosdns_plugin(mosdns_document, "internal_sequence")["args"])
                manager.cancel(preview["importId"])
            finally:
                (cio.MODEL_PATH, cio.MOSDNS_PATH,
                 cio.MIHOMO_PROVIDER_DIR, cio.RULESET_META_PATH) = old_paths

            captured = {}
            original_commit = bot._restore_commit
            def fake_commit(extracted, expected=None):
                captured["members"] = {
                    str(path.relative_to(extracted)).replace(os.sep, "/")
                    for path in Path(extracted).rglob("*") if path.is_file()
                }
                return True, "ok"
            bot._restore_commit = fake_commit
            try:
                ok, _message = bot.restore_from(payload)
                self.assertTrue(ok)
                self.assertIn("manifest.json", captured["members"])
                self.assertIn("etc/mihomo/providers/" + leaf, captured["members"])
            finally:
                bot._restore_commit = original_commit

    def test_backup_generation_reads_fixed_member_limits_before_stability_retry(self):
        bot = load_bot_module()
        bot.RESTORE_MAX_FILE_BYTES = 512 * 1024 * 1024
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            sb = root / "config.json"
            ordinary = root / "config.yaml"
            sb.write_bytes(cio._model_bytes(model()))
            ordinary.write_bytes(b"x" * (bot.BACKUP_MAX_FILE_BYTES + 1))
            bot.SB = str(sb)
            bot.MOSDNS_CONF = str(ordinary)
            bot.BACKUP_FILES = [bot.SB, bot.MOSDNS_CONF]

            original_entries = bot._backup_entries_once
            entry_calls = []
            bot._backup_entries_once = lambda: (
                entry_calls.append(True), original_entries())[1]
            try:
                with self.assertRaisesRegex(ValueError, "普通文件|受管备份路径"):
                    bot.backup_blob()
            finally:
                bot._backup_entries_once = original_entries
            self.assertEqual(len(entry_calls), 1)

            reads = []
            original_read = bot.os.read
            bot.os.read = lambda fd, size: (
                reads.append(size), original_read(fd, size))[1]
            try:
                with self.assertRaises(ValueError):
                    bot._backup_read(str(ordinary), bot.BACKUP_MAX_FILE_BYTES)
                self.assertLessEqual(sum(reads), bot.BACKUP_MAX_FILE_BYTES + 1)
                reads.clear()
                sb.write_bytes(b"{" + b" " * bot.BACKUP_MAX_MODEL_BYTES)
                with self.assertRaises(ValueError):
                    bot._backup_read(str(sb), bot.BACKUP_MAX_MODEL_BYTES)
                self.assertLessEqual(sum(reads), bot.BACKUP_MAX_MODEL_BYTES + 1)
            finally:
                bot.os.read = original_read

    def test_backup_generation_stops_before_reading_total_overflow_member(self):
        bot = load_bot_module()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            sb = root / "config.json"
            sb.write_bytes(cio._model_bytes(model()))
            ordinary = []
            for index, size in enumerate([7, 7, 7, 7, 5]):
                path = root / f"member-{index}.bin"
                path.write_bytes(bytes([65 + index]) * (size * 1024 * 1024))
                ordinary.append(path)
            bot.SB = str(sb)
            bot.BACKUP_FILES = [bot.SB] + [str(path) for path in ordinary]

            active_path = [None]
            body_reads = []
            original_backup_read = bot._backup_read
            original_os_read = bot.os.read
            original_entries = bot._backup_entries_once
            entry_calls = []

            def traced_backup_read(path, maximum=None):
                active_path[0] = path
                try:
                    return original_backup_read(path, maximum)
                finally:
                    active_path[0] = None

            def traced_os_read(fd, size):
                body_reads.append(active_path[0])
                return original_os_read(fd, size)

            bot._backup_read = traced_backup_read
            bot.os.read = traced_os_read
            bot._backup_entries_once = lambda: (
                entry_calls.append(True), original_entries())[1]
            try:
                with self.assertRaisesRegex(ValueError, "总量|普通文件|受管备份路径"):
                    bot.backup_blob()
            finally:
                bot._backup_read = original_backup_read
                bot.os.read = original_os_read
                bot._backup_entries_once = original_entries
            self.assertEqual(len(entry_calls), 1)
            self.assertNotIn(str(ordinary[-1]), body_reads)

    def test_backup_generation_rejects_member_512_before_body_read(self):
        bot = load_bot_module()
        bot.SB = "/managed/config.json"
        paths = [f"/managed/member-{index:04d}.txt" for index in range(512)]
        bot.BACKUP_FILES = [bot.SB] + paths
        calls = []
        entry_calls = []
        original_read = bot._backup_read
        original_entries = bot._backup_entries_once

        def fake_read(path, _maximum=None):
            calls.append(path)
            return cio._model_bytes(model()) if path == bot.SB else b"x"

        bot._backup_read = fake_read
        bot._backup_entries_once = lambda: (
            entry_calls.append(True), original_entries())[1]
        try:
            with self.assertRaisesRegex(ValueError, "成员过多"):
                bot.backup_blob()
        finally:
            bot._backup_read = original_read
            bot._backup_entries_once = original_entries
        self.assertEqual(len(entry_calls), 1)
        self.assertEqual(len(calls), bot.BACKUP_MAX_MEMBERS - 1)
        self.assertNotIn(paths[bot.BACKUP_MAX_MEMBERS - 2], calls)

    def test_bot_restore_checks_component_baselines_inside_transaction(self):
        bot = load_bot_module()

        class Refused(RuntimeError):
            pass

        class FakeTransaction:
            def read_for_update(self, target):
                data = b"changed-component" if target.startswith("mosdns_rule:") else b"{}"
                return data, cio._sha(data)

            def abort_unstarted(self):
                return None

        fake_tx = types.SimpleNamespace(
            Tx=lambda **_kwargs: FakeTransaction(), TxBusy=type("Busy", (Exception,), {}),
            TxRefused=Refused, TxError=type("TxError", (Exception,), {}),
            redact=str, COMMITTED="COMMITTED", ROLLBACK_FAILED="ROLLBACK_FAILED")
        original_pdgtx = bot._pdgtx
        bot._pdgtx = lambda: fake_tx
        try:
            with tempfile.TemporaryDirectory() as tmp:
                model_path = Path(tmp, "etc", "sing-box", "config.json")
                model_path.parent.mkdir(parents=True)
                model_path.write_bytes(cio._model_bytes(model()))
                for target in ("mosdns_rule:custom_direct.txt", "rs_meta"):
                    with self.subTest(target=target):
                        ok, message = bot._restore_commit(tmp, expected={
                            "files": {target: cio._sha(b"before")}})
                        self.assertFalse(ok)
                        self.assertIn("PRECONDITION_FAILED", message)
        finally:
            bot._pdgtx = original_pdgtx

    def test_bot_restore_rejects_malformed_declared_v3_before_any_stage(self):
        bot = load_bot_module()
        current = cio._model_bytes(model())
        malformed = model()
        malformed["_pdg"]["mihomo"].pop("managed-files")

        class Refused(RuntimeError):
            pass

        class FakeTransaction:
            def __init__(self):
                self.staged = []

            def read_for_update(self, target):
                data = current if target == "model" else b"{}"
                return data, cio._sha(data)

            def watch(self, _target, optional=False):
                return b"{}"

            def stage(self, *args, **kwargs):
                self.staged.append((args, kwargs))

            def abort_unstarted(self):
                return None

        transaction = FakeTransaction()
        fake_tx = types.SimpleNamespace(
            Tx=lambda **_kwargs: transaction,
            TxBusy=type("Busy", (Exception,), {}), TxRefused=Refused,
            TxError=type("TxError", (Exception,), {}), redact=str,
            COMMITTED="COMMITTED", ROLLBACK_FAILED="ROLLBACK_FAILED")
        original_pdgtx = bot._pdgtx
        bot._pdgtx = lambda: fake_tx
        try:
            with tempfile.TemporaryDirectory() as tmp:
                path = Path(tmp, "etc", "sing-box", "config.json")
                path.parent.mkdir(parents=True)
                path.write_bytes(json.dumps(malformed).encode("utf-8"))
                ok, message = bot._restore_commit(tmp)
            self.assertFalse(ok)
            self.assertIn("v3", message)
            self.assertEqual(transaction.staged, [])
        finally:
            bot._pdgtx = original_pdgtx


class ModelAndConversionTests(unittest.TestCase):
    def test_declared_v3_malformed_shape_fails_in_bot_and_config_io(self):
        bot_module = load_bot_module()
        candidate = model()
        candidate["_pdg"]["mihomo"].pop("managed-files")
        with self.assertRaises(ValueError):
            bot_module._model_schema_v3(copy.deepcopy(candidate))
        with self.assertRaisesRegex(cio.ImportInvalid, "schema v3"):
            cio.normalize_model(copy.deepcopy(candidate))

    def test_native_model_cannot_override_managed_or_proxy_identity(self):
        candidate = model({"type": "direct", "tag": "JP"})
        candidate["_pdg"]["mihomo"]["advanced"] = {"dns": {"enable": False}}
        with self.assertRaisesRegex(cio.ImportInvalid, "managed runtime"):
            cio.normalize_model(candidate)
        candidate = {
            "outbounds": [
                {"type": "vless", "tag": "p", "server": "one", "server_port": 443,
                 "uuid": "u", "_pdg_mihomo": {"advanced": {"server": "evil"}}},
                {"type": "direct", "tag": "JP"},
            ],
            "route": {"rules": [], "final": "JP"},
        }
        with self.assertRaisesRegex(cio.ImportInvalid, "canonical field"):
            cio.normalize_model(candidate)

    def test_native_provider_paths_and_embedded_file_closure_are_managed(self):
        candidate = model()
        candidate["_pdg"]["mihomo"]["proxy-providers"] = {
            "escape": {"type": "file", "path": "/etc/shadow"}}
        with self.assertRaisesRegex(cio.ImportInvalid, "path|embedded"):
            cio.normalize_model(candidate)
        candidate = model()
        raw = b"proxies: []\n"
        leaf = cio._sha(raw) + ".yaml"
        candidate["_pdg"]["mihomo"]["managed-files"] = {
            leaf: base64.b64encode(raw).decode("ascii")}
        with self.assertRaisesRegex(cio.ImportInvalid, "closure"):
            cio.normalize_model(candidate)

    @unittest.skipIf(pdgtx is None, "pdgtx requires POSIX fcntl")
    def test_transaction_validator_independently_rejects_group_collisions(self):
        candidate = model(
            {"type": "vless", "tag": "same", "server": "one.example",
             "server_port": 443, "uuid": "u"},
            {"type": "direct", "tag": "JP"})
        candidate["_pdg"]["policy-groups"] = [{
            "name": "same", "type": "select", "proxies": ["JP"], "use": [],
        }]
        ok, error = pdgtx._v_json_model(
            "config.json", json.dumps(candidate).encode(), None)
        self.assertFalse(ok)
        self.assertIn("share one namespace", error)

        candidate = model({"type": "direct", "tag": "JP"})
        candidate["_pdg"]["mihomo"]["proxy-groups"] = [{
            "name": "group", "type": "fallback", "proxies": ["JP"],
        }]
        ok, error = pdgtx._v_json_model(
            "config.json", json.dumps(candidate).encode(), None)
        self.assertFalse(ok)
        self.assertIn("扩展字段", error)

    @unittest.skipIf(pdgtx is None, "pdgtx requires POSIX fcntl")
    def test_transaction_validator_independently_enforces_runtime_metadata(self):
        candidate = model(
            {"type": "vless", "tag": "p", "server": "one.example",
             "server_port": 443, "uuid": "u",
             "_pdg_mihomo": {"advanced": {"udp": True}}},
            {"type": "direct", "tag": "JP"})
        candidate["_pdg"]["mihomo"]["advanced"] = {
            "tcp-concurrent": True,
            # Opaque state is portable metadata only; the renderer must not
            # activate it even though the transaction validator preserves it.
            "state-dir": "/etc/mihomo/state",
        }
        ok, error = pdgtx._v_json_model(
            "config.json", json.dumps(candidate).encode(), None)
        self.assertTrue(ok, error)
        rendered, _warnings = sb2mihomo.singbox_to_mihomo(candidate)
        self.assertTrue(rendered["tcp-concurrent"])
        self.assertNotIn("state-dir", rendered)

        bad = copy.deepcopy(candidate)
        bad["_pdg"]["mihomo"]["advanced"]["tcp-concurrent"] = "yes"
        ok, _error = pdgtx._v_json_model(
            "config.json", json.dumps(bad).encode(), None)
        self.assertFalse(ok)
        bad = copy.deepcopy(candidate)
        bad["outbounds"][0]["_pdg_mihomo"]["advanced"]["udp"] = "yes"
        ok, _error = pdgtx._v_json_model(
            "config.json", json.dumps(bad).encode(), None)
        self.assertFalse(ok)

        bad_provider = copy.deepcopy(candidate)
        provider_name = "remote"
        provider_hash = hashlib.sha256(
            ("proxy-provider:" + provider_name).encode()).hexdigest()
        bad_provider["_pdg"]["mihomo"]["proxy-providers"] = {
            provider_name: {
                "type": "http", "url": "https://provider.example/config.yaml",
                "path": "/etc/mihomo/providers/" + provider_hash + ".yaml",
                "override": {"interface-name": "eth0"},
            }}
        ok, _error = pdgtx._v_json_model(
            "config.json", json.dumps(bad_provider).encode(), None)
        self.assertFalse(ok)

        bad_group = model(
            {"type": "selector", "tag": "G", "outbounds": ["JP"]},
            {"type": "direct", "tag": "JP"})
        bad_group["_pdg"]["mihomo"]["proxy-groups"] = [{
            "name": "G", "type": "select", "proxies": ["DIRECT"],
            "interface-name": "eth0",
        }]
        ok, _error = pdgtx._v_json_model(
            "config.json", json.dumps(bad_group).encode(), None)
        self.assertFalse(ok)

    @unittest.skipIf(pdgtx is None, "pdgtx requires POSIX fcntl")
    def test_transaction_ruleset_collision_uses_candidate_first_and_bounded_live_read(self):
        provider_name = "shared"
        provider_hash = hashlib.sha256(
            ("rule-provider:" + provider_name).encode("utf-8")).hexdigest()
        candidate = model()
        candidate["_pdg"]["mihomo"]["rule-providers"] = {
            provider_name: {
                "type": "http",
                "url": "https://provider.example/shared.txt",
                "path": "/etc/mihomo/providers/" + provider_hash + ".txt",
                "format": "text",
                "behavior": "classical",
            }
        }
        candidate_data = cio._model_bytes(candidate)

        def context(meta):
            return types.SimpleNamespace(targets={
                "rs_meta": {"data": json.dumps(meta).encode("utf-8")}
            })

        occupied_variants = {
            "runtime": {
                "url": "https://rules.example/shared.txt",
                "outbound": "JP", "format": "source",
            },
            "direct": {
                "url": "https://rules.example/direct.txt",
                "outbound": "direct", "format": "source",
            },
            "legacy-srs": {
                "url": "https://rules.example/shared.srs",
                "outbound": "JP", "format": "binary",
            },
        }
        for variant, metadata in occupied_variants.items():
            with self.subTest(variant=variant):
                ok, error = pdgtx._v_json_model(
                    "config.json", candidate_data,
                    context({provider_name: metadata}))
                self.assertFalse(ok)
                self.assertIn("同名", error)

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            live_path = root / "opt/pdg-bot/rulesets.json"
            live_path.parent.mkdir(parents=True)
            live_path.write_text(json.dumps({
                provider_name: occupied_variants["runtime"]
            }), encoding="utf-8")
            old_root = pdgtx.FSROOT
            pdgtx.FSROOT = str(root)
            try:
                # A staged rs_meta candidate is authoritative and must not be
                # contaminated by a colliding live namespace.
                staged = context({"candidate-only": {
                    "url": "https://rules.example/candidate.txt",
                    "outbound": "JP", "format": "source",
                }})
                ok, error = pdgtx._v_json_model(
                    "config.json", candidate_data, staged)
                self.assertTrue(ok, error)
                providers_ok, providers, _sources, providers_error = (
                    pdgtx._pdg_mihomo_rule_providers(staged))
                self.assertTrue(providers_ok, providers_error)
                self.assertEqual(set(providers), {"candidate-only"})

                deleted = types.SimpleNamespace(targets={
                    "rs_meta": {"data": None}
                })
                ok, error = pdgtx._v_json_model(
                    "config.json", candidate_data, deleted)
                self.assertTrue(ok, error)
                providers_ok, providers, _sources, providers_error = (
                    pdgtx._pdg_mihomo_rule_providers(deleted))
                self.assertTrue(providers_ok, providers_error)
                self.assertEqual(providers, {})

                ok, error = pdgtx._v_json_model(
                    "config.json", candidate_data, None)
                self.assertFalse(ok)
                self.assertIn("同名", error)
            finally:
                pdgtx.FSROOT = old_root

        reads = []

        class OversizedRulesetFile:
            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return False

            def read(self, amount=-1):
                reads.append(amount)
                return b"x" * amount

        with mock.patch("builtins.open", return_value=OversizedRulesetFile()):
            ok, _meta, error = pdgtx._candidate_ruleset_meta(None)
        self.assertFalse(ok)
        self.assertIn("超过", error)
        self.assertEqual(reads, [pdgtx.MAX_MANAGED_FILE + 1])

    def test_proxy_advanced_round_trip_and_canonical_fields_win(self):
        current = model()
        doc = {
            "proxies": [{"name": "p", "type": "vless", "server": "one.example",
                         "port": 443, "uuid": "u", "udp": False,
                         "packet-encoding": "xudp"}],
            "proxy-providers": {}, "proxy-groups": [], "rule-providers": {},
            "rules": ["MATCH,DIRECT"],
        }
        converted, _warnings = cio.mihomo_to_model(
            doc, current, archive=None, config_name="config.yaml")
        outbound = next(item for item in converted["outbounds"] if item.get("tag") == "p")
        self.assertEqual(outbound["_pdg_mihomo"]["advanced"], {
            "udp": False, "packet-encoding": "xudp"})
        rendered, _meta = sb2mihomo.singbox_to_mihomo(converted)
        proxy = next(item for item in rendered["proxies"] if item["name"] == "p")
        self.assertEqual(proxy["server"], "one.example")
        self.assertFalse(proxy["udp"])
        self.assertEqual(proxy["packet-encoding"], "xudp")

    def test_opaque_advanced_paths_and_machine_routing_never_activate(self):
        doc = {
            "proxies": [{
                "name": "p", "type": "vless", "server": "one.example",
                "port": 443, "uuid": "u", "udp": True,
                "interface-name": "eth0", "routing-mark": 123,
                "dialer-proxy": "other", "certificate": "/etc/pdg/client.pem",
                "private-key": "../private.key", "state": "./state.db",
            }],
            "proxy-providers": {}, "proxy-groups": [], "rule-providers": {},
            "rules": ["MATCH,DIRECT"],
            "tcp-concurrent": True, "unified-delay": False,
            "interface-name": "eth0", "routing-mark": 456,
            "tls": {"certificate": "/etc/pdg/server.pem", "private-key": "/root/key"},
            "profile": {"store-selected": True}, "state": "/var/lib/mihomo/state",
        }
        converted, warnings = cio.mihomo_to_model(
            doc, model(), archive=None, config_name="config.yaml")
        self.assertTrue(any("interface-name" in warning and "certificate" in warning
                            for warning in warnings))
        metadata = next(item for item in converted["outbounds"] if item.get("tag") == "p")[
            "_pdg_mihomo"]["advanced"]
        self.assertEqual(metadata["certificate"], "/etc/pdg/client.pem")
        self.assertEqual(converted["_pdg"]["mihomo"]["advanced"]["state"],
                         "/var/lib/mihomo/state")
        rendered, _meta = sb2mihomo.singbox_to_mihomo(converted)
        self.assertTrue(rendered["tcp-concurrent"])
        self.assertFalse(rendered["unified-delay"])
        for key in ("interface-name", "routing-mark", "tls", "profile", "state"):
            self.assertNotIn(key, rendered)
        proxy = next(item for item in rendered["proxies"] if item["name"] == "p")
        self.assertTrue(proxy["udp"])
        for key in ("interface-name", "routing-mark", "dialer-proxy",
                    "certificate", "private-key", "state"):
            self.assertNotIn(key, proxy)

        # Renderer defense remains safe even if called on an unnormalized
        # model supplied by another in-process caller.
        malicious = copy.deepcopy(converted)
        malicious["_pdg"]["mihomo"]["advanced"]["hosts"] = {
            "secret.local": "/etc/shadow"}
        malicious["outbounds"][1]["_pdg_mihomo"]["advanced"]["ca"] = "/etc/ssl/key"
        rendered, _meta = sb2mihomo.singbox_to_mihomo(malicious)
        self.assertNotIn("hosts", rendered)
        self.assertNotIn("ca", rendered["proxies"][0])

    def test_group_and_provider_runtime_schemas_reject_machine_controls(self):
        base = {
            "proxies": [{"name": "p", "type": "socks5", "server": "one.example",
                         "port": 1080}],
            "proxy-providers": {}, "rule-providers": {},
            "proxy-groups": [{"name": "Proxy", "type": "select", "proxies": ["p"]}],
            "rules": ["MATCH,Proxy"],
        }
        for field, value in (("interface-name", "eth0"), ("routing-mark", 9),
                             ("dialer-proxy", "p"), ("certificate", "/etc/cert")):
            bad = copy.deepcopy(base)
            bad["proxy-groups"][0][field] = value
            with self.subTest(group_field=field), self.assertRaisesRegex(
                    cio.ImportInvalid, "unsupported runtime fields"):
                cio.mihomo_to_model(bad, model(), archive=None, config_name="config.yaml")

        provider = {
            "type": "http", "url": "https://example.invalid/sub.yaml",
            "path": "./provider.yaml", "interval": 3600,
            "health-check": {"enable": True,
                             "url": "https://www.gstatic.com/generate_204",
                             "interval": 300},
            "override": {"additional-prefix": "safe-", "udp": True},
        }
        safe = copy.deepcopy(base)
        safe["proxy-providers"] = {"sub": provider}
        safe["proxy-groups"][0]["use"] = ["sub"]
        converted, _ = cio.mihomo_to_model(
            safe, model(), archive=None, config_name="config.yaml")
        rendered, _meta = sb2mihomo.singbox_to_mihomo(converted)
        self.assertEqual(rendered["proxy-providers"]["sub"]["override"],
                         {"additional-prefix": "safe-", "udp": True})
        self.assertEqual(rendered["proxy-providers"]["sub"]["health-check"]["interval"], 300)
        for nested, value in (("interface-name", "eth0"),
                              ("routing-mark", 7), ("dialer-proxy", "p"),
                              ("private-key", "/etc/key")):
            bad = copy.deepcopy(safe)
            bad["proxy-providers"]["sub"]["override"][nested] = value
            with self.subTest(provider_field=nested), self.assertRaisesRegex(
                    cio.ImportInvalid, "unsafe runtime fields"):
                cio.mihomo_to_model(bad, model(), archive=None, config_name="config.yaml")

    def test_mihomo_requires_provider_mappings_and_final_match(self):
        base = {"proxies": [], "proxy-groups": [], "rules": ["MATCH,DIRECT"]}
        with self.assertRaisesRegex(cio.ImportInvalid, "proxy-providers"):
            cio.mihomo_to_model({**base, "proxy-providers": []}, model(),
                                archive=None, config_name="config.yaml")
        with self.assertRaisesRegex(cio.ImportInvalid, "MATCH"):
            cio.mihomo_to_model({**base, "rules": ["MATCH,DIRECT", "DOMAIN,x,DIRECT"]},
                                model(), archive=None, config_name="config.yaml")

    def test_mihomo_rejects_reserved_names_and_unmodelled_rule_suffixes(self):
        base = {
            "proxies": [{"name": "JP", "type": "socks5", "server": "one.example",
                         "port": 1080}],
            "proxy-providers": {}, "proxy-groups": [], "rule-providers": {},
            "rules": ["MATCH,DIRECT"],
        }
        with self.assertRaisesRegex(cio.ImportInvalid, "reserved"):
            cio.mihomo_to_model(base, model(), archive=None, config_name="config.yaml")
        base["proxies"][0]["name"] = "p"
        base["rules"] = ["IP-CIDR,192.0.2.0/24,p,no-resolve", "MATCH,DIRECT"]
        with self.assertRaisesRegex(cio.ImportInvalid, "not supported"):
            cio.mihomo_to_model(base, model(), archive=None, config_name="config.yaml")

    def test_first_class_group_survives_bot_edit_and_renderer_round_trip(self):
        document = {
            "proxies": [
                {"name": "one", "type": "socks5", "server": "one.example", "port": 1080},
                {"name": "two", "type": "socks5", "server": "two.example", "port": 1080},
            ],
            "proxy-providers": {}, "rule-providers": {},
            "proxy-groups": [{
                "name": "Auto", "type": "select", "proxies": ["one", "two", "DIRECT"],
                "lazy": True,
            }],
            "rules": ["MATCH,Auto"],
        }
        candidate, _warnings = cio.mihomo_to_model(
            document, model(), archive=None, config_name="config.yaml")
        bot = load_bot_module()
        original_load, original_apply = bot.load, bot.apply_sb
        try:
            bot.load = lambda: copy.deepcopy(candidate)
            bot.apply_sb = lambda modifier: (modifier(candidate) or True, "")
            ok, _message = bot.add_group("Auto", ["two", "one"])
            self.assertTrue(ok)
            self.assertFalse(any(item.get("tag") == "Auto"
                                 for item in candidate["outbounds"]))
            group = next(item for item in candidate["_pdg"]["policy-groups"]
                         if item.get("name") == "Auto")
            self.assertEqual(group["type"], "select")
            self.assertEqual(group["proxies"], ["two", "one"])
        finally:
            bot.load, bot.apply_sb = original_load, original_apply
        bot._mihomo_group_rename(candidate, "Auto", "Fast")
        group = next(item for item in candidate["_pdg"]["policy-groups"]
                     if item.get("name") == "Fast")
        group["proxies"] = ["two", "JP"]
        candidate = cio.normalize_model(candidate)
        rendered, _meta = sb2mihomo.singbox_to_mihomo(candidate)
        rendered_group = next(item for item in rendered["proxy-groups"]
                              if item.get("name") == "Fast")
        self.assertEqual(rendered_group["proxies"], ["two", "DIRECT"])
        self.assertTrue(rendered_group["lazy"])
        bot._mihomo_group_delete(candidate, {"two"})
        cio.normalize_model(candidate)

    def test_local_provider_archive_and_unresolved_references(self):
        provider_data = b"proxies:\n  - {name: local, type: ss}\n"
        doc = {
            "proxies": [],
            "proxy-providers": {"local": {"type": "file", "path": "./providers/local.yaml"}},
            "proxy-groups": [{"name": "Proxy", "type": "select", "use": ["local"]}],
            "rule-providers": {}, "rules": ["MATCH,Proxy"],
        }
        converted, _ = cio.mihomo_to_model(
            doc, model(), archive={"config.yaml": b"", "providers/local.yaml": provider_data},
            config_name="config.yaml")
        managed = converted["_pdg"]["mihomo"]["managed-files"]
        self.assertEqual(len(managed), 1)
        self.assertEqual(next(iter(managed)).split(".", 1)[0], cio._sha(provider_data))
        with self.assertRaisesRegex(cio.ImportInvalid, "missing"):
            cio.mihomo_to_model(doc, model(), archive={"config.yaml": b""},
                                config_name="config.yaml")
        bad = copy.deepcopy(doc)
        bad["proxy-groups"][0]["use"] = ["undefined"]
        with self.assertRaisesRegex(cio.ImportInvalid, "undefined"):
            cio.mihomo_to_model(
                bad, model(), archive={"config.yaml": b"", "providers/local.yaml": provider_data},
                config_name="config.yaml")
        with self.assertRaisesRegex(cio.ImportInvalid, "exact provider reference closure"):
            cio.mihomo_to_model(
                doc, model(), archive={
                    "config.yaml": b"", "providers/local.yaml": provider_data,
                    "providers/orphan.yaml": b"proxies: []\n",
                }, config_name="config.yaml")

    def test_pdg_merge_does_not_silently_replace_non_model_components(self):
        incoming = tar_bytes({
            "etc/sing-box/config.json": json.dumps(model()).encode(),
            "etc/mosdns/config.yaml": b"incoming-mosdns",
            "etc/mosdns/rules/custom_hijack.txt": b"incoming-rule",
            "opt/pdg-bot/rulesets.json": b"{}",
            "etc/sing-box/rs/x.json": b"incoming-ruleset",
            "etc/mihomo/providers/" + "a" * 64 + ".yaml": b"provider",
        })
        merged = cio._archive_files(cio._restore_bundle(incoming, model(), "merge", {}))
        self.assertNotIn("etc/mosdns/config.yaml", merged)
        self.assertNotIn("opt/pdg-bot/rulesets.json", merged)
        self.assertNotIn("etc/mihomo/providers/" + "a" * 64 + ".yaml", merged)
        replaced = cio._archive_files(cio._restore_bundle(incoming, model(), "replace", {}))
        self.assertIn("etc/mosdns/config.yaml", replaced)
        self.assertIn("opt/pdg-bot/rulesets.json", replaced)
        cio._verify_manifest(replaced)


class MosdnsContractTests(unittest.TestCase):
    def setUp(self):
        current_text = (ROOT / "deploy" / "mosdns" / "config.yaml").read_text(encoding="utf-8")
        example = (ROOT / "deploy" / "web" / "static" / "templates" /
                   "mosdns-import.example.yaml").read_text(encoding="utf-8")
        replacements = {
            "__SERVER_IP__": "203.0.113.10",
            "__INTERNAL_CIDR__": "192.0.2.0/24",
            "__CERT_DIR__": "/etc/mosdns/certs",
            "__HIJACK_SET_FILE__": "ruleset_hijack.txt",
            "__MOSDNS_CACHE__": "1234",
        }
        for old, new in replacements.items():
            example = example.replace(old, new)
            current_text = current_text.replace(old, new)
        self.current = cio._safe_yaml_load(current_text.encode())
        self.incoming = cio._safe_yaml_load(example.encode())

    def test_accepts_both_managed_hijack_shapes_and_preserves_live_mode(self):
        current_all = mosdns_all_mode(self.current)
        incoming_all = mosdns_all_mode(self.incoming)
        cases = (
            ("gfw-to-gfw", self.incoming, self.current, self.current),
            ("all-to-all", incoming_all, current_all, current_all),
            ("gfw-to-all", self.incoming, current_all, current_all),
            ("all-to-gfw", incoming_all, self.current, self.current),
        )
        for label, incoming, current, expected in cases:
            with self.subTest(label=label):
                candidate = cio._mosdns_contract(
                    copy.deepcopy(incoming), copy.deepcopy(current))
                self.assertEqual(
                    mosdns_plugin(candidate, "internal_sequence")["args"],
                    mosdns_plugin(expected, "internal_sequence")["args"])

    def test_rejects_damaged_incoming_and_current_managed_sequences(self):
        def delete_wrong_step(document):
            del mosdns_plugin(document, "internal_sequence")["args"][7]

        def reorder_steps(document):
            args = mosdns_plugin(document, "internal_sequence")["args"]
            args[0], args[1] = args[1], args[0]

        def change_execution(document):
            mosdns_plugin(document, "internal_sequence")["args"][0]["exec"] = "reject 4"

        for side in ("incoming", "current"):
            for label, mutate in (
                    ("wrong-delete", delete_wrong_step),
                    ("reorder", reorder_steps),
                    ("changed-exec", change_execution)):
                with self.subTest(side=side, damage=label):
                    incoming = copy.deepcopy(self.incoming)
                    current = copy.deepcopy(self.current)
                    mutate(incoming if side == "incoming" else current)
                    with self.assertRaisesRegex(cio.ImportInvalid, "sequence"):
                        cio._mosdns_contract(incoming, current)

        # Removing just half of the managed two-entry gate is not a third
        # profile and must never be mistaken for all mode.
        half_gate = copy.deepcopy(self.incoming)
        del mosdns_plugin(half_gate, "internal_sequence")["args"][8]
        with self.assertRaisesRegex(cio.ImportInvalid, "sequence"):
            cio._mosdns_contract(half_gate, self.current)

    def test_full_graph_rebinds_machine_identity(self):
        candidate = cio._mosdns_contract(copy.deepcopy(self.incoming), self.current)
        current = {item["tag"]: item for item in self.current["plugins"]}
        actual = {item["tag"]: item for item in candidate["plugins"]}
        self.assertEqual(actual["npn_clients"]["args"], current["npn_clients"]["args"])
        self.assertEqual(actual["dot_server"]["args"]["cert"],
                         current["dot_server"]["args"]["cert"])
        self.assertEqual(actual["lazy_cache"]["args"]["size"],
                         current["lazy_cache"]["args"]["size"])
        self.assertEqual(actual["udp_server"]["args"]["listen"],
                         current["udp_server"]["args"]["listen"])
        self.assertEqual(actual["geosite_cn"]["args"]["files"],
                         current["geosite_cn"]["args"]["files"])

    def test_rejects_extra_top_level_and_incomplete_graph(self):
        bad = copy.deepcopy(self.incoming)
        bad["api"] = {"http": "0.0.0.0:8080"}
        with self.assertRaisesRegex(cio.ImportInvalid, "top-level"):
            cio._mosdns_contract(bad, self.current)
        bad = copy.deepcopy(self.incoming)
        bad["plugins"] = bad["plugins"][:-1]
        with self.assertRaises(cio.ImportInvalid):
            cio._mosdns_contract(bad, self.current)

    def test_rejects_plugin_arg_injection_and_unmanaged_live_identity(self):
        bad = copy.deepcopy(self.incoming)
        limiter = next(item for item in bad["plugins"]
                       if item["tag"] == "client_limiter")
        limiter["args"]["include"] = "/etc/shadow"
        with self.assertRaisesRegex(cio.ImportInvalid, "limiter args"):
            cio._mosdns_contract(bad, self.current)

        bad_current = copy.deepcopy(self.current)
        geosite = next(item for item in bad_current["plugins"]
                       if item["tag"] == "geosite_cn")
        geosite["args"]["files"][0] = "/tmp/escape.txt"
        with self.assertRaisesRegex(cio.ImportInvalid, "rule path"):
            cio._mosdns_contract(copy.deepcopy(self.incoming), bad_current)

        bad_current = copy.deepcopy(self.current)
        udp = next(item for item in bad_current["plugins"] if item["tag"] == "udp_server")
        udp["args"]["listen"] = "127.0.0.1:5353"
        with self.assertRaisesRegex(cio.ImportInvalid, "listener"):
            cio._mosdns_contract(copy.deepcopy(self.incoming), bad_current)


class StagingTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.old_model_path = cio.MODEL_PATH
        self.old_mosdns_path = cio.MOSDNS_PATH
        self.old_provider_dir = cio.MIHOMO_PROVIDER_DIR
        self.old_ruleset_meta_path = cio.RULESET_META_PATH
        self.old_ruleset_dir = cio.RULESET_DIR
        self.old_mosdns_rule_dir = cio.MOSDNS_RULE_DIR
        cio.MODEL_PATH = str(Path(self.tmp.name, "model.json"))
        cio.MOSDNS_PATH = str(Path(self.tmp.name, "mosdns.yaml"))
        cio.MIHOMO_PROVIDER_DIR = str(Path(self.tmp.name, "providers"))
        cio.RULESET_META_PATH = str(Path(self.tmp.name, "rulesets.json"))
        cio.RULESET_DIR = str(Path(self.tmp.name, "rs"))
        cio.MOSDNS_RULE_DIR = str(Path(self.tmp.name, "mosdns-rules"))
        Path(cio.MIHOMO_PROVIDER_DIR).mkdir()
        Path(cio.RULESET_DIR).mkdir()
        Path(cio.MOSDNS_RULE_DIR).mkdir()
        Path(cio.RULESET_META_PATH).write_text("{}\n", encoding="utf-8")
        self.manager = cio.ConfigIO(
            bot=FakeBot(), staging_dir=self.tmp.name, enforce_root_owner=False)
        Path(cio.MODEL_PATH).write_bytes(cio._model_bytes(self.manager.bot.current))

    def tearDown(self):
        cio.MODEL_PATH = self.old_model_path
        cio.MOSDNS_PATH = self.old_mosdns_path
        cio.MIHOMO_PROVIDER_DIR = self.old_provider_dir
        cio.RULESET_META_PATH = self.old_ruleset_meta_path
        cio.RULESET_DIR = self.old_ruleset_dir
        cio.MOSDNS_RULE_DIR = self.old_mosdns_rule_dir
        self.tmp.cleanup()

    def test_malformed_declared_v3_import_is_rejected_before_staging(self):
        candidate = model()
        candidate["_pdg"]["policy-groups"] = {}
        before = sorted(Path(self.tmp.name).iterdir())
        with self.assertRaisesRegex(cio.ImportInvalid, "schema v3"):
            self.manager.preview(
                "pdg", json.dumps(candidate).encode("utf-8"),
                "application/json")
        self.assertEqual(sorted(Path(self.tmp.name).iterdir()), before)

    def test_mihomo_apply_passes_locked_model_cas_to_transaction(self):
        incoming = model(
            {"type": "vless", "tag": "new", "server": "new.example",
             "server_port": 443, "uuid": "u"},
            {"type": "direct", "tag": "JP"})
        document, _metadata = sb2mihomo.singbox_to_mihomo(incoming)
        preview = self.manager.preview(
            "mihomo", json.dumps(document).encode(), "application/yaml")
        self.manager.prepare_apply(preview["importId"], {
            "confirm": True, "mode": "merge", "conflicts": {}})
        expected = cio._sha(Path(cio.MODEL_PATH).read_bytes())
        self.manager.apply(preview["importId"])
        _args, kwargs = self.manager.bot.calls[-1]
        self.assertEqual(kwargs["model_expect"], expected)

    def test_pdg_ruleset_collisions_follow_selected_component_state(self):
        provider_name = "shared"
        provider_hash = hashlib.sha256(
            ("rule-provider:" + provider_name).encode("utf-8")).hexdigest()
        incoming_model = model()
        incoming_model["_pdg"]["mihomo"]["rule-providers"] = {
            provider_name: {
                "type": "http",
                "url": "https://provider.example/shared.txt",
                "path": "/etc/mihomo/providers/" + provider_hash + ".txt",
                "format": "text", "behavior": "classical",
            }
        }

        def archive(meta_name, *, direct=False):
            leaf = meta_name + ".json"
            metadata = {
                meta_name: {
                    "url": "https://rules.example/" + leaf,
                    "outbound": "direct" if direct else "JP",
                    "format": "source",
                    "path": "/etc/sing-box/rs/" + leaf,
                }
            }
            return v2_pdg_bytes({
                "etc/sing-box/config.json": cio._model_bytes(incoming_model),
                "opt/pdg-bot/rulesets.json": json.dumps(metadata).encode("utf-8"),
                "etc/sing-box/rs/" + leaf: b'{"version":1,"rules":[]}',
            })

        def choices(preview, rulesets):
            return {
                item["conflictId"]: (
                    rulesets if item["kind"] == "component"
                    and item["name"] == "rulesets" else "incoming")
                for item in preview["conflicts"]
            }

        # Every imported metadata key is a rule-provider name, even when the
        # current representation would not render it.  Import rejects this
        # ambiguous archive atomically before staging a preview.
        Path(cio.RULESET_META_PATH).write_text("{}\n", encoding="utf-8")
        payload = archive(provider_name, direct=True)
        before = sorted(Path(self.tmp.name).iterdir())
        with self.assertRaisesRegex(cio.ImportInvalid, "ruleset namespace"):
            self.manager.preview("pdg", payload, "application/gzip")
        self.assertEqual(sorted(Path(self.tmp.name).iterdir()), before)

        # Conversely, a live collision is unsafe only when merge keeps the
        # existing component.  Selecting the non-colliding incoming metadata
        # must pass the pre-job gate.
        self.manager.bot.current = model()
        Path(cio.MODEL_PATH).write_bytes(cio._model_bytes(self.manager.bot.current))
        Path(cio.RULESET_META_PATH).write_text(json.dumps({
            provider_name: {
                "url": "https://rules.example/live.json", "outbound": "JP",
                "format": "source", "path": "/etc/sing-box/rs/live.json",
            }
        }), encoding="utf-8")
        payload = archive("incoming-only")
        preview = self.manager.preview("pdg", payload, "application/gzip")
        with self.assertRaisesRegex(cio.ImportInvalid, "selected PDG ruleset"):
            self.manager.prepare_apply(preview["importId"], {
                "confirm": True, "mode": "merge",
                "conflicts": choices(preview, "existing")})

    def test_current_ruleset_names_reads_only_the_fixed_envelope(self):
        reads = []

        class OversizedRulesetFile:
            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return False

            def read(self, amount=-1):
                reads.append(amount)
                return b"x" * amount

        with mock.patch("builtins.open", return_value=OversizedRulesetFile()):
            with self.assertRaisesRegex(cio.ImportInvalid, "too large"):
                cio._current_ruleset_names()
        self.assertEqual(reads, [cio.MAX_ARCHIVE_FILE + 1])

    def test_legacy_direct_tag_rebinds_for_json_and_manifestless_tar_apply(self):
        incoming = {
            "outbounds": [
                {"type": "vless", "tag": "p", "server": "proxy.example",
                 "server_port": 443, "uuid": "u"},
                {"type": "selector", "tag": "G", "outbounds": ["jp", "p"]},
                {"type": "direct", "tag": "jp"},
            ],
            "route": {
                "rules": [{"domain_suffix": ["legacy.example"], "outbound": "jp"}],
                "final": "jp",
            },
            "_pdg": {"schema": 2, "mihomo": {
                "proxy-groups": [{"name": "G", "type": "select",
                                  "proxies": ["jp", "p"]}],
                "proxy-providers": {}, "rule-providers": {}, "advanced": {},
                "managed-files": {},
            }},
        }
        incoming = cio.normalize_model(incoming)
        raw_json = cio._model_bytes(incoming)
        payloads = {
            "json": raw_json,
            "tar": tar_bytes({"etc/sing-box/config.json": raw_json}),
        }

        for payload_name, payload in payloads.items():
            for mode in ("merge", "replace"):
                with self.subTest(payload=payload_name, mode=mode):
                    self.manager.bot.current = cio.normalize_model({
                        "outbounds": [{"type": "direct", "tag": "KFC_JP"}],
                        "route": {"rules": [], "final": "KFC_JP"},
                    })
                    Path(cio.MODEL_PATH).write_bytes(
                        cio._model_bytes(self.manager.bot.current))
                    preview = self.manager.preview("pdg", payload)
                    staged = self.manager._record(preview["importId"])["candidate"]["model"]
                    self.assertEqual(staged["route"]["final"], "KFC_JP")
                    choices = {item["conflictId"]: "incoming"
                               for item in preview["conflicts"]}
                    self.manager.prepare_apply(preview["importId"], {
                        "confirm": True, "mode": mode, "conflicts": choices})
                    self.manager.apply(preview["importId"])
                    final = cio.normalize_model(self.manager.bot.current)
                    direct = [item for item in final["outbounds"]
                              if item.get("type") == "direct"]
                    group = final["_pdg"]["policy-groups"][0]
                    self.assertEqual([item["tag"] for item in direct], ["KFC_JP"])
                    self.assertEqual(final["route"]["final"], "KFC_JP")
                    self.assertEqual(final["route"]["rules"][0]["outbound"], "KFC_JP")
                    self.assertEqual(group["proxies"], ["KFC_JP", "p"])
                    rendered, _warnings = sb2mihomo.singbox_to_mihomo(final)
                    self.assertIn("G", {item["name"] for item in rendered["proxy-groups"]})

    def test_web_previews_and_applies_historical_pdg_bundle_over_32_mib(self):
        entries = {
            "etc/sing-box/config.json": cio._model_bytes(model()),
            "opt/pdg-bot/rulesets.json": b"{}\n",
        }
        entries.update({
            f"etc/sing-box/rs/legacy-{index}.json": b"x" * (7 * 1024 * 1024)
            for index in range(5)
        })
        payload = tar_bytes(entries)
        preview = self.manager.preview("pdg", payload, "application/gzip")
        self.assertTrue(preview["summary"]["bundleRulesets"])
        choices = {item["conflictId"]: "incoming" for item in preview["conflicts"]}
        self.manager.prepare_apply(preview["importId"], {
            "confirm": True, "mode": "replace", "conflicts": choices})
        self.manager.apply(preview["importId"])
        restored = cio._archive_files(
            self.manager.bot.calls[-1][0][0], total_limit=cio.MAX_LEGACY_PDG_TOTAL)
        self.assertNotIn("manifest.json", restored)
        self.assertGreater(sum(len(data) for data in restored.values()),
                           cio.MAX_ARCHIVE_TOTAL)

    def test_preview_rejects_direct_rebind_collision_and_multiple_directs(self):
        collision = model(
            {"type": "vless", "tag": "JP", "server": "proxy.example",
             "server_port": 443, "uuid": "u"},
            {"type": "direct", "tag": "jp"})
        with self.assertRaisesRegex(cio.ImportInvalid, "collides"):
            self.manager.preview("pdg", cio._model_bytes(collision))

        duplicate = {
            "outbounds": [{"type": "direct", "tag": "jp"},
                          {"type": "direct", "tag": "other"}],
            "route": {"rules": [], "final": "jp"},
        }
        with self.assertRaisesRegex(cio.ImportInvalid, "exactly one"):
            self.manager.preview("pdg", json.dumps(duplicate).encode())

    def test_cross_type_name_conflicts_atomically_choose_proxy_or_group(self):
        def proxy_model():
            return model(
                {"type": "vless", "tag": "X", "server": "proxy.example",
                 "server_port": 443, "uuid": "u"},
                {"type": "direct", "tag": "JP"})

        def editable_group_model():
            candidate = model({"type": "direct", "tag": "JP"})
            candidate["_pdg"]["policy-groups"] = [{
                "name": "X", "type": "select", "proxies": ["JP"],
                "use": [], "hidden": True,
            }]
            return cio.normalize_model(candidate)

        def metadata_group_model():
            candidate = model({"type": "direct", "tag": "JP"})
            provider_name = "remote"
            digest = hashlib.sha256(
                ("proxy-provider:" + provider_name).encode()).hexdigest()
            candidate["_pdg"]["mihomo"]["proxy-providers"] = {
                provider_name: {
                    "type": "http", "url": "https://provider.example/sub.yaml",
                    "path": "/etc/mihomo/providers/" + digest + ".yaml",
                }}
            candidate["_pdg"]["policy-groups"] = [{
                "name": "X", "type": "select", "proxies": [],
                "use": [provider_name], "hidden": True,
            }]
            return cio.normalize_model(candidate)

        def shape(candidate):
            outbound = next((item for item in candidate["outbounds"]
                             if item.get("tag") == "X"), None)
            group = next((item for item in candidate["_pdg"]["policy-groups"]
                          if item.get("name") == "X"), None)
            if outbound and outbound.get("type") == "vless" and group is None:
                return "proxy"
            if outbound is None and group and not group.get("use"):
                return "editable"
            if outbound is None and group and group.get("use") == ["remote"]:
                return "metadata"
            return "invalid"

        cases = [
            ("proxy-to-editable", proxy_model(), editable_group_model()),
            ("editable-to-proxy", editable_group_model(), proxy_model()),
            ("proxy-to-metadata", proxy_model(), metadata_group_model()),
            ("metadata-to-proxy", metadata_group_model(), proxy_model()),
        ]
        for label, current, incoming in cases:
            for mode, choice, expected in (
                    ("merge", "existing", shape(current)),
                    ("merge", "incoming", shape(incoming)),
                    ("replace", "incoming", shape(incoming))):
                with self.subTest(case=label, mode=mode, choice=choice):
                    self.manager.bot.current = copy.deepcopy(current)
                    Path(cio.MODEL_PATH).write_bytes(cio._model_bytes(current))
                    preview = self.manager.preview("pdg", cio._model_bytes(incoming))
                    name_conflicts = [item for item in preview["conflicts"]
                                      if item["kind"] == "name" and item["name"] == "X"]
                    self.assertEqual(len(name_conflicts), 1)
                    choices = {item["conflictId"]: (
                        choice if item in name_conflicts else "incoming")
                               for item in preview["conflicts"]}
                    self.manager.prepare_apply(preview["importId"], {
                        "confirm": True, "mode": mode, "conflicts": choices})
                    self.manager.apply(preview["importId"])
                    final = cio.normalize_model(self.manager.bot.current)
                    self.assertEqual(shape(final), expected)
                    rendered, _warnings = sb2mihomo.singbox_to_mihomo(final)
                    if expected == "proxy":
                        self.assertIn("X", {item["name"] for item in rendered["proxies"]})
                        self.assertNotIn("X", {item["name"] for item in rendered["proxy-groups"]})
                    else:
                        self.assertIn("X", {item["name"] for item in rendered["proxy-groups"]})
                    if pdgtx is not None:
                        ok, error = pdgtx._v_json_model(
                            "config.json", cio._model_bytes(final), None)
                        self.assertTrue(ok, error)

    def test_short_stream_is_deleted(self):
        before = set(os.listdir(self.tmp.name))
        with self.assertRaisesRegex(cio.ImportInvalid, "incomplete"):
            self.manager.preview_stream("pdg", io.BytesIO(b"{}"), 10)
        self.assertEqual(set(os.listdir(self.tmp.name)), before)

    def test_preview_slot_is_claimed_before_any_staging_write(self):
        self.assertTrue(self.manager._preview_slots.acquire(blocking=False))
        self.assertFalse(self.manager._preview_slots.acquire(blocking=False))
        before = set(os.listdir(self.tmp.name))
        try:
            with self.assertRaisesRegex(cio.ConfigIOError, "too many"):
                self.manager.preview_stream("pdg", io.BytesIO(b"{}"), 2)
            self.assertEqual(set(os.listdir(self.tmp.name)), before)
        finally:
            self.manager._preview_slots.release()

    def test_replace_conflicts_are_incoming_and_cancel_cleans_staging(self):
        current = model(
            {"type": "vless", "tag": "same", "server": "old", "server_port": 443,
             "uuid": "old"}, {"type": "direct", "tag": "JP"})
        self.manager.bot.current = current
        preview = self.manager.preview("pdg", json.dumps(current).encode())
        existing = {item["conflictId"]: "existing" for item in preview["conflicts"]}
        with self.assertRaisesRegex(cio.ImportInvalid, "replace mode"):
            self.manager.prepare_apply(preview["importId"], {
                "confirm": True, "mode": "replace", "conflicts": existing})
        self.manager.cancel(preview["importId"])
        self.assertFalse(any(name.startswith(preview["importId"])
                             for name in os.listdir(self.tmp.name)))

    def test_cancel_rejects_claimed_preview(self):
        preview = self.manager.preview("pdg", json.dumps(model()).encode())
        self.manager.prepare_apply(preview["importId"], {
            "confirm": True, "mode": "merge", "conflicts": {}})
        with self.assertRaises(cio.ImportConflict):
            self.manager.cancel(preview["importId"])

    def test_cancel_and_apply_claim_are_one_atomic_state_transition(self):
        preview = self.manager.preview("pdg", json.dumps(model()).encode())
        import_id = preview["importId"]
        barrier = threading.Barrier(3)
        outcomes = []

        def claim():
            barrier.wait()
            try:
                self.manager.prepare_apply(import_id, {
                    "confirm": True, "mode": "merge", "conflicts": {}})
                outcomes.append("claimed")
            except cio.ConfigIOError:
                outcomes.append("claim-rejected")

        def cancel():
            barrier.wait()
            try:
                self.manager.cancel(import_id)
                outcomes.append("cancelled")
            except cio.ConfigIOError:
                outcomes.append("cancel-rejected")

        threads = [threading.Thread(target=claim), threading.Thread(target=cancel)]
        for thread in threads:
            thread.start()
        barrier.wait()
        for thread in threads:
            thread.join(timeout=5)
            self.assertFalse(thread.is_alive())
        self.assertIn(sorted(outcomes), [
            ["cancel-rejected", "claimed"],
            ["cancelled", "claim-rejected"],
        ])
        metadata = Path(self.tmp.name, import_id + ".json")
        claim_path = Path(self.tmp.name, import_id + ".claim")
        if "claimed" in outcomes:
            self.assertTrue(metadata.exists())
            self.assertTrue(claim_path.exists())
            record = json.loads(metadata.read_text(encoding="utf-8"))
            self.assertTrue(record["apply"]["claimed"])
            self.manager.discard(import_id)
        else:
            self.assertFalse(metadata.exists())
            self.assertFalse(claim_path.exists())

    def test_conflict_ids_are_unique_and_claim_requires_exact_choices(self):
        current = model(
            {"type": "vless", "tag": "same", "server": "old", "server_port": 443,
             "uuid": "old"}, {"type": "direct", "tag": "JP"})
        self.manager.bot.current = current
        incoming = model(
            {"type": "vless", "tag": "same", "server": "new", "server_port": 443,
             "uuid": "new"}, {"type": "direct", "tag": "JP"})
        preview = self.manager.preview("pdg", json.dumps(incoming).encode())
        ids = {item["conflictId"] for item in preview["conflicts"]}
        self.assertEqual(len(ids), len(preview["conflicts"]))
        with self.assertRaisesRegex(cio.ImportInvalid, "choices"):
            self.manager.prepare_apply(preview["importId"], {
                "confirm": True, "mode": "merge", "conflicts": {}})
        self.assertFalse(Path(self.tmp.name, preview["importId"] + ".claim").exists())
        choices = {item["conflictId"]: item["default"] for item in preview["conflicts"]}
        self.manager.prepare_apply(preview["importId"], {
            "confirm": True, "mode": "merge", "conflicts": choices})
        with self.assertRaises(cio.ImportConflict):
            self.manager.prepare_apply(preview["importId"], {
                "confirm": True, "mode": "merge", "conflicts": choices})
        self.manager.release_claim(preview["importId"])
        self.assertFalse(Path(self.tmp.name, preview["importId"] + ".claim").exists())

    def test_conflict_limit_accepts_200_and_rejects_201_without_staging(self):
        def conflicting_model(count):
            outbounds = [
                {"type": "vless", "tag": f"p{index}",
                 "server": "proxy.example", "server_port": 443,
                 "uuid": f"00000000-0000-0000-0000-{index:012d}"}
                for index in range(count)
            ]
            outbounds.append({"type": "direct", "tag": "JP"})
            return model(*outbounds)

        current = conflicting_model(cio.MAX_CONFLICTS)
        self.manager.bot.current = current
        raw = json.dumps(current).encode()
        preview = self.manager.preview_stream(
            "pdg", io.BytesIO(raw), len(raw), "application/json")
        self.assertEqual(len(preview["conflicts"]), cio.MAX_CONFLICTS)
        self.assertLess(len(json.dumps(preview).encode()), 1024 * 1024)
        self.manager.cancel(preview["importId"])

        oversized = conflicting_model(cio.MAX_CONFLICTS + 1)
        self.manager.bot.current = oversized
        raw = json.dumps(oversized).encode()
        before = set(os.listdir(self.tmp.name))
        with self.assertRaisesRegex(cio.ImportInvalid, "too many conflicts"):
            self.manager.preview_stream(
                "pdg", io.BytesIO(raw), len(raw), "application/json")
        self.assertEqual(set(os.listdir(self.tmp.name)), before)

    def test_tampered_and_expired_staging_is_rejected_and_removed(self):
        preview = self.manager.preview("pdg", json.dumps(model()).encode())
        upload = Path(self.tmp.name, preview["importId"] + ".upload")
        upload.write_bytes(b"tampered")
        with self.assertRaisesRegex(cio.ImportConflict, "integrity"):
            self.manager.prepare_apply(preview["importId"], {
                "confirm": True, "mode": "merge", "conflicts": {}})
        self.manager.discard(preview["importId"])

        preview = self.manager.preview("pdg", json.dumps(model()).encode())
        metadata = Path(self.tmp.name, preview["importId"] + ".json")
        record = json.loads(metadata.read_text(encoding="utf-8"))
        record["created"] = 1
        metadata.write_text(json.dumps(record), encoding="utf-8")
        with self.assertRaises(cio.ImportExpired):
            self.manager.prepare_apply(preview["importId"], {
                "confirm": True, "mode": "merge", "conflicts": {}})
        self.assertFalse(metadata.exists())

    def test_staging_gc_reads_metadata_through_the_bounded_regular_file_gate(self):
        import_id = "imp-" + "d" * 32
        metadata = Path(self.tmp.name, import_id + ".json")
        metadata.write_text("not-json", encoding="utf-8")
        os.utime(metadata, (1, 1))
        calls = []
        original = self.manager._read_regular

        def bounded(path, maximum):
            calls.append((path, maximum))
            return original(path, maximum)

        self.manager._read_regular = bounded
        self.manager._gc()
        self.assertIn((str(metadata), cio.MAX_RECORD_BYTES), calls)
        self.assertFalse(metadata.exists())

    def test_background_janitor_expires_idle_but_preserves_claimed_preview(self):
        clock = [time.time()]
        manager = cio.ConfigIO(
            bot=self.manager.bot, staging_dir=self.tmp.name,
            enforce_root_owner=False, janitor_interval=0.01,
            clock=lambda: clock[0])
        try:
            idle = manager.preview("pdg", json.dumps(model()).encode())
            claimed = manager.preview("pdg", json.dumps(model()).encode())
            manager.prepare_apply(claimed["importId"], {
                "confirm": True, "mode": "merge", "conflicts": {}})
            clock[0] += cio.PREVIEW_TTL + 1
            deadline = time.time() + 1
            idle_json = Path(self.tmp.name, idle["importId"] + ".json")
            idle_upload = Path(self.tmp.name, idle["importId"] + ".upload")
            while time.time() < deadline and (idle_json.exists() or idle_upload.exists()):
                time.sleep(0.01)
            self.assertFalse(idle_json.exists())
            self.assertFalse(idle_upload.exists())
            self.assertTrue(Path(self.tmp.name, claimed["importId"] + ".json").exists())
            self.assertTrue(Path(self.tmp.name, claimed["importId"] + ".upload").exists())
        finally:
            thread = manager._janitor_thread
            manager.close()
            self.assertIsNotNone(thread)
            self.assertFalse(thread.is_alive())
            manager.discard(claimed["importId"] if "claimed" in locals() else "imp-" + "0" * 32)

    def test_gc_reclaims_stale_orphan_claim_but_preserves_fresh_claim(self):
        previews = [self.manager.preview("pdg", json.dumps(model()).encode())
                    for _ in range(2)]
        for preview in previews:
            self.manager.prepare_apply(preview["importId"], {
                "confirm": True, "mode": "merge", "conflicts": {}})

        stale, fresh = previews
        old = time.time() - cio.CLAIM_PROTECTION_TTL - 10
        stale_json = Path(self.tmp.name, stale["importId"] + ".json")
        stale_record = json.loads(stale_json.read_text(encoding="utf-8"))
        stale_record["apply"]["claimedAt"] = old
        stale_json.write_text(json.dumps(stale_record), encoding="utf-8")
        for suffix in (".json", ".upload", ".claim"):
            os.utime(Path(self.tmp.name, stale["importId"] + suffix), (old, old))

        # Make the fresh record old enough for preview GC while retaining a
        # recent claim/claimedAt; an accepted queued or running job stays safe.
        preview_old = time.time() - cio.PREVIEW_TTL - 10
        for suffix in (".json", ".upload"):
            os.utime(Path(self.tmp.name, fresh["importId"] + suffix),
                     (preview_old, preview_old))

        self.manager._gc()
        self.assertFalse(any(name.startswith(stale["importId"])
                             for name in os.listdir(self.tmp.name)))
        self.assertTrue(Path(self.tmp.name, fresh["importId"] + ".json").exists())
        self.assertTrue(Path(self.tmp.name, fresh["importId"] + ".upload").exists())
        self.assertTrue(Path(self.tmp.name, fresh["importId"] + ".claim").exists())
        self.manager.discard(fresh["importId"])

    @unittest.skipIf(os.name == "nt", "POSIX symlink and mode contract")
    def test_metadata_symlink_and_permissive_mode_are_rejected(self):
        preview = self.manager.preview("pdg", json.dumps(model()).encode())
        metadata = Path(self.tmp.name, preview["importId"] + ".json")
        target = Path(self.tmp.name, "outside")
        target.write_bytes(metadata.read_bytes())
        metadata.unlink()
        metadata.symlink_to(target)
        with self.assertRaises(cio.ImportNotFound):
            self.manager.prepare_apply(preview["importId"], {
                "confirm": True, "mode": "merge", "conflicts": {}})
        metadata.unlink()
        metadata.write_bytes(target.read_bytes())
        os.chmod(metadata, 0o666)
        with self.assertRaises(cio.ImportNotFound):
            self.manager.prepare_apply(preview["importId"], {
                "confirm": True, "mode": "merge", "conflicts": {}})

    def test_model_cas_drift_blocks_apply(self):
        incoming = model(
            {"type": "vless", "tag": "p", "server": "new", "server_port": 443,
             "uuid": "u"}, {"type": "direct", "tag": "JP"})
        preview = self.manager.preview("pdg", json.dumps(incoming).encode())
        choices = {item["conflictId"]: item["default"] for item in preview["conflicts"]}
        self.manager.prepare_apply(preview["importId"], {
            "confirm": True, "mode": "merge", "conflicts": choices})
        self.manager.bot.current["route"]["rules"].append({"domain": ["drift.example"],
                                                            "outbound": "JP"})
        with self.assertRaisesRegex(cio.ImportConflict, "changed after preview"):
            self.manager.apply(preview["importId"])

    def test_mosdns_and_provider_cas_drift_block_apply(self):
        current_text = (ROOT / "deploy" / "mosdns" / "config.yaml").read_text(encoding="utf-8")
        replacements = {
            "__SERVER_IP__": "203.0.113.10", "__INTERNAL_CIDR__": "192.0.2.0/24",
            "__CERT_DIR__": "/etc/mosdns/certs",
            "__HIJACK_SET_FILE__": "ruleset_hijack.txt", "__MOSDNS_CACHE__": "1024",
        }
        for old, new in replacements.items():
            current_text = current_text.replace(old, new)
        current_text = current_text.replace(
            "/etc/mosdns/rules/", Path(cio.MOSDNS_RULE_DIR).as_posix() + "/")
        Path(cio.MOSDNS_PATH).write_text(current_text, encoding="utf-8")
        preview = self.manager.preview("mosdns", current_text.encode(), "application/yaml")
        self.manager.prepare_apply(preview["importId"], {
            "confirm": True, "mode": "replace", "conflicts": {}})
        Path(cio.MOSDNS_PATH).write_text(current_text + "\n# drift\n", encoding="utf-8")
        with self.assertRaisesRegex(cio.ImportConflict, "MosDNS configuration changed"):
            self.manager.apply(preview["importId"])
        self.manager.discard(preview["importId"])

        provider = b"proxies:\n  - {name: p}\n"
        leaf = cio._sha(provider) + ".yaml"
        Path(cio.MIHOMO_PROVIDER_DIR, leaf).write_bytes(provider)
        current = model()
        current["_pdg"]["mihomo"]["managed-files"] = {
            leaf: base64.b64encode(provider).decode("ascii")}
        current["_pdg"]["mihomo"]["proxy-providers"] = {
            "local": {"type": "file", "path": "/etc/mihomo/providers/" + leaf}}
        self.manager.bot.current = current
        incoming = tar_bytes({
            "etc/sing-box/config.json": cio._model_bytes(current),
            "etc/mihomo/providers/" + leaf: provider,
        })
        preview = self.manager.preview("pdg", incoming, "application/gzip")
        choices = {item["conflictId"]: item["default"] for item in preview["conflicts"]}
        self.manager.prepare_apply(preview["importId"], {
            "confirm": True, "mode": "merge", "conflicts": choices})
        Path(cio.MIHOMO_PROVIDER_DIR, leaf).write_bytes(provider + b"# drift")
        with self.assertRaisesRegex(cio.ImportConflict, "integrity|changed"):
            self.manager.apply(preview["importId"])


if __name__ == "__main__":
    unittest.main(verbosity=2)

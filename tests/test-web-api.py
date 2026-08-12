#!/usr/bin/env python3
"""Black-box contract and security tests for the native PDG Web API."""
from __future__ import annotations

import base64
import contextlib
import copy
import hashlib
import http.client
import importlib.util
import io
import json
import os
import pathlib
import socket
import stat
import sys
import tempfile
import threading
import time
import types
import unittest
from unittest import mock


ROOT = pathlib.Path(__file__).resolve().parents[1]
WEB_DIR = ROOT / "deploy" / "web"
sys.path.insert(0, str(WEB_DIR))

import pdgcontrol  # noqa: E402
import pdgwebconfig  # noqa: E402


def _load_web_module():
    spec = importlib.util.spec_from_file_location(
        "pdg_web_under_test", WEB_DIR / "pdg-web.py"
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load pdg-web.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


web = _load_web_module()
_UNSET = object()
_AUTO = object()
UUID_SECRET = "123e4567-e89b-12d3-a456-426614174000"
PLAIN_SECRET = "TOPSECRET-CREDENTIAL"


def _b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


class FakeResult:
    def __init__(self, returncode=0, stdout="", stderr=""):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


class FakeBot:
    """In-memory implementation of the existing Bot wrapper surface."""

    BUSY_MSG = "busy"
    NOLOCK_MSG = "no-lock"
    PROXY_TYPES = (
        "shadowsocks",
        "vmess",
        "trojan",
        "vless",
        "hysteria2",
        "tuic",
    )
    UPDATE_SCRIPT = "/opt/pdg-bot/update-rules.sh"
    MOSDNS_DIRECT = "/fake/custom_direct.txt"
    MOSDNS_HIJACK = "/fake/custom_hijack.txt"

    def __init__(self):
        self.model = {
            "outbounds": [
                {"type": "direct", "tag": "jp"},
                {
                    "type": "shadowsocks",
                    "tag": "hk",
                    "server": "hk.example",
                    "server_port": 443,
                    "password": PLAIN_SECRET,
                },
                {
                    "type": "shadowsocks",
                    "tag": "tw",
                    "server": "2001:db8::8",
                    "server_port": 8443,
                    "password": PLAIN_SECRET,
                },
                {
                    "type": "urltest",
                    "tag": "auto",
                    "outbounds": ["hk", "tw"],
                },
            ],
            "route": {
                "final": "auto",
                "rule_set": [
                    {
                        "tag": "rs_deadbeef",
                        "type": "local",
                        "format": "source",
                        "path": "/etc/sing-box/rs/rs_deadbeef.json",
                    }
                ],
                "rules": [
                    {"action": "reject", "protocol": "quic"},
                    {"domain": ["exact.example"], "outbound": "hk"},
                    {"domain_suffix": ["example.com"], "outbound": "hk"},
                    {"rule_set": "rs_deadbeef", "outbound": "tw"},
                ],
            },
        }
        self.direct = ["direct.example"]
        self.hijack = ["exact.example", "example.com"]
        self.upstream_values = {
            "remote": [
                "https://user:password@dns.example/dns-query"
                "?token=hidden#fragment",
                "https://dns.example/really-secret-token-path",
            ],
            "local": ["udp://223.5.5.5"],
        }
        self.meta = {
            "rs_deadbeef": {
                "url": (
                    "https://user:password@rules.example/path/list.txt"
                    "?token=hidden#fragment"
                ),
                "outbound": "tw",
                "format": "source",
                "path": "/etc/sing-box/rs/rs_deadbeef.json",
                "count": 12,
                "behavior": "domain",
                "label": "Initial rules",
            }
        }
        self.profile = {
            "PDG_HIJACK_MODE": "gfw",
            "PDG_QUIC_MODE": "tproxy",
            "PDG_FIREWALL_MODE": "external",
        }
        self.tfo = False
        self.transactions = []
        self.wrapper_calls = []
        self.sh_calls = []
        self.refresh_result = (2, [])
        self.update_check_result = (True, "release available")
        self.update_check_error = None
        self.invalid_link_error = RuntimeError(
            f"bad ss://{PLAIN_SECRET}@secret.example"
        )
        self.before_file_expect_check = None
        self.before_model_expect_check = None
        self.runtime_selections = []
        self.runtime_now = {}
        self.runtime_all = {}
        self.pdgmodel = types.SimpleNamespace(
            rename_references=self._rename_model_references,
            validate_direct_tag_setting=lambda value: (
                (_ for _ in ()).throw(ValueError("reserved"))
                if value.casefold() in {"direct", "jp"} else value))

    def load(self):
        return copy.deepcopy(self.model)

    def _model_snapshot(self):
        raw = json.dumps(
            self.model, ensure_ascii=False, indent=2
        ).encode("utf-8")
        return copy.deepcopy(self.model), hashlib.sha256(raw).hexdigest()

    def _rs_meta(self):
        return copy.deepcopy(self.meta)

    def _rs_meta_snapshot(self):
        raw = json.dumps(
            self.meta, ensure_ascii=False, indent=2
        ).encode("utf-8")
        return copy.deepcopy(self.meta), hashlib.sha256(raw).hexdigest()

    def exit_tags(self, model):
        allowed = self.PROXY_TYPES + ("direct", "urltest")
        tags = [
            item["tag"]
            for item in model.get("outbounds", [])
            if item.get("type") in allowed
        ]
        tags.extend(item.get("name") for item in (
            (model.get("_pdg") or {}).get("policy-groups") or [])
                    if isinstance(item, dict) and isinstance(item.get("name"), str))
        return tags

    @staticmethod
    def _rename_model_references(model, old, new, *, rename_group=False):
        groups = (model.get("_pdg") or {}).get("policy-groups") or []
        for group in groups:
            if rename_group and group.get("name") == old:
                group["name"] = new
            group["proxies"] = [new if value == old else value
                                for value in group.get("proxies", [])]
        route = model.get("route") or {}
        if route.get("final") == old:
            route["final"] = new
        for rule in route.get("rules") or []:
            if rule.get("outbound") == old:
                rule["outbound"] = new

    @staticmethod
    def _mihomo_group_delete(model, removed):
        removed = set(removed)
        groups = (model.get("_pdg") or {}).get("policy-groups") or []
        while True:
            groups[:] = [item for item in groups if item.get("name") not in removed]
            empty = set()
            for group in groups:
                group["proxies"] = [value for value in group.get("proxies", [])
                                    if value not in removed]
                if not group["proxies"] and not group.get("use"):
                    empty.add(group.get("name"))
            if not empty - removed:
                return
            removed |= empty

    def clash_get(self, path):
        name = path.rsplit("/", 1)[-1]
        return {"now": self.runtime_now.get(name),
                "all": copy.deepcopy(self.runtime_all.get(name, []))}

    def clash_select(self, group, member):
        self.runtime_selections.append((group, member))
        self.runtime_now[group] = member

    def set_direct_tag(self, new):
        current = next((item.get("tag") for item in self.model.get("outbounds", [])
                        if item.get("type") == "direct"), None)
        if current is None:
            return False, "direct missing"
        def modify(model):
            for item in model["outbounds"]:
                if item.get("type") == "direct":
                    item["tag"] = new
            self._rename_model_references(model, current, new)
        return self.tx_apply("direct_tag_set", model_mod=modify)

    def concrete_tags(self, model):
        allowed = self.PROXY_TYPES + ("direct",)
        return [
            item["tag"]
            for item in model.get("outbounds", [])
            if item.get("type") in allowed
        ]

    @staticmethod
    def _domains_from_text(data):
        return [
            line.split(":", 1)[1].strip()
            for line in data.decode("utf-8").splitlines()
            if line.startswith("domain:")
        ]

    def tx_apply(self, op, model_mod=None, files=None, services=(), **kwargs):
        candidate = copy.deepcopy(self.model)
        file_expects = kwargs.get("file_expects")
        if file_expects is None:
            file_expects = {}
        record = {
            "op": op,
            "has_model_mod": model_mod is not None,
            "services": tuple(services or ()),
            "file_keys": [],
            "file_expects": {},
            "model_expect": kwargs.get("model_expect"),
        }
        try:
            if "model_expect" in kwargs:
                hook = self.before_model_expect_check
                if callable(hook):
                    self.before_model_expect_check = None
                    hook(self)
                _model, current_revision = self._model_snapshot()
                if kwargs["model_expect"] != current_revision:
                    self.transactions.append(record)
                    return False, "PRECONDITION_FAILED: model changed"
            if model_mod is not None:
                model_mod(candidate)
            record["file_keys"] = sorted((files or {}).keys())
            record["file_expects"] = copy.deepcopy(file_expects)
            hook = self.before_file_expect_check
            if callable(hook):
                self.before_file_expect_check = None
                hook(self)
            current_files = {
                "mosdns_rule:custom_direct.txt": self._direct_text(self.direct),
                "mosdns_rule:custom_hijack.txt": self._hijack_text(self.hijack),
                "rs_meta": json.dumps(
                    self.meta, ensure_ascii=False, indent=2
                ).encode("utf-8"),
            }
            for name, expected in file_expects.items():
                current = current_files.get(name)
                actual = (
                    hashlib.sha256(current).hexdigest()
                    if current is not None else None
                )
                if actual != expected:
                    self.transactions.append(record)
                    return False, "transaction conflict"
            next_meta = copy.deepcopy(self.meta)
            next_direct = list(self.direct)
            next_hijack = list(self.hijack)
            for name, data in (files or {}).items():
                if name == "rs_meta" and data is not None:
                    next_meta = json.loads(data.decode("utf-8"))
                elif name == "mosdns_rule:custom_direct.txt" and data is not None:
                    next_direct = self._domains_from_text(data)
                elif name == "mosdns_rule:custom_hijack.txt" and data is not None:
                    next_hijack = self._domains_from_text(data)
        except Exception:
            self.transactions.append(record)
            return False, "transaction failed"
        self.model = candidate
        self.meta = next_meta
        self.direct = next_direct
        self.hijack = next_hijack
        self.transactions.append(record)
        return True, "transaction committed"

    def parse_link(self, link):
        self.wrapper_calls.append(("parse_link",))
        if "invalid" in link:
            raise self.invalid_link_error
        return {
            "type": "shadowsocks",
            "tag": "newnode",
            "server": "new.example",
            "server_port": 10443,
            "password": PLAIN_SECRET,
        }

    def rename_exit(self, old, new):
        self.wrapper_calls.append(("rename_exit", old, new))
        if new in self.exit_tags(self.model):
            return False, "name conflict"
        found = False
        for item in self.model["outbounds"]:
            if item.get("tag") == old:
                item["tag"] = new
                found = True
            if item.get("type") == "urltest":
                item["outbounds"] = [
                    new if value == old else value
                    for value in item.get("outbounds", [])
                ]
        if not found:
            return False, "not found"
        route = self.model["route"]
        if route.get("final") == old:
            route["final"] = new
        for rule in route.get("rules", []):
            if rule.get("outbound") == old:
                rule["outbound"] = new
        for item in self.meta.values():
            if item.get("outbound") == old:
                item["outbound"] = new
        return True, "renamed"

    def reorder_exits(self, order):
        self.wrapper_calls.append(("reorder_exits", tuple(order)))
        by_tag = {item.get("tag"): item for item in self.model["outbounds"]}
        if set(order) != set(by_tag):
            return False, "invalid order"
        self.model["outbounds"] = [by_tag[tag] for tag in order]
        return True, "reordered"

    def add_group(self, tag, members, model_expect=None):
        self.wrapper_calls.append(("add_group", tag, tuple(members)))
        hook = self.before_model_expect_check
        if callable(hook):
            self.before_model_expect_check = None
            hook(self)
        if model_expect is not None and model_expect != self._model_snapshot()[1]:
            return False, "PRECONDITION_FAILED: model changed"
        allowed = set(self.concrete_tags(self.model))
        if not set(members).issubset(allowed):
            return False, "unknown member"
        for item in self.model["outbounds"]:
            if item.get("tag") == tag:
                if item.get("type") not in {"urltest", "selector"}:
                    return False, "tag conflict"
                item["outbounds"] = list(members)
                return True, "updated"
        self.model["outbounds"].append(
            {"type": "urltest", "tag": tag, "outbounds": list(members)}
        )
        return True, "created"

    def _read_direct(self):
        return list(self.direct)

    def _domain_file_snapshot(self, path):
        if path == self.MOSDNS_DIRECT:
            domains = list(self.direct)
            raw = self._direct_text(domains)
        elif path == self.MOSDNS_HIJACK:
            domains = list(self.hijack)
            raw = self._hijack_text(domains)
        else:
            raise FileNotFoundError(path)
        return domains, hashlib.sha256(raw).hexdigest()

    @staticmethod
    def _direct_text(domains):
        return (
            "# test direct\n"
            + "".join(f"domain:{item}\n" for item in sorted(set(domains)))
        ).encode("utf-8")

    def _read_hijack(self):
        return list(self.hijack)

    @staticmethod
    def _hijack_text(domains):
        return (
            "# test hijack\n"
            + "".join(f"domain:{item}\n" for item in sorted(set(domains)))
        ).encode("utf-8")

    def add_rule(self, domain, target):
        self.wrapper_calls.append(("add_rule", domain, target))
        if target == "direct":
            if domain not in self.direct:
                self.direct.append(domain)
            self.hijack = [item for item in self.hijack if item != domain]
            return True, "added"
        if target not in self.exit_tags(self.model):
            return False, "unknown exit"
        self.model["route"]["rules"].append(
            {"domain_suffix": [domain], "outbound": target}
        )
        if domain not in self.hijack:
            self.hijack.append(domain)
        return True, "added"

    def del_rule(self, domain):
        self.wrapper_calls.append(("del_rule", domain))
        found = domain in self.direct
        self.direct = [item for item in self.direct if item != domain]
        self.hijack = [item for item in self.hijack if item != domain]
        for rule in self.model["route"]["rules"]:
            for key in ("domain", "domain_suffix"):
                if domain in (rule.get(key) or []):
                    rule[key] = [item for item in rule[key] if item != domain]
                    found = True
        self.model["route"]["rules"] = [
            rule
            for rule in self.model["route"]["rules"]
            if rule.get("action")
            or rule.get("rule_set")
            or rule.get("domain")
            or rule.get("domain_suffix")
        ]
        return (True, "deleted") if found else (False, "not found")

    def add_ruleset(self, url, target, label="", behavior=""):
        self.wrapper_calls.append(("add_ruleset", target))
        # Literal "direct" is the mobile/MosDNS pseudo target.  The production
        # core must handle it atomically rather than treating it as a VPS tag.
        if target != "direct" and target not in self.exit_tags(self.model):
            return False, "unknown exit"
        name = "rs_" + hashlib.sha1(url.encode()).hexdigest()[:8]
        info = {
            "url": url,
            "outbound": target,
            "format": "source",
            "path": f"/etc/sing-box/rs/{name}.json",
            "count": 4,
        }
        if label:
            info["label"] = label
        if behavior:
            info["behavior"] = behavior
        self.meta[name] = info
        self.model["route"].setdefault("rule_set", []).append(
            {
                "tag": name,
                "type": "local",
                "format": "source",
                "path": info["path"],
            }
        )
        self.model["route"]["rules"].append(
            {"rule_set": name, "outbound": target}
        )
        return True, "added"

    def set_ruleset_label(self, name, label):
        self.wrapper_calls.append(("set_ruleset_label", name))
        if name not in self.meta:
            return False, "not found"
        if label:
            self.meta[name]["label"] = label
        else:
            self.meta[name].pop("label", None)
        return True, "label set"

    def set_ruleset_target(self, name, target):
        self.wrapper_calls.append(("set_ruleset_target", name, target))
        if name not in self.meta:
            return False, "not found"
        self.meta[name]["outbound"] = target
        for rule in self.model["route"]["rules"]:
            if rule.get("rule_set") == name:
                rule["outbound"] = target
        return True, "target set"

    def probe_exit_delays(self, **_kwargs):
        return {
            "method": "clash",
            "items": [
                {
                    "tag": "jp",
                    "status": "ok",
                    "delay_ms": 8,
                    "server": f"vless://{UUID_SECRET}@secret.example",
                },
                {"tag": "hk", "status": "timeout"},
            ],
        }

    @staticmethod
    def probe_domain_route(domain):
        return {
            "domain": domain,
            "path": "gateway",
            "target": "hk",
            "reason": "explicit_domain",
            "dns_verified": True,
            "route_confidence": "simulated",
            "verified": False,
            "confidence": "simulated",
            "resolved_ip": PLAIN_SECRET,
        }

    def del_ruleset(self, name):
        self.wrapper_calls.append(("del_ruleset", name))
        if name not in self.meta:
            return False, "not found"
        self.meta.pop(name)
        route = self.model["route"]
        route["rule_set"] = [
            item for item in route.get("rule_set", []) if item.get("tag") != name
        ]
        route["rules"] = [
            item for item in route["rules"] if item.get("rule_set") != name
        ]
        return True, "deleted"

    def refresh_rulesets(self):
        self.wrapper_calls.append(("refresh_rulesets",))
        return self.refresh_result

    def _upstreams(self, which):
        return list(self.upstream_values[which])

    def set_mosdns_upstream(self, which, addresses):
        self.wrapper_calls.append(("set_mosdns_upstream", which))
        self.upstream_values[which] = list(addresses)
        return True, "updated"

    def _tfo_on(self, _model):
        return self.tfo

    def set_tfo(self, enabled):
        self.wrapper_calls.append(("set_tfo", enabled))
        self.tfo = enabled
        return True, "updated"

    def _profile_get(self, key, default=""):
        return self.profile.get(key, default)

    @staticmethod
    def _platform():
        return "ios"

    @staticmethod
    def _dot_host():
        return "dot.example"

    @staticmethod
    def _server_ip():
        return "192.0.2.20"

    @staticmethod
    def _git(*_args):
        return FakeResult(stdout="v-test-1")

    @staticmethod
    def doctor_text():
        return (
            f"warn password={PLAIN_SECRET} "
            f"vless://{UUID_SECRET}@secret.example"
        )

    def sh(self, argv):
        self.sh_calls.append(list(argv))
        if argv[:2] == ["systemctl", "is-active"]:
            return FakeResult(stdout="active\n")
        if argv and argv[0] == "journalctl":
            return FakeResult(
                stdout=(
                    f"password={PLAIN_SECRET}\n"
                    f"vless://{UUID_SECRET}@secret.example\n"
                )
            )
        return FakeResult(returncode=0, stdout="ok\n")

    def clash_get(self, path):
        if path.startswith("/proxies/"):
            name = path.rsplit("/", 1)[-1]
            return {"now": self.runtime_now.get(name),
                    "all": copy.deepcopy(self.runtime_all.get(name, []))}
        if path == "/connections":
            return {
                "uploadTotal": 30,
                "downloadTotal": 70,
                "connections": [
                    {
                        "chains": ["hk"],
                        "upload": 10,
                        "download": 20,
                        "metadata": {
                            "host": "private.destination.example",
                            "password": PLAIN_SECRET,
                        },
                    },
                    {
                        "chains": ["tw"],
                        "upload": 20,
                        "download": 50,
                    },
                ],
            }
        if path == "/version":
            return {"version": "mihomo-test-1"}
        if path == "/memory":
            return {"inuse": 999, "inuse": 123456}
        raise RuntimeError("unknown clash path")

    def update_check(self):
        self.wrapper_calls.append(("update_check",))
        if self.update_check_error is not None:
            raise self.update_check_error
        return self.update_check_result

    def start_update(self):
        self.wrapper_calls.append(("start_update",))
        return True


class FakeJobStore:
    JOB_ID = "20260729t010203z-a1b2c3d4e5f6"
    SNAPSHOT_ID = "20260729-010203-a1b2c3d4"

    def __init__(self):
        self.calls = []
        self.records = []

    @contextlib.contextmanager
    def maintenance_guard(self):
        self.calls.append(("guard",))
        yield

    def list_snapshots(self):
        return [{
            "id": self.SNAPSHOT_ID,
            "createdAt": "2026-07-29T01:02:03Z",
            "size": 1024,
        }]

    def resolve_snapshot_id(self, snapshot_id):
        self.calls.append(("resolve", snapshot_id))
        if snapshot_id != self.SNAPSHOT_ID:
            raise type("JobNotFound", (RuntimeError,), {})()
        return snapshot_id

    def snapshot_id_for_index(self, index):
        self.calls.append(("index", index))
        if index != 0:
            raise type("JobNotFound", (RuntimeError,), {})()
        return self.SNAPSHOT_ID

    def start(self, kind, snapshot_id=None, import_id=None):
        self.calls.append(("start", kind, import_id if import_id is not None else snapshot_id))
        record = {
            "id": self.JOB_ID,
            "kind": kind,
            "status": "queued",
            "createdAt": "2026-07-29T01:02:04Z",
        }
        if snapshot_id is not None:
            record["snapshotId"] = snapshot_id
        if import_id is not None:
            record["importId"] = import_id
        self.records = [record]
        return copy.deepcopy(record)

    def list(self):
        return copy.deepcopy(self.records)

    def get(self, job_id):
        if job_id != self.JOB_ID or not self.records:
            raise type("JobNotFound", (RuntimeError,), {})()
        return copy.deepcopy(self.records[0])


class FakeConfigIO:
    IMPORT_ID = "imp-" + "b" * 32

    def __init__(self):
        self.calls = []

    def export(self, kind):
        self.calls.append(("export", kind))
        return b"managed-config\n", f"{kind}-config.yaml", "application/yaml; charset=utf-8"

    def preview_stream(self, kind, stream, size, content_type):
        payload = stream.read(size)
        self.calls.append(("preview", kind, payload, content_type))
        return {
            "importId": self.IMPORT_ID, "kind": kind, "expiresIn": 1800,
            "summary": {"bytes": len(payload)}, "warnings": [],
            "conflicts": [], "modes": ["merge", "replace"],
        }

    def prepare_apply(self, import_id, body):
        self.calls.append(("prepare", import_id, copy.deepcopy(body)))
        return {"importId": import_id, "kind": "mihomo", "mode": body.get("mode")}

    def release_claim(self, import_id):
        self.calls.append(("release", import_id))

    def cancel(self, import_id):
        self.calls.append(("cancel", import_id))


class LazyServiceInitializationTestCase(unittest.TestCase):
    def test_concurrent_first_config_io_call_publishes_one_manager_and_slot(self):
        workers = 12
        start = threading.Barrier(workers)
        counter_lock = threading.Lock()
        created = []
        closed = []
        preview_entered = threading.Event()
        release_preview = threading.Event()

        class CountingConfigIO:
            def __init__(self, *, bot):
                self.bot = bot
                self.slot = threading.BoundedSemaphore(1)
                with counter_lock:
                    created.append(self)
                # Widen the historical race without relying on the scheduler.
                time.sleep(0.01)

            def close(self):
                with counter_lock:
                    closed.append(self)

            def preview_stream(self, kind, stream, size, content_type):
                if not self.slot.acquire(blocking=False):
                    raise pdgcontrol.BusyError()
                try:
                    preview_entered.set()
                    if not release_preview.wait(timeout=2):
                        raise AssertionError("preview release timed out")
                    payload = stream.read(size)
                    return {"kind": kind, "summary": {"bytes": len(payload)}}
                finally:
                    self.slot.release()

        control = pdgcontrol.PDGControl(
            FakeBot(), job_store=FakeJobStore())
        module = types.SimpleNamespace(ConfigIO=CountingConfigIO)
        managers = []
        errors = []

        def resolve_manager():
            try:
                start.wait(timeout=2)
                managers.append(control._config_io())
            except Exception as exc:  # pragma: no cover - asserted below
                errors.append(exc)

        with mock.patch.object(
                pdgcontrol, "load_config_io_module", return_value=module):
            threads = [threading.Thread(target=resolve_manager)
                       for _ in range(workers)]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join(timeout=2)

            self.assertFalse(errors)
            self.assertEqual(len(managers), workers)
            self.assertEqual(len(created), 1)
            self.assertFalse(closed)
            self.assertTrue(all(item is created[0] for item in managers))

            results = []

            def first_preview():
                try:
                    results.append(control.preview_import_stream(
                        "mihomo", io.BytesIO(b"first"), 5,
                        "application/yaml"))
                except Exception as exc:  # pragma: no cover - asserted below
                    results.append(exc)

            first = threading.Thread(target=first_preview)
            first.start()
            self.assertTrue(preview_entered.wait(timeout=2))
            with self.assertRaises(pdgcontrol.BusyError):
                control.preview_import_stream(
                    "mihomo", io.BytesIO(b"second"), 6,
                    "application/yaml")
            release_preview.set()
            first.join(timeout=2)
            self.assertEqual(results, [
                {"kind": "mihomo", "summary": {"bytes": 5}}
            ])

    def test_concurrent_first_job_store_call_publishes_one_store(self):
        workers = 12
        start = threading.Barrier(workers)
        created = []

        class CountingJobStore:
            def __init__(self):
                created.append(self)
                time.sleep(0.01)

        control = pdgcontrol.PDGControl(FakeBot())
        module = types.SimpleNamespace(JobStore=CountingJobStore)
        stores = []
        errors = []

        def resolve_store():
            try:
                start.wait(timeout=2)
                stores.append(control._job_store())
            except Exception as exc:  # pragma: no cover - asserted below
                errors.append(exc)

        with mock.patch.object(
                pdgcontrol, "load_job_module", return_value=module):
            threads = [threading.Thread(target=resolve_store)
                       for _ in range(workers)]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join(timeout=2)

        self.assertFalse(errors)
        self.assertEqual(len(stores), workers)
        self.assertEqual(len(created), 1)
        self.assertTrue(all(item is created[0] for item in stores))


class WebAPITestCase(unittest.TestCase):
    password = "correct horse battery staple"

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="pdg-web-test.")
        self.temp_path = pathlib.Path(self.temp.name)
        self.static = self.temp_path / "static"
        self.static.mkdir()
        (self.static / "index.html").write_text(
            "<!doctype html><title>PDG test</title>", encoding="utf-8"
        )
        (self.static / "app.js").write_text(
            '"use strict";', encoding="utf-8"
        )
        (self.static / "manifest.webmanifest").write_text(
            '{"name":"PDG"}', encoding="utf-8"
        )
        probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        probe.bind(("127.0.0.1", 0))
        self.port = probe.getsockname()[1]
        probe.close()
        self.host = f"pdg.example:{self.port}"
        self.origin = f"https://{self.host}"
        salt = b"0123456789abcdef"
        password_hash = hashlib.pbkdf2_hmac(
            "sha256", self.password.encode(), salt, 1000, dklen=32
        )
        self.config_raw = {
            "listen": "127.0.0.1",
            "port": self.port,
            "trusted_cidrs": ["127.0.0.1/32", "::1/128"],
            "allowed_hosts": [self.host],
            "allowed_origins": [self.origin],
            "session_hours": 8,
            "tls": {
                "cert": str((self.temp_path / "cert.pem").resolve()),
                "key": str((self.temp_path / "key.pem").resolve()),
            },
            "auth": {
                "algorithm": "pbkdf2_sha256",
                "iterations": 1000,
                "salt": _b64url(salt),
                "password_hash": _b64url(password_hash),
                "session_secret": _b64url(b"S" * 32),
            },
        }
        self.config_path = self.temp_path / "web.json"
        self.config_path.write_text(
            json.dumps(self.config_raw), encoding="utf-8"
        )
        self.config = web.load_config(str(self.config_path), testing=True)
        self.fake = FakeBot()
        self.jobs = FakeJobStore()
        self.config_io = FakeConfigIO()
        self.control = pdgcontrol.PDGControl(
            self.fake, job_store=self.jobs, config_io=self.config_io)
        self._old_http_env = os.environ.get("PDG_WEB_TEST_ALLOW_HTTP")
        os.environ["PDG_WEB_TEST_ALLOW_HTTP"] = "1"
        self.server = web.make_server(
            self.config,
            control=self.control,
            static_root=str(self.static),
            allow_http=True,
        )
        self.thread = threading.Thread(
            target=self.server.serve_forever,
            kwargs={"poll_interval": 0.01},
            daemon=True,
        )
        self.thread.start()
        self.cookie = None
        self.csrf = None

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)
        if self._old_http_env is None:
            os.environ.pop("PDG_WEB_TEST_ALLOW_HTTP", None)
        else:
            os.environ["PDG_WEB_TEST_ALLOW_HTTP"] = self._old_http_env
        self.temp.cleanup()

    def request(
        self,
        method,
        path,
        body=_UNSET,
        *,
        host=_AUTO,
        origin=_AUTO,
        csrf=_AUTO,
        cookie=_AUTO,
        content_type=_AUTO,
        content_length=_AUTO,
        extra_headers=None,
    ):
        headers = {}
        if host is _AUTO:
            host = self.host
        if host is not None:
            headers["Host"] = host
        mutation = method in {"POST", "PUT", "PATCH", "DELETE"}
        if origin is _AUTO:
            origin = self.origin if mutation else None
        if origin is not None:
            headers["Origin"] = origin
        if cookie is _AUTO:
            cookie = self.cookie
        if cookie:
            headers["Cookie"] = cookie
        if csrf is _AUTO:
            csrf = self.csrf if mutation else None
        if csrf is not None:
            headers[web.CSRF_HEADER] = csrf
        if body is _UNSET:
            wire_body = None
        elif isinstance(body, bytes):
            wire_body = body
        else:
            wire_body = json.dumps(
                body, ensure_ascii=False, separators=(",", ":")
            ).encode("utf-8")
        if wire_body is not None:
            if content_type is _AUTO:
                content_type = "application/json"
            if content_type is not None:
                headers["Content-Type"] = content_type
            if content_length is _AUTO:
                content_length = len(wire_body)
            if content_length is not None:
                headers["Content-Length"] = str(content_length)
        if extra_headers:
            headers.update(extra_headers)
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        conn.request(method, path, body=wire_body, headers=headers)
        response = conn.getresponse()
        raw = response.read()
        result = {
            "status": response.status,
            "headers": dict(response.getheaders()),
            "raw": raw,
            "text": raw.decode("utf-8", "replace"),
        }
        content_type_header = response.getheader("Content-Type") or ""
        if content_type_header.startswith("application/json"):
            result["json"] = json.loads(raw.decode("utf-8"))
        conn.close()
        return result

    def assert_error(self, response, status=400):
        self.assertEqual(response["status"], status, response["text"])
        envelope = response["json"]
        self.assertFalse(envelope["ok"])
        self.assertEqual(set(envelope), {"ok", "error"})
        self.assertEqual(set(envelope["error"]), {"code", "message"})
        return envelope["error"]

    def login(self):
        session = self.request("GET", "/api/v1/session", cookie=None)
        self.assertEqual(session["status"], 200)
        prelogin_csrf = session["json"]["data"]["csrf"]
        response = self.request(
            "POST",
            "/api/v1/login",
            {"password": self.password},
            csrf=prelogin_csrf,
            cookie=None,
        )
        self.assertEqual(response["status"], 200, response["text"])
        self.cookie = response["headers"]["Set-Cookie"].split(";", 1)[0]
        self.csrf = response["json"]["data"]["csrf"]
        return response

    def test_session_login_logout_cookie_and_headers(self):
        response = self.request("GET", "/api/v1/session", cookie=None)
        self.assertEqual(response["status"], 200)
        self.assertEqual(
            set(response["json"]["data"]), {"authenticated", "csrf"}
        )
        self.assertFalse(response["json"]["data"]["authenticated"])
        csp = response["headers"]["Content-Security-Policy"]
        self.assertNotIn("unsafe-inline", csp)
        self.assertNotIn("wss:", csp)
        self.assertIn("script-src 'self'", csp)
        self.assertEqual(response["headers"]["X-Frame-Options"], "DENY")
        self.assertEqual(response["headers"]["Cache-Control"], "no-store, max-age=0")

        missing_csrf = self.request(
            "POST",
            "/api/v1/login",
            {"password": self.password},
            csrf=None,
            cookie=None,
        )
        self.assert_error(missing_csrf, 403)

        login = self.login()
        self.assertEqual(
            set(login["json"]["data"]),
            {"authenticated", "csrf", "expires_at"},
        )
        set_cookie = login["headers"]["Set-Cookie"]
        for attribute in (
            "__Host-pdg_session=",
            "Path=/",
            "Max-Age=28800",
            "HttpOnly",
            "Secure",
            "SameSite=Strict",
        ):
            self.assertIn(attribute, set_cookie)
        self.assertNotIn("Domain=", set_cookie)

        authenticated = self.request("GET", "/api/v1/session")
        self.assertTrue(authenticated["json"]["data"]["authenticated"])
        self.assertEqual(authenticated["json"]["data"]["csrf"], self.csrf)

        logout = self.request("POST", "/api/v1/logout", {})
        self.assertEqual(logout["status"], 200)
        self.assertFalse(logout["json"]["data"]["authenticated"])
        self.assertIn("Max-Age=0", logout["headers"]["Set-Cookie"])
        denied = self.request("GET", "/api/v1/overview")
        self.assert_error(denied, 401)

    def test_all_get_routes_have_sanitized_frozen_shapes(self):
        self.login()

        overview = self.request("GET", "/api/v1/overview")
        self.assertEqual(overview["status"], 200)
        self.assertEqual(
            set(overview["json"]["data"]),
            {"status", "doctor", "version", "platform", "dot_domain"},
        )
        self.assertEqual(overview["json"]["data"]["platform"], "ios")
        self.assertNotIn(PLAIN_SECRET, overview["text"])
        self.assertNotIn(UUID_SECRET, overview["text"])

        exits = self.request("GET", "/api/v1/exits")
        self.assertEqual(
            set(exits["json"]["data"]),
            {"items", "order", "default", "targets"},
        )
        allowed_exit_keys = {"tag", "type", "server", "server_port", "members"}
        for item in exits["json"]["data"]["items"]:
            self.assertTrue(set(item).issubset(allowed_exit_keys))
            self.assertNotIn("kind", item)
            self.assertNotIn("position", item)
            self.assertNotIn("editable", item)
        self.assertNotIn(PLAIN_SECRET, exits["text"])

        groups = self.request("GET", "/api/v1/groups")
        self.assertEqual(set(groups["json"]["data"]), {"items"})
        for item in groups["json"]["data"]["items"]:
            self.assertEqual(set(item), {"tag", "members"})

        rules = self.request("GET", "/api/v1/rules")
        self.assertEqual(set(rules["json"]["data"]), {"items", "targets"})
        for item in rules["json"]["data"]["items"]:
            self.assertEqual(set(item), {"domain", "target", "kind"})
        self.assertIn("direct", rules["json"]["data"]["targets"])

        rulesets = self.request("GET", "/api/v1/rulesets")
        self.assertEqual(set(rulesets["json"]["data"]), {"items"})
        item = rulesets["json"]["data"]["items"][0]
        self.assertEqual(
            set(item), {"name", "label", "target", "url", "behavior"}
        )
        self.assertEqual(item["url"], "https://rules.example")
        self.assertNotIn("password", rulesets["text"])
        self.assertNotIn("token=hidden", rulesets["text"])
        self.assertNotIn("#fragment", rulesets["text"])

        dns = self.request("GET", "/api/v1/dns")
        self.assertEqual(set(dns["json"]["data"]), {"remote", "local"})
        self.assertEqual(
            dns["json"]["data"]["remote"][0],
            "https://dns.example/dns-query",
        )
        self.assertEqual(
            dns["json"]["data"]["remote"][1],
            "https://dns.example",
        )
        self.assertNotIn("user:password", dns["text"])
        self.assertNotIn("token=hidden", dns["text"])

        settings = self.request("GET", "/api/v1/settings")
        self.assertEqual(
            set(settings["json"]["data"]),
            {"tfo", "hijack_mode", "quic_mode", "firewall_mode"},
        )

        logs = self.request("GET", "/api/v1/logs?lines=10")
        self.assertEqual(set(logs["json"]["data"]), {"lines"})
        self.assertLessEqual(len(logs["json"]["data"]["lines"]), 10)
        self.assertNotIn(PLAIN_SECRET, logs["text"])
        self.assertNotIn(UUID_SECRET, logs["text"])

        traffic = self.request("GET", "/api/v1/traffic")
        self.assertEqual(
            set(traffic["json"]["data"]),
            {
                "available",
                "connections",
                "uploadTotal",
                "downloadTotal",
                "byExit",
            },
        )
        self.assertNotIn("private.destination.example", traffic["text"])
        self.assertNotIn(PLAIN_SECRET, traffic["text"])

        runtime = self.request("GET", "/api/v1/runtime")
        self.assertEqual(
            set(runtime["json"]["data"]),
            {"backend", "services", "traffic", "version", "memory"},
        )
        self.assertNotIn("private.destination.example", runtime["text"])

        snapshots = self.request("GET", "/api/v1/snapshots")
        self.assertEqual(snapshots["status"], 200)
        self.assertEqual(set(snapshots["json"]["data"]), {"items"})
        self.assertEqual(
            set(snapshots["json"]["data"]["items"][0]),
            {"id", "createdAt", "size", "legacy"},
        )
        self.assertFalse(snapshots["json"]["data"]["items"][0]["legacy"])

        jobs = self.request("GET", "/api/v1/jobs")
        self.assertEqual(jobs["status"], 200)
        self.assertEqual(jobs["json"]["data"], {"items": []})

        manifest = self.request(
            "GET", "/manifest.webmanifest", cookie=None
        )
        self.assertEqual(manifest["status"], 200)
        self.assertEqual(
            manifest["headers"]["Content-Type"],
            "application/manifest+json; charset=utf-8",
        )

    def test_every_mutation_route_and_transaction_semantics(self):
        self.login()

        link = f"ss://{PLAIN_SECRET}@new.example:10443#newnode"
        added = self.request("POST", "/api/v1/exits", {"link": link})
        self.assertEqual(added["status"], 201, added["text"])
        self.assertEqual(
            set(added["json"]["data"]),
            {"tag", "type", "server", "server_port"},
        )
        self.assertNotIn(link, added["text"])
        self.assertNotIn(PLAIN_SECRET, added["text"])

        renamed = self.request(
            "PATCH", "/api/v1/exits/newnode", {"name": "newer"}
        )
        self.assertEqual(renamed["status"], 200, renamed["text"])
        self.assertEqual(renamed["json"]["data"]["tag"], "newer")
        old_position = next(
            index for index, item in enumerate(self.fake.model["outbounds"])
            if item.get("tag") == "newer"
        )
        replaced = self.request(
            "PUT", "/api/v1/exits/newer",
            {"link": f"ss://{PLAIN_SECRET}@replacement.example:443#ignored"},
        )
        self.assertEqual(replaced["status"], 200, replaced["text"])
        self.assertEqual(replaced["json"]["data"]["tag"], "newer")
        self.assertNotIn(PLAIN_SECRET, replaced["text"])
        self.assertEqual(
            self.fake.model["outbounds"][old_position]["tag"], "newer")

        current = self.request("GET", "/api/v1/exits")["json"]["data"]["order"]
        reordered = self.request(
            "PUT", "/api/v1/exits/order", {"order": list(reversed(current))}
        )
        self.assertEqual(reordered["status"], 200, reordered["text"])
        self.assertEqual(
            reordered["json"]["data"]["order"], list(reversed(current))
        )
        defaulted = self.request(
            "PUT", "/api/v1/default-exit", {"tag": "newer"}
        )
        self.assertEqual(defaulted["status"], 200, defaulted["text"])

        group = self.request(
            "POST",
            "/api/v1/groups",
            {"name": "fail", "members": ["hk", "tw"]},
        )
        self.assertEqual(group["status"], 201, group["text"])
        patched_group = self.request(
            "PATCH",
            "/api/v1/groups/fail",
            {"members": ["tw", "newer"]},
        )
        self.assertEqual(patched_group["status"], 200, patched_group["text"])

        rule = self.request(
            "POST",
            "/api/v1/rules",
            {"domain": "new.example", "target": "hk"},
        )
        self.assertEqual(rule["status"], 201, rule["text"])
        direct_rule = self.request(
            "POST",
            "/api/v1/rules",
            {"domain": "mobile-direct.example", "target": "direct"},
        )
        self.assertEqual(direct_rule["status"], 201, direct_rule["text"])

        exact = self.request(
            "PATCH",
            "/api/v1/rules/exact.example",
            {"target": "tw"},
        )
        self.assertEqual(exact["status"], 200, exact["text"])
        exact_rules = [
            item
            for item in self.fake.model["route"]["rules"]
            if "exact.example" in item.get("domain", [])
        ]
        self.assertEqual(len(exact_rules), 1)
        self.assertEqual(exact_rules[0]["outbound"], "tw")
        self.assertFalse(
            any(
                "exact.example" in item.get("domain_suffix", [])
                for item in self.fake.model["route"]["rules"]
            )
        )

        suffix = self.request(
            "PATCH",
            "/api/v1/rules/example.com",
            {"target": "tw"},
        )
        self.assertEqual(suffix["status"], 200, suffix["text"])
        self.assertTrue(
            any(
                "example.com" in item.get("domain_suffix", [])
                and item.get("outbound") == "tw"
                for item in self.fake.model["route"]["rules"]
            )
        )
        direct_to_proxy = self.request(
            "PATCH",
            "/api/v1/rules/mobile-direct.example",
            {"target": "hk"},
        )
        self.assertEqual(direct_to_proxy["status"], 200, direct_to_proxy["text"])
        deleted_rule = self.request(
            "DELETE", "/api/v1/rules/new.example"
        )
        self.assertEqual(deleted_rule["status"], 200, deleted_rule["text"])

        source_url = (
            "https://user:password@feed.example/path/list.txt?token=hidden"
        )
        ruleset = self.request(
            "POST",
            "/api/v1/rulesets",
            {
                "url": source_url,
                "target": "hk",
                "label": "Feed",
                "behavior": "domain",
            },
        )
        self.assertEqual(ruleset["status"], 201, ruleset["text"])
        self.assertEqual(
            ruleset["json"]["data"]["url"],
            "https://feed.example",
        )
        self.assertNotIn("user:password", ruleset["text"])
        self.assertNotIn("token=hidden", ruleset["text"])
        ruleset_name = "rs_" + hashlib.sha1(source_url.encode()).hexdigest()[:8]
        relabeled = self.request(
            "PATCH",
            f"/api/v1/rulesets/{ruleset_name}",
            {"label": "Renamed feed"},
        )
        self.assertEqual(relabeled["status"], 200, relabeled["text"])
        retargeted = self.request(
            "PUT",
            f"/api/v1/rulesets/{ruleset_name}/target",
            {"target": "tw"},
        )
        self.assertEqual(retargeted["status"], 200, retargeted["text"])
        self.assertEqual(retargeted["json"]["data"]["target"], "tw")

        direct_url = "https://feed.example/china-domains.txt"
        direct_ruleset = self.request(
            "POST",
            "/api/v1/rulesets",
            {"url": direct_url, "target": "direct", "behavior": "domain"},
        )
        self.assertEqual(
            direct_ruleset["status"], 201, direct_ruleset["text"]
        )
        self.assertEqual(direct_ruleset["json"]["data"]["target"], "direct")
        direct_name = (
            "rs_" + hashlib.sha1(direct_url.encode()).hexdigest()[:8]
        )
        deleted_ruleset = self.request(
            "DELETE", f"/api/v1/rulesets/{direct_name}"
        )
        self.assertEqual(
            deleted_ruleset["status"], 200, deleted_ruleset["text"]
        )

        for which, addresses in (
            ("remote", ["https://dns.google/dns-query"]),
            ("local", ["udp://223.5.5.5", "udp://119.29.29.29"]),
        ):
            dns = self.request(
                "PUT",
                f"/api/v1/dns/{which}",
                {"addresses": addresses},
            )
            self.assertEqual(dns["status"], 200, dns["text"])
        tfo = self.request(
            "PUT", "/api/v1/settings/tfo", {"enabled": True}
        )
        self.assertEqual(tfo["status"], 200, tfo["text"])

        action_results = {}
        for action, body in (
            ("restart", {}),
            ("rules-update", {}),
            ("snapshot", {}),
            ("rollback", {"index": 0}),
            ("software-update", {"confirm": True}),
        ):
            result = self.request(
                "POST", f"/api/v1/actions/{action}", body
            )
            self.assertEqual(result["status"], 202, result["text"])
            action_results[action] = result["json"]["data"]
        restart_records = [
            item for item in self.fake.transactions if item["op"] == "web_restart"
        ]
        self.assertEqual(len(restart_records), 1)
        self.assertFalse(restart_records[0]["has_model_mod"])
        self.assertEqual(restart_records[0]["file_keys"], [])
        self.assertEqual(
            set(restart_records[0]["services"]), {"mihomo", "mosdns"}
        )
        self.assertIn(
            ["/usr/local/bin/pdg", "snapshot"],
            self.fake.sh_calls,
        )
        self.assertEqual(
            action_results["rollback"]["job"]["operation"], "rollback")
        self.assertEqual(
            action_results["software-update"]["job"]["operation"],
            "software-update",
        )
        self.assertIn(("index", 0), self.jobs.calls)
        self.assertIn(
            ("start", "rollback", FakeJobStore.SNAPSHOT_ID),
            self.jobs.calls,
        )
        self.assertIn(
            ("start", "software-update", None), self.jobs.calls)
        self.assertIn(("update_check",), self.fake.wrapper_calls)
        self.assertNotIn(("start_update",), self.fake.wrapper_calls)

        deleted_group = self.request(
            "DELETE", "/api/v1/groups/fail"
        )
        self.assertEqual(deleted_group["status"], 200, deleted_group["text"])
        deleted_exit = self.request(
            "DELETE", "/api/v1/exits/newer"
        )
        self.assertEqual(deleted_exit["status"], 200, deleted_exit["text"])
        deleted_normal_ruleset = self.request(
            "DELETE", f"/api/v1/rulesets/{ruleset_name}"
        )
        self.assertEqual(
            deleted_normal_ruleset["status"],
            200,
            deleted_normal_ruleset["text"],
        )

    def test_imported_selector_is_an_editable_group_across_web_paths(self):
        self.fake.model["outbounds"].append({
            "type": "selector", "tag": "choice", "outbounds": ["hk", "tw"],
        })
        self.login()
        groups = self.request("GET", "/api/v1/groups")
        self.assertEqual(groups["status"], 200, groups["text"])
        choice = next(item for item in groups["json"]["data"]["items"]
                      if item["tag"] == "choice")
        self.assertEqual(choice["members"], ["hk", "tw"])
        patched = self.request(
            "PATCH", "/api/v1/groups/choice", {"members": ["tw", "hk"]})
        self.assertEqual(patched["status"], 200, patched["text"])
        canonical = next(item for item in self.fake.model["outbounds"]
                         if item.get("tag") == "choice")
        self.assertEqual(canonical["type"], "selector")
        self.assertEqual(canonical["outbounds"], ["tw", "hk"])
        deleted = self.request("DELETE", "/api/v1/groups/choice")
        self.assertEqual(deleted["status"], 200, deleted["text"])
        self.assertFalse(any(item.get("tag") == "choice"
                             for item in self.fake.model["outbounds"]))

    def test_legacy_group_writes_are_cas_pinned_with_optional_revision(self):
        self.login()
        created = self.request(
            "POST", "/api/v1/groups",
            {"name": "legacy", "members": ["hk", "tw"]})
        self.assertEqual(created["status"], 201, created["text"])
        self.assertTrue(created["json"]["data"]["deprecated"])

        stale = "0" * 64
        before = copy.deepcopy(self.fake.model)
        rejected = self.request(
            "PATCH", "/api/v1/groups/legacy",
            {"revision": stale, "members": ["tw", "hk"]})
        self.assert_error(rejected, 409)
        self.assertEqual(self.fake.model, before)

        def concurrent_change(fake):
            fake.model.setdefault("route", {}).setdefault("rules", []).append({
                "domain_suffix": ["concurrent.example"], "outbound": "hk"})

        operations = [
            ("POST", "/api/v1/groups",
             {"name": "racing", "members": ["hk", "tw"]}),
            ("PATCH", "/api/v1/groups/legacy",
             {"members": ["tw", "hk"]}),
            ("DELETE", "/api/v1/groups/legacy", None),
        ]
        for method, path, body in operations:
            with self.subTest(method=method):
                before_group = copy.deepcopy(self.fake.model["outbounds"])
                self.fake.before_model_expect_check = concurrent_change
                response = (self.request(method, path) if body is None
                            else self.request(method, path, body))
                self.assert_error(response, 409)
                self.assertEqual(self.fake.model["outbounds"], before_group)
                self.assertTrue(any(
                    rule.get("domain_suffix") == ["concurrent.example"]
                    for rule in self.fake.model["route"]["rules"]))

        revision = self.fake._model_snapshot()[1]
        deleted = self.request(
            "DELETE", "/api/v1/groups/legacy", {"revision": revision})
        self.assertEqual(deleted["status"], 200, deleted["text"])
        self.assertNotIn("deprecated", deleted["json"]["data"])

    def test_direct_tag_reserved_compatibility_names_reject_atomically(self):
        self.login()
        for name in ("direct", "DiReCt", "jp", "JP"):
            before = copy.deepcopy(self.fake.model)
            with self.subTest(name=name):
                response = self.request("PUT", "/api/v1/direct-tag", {"tag": name})
                self.assert_error(response, 400)
                self.assertEqual(self.fake.model, before)

    def test_diagnostics_are_structured_and_drop_internal_fields(self):
        self.login()
        exits = self.request(
            "POST", "/api/v1/diagnostics/exits", {})
        self.assertEqual(exits["status"], 200, exits["text"])
        self.assertEqual(
            exits["json"]["data"],
            {
                "available": True,
                "items": [
                    {"tag": "jp", "status": "ok", "delayMs": 8},
                    {"tag": "hk", "status": "timeout"},
                ],
            },
        )
        domain = self.request(
            "POST", "/api/v1/diagnostics/domain",
            {"domain": "exact.example"},
        )
        self.assertEqual(domain["status"], 200, domain["text"])
        self.assertEqual(
            domain["json"]["data"],
            {
                "domain": "exact.example",
                "path": "gateway",
                "target": "hk",
                "reason": "explicit_domain",
                "dnsVerified": True,
                "routeConfidence": "simulated",
                "verified": False,
                "confidence": "simulated",
            },
        )
        self.assertNotIn(PLAIN_SECRET, exits["text"] + domain["text"])
        self.assertNotIn(UUID_SECRET, exits["text"] + domain["text"])
        self.fake.probe_domain_route = lambda value: {
            "domain": value,
            "path": "unknown",
            "reason": "probe_busy",
            "dns_verified": False,
            "route_confidence": "unknown",
            "verified": False,
            "confidence": "unknown",
            "internal_error": f"ss://{PLAIN_SECRET}@secret.example",
        }
        busy = self.request(
            "POST", "/api/v1/diagnostics/domain",
            {"domain": "busy.example"},
        )
        self.assertEqual(busy["status"], 200, busy["text"])
        self.assertEqual(
            busy["json"]["data"],
            {
                "domain": "busy.example",
                "path": "unknown",
                "reason": "probe_busy",
                "dnsVerified": False,
                "routeConfidence": "unknown",
                "verified": False,
                "confidence": "unknown",
            },
        )
        self.assertNotIn(PLAIN_SECRET, busy["text"])
        self.fake.probe_domain_route = lambda value: {
            "domain": value,
            "path": "unknown",
            "reason": "config_changed",
            "dns_verified": False,
            "route_confidence": "unknown",
            "verified": False,
            "confidence": "unknown",
        }
        changed = self.request(
            "POST", "/api/v1/diagnostics/domain",
            {"domain": "changed.example"},
        )
        self.assertEqual(changed["status"], 200, changed["text"])
        self.assertEqual(
            changed["json"]["data"]["reason"], "config_changed"
        )
        self.assertFalse(changed["json"]["data"]["dnsVerified"])
        self.assertEqual(
            changed["json"]["data"]["routeConfidence"], "unknown"
        )
        self.fake.probe_domain_route = lambda value: {
            "domain": value,
            "path": "gateway",
            "reason": "dns_no_answer",
            "dns_verified": True,
            "route_confidence": "unknown",
            "verified": False,
            "confidence": "unknown",
        }
        inconsistent = self.request(
            "POST", "/api/v1/diagnostics/domain",
            {"domain": "inconsistent.example"},
        )
        self.assert_error(inconsistent, 500)

    def test_deleting_proxy_never_remaps_literal_direct_ruleset(self):
        self.login()
        self.fake.meta["rs_deadbeef"]["outbound"] = "direct"
        for rule in self.fake.model["route"]["rules"]:
            if rule.get("rule_set") == "rs_deadbeef":
                rule["outbound"] = "direct"
        response = self.request("DELETE", "/api/v1/exits/hk")
        self.assertEqual(response["status"], 200, response["text"])
        self.assertEqual(
            self.fake.meta["rs_deadbeef"]["outbound"], "direct")
        route_rule = next(
            rule for rule in self.fake.model["route"]["rules"]
            if rule.get("rule_set") == "rs_deadbeef"
        )
        self.assertEqual(route_rule["outbound"], "direct")

    def test_delete_exit_rejects_concurrent_ruleset_metadata_update(self):
        self.login()
        self.fake.meta["rs_literal_direct"] = {
            "outbound": "direct",
            "format": "source",
            "path": "/etc/sing-box/rs/rs-literal-direct.json",
            "label": "Literal direct",
        }

        def concurrent_commit(bot):
            bot.meta["rs_deadbeef"]["label"] = "Concurrent label"

        self.fake.before_file_expect_check = concurrent_commit
        response = self.request("DELETE", "/api/v1/exits/tw")
        self.assert_error(response, 500)
        self.assertTrue(any(
            item.get("tag") == "tw"
            for item in self.fake.model["outbounds"]
        ))
        self.assertEqual(
            self.fake.meta["rs_deadbeef"]["label"], "Concurrent label"
        )
        self.assertEqual(
            self.fake.meta["rs_literal_direct"]["outbound"], "direct"
        )
        transaction = self.fake.transactions[-1]
        self.assertEqual(
            transaction["file_expects"],
            {"rs_meta": transaction["file_expects"]["rs_meta"]},
        )
        self.assertRegex(
            transaction["file_expects"]["rs_meta"], r"^[0-9a-f]{64}$"
        )

    def test_snapshot_id_rollback_and_persistent_job_queries(self):
        self.login()
        rollback = self.request(
            "POST", "/api/v1/actions/rollback",
            {
                "snapshotId": FakeJobStore.SNAPSHOT_ID,
                "confirm": True,
            },
        )
        self.assertEqual(rollback["status"], 202, rollback["text"])
        job = rollback["json"]["data"]["job"]
        self.assertEqual(job["operation"], "rollback")
        self.assertEqual(job["snapshotId"], FakeJobStore.SNAPSHOT_ID)
        listing = self.request("GET", "/api/v1/jobs")
        self.assertEqual(listing["status"], 200, listing["text"])
        self.assertEqual(listing["json"]["data"]["items"], [job])
        fetched = self.request(
            "GET", f"/api/v1/jobs/{FakeJobStore.JOB_ID}")
        self.assertEqual(fetched["status"], 200, fetched["text"])
        self.assertEqual(fetched["json"]["data"], job)

    def test_schema_query_identifier_and_request_security_rejections(self):
        unauth_host = self.request(
            "GET", "/api/v1/session", host="evil.example", cookie=None
        )
        self.assert_error(unauth_host, 421)
        for noncanonical_host in (
            self.host.upper(),
            f"pdg.example:0{self.port}",
            f"pdg.example:{self.port}:",
        ):
            with self.subTest(host=noncanonical_host):
                self.assert_error(
                    self.request(
                        "GET",
                        "/api/v1/session",
                        host=noncanonical_host,
                        cookie=None,
                    ),
                    421,
                )
        forwarded = self.request(
            "GET",
            "/api/v1/session",
            cookie=None,
            extra_headers={
                "X-Forwarded-For": "203.0.113.55",
                "Forwarded": "for=203.0.113.55",
            },
        )
        self.assertEqual(forwarded["status"], 200)
        self.assertFalse(web._ip_trusted(self.config, "203.0.113.55"))

        self.login()
        missing_csrf = self.request(
            "PUT",
            "/api/v1/default-exit",
            {"tag": "hk"},
            csrf=None,
        )
        self.assert_error(missing_csrf, 403)
        bad_origin = self.request(
            "PUT",
            "/api/v1/default-exit",
            {"tag": "hk"},
            origin="https://evil.example",
        )
        self.assert_error(bad_origin, 403)
        for noncanonical_origin in (
            self.origin.upper(),
            f"https://pdg.example:0{self.port}",
        ):
            with self.subTest(origin=noncanonical_origin):
                self.assert_error(
                    self.request(
                        "PUT",
                        "/api/v1/default-exit",
                        {"tag": "hk"},
                        origin=noncanonical_origin,
                    ),
                    403,
                )

        for method in ("TRACE", "CONNECT", "BREW"):
            with self.subTest(method=method):
                unknown_method = self.request(
                    method, "/api/v1/session", cookie=None
                )
                self.assert_error(unknown_method, 405)
                self.assertIn(
                    "Content-Security-Policy", unknown_method["headers"]
                )
                self.assertNotIn("<html", unknown_method["text"].lower())
                self.assertNotIn("unsupported method", unknown_method["text"].lower())

        bad_schemas = [
            ("POST", "/api/v1/exits", {"link": "ss://x", "name": "x"}),
            ("PATCH", "/api/v1/exits/hk", {"tag": "x"}),
            ("PUT", "/api/v1/exits/hk", {"link": "ss://x", "extra": True}),
            ("PUT", "/api/v1/exits/order", {"order": []}),
            ("PUT", "/api/v1/default-exit", {"tag": "hk", "extra": True}),
            ("POST", "/api/v1/groups", {"tag": "bad", "members": ["hk", "tw"]}),
            ("PATCH", "/api/v1/groups/auto", {"name": "bad"}),
            ("POST", "/api/v1/rules", {"domain": "bad.example", "outbound": "hk"}),
            ("PATCH", "/api/v1/rules/example.com", {"outbound": "tw"}),
            (
                "POST",
                "/api/v1/rulesets",
                {"url": "https://feed.example/list", "outbound": "hk"},
            ),
            ("PATCH", "/api/v1/rulesets/rs_deadbeef", {"target": "hk"}),
            (
                "PUT",
                "/api/v1/rulesets/rs_deadbeef/target",
                {"target": "hk", "extra": True},
            ),
            ("POST", "/api/v1/diagnostics/exits", {"extra": True}),
            (
                "POST",
                "/api/v1/diagnostics/domain",
                {"domain": "not a domain"},
            ),
            ("PUT", "/api/v1/dns/remote", {"upstreams": ["udp://1.1.1.1"]}),
            ("PUT", "/api/v1/settings/tfo", {"enabled": 1}),
            ("POST", "/api/v1/actions/restart", {"confirm": True}),
            ("POST", "/api/v1/actions/rollback", {"index": -1}),
            ("POST", "/api/v1/actions/rollback", {"index": True}),
            (
                "POST",
                "/api/v1/actions/rollback",
                {"snapshotId": FakeJobStore.SNAPSHOT_ID},
            ),
            ("POST", "/api/v1/actions/software-update", {"confirm": False}),
        ]
        for method, path, body in bad_schemas:
            with self.subTest(method=method, path=path, body=body):
                self.assert_error(self.request(method, path, body), 400)

        for path in (
            "/api/v1/overview?x=1",
            "/manifest.webmanifest?x=1",
            "/api/v1/logs?lines=9",
            "/api/v1/logs?lines=201",
            "/api/v1/logs?lines=010",
            "/api/v1/logs?lines=10&lines=11",
            "/api/v1/logs?x=10",
            "/api/v1/snapshots?x=1",
            "/api/v1/jobs?x=1",
            "/api/v1/logs?lines=%31%30",
        ):
            with self.subTest(path=path):
                self.assert_error(self.request("GET", path), 400)

        for method, path, body in (
            ("PATCH", "/api/v1/exits/%ZZ", {"name": "x"}),
            ("PATCH", "/api/v1/exits/%2F", {"name": "x"}),
            ("DELETE", "/api/v1/rules/%2e%2e", _UNSET),
        ):
            with self.subTest(path=path):
                self.assert_error(self.request(method, path, body), 400)

        duplicate = self.request(
            "PUT",
            "/api/v1/default-exit",
            b'{"tag":"hk","tag":"tw"}',
        )
        error = self.assert_error(duplicate, 400)
        self.assertEqual(error["code"], "invalid_json")
        unsupported = self.request(
            "PUT",
            "/api/v1/default-exit",
            b'{"tag":"hk"}',
            content_type="text/plain",
        )
        self.assert_error(unsupported, 415)
        oversized = self.request(
            "PUT",
            "/api/v1/default-exit",
            b"",
            content_length=web.MAX_JSON_BYTES + 1,
        )
        self.assert_error(oversized, 413)

        invalid_link = self.request(
            "POST", "/api/v1/exits", {"link": f"invalid://{PLAIN_SECRET}"}
        )
        self.assert_error(invalid_link, 400)
        self.assertNotIn(PLAIN_SECRET, invalid_link["text"])
        self.assertNotIn("ss://", invalid_link["text"])

    def test_rule_patch_rejects_concurrent_domain_file_update(self):
        self.login()

        def concurrent_commit(bot):
            bot.direct.append("concurrent.example")

        self.fake.before_file_expect_check = concurrent_commit
        response = self.request(
            "PATCH",
            "/api/v1/rules/exact.example",
            {"target": "direct"},
        )
        self.assert_error(response, 500)
        self.assertIn("concurrent.example", self.fake.direct)
        self.assertNotIn("exact.example", self.fake.direct)
        self.assertIn("exact.example", self.fake.hijack)
        exact_rule = next(
            rule
            for rule in self.fake.model["route"]["rules"]
            if "exact.example" in rule.get("domain", [])
        )
        self.assertEqual(exact_rule["outbound"], "hk")
        transaction = self.fake.transactions[-1]
        self.assertEqual(
            set(transaction["file_expects"]),
            {
                "mosdns_rule:custom_direct.txt",
                "mosdns_rule:custom_hijack.txt",
            },
        )

    def test_rules_update_partial_failure_is_not_reported_as_success(self):
        self.login()
        self.fake.refresh_result = (
            1,
            [f"private source failed: ss://{PLAIN_SECRET}@secret.example"],
        )
        response = self.request(
            "POST", "/api/v1/actions/rules-update", {}
        )
        error = self.assert_error(response, 500)
        self.assertEqual(error["code"], "operation_failed")
        self.assertIn("failed sources", error["message"])
        self.assertNotIn(PLAIN_SECRET, response["text"])
        self.assertNotIn("ss://", response["text"])

    def test_unavailable_job_gate_blocks_synchronous_maintenance(self):
        self.login()

        class BrokenJobStore:
            @staticmethod
            def maintenance_guard():
                raise RuntimeError("corrupt maintenance state")

        self.control._job_store_instance = BrokenJobStore()
        before_transactions = len(self.fake.transactions)
        before_shell = len(self.fake.sh_calls)
        restart = self.request(
            "POST", "/api/v1/actions/restart", {}
        )
        rules = self.request(
            "POST", "/api/v1/actions/rules-update", {}
        )
        self.assert_error(restart, 500)
        self.assert_error(rules, 500)
        self.assertEqual(len(self.fake.transactions), before_transactions)
        self.assertEqual(len(self.fake.sh_calls), before_shell)

    def test_active_maintenance_rejects_preview_before_stream_read_or_staging(self):
        self.login()
        JobBusy = type("JobBusy", (RuntimeError,), {})

        class ActiveJobStore:
            @staticmethod
            @contextlib.contextmanager
            def maintenance_guard():
                raise JobBusy("maintenance active")
                yield  # pragma: no cover

        class CountingStream(io.BytesIO):
            def __init__(self, payload):
                super().__init__(payload)
                self.reads = 0

            def read(self, *args, **kwargs):
                self.reads += 1
                return super().read(*args, **kwargs)

        self.control._job_store_instance = ActiveJobStore()
        before = list(self.config_io.calls)
        stream = CountingStream(b"rules:\n  - MATCH,DIRECT\n")
        with self.assertRaises(pdgcontrol.BusyError):
            self.control.preview_import_stream(
                "mihomo", stream, len(stream.getvalue()), "application/yaml")
        self.assertEqual(stream.reads, 0)
        with self.assertRaises(pdgcontrol.BusyError):
            self.control.preview_import(
                "mihomo", stream.getvalue(), "application/yaml")
        self.assertEqual(self.config_io.calls, before)

        response = self.request(
            "POST", "/api/v1/imports/mihomo/preview",
            b"rules:\n  - MATCH,DIRECT\n", content_type="application/yaml")
        self.assert_error(response, 409)
        self.assertEqual(self.config_io.calls, before)

    def test_software_update_preflight_is_fail_closed_and_sanitized(self):
        self.login()
        sensitive = f"internal ss://{PLAIN_SECRET}@secret.example"
        for checked in (
            (False, "repository has no release tag " + sensitive),
            (False, "already at newest release " + sensitive),
            (False, "git fetch failed " + sensitive),
            (1, sensitive),
            {"available": True, "details": sensitive},
        ):
            with self.subTest(checked=checked):
                self.fake.update_check_result = checked
                before = len([
                    call for call in self.jobs.calls
                    if call[:2] == ("start", "software-update")
                ])
                response = self.request(
                    "POST",
                    "/api/v1/actions/software-update",
                    {"confirm": True},
                )
                error = self.assert_error(response, 500)
                self.assertEqual(error["code"], "operation_failed")
                self.assertEqual(
                    error["message"], "Operation could not be completed."
                )
                self.assertEqual(
                    len([
                        call for call in self.jobs.calls
                        if call[:2] == ("start", "software-update")
                    ]),
                    before,
                )
                self.assertNotIn(PLAIN_SECRET, response["text"])
                self.assertNotIn("ss://", response["text"])

        self.fake.update_check_error = RuntimeError(sensitive)
        response = self.request(
            "POST",
            "/api/v1/actions/software-update",
            {"confirm": True},
        )
        self.assert_error(response, 500)
        self.assertNotIn(PLAIN_SECRET, response["text"])
        self.assertNotIn("ss://", response["text"])
        self.fake.update_check_error = None

        self.fake.update_check_result = (True, sensitive)
        before = len(self.fake.wrapper_calls)
        response = self.request(
            "POST",
            "/api/v1/actions/software-update",
            {"confirm": True},
        )
        self.assertEqual(response["status"], 202, response["text"])
        self.assertEqual(
            self.fake.wrapper_calls[before:],
            [("update_check",)],
        )
        self.assertNotIn(PLAIN_SECRET, response["text"])

    def test_legacy_rollback_index_resolves_to_stable_snapshot_job(self):
        self.login()
        response = self.request(
            "POST", "/api/v1/actions/rollback", {"index": 0}
        )
        self.assertEqual(response["status"], 202, response["text"])
        self.assertEqual(
            response["json"]["data"]["job"]["snapshotId"],
            FakeJobStore.SNAPSHOT_ID,
        )
        self.assertIn(("index", 0), self.jobs.calls)
        self.assertIn(
            ("start", "rollback", FakeJobStore.SNAPSHOT_ID),
            self.jobs.calls,
        )

    def test_security_state_limits_sessions_and_bounded_maps(self):
        state = web.SecurityState(self.config)
        for _ in range(web.LOGIN_RATE_ATTEMPTS):
            state.record_login_failure("192.0.2.1", now=1000)
        self.assertFalse(state.login_rate_allowed("192.0.2.1", now=1001))
        state.clear_login_failures("192.0.2.1")
        self.assertTrue(state.login_rate_allowed("192.0.2.1", now=1001))

        state = web.SecurityState(self.config)
        for index in range(web.LOGIN_ALL_RATE_ATTEMPTS):
            state.record_login_failure(f"192.0.2.{index + 1}", now=2000 + index)
        self.assertFalse(state.login_rate_allowed("198.51.100.1", now=2031))
        self.assertTrue(
            state.login_rate_allowed(
                "198.51.100.1", now=2031 + web.LOGIN_RATE_WINDOW
            )
        )

        bounded = web.SecurityState(self.config)
        for index in range(web.RATE_MAP_LIMIT + 100):
            bounded.record_login_failure(f"2001:db8::{index}", now=3000 + index)
        self.assertLessEqual(len(bounded._logins), web.RATE_MAP_LIMIT)

        sessions = web.SecurityState(self.config)
        for index in range(web.MAX_SESSIONS + 10):
            sessions.create_session(now=4000 + index)
        self.assertLessEqual(len(sessions._sessions), web.MAX_SESSIONS)

    def test_strict_config_validation(self):
        cases = []

        value = copy.deepcopy(self.config_raw)
        value["session_hours"] = 1.5
        cases.append(value)

        value = copy.deepcopy(self.config_raw)
        value["trusted_cidrs"] = ["127.0.0.0/8", "::1/128"]
        cases.append(value)

        value = copy.deepcopy(self.config_raw)
        value["trusted_cidrs"] = ["0.0.0.0/0", "127.0.0.1/32", "::1/128"]
        cases.append(value)

        value = copy.deepcopy(self.config_raw)
        value["trusted_cidrs"] = ["::1/128", "127.0.0.1/32"]
        cases.append(value)

        value = copy.deepcopy(self.config_raw)
        value["allowed_origins"] = ["https://other.example"]
        cases.append(value)

        value = copy.deepcopy(self.config_raw)
        value["unexpected"] = True
        cases.append(value)

        value = copy.deepcopy(self.config_raw)
        value["auth"]["iterations"] = 999
        cases.append(value)

        for index, bad in enumerate(cases):
            with self.subTest(index=index):
                path = self.temp_path / f"bad-{index}.json"
                path.write_text(json.dumps(bad), encoding="utf-8")
                with self.assertRaises(web.ConfigError):
                    web.load_config(str(path), testing=True)

        duplicate = self.temp_path / "duplicate.json"
        duplicate.write_text(
            json.dumps(self.config_raw)[:-1] + ',"port":9091}',
            encoding="utf-8",
        )
        with self.assertRaises(web.ConfigError):
            web.load_config(str(duplicate), testing=True)

        weak_production = copy.deepcopy(self.config_raw)
        weak_production["auth"]["iterations"] = 599_999
        with mock.patch.object(
            pdgwebconfig,
            "_read_config_file",
            return_value=json.dumps(weak_production).encode("utf-8"),
        ):
            with self.assertRaises(web.ConfigError):
                web.load_config("/etc/privdns-gateway/web.json", testing=False)


    def test_config_export_import_http_security_and_attachment_channel(self):
        self.login()
        denied = self.request(
            "POST", "/api/v1/exports/mihomo", {"password": "wrong"})
        self.assert_error(denied, 401)
        self.assertEqual(self.config_io.calls, [])

        for kind in ("pdg", "mihomo", "mosdns"):
            exported = self.request(
                "POST", f"/api/v1/exports/{kind}", {"password": self.password})
            self.assertEqual(exported["status"], 200, exported["text"])
            self.assertEqual(exported["raw"], b"managed-config\n")
            self.assertEqual(
                exported["headers"]["Content-Disposition"],
                f'attachment; filename="{kind}-config.yaml"')
            self.assertEqual(exported["headers"]["Cache-Control"], "no-store, max-age=0")
            self.assertEqual(exported["headers"]["X-Content-Type-Options"], "nosniff")
        self.assertEqual(self.jobs.records, [])

        missing_csrf = self.request(
            "POST", "/api/v1/imports/mihomo/preview", b"rules:\n  - MATCH,DIRECT\n",
            csrf=None, content_type="application/yaml")
        self.assert_error(missing_csrf, 403)
        unsupported = self.request(
            "POST", "/api/v1/imports/mihomo/preview", b"x",
            content_type="text/plain")
        self.assert_error(unsupported, 415)
        preview = self.request(
            "POST", "/api/v1/imports/mihomo/preview",
            b"rules:\n  - MATCH,DIRECT\n", content_type="application/yaml")
        self.assertEqual(preview["status"], 201, preview["text"])
        self.assertEqual(
            preview["json"]["data"]["importId"], FakeConfigIO.IMPORT_ID)
        denied_cancel = self.request(
            "DELETE", f"/api/v1/imports/{FakeConfigIO.IMPORT_ID}", csrf=None)
        self.assert_error(denied_cancel, 403)
        cancelled = self.request(
            "DELETE", f"/api/v1/imports/{FakeConfigIO.IMPORT_ID}")
        self.assertEqual(cancelled["status"], 200, cancelled["text"])
        self.assertIn(("cancel", FakeConfigIO.IMPORT_ID), self.config_io.calls)
        preview = self.request(
            "POST", "/api/v1/imports/mihomo/preview",
            b"rules:\n  - MATCH,DIRECT\n", content_type="application/yaml")
        self.assertEqual(preview["status"], 201, preview["text"])
        applied = self.request(
            "POST", f"/api/v1/imports/{FakeConfigIO.IMPORT_ID}/apply",
            {"confirm": True, "mode": "merge", "conflicts": {}})
        self.assertEqual(applied["status"], 202, applied["text"])
        self.assertEqual(applied["json"]["data"]["action"], "config-import")
        self.assertIn(
            ("start", "config-import", FakeConfigIO.IMPORT_ID), self.jobs.calls)

    def test_policy_groups_v3_crud_cas_runtime_and_direct_tag_routes(self):
        self.login()
        self.fake.model = {
            "outbounds": [
                {"type": "direct", "tag": "KFC_JP"},
                {"type": "shadowsocks", "tag": "hk"},
                {"type": "shadowsocks", "tag": "tw"},
            ],
            "route": {
                "rules": [{"domain_suffix": ["group.example"],
                           "outbound": "choice"}],
                "final": "choice",
            },
            "_pdg": {"schema": 3, "policy-groups": [{
                "name": "choice", "type": "select",
                "proxies": ["KFC_JP", "hk"], "use": [],
            }], "mihomo": {"proxy-providers": {"remote": {}},
                              "rule-providers": {}, "advanced": {},
                              "managed-files": {}}},
        }
        self.fake.runtime_now = {"choice": "DIRECT"}
        self.fake.runtime_all = {"choice": ["DIRECT", "hk"]}
        groups = self.request("GET", "/api/v1/policy-groups")
        self.assertEqual(groups["status"], 200, groups["text"])
        payload = groups["json"]["data"]
        self.assertEqual(payload["items"][0]["runtimeSelected"], "KFC_JP")
        self.assertEqual(payload["items"][0]["runtimeCandidates"], ["KFC_JP", "hk"])
        self.assertEqual(payload["providers"], ["remote"])
        self.assertIn("choice", payload["targets"])
        self.assertRegex(payload["revision"], r"^[0-9a-f]{64}$")

        created = self.request("POST", "/api/v1/policy-groups", {
            "revision": payload["revision"],
            "name": "failover", "type": "fallback",
            "proxies": ["choice", "tw"], "use": [],
            "url": "https://www.gstatic.com/generate_204", "interval": 120,
        })
        self.assertEqual(created["status"], 201, created["text"])
        self.assertEqual(created["json"]["data"]["type"], "fallback")
        after_create = self.request("GET", "/api/v1/policy-groups")["json"]["data"]
        self.fake.meta["rs_deadbeef"]["outbound"] = "failover"
        patched = self.request(
            "PATCH", "/api/v1/policy-groups/failover", {
                "revision": after_create["revision"],
                "name": "balanced", "type": "load-balance",
                "proxies": ["choice", "tw"], "use": [],
                "url": "https://www.gstatic.com/generate_204", "interval": 300,
                "strategy": "round-robin",
            })
        self.assertEqual(patched["status"], 200, patched["text"])
        self.assertEqual(patched["json"]["data"]["name"], "balanced")
        self.assertEqual(self.fake.meta["rs_deadbeef"]["outbound"], "balanced")
        self.assertEqual(self.fake.transactions[-1]["file_keys"], ["rs_meta"])
        self.assertEqual(set(self.fake.transactions[-1]["file_expects"]), {"rs_meta"})
        self.assertEqual(self.fake.transactions[-1]["model_expect"],
                         after_create["revision"])

        before_transactions = len(self.fake.transactions)
        selected = self.request(
            "PUT", "/api/v1/policy-groups/choice/runtime",
            {"member": "KFC_JP"})
        self.assertEqual(selected["status"], 200, selected["text"])
        self.assertFalse(selected["json"]["data"]["persistent"])
        self.assertEqual(self.fake.runtime_selections[-1], ("choice", "DIRECT"))
        self.assertEqual(len(self.fake.transactions), before_transactions)

        after_patch = self.request("GET", "/api/v1/policy-groups")["json"]["data"]
        deleted = self.request(
            "DELETE", "/api/v1/policy-groups/balanced",
            {"revision": after_patch["revision"]})
        self.assertEqual(deleted["status"], 200, deleted["text"])
        self.assertFalse(any(item.get("name") == "balanced" for item in
                             self.fake.model["_pdg"]["policy-groups"]))
        renamed_direct = self.request(
            "PUT", "/api/v1/direct-tag", {"tag": "LOCAL_EGRESS"})
        self.assertEqual(renamed_direct["status"], 200, renamed_direct["text"])
        self.assertEqual(self.fake.model["outbounds"][0]["tag"], "LOCAL_EGRESS")
        self.assertEqual(
            self.fake.model["_pdg"]["policy-groups"][0]["proxies"][0],
            "LOCAL_EGRESS")

    def test_policy_group_runtime_provider_candidates_reject_mapping_and_stale_cas(self):
        self.login()
        self.fake.model = {
            "outbounds": [
                {"type": "direct", "tag": "KFC_JP"},
                {"type": "block", "tag": "deny"},
                {"type": "shadowsocks", "tag": "hk"},
            ],
            "route": {"rules": [], "final": "provider_only"},
            "_pdg": {"schema": 3, "policy-groups": [
                {"name": "provider_only", "type": "select", "proxies": [],
                 "use": ["remote"]},
                {"name": "literal_reject", "type": "select",
                 "proxies": ["REJECT", "hk"], "use": []},
                {"name": "mapped_block", "type": "select",
                 "proxies": ["deny", "hk"], "use": []},
            ], "mihomo": {"proxy-providers": {"remote": {}},
                            "rule-providers": {}, "advanced": {},
                            "managed-files": {}}},
        }
        self.fake.runtime_now = {
            "provider_only": "provider node 1",
            "literal_reject": "REJECT", "mapped_block": "REJECT",
        }
        self.fake.runtime_all = {
            "provider_only": ["provider node 1", "provider-node-2"],
            "literal_reject": ["REJECT", "hk"],
            "mapped_block": ["REJECT", "hk"],
        }
        response = self.request("GET", "/api/v1/policy-groups")
        self.assertEqual(response["status"], 200, response["text"])
        payload = response["json"]["data"]
        items = {item["name"]: item for item in payload["items"]}
        self.assertEqual(items["provider_only"]["runtimeCandidates"],
                         ["provider node 1", "provider-node-2"])
        self.assertEqual(items["provider_only"]["runtimeSelected"], "provider node 1")
        self.assertEqual(items["literal_reject"]["runtimeSelected"], "REJECT")
        self.assertEqual(items["mapped_block"]["runtimeSelected"], "deny")

        before_model = copy.deepcopy(self.fake.model)
        selected = self.request(
            "PUT", "/api/v1/policy-groups/provider_only/runtime",
            {"member": "provider-node-2"})
        self.assertEqual(selected["status"], 200, selected["text"])
        self.assertEqual(self.fake.runtime_selections[-1],
                         ("provider_only", "provider-node-2"))
        self.assertEqual(self.fake.model, before_model)

        stale_revision = payload["revision"]
        self.fake.model["route"]["final"] = "hk"
        before_groups = copy.deepcopy(self.fake.model["_pdg"]["policy-groups"])
        stale = self.request("POST", "/api/v1/policy-groups", {
            "revision": stale_revision, "name": "stale", "type": "select",
            "proxies": ["hk"], "use": [],
        })
        self.assert_error(stale, 409)
        self.assertEqual(self.fake.model["_pdg"]["policy-groups"], before_groups)


class PersistentJobStoreTestCase(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="pdg-job-test.")
        self.root = pathlib.Path(self.temp.name)
        self.state = self.root / "jobs"
        self.snapshots = self.root / "backups"
        self.snapshot_id = "20260729-010203-a1b2c3d4"
        archive = self.snapshots / self.snapshot_id / "snap.tar.gz"
        archive.parent.mkdir(parents=True)
        archive.write_bytes(b"snapshot")
        self.calls = []
        self.launch_lock_was_free = False
        self.cleanup_lock_was_free = False
        self.module = pdgcontrol.load_job_module()

        def fake_run(argv, **_kwargs):
            self.calls.append(list(argv))
            if argv[:2] == ["systemctl", "is-active"]:
                return FakeResult(returncode=3, stdout="inactive\n")
            if argv and argv[0] == str(self.root / "systemd-run"):
                with self.store._locked():
                    self.launch_lock_was_free = True
            if "discard" in argv:
                with self.store._locked():
                    self.cleanup_lock_was_free = True
            return FakeResult(returncode=0)

        self.store = self.module.JobStore(
            state_dir=str(self.state),
            snapshot_dir=str(self.snapshots),
            cli=str(self.root / "pdg"),
            runner=str(self.root / "pdg-web-job.py"),
            config_io_runner=str(self.root / "pdgconfigio.py"),
            systemd_run=str(self.root / "systemd-run"),
            python=str(self.root / "python3"),
            run_command=fake_run,
            enforce_root_owner=False,
        )

    def tearDown(self):
        self.temp.cleanup()

    def test_launcher_and_runner_use_fixed_argv_and_persist_final_state(self):
        record = self.store.start(
            "rollback", snapshot_id=self.snapshot_id)
        launch = self.calls[-1]
        self.assertEqual(launch[0], str(self.root / "systemd-run"))
        self.assertIn("--property=Type=exec", launch)
        self.assertNotIn("/bin/sh", launch)
        self.assertEqual(launch[-2:], ["--job-id", record["id"]])
        self.assertTrue(self.launch_lock_was_free)
        self.assertTrue(
            launch[3].startswith("--unit=pdg-web-job-"))
        self.assertEqual(self.store.run(record["id"]), 0)
        command = self.calls[-1]
        self.assertEqual(
            command,
            [
                str(self.root / "pdg"),
                "rollback",
                "--dir",
                str(self.snapshots / self.snapshot_id),
            ],
        )
        final = self.store.get(record["id"])
        self.assertEqual(final["status"], "succeeded")
        serialized = json.dumps(final)
        self.assertNotIn("stdout", serialized)
        self.assertNotIn("stderr", serialized)

    def test_single_active_job_and_cross_boot_interruption(self):
        record = self.store.start("software-update")
        with self.assertRaises(self.module.JobBusy):
            self.store.start("software-update")
        with self.store._locked():
            changed = self.store._read_record(record["id"])
            changed["bootId"] = "00000000-0000-0000-0000-000000000000"
            self.store._write_record(changed)
        reconciled = self.store.get(record["id"])
        self.assertEqual(reconciled["status"], "interrupted")

    def test_snapshot_resolution_follows_idle_gate_inside_start_lock(self):
        order = []
        original_idle = self.store._assert_idle_locked
        original_resolve = self.store.resolve_snapshot_id

        def marked_idle(cleanups=None):
            order.append("idle")
            return original_idle(cleanups)

        def marked_resolve(snapshot_id):
            order.append("resolve")
            self.assertEqual(order[:2], ["idle", "resolve"])
            return original_resolve(snapshot_id)

        self.store._assert_idle_locked = marked_idle
        self.store.resolve_snapshot_id = marked_resolve
        self.store.start("rollback", snapshot_id=self.snapshot_id)
        self.assertEqual(order[:2], ["idle", "resolve"])

    def test_config_import_fixed_argv_and_terminal_cleanup_outside_lock(self):
        import_id = "imp-" + "a" * 32
        record = self.store.start("config-import", import_id=import_id)
        self.assertEqual(self.store.run(record["id"]), 0)
        apply_argv = [
            str(self.root / "python3"), str(self.root / "pdgconfigio.py"),
            "apply", "--import-id", import_id,
        ]
        discard_argv = [
            str(self.root / "python3"), str(self.root / "pdgconfigio.py"),
            "discard", "--import-id", import_id,
        ]
        self.assertIn(apply_argv, self.calls)
        self.assertIn(discard_argv, self.calls)
        self.assertTrue(self.cleanup_lock_was_free)
        final = self.store.get(record["id"])
        self.assertEqual(final["status"], "succeeded")

    def test_launcher_exception_after_runner_started_keeps_durable_import_claim(self):
        import_id = "imp-" + "c" * 32
        original_run = self.store._run_command

        def accepted_then_raised(argv, **kwargs):
            if argv and argv[0] == str(self.root / "systemd-run"):
                job_id = argv[-1]
                with self.store._locked(blocking=True):
                    record = self.store._read_record(job_id)
                    record["status"] = "running"
                    record["startedAt"] = self.module._utc_now()
                    self.store._write_record(record)
                raise RuntimeError("client hook failed after systemd accepted unit")
            if argv[:2] == ["systemctl", "is-active"]:
                return FakeResult(returncode=0, stdout="active\n")
            return original_run(argv, **kwargs)

        self.store._run_command = accepted_then_raised
        record = self.store.start("config-import", import_id=import_id)
        self.assertEqual(record["status"], "running")
        self.assertFalse(self.store.can_release_import(import_id))
        self.assertFalse(any("discard" in call for call in self.calls))

    def test_launcher_exception_after_unit_accept_before_runner_keeps_claim(self):
        import_id = "imp-" + "d" * 32
        original_run = self.store._run_command

        def accepted_queued_then_raised(argv, **kwargs):
            if argv and argv[0] == str(self.root / "systemd-run"):
                raise RuntimeError(
                    "client hook failed after unit acceptance but before runner start")
            if argv[:2] == ["systemctl", "show"]:
                return FakeResult(returncode=0, stdout="loaded\n")
            if argv[:2] == ["systemctl", "is-active"]:
                return FakeResult(returncode=3, stdout="inactive\n")
            return original_run(argv, **kwargs)

        self.store._run_command = accepted_queued_then_raised
        record = self.store.start("config-import", import_id=import_id)
        self.assertEqual(record["status"], "queued")
        self.assertFalse(self.store.can_release_import(import_id))
        self.assertFalse(any("discard" in call for call in self.calls))

    def test_definitive_launcher_rejection_terminalizes_and_cleans_import(self):
        import_id = "imp-" + "e" * 32
        original_run = self.store._run_command

        def rejected(argv, **kwargs):
            if argv and argv[0] == str(self.root / "systemd-run"):
                return FakeResult(returncode=1)
            if argv[:2] == ["systemctl", "show"]:
                return FakeResult(returncode=0, stdout="not-found\n")
            return original_run(argv, **kwargs)

        self.store._run_command = rejected
        with self.assertRaises(self.module.JobStartError):
            self.store.start("config-import", import_id=import_id)
        jobs = self.store.list()
        self.assertEqual(jobs[0]["status"], "failed")
        self.assertEqual(jobs[0]["result"], "launcher_failed")
        self.assertTrue(any("discard" in call for call in self.calls))

    def test_start_failure_still_cleans_reconciled_import_outside_lock(self):
        interrupted_id = "20260729t010203z-ffffffffffff"
        active_id = "20260729t010203z-000000000001"
        import_id = "imp-" + "b" * 32
        with self.store._locked():
            self.store._write_record({
                "id": interrupted_id, "kind": "config-import",
                "importId": import_id, "status": "queued",
                "createdAt": "2026-07-29T01:02:03Z",
                "bootId": "00000000-0000-0000-0000-000000000000",
                "unit": "pdg-web-job-" + interrupted_id + ".service",
            })
            self.store._write_record({
                "id": active_id, "kind": "software-update", "status": "queued",
                "createdAt": self.module._utc_now(),
                "bootId": self.module._boot_id(),
                "unit": "pdg-web-job-" + active_id + ".service",
            })
        with self.assertRaises(self.module.JobBusy):
            self.store.start("software-update")
        self.assertIn([
            str(self.root / "python3"), str(self.root / "pdgconfigio.py"),
            "discard", "--import-id", import_id,
        ], self.calls)
        self.assertTrue(self.cleanup_lock_was_free)

    def test_terminal_job_pruning_is_bounded_and_never_removes_active(self):
        active = self.store.start("software-update")
        with self.store._locked():
            for index in range(55):
                self.store._write_record({
                    "id": (
                        "20260729t010203z-"
                        + f"{index:012x}"
                    ),
                    "kind": "software-update",
                    "status": "succeeded",
                    "createdAt": "2026-07-29T01:02:03Z",
                    "startedAt": "2026-07-29T01:02:03Z",
                    "finishedAt": "2026-07-29T01:02:04Z",
                    "bootId": "unknown",
                    "unit": (
                        "pdg-web-job-20260729t010203z-"
                        + f"{index:012x}"
                        + ".service"
                    ),
                    "result": "completed",
                })
            self.store._prune_terminal_locked()
            records = [
                self.store._read_record(job_id)
                for job_id in self.store._record_ids()
            ]
        self.assertTrue(any(
            record["id"] == active["id"] for record in records
        ))
        self.assertEqual(
            sum(record["status"] in {"succeeded", "failed", "interrupted"}
                for record in records),
            50,
        )

    def test_corrupted_active_record_fails_closed(self):
        active = self.store.start("software-update")
        path = pathlib.Path(self.store._record_path(active["id"]))
        corrupted = json.loads(path.read_text(encoding="utf-8"))
        corrupted["status"] = "not-a-real-status"
        path.write_text(json.dumps(corrupted), encoding="utf-8")
        os.chmod(path, 0o600)
        with self.assertRaises(self.module.JobInvalid):
            self.store._read_record(active["id"])
        corrupted["createdAt"] = None
        path.write_text(json.dumps(corrupted), encoding="utf-8")
        os.chmod(path, 0o600)
        with self.assertRaises(self.module.JobInvalid):
            self.store._read_record(active["id"])
        corrupted["createdAt"] = active["createdAt"]
        corrupted["status"] = "succeeded"
        corrupted["finishedAt"] = corrupted["createdAt"]
        corrupted["result"] = "operation_failed"
        path.write_text(json.dumps(corrupted), encoding="utf-8")
        os.chmod(path, 0o600)
        with self.assertRaises(self.module.JobInvalid):
            self.store._read_record(active["id"])
        launches = len([
            call for call in self.calls
            if call and call[0] == str(self.root / "systemd-run")
        ])
        with self.assertRaises(self.module.JobInvalid):
            self.store.start("software-update")
        self.assertEqual(
            len([
                call for call in self.calls
                if call and call[0] == str(self.root / "systemd-run")
            ]),
            launches,
        )

    def test_legacy_cleanup_stops_import_units_and_preserves_older_job_records(self):
        stamp = "2026-07-29T01:02:03Z"
        import_id = "imp-" + "a" * 32
        import_job = "20260729t010203z-abcdef123456"
        old_job = "20260729t010204z-abcdef123457"
        self.store._write_record({
            "id": import_job, "kind": "config-import", "status": "succeeded",
            "createdAt": stamp, "startedAt": stamp, "finishedAt": stamp,
            "bootId": "unknown", "result": "completed", "importId": import_id,
            "unit": "pdg-web-job-" + import_job + ".service",
        })
        self.store._write_record({
            "id": old_job, "kind": "software-update", "status": "failed",
            "createdAt": stamp, "finishedAt": stamp, "bootId": "unknown",
            "result": "launcher_failed",
            "unit": "pdg-web-job-" + old_job + ".service",
        })
        original_run = self.store._run_command

        def loaded_then_stopped(argv, **kwargs):
            self.calls.append(list(argv))
            if argv[:2] == ["systemctl", "show"]:
                return FakeResult(returncode=0, stdout="loaded\n")
            if argv[:2] == ["systemctl", "stop"]:
                return FakeResult(returncode=0)
            if argv[:2] == ["systemctl", "is-active"]:
                return FakeResult(returncode=3, stdout="inactive\n")
            return original_run(argv, **kwargs)

        self.store._run_command = loaded_then_stopped
        self.store.cleanup_config_import_for_legacy()
        self.assertFalse(pathlib.Path(self.store._record_path(import_job)).exists())
        self.assertEqual(self.store._read_record(old_job)["kind"], "software-update")
        self.assertIn(["systemctl", "stop",
                       "pdg-web-job-" + import_job + ".service"], self.calls)

    def test_legacy_cleanup_keeps_import_record_if_unit_cannot_be_stopped(self):
        stamp = "2026-07-29T01:02:03Z"
        job_id = "20260729t010203z-abcdef123456"
        self.store._write_record({
            "id": job_id, "kind": "config-import", "status": "running",
            "createdAt": stamp, "startedAt": stamp, "bootId": "unknown",
            "importId": "imp-" + "b" * 32,
            "unit": "pdg-web-job-" + job_id + ".service",
        })

        def cannot_stop(argv, **_kwargs):
            if argv[:2] == ["systemctl", "show"]:
                return FakeResult(returncode=0, stdout="loaded\n")
            if argv[:2] == ["systemctl", "stop"]:
                return FakeResult(returncode=1)
            return FakeResult(returncode=0, stdout="active\n")

        self.store._run_command = cannot_stop
        with self.assertRaises(self.module.JobInvalid):
            self.store.cleanup_config_import_for_legacy()
        self.assertTrue(pathlib.Path(self.store._record_path(job_id)).exists())

    def test_record_started_timestamp_result_combinations(self):
        job_id = "20260729t010203z-abcdef123456"
        common = {
            "id": job_id,
            "kind": "software-update",
            "createdAt": "2026-07-29T01:02:03Z",
            "bootId": "unknown",
            "unit": "pdg-web-job-" + job_id + ".service",
        }

        def terminal(status, result, *, started=False):
            record = {
                **common,
                "status": status,
                "finishedAt": "2026-07-29T01:02:05Z",
                "result": result,
            }
            if started:
                record["startedAt"] = "2026-07-29T01:02:04Z"
            return record

        invalid = [
            {**common, "status": "queued", "createdAt": None},
            {**common, "status": "running", "startedAt": None},
            terminal("succeeded", "completed"),
            {
                **terminal("succeeded", "completed", started=True),
                "finishedAt": None,
            },
            terminal("failed", "operation_failed"),
            terminal("failed", "operation_timed_out"),
            terminal("failed", "launcher_failed", started=True),
            terminal("interrupted", "boot_changed", started=True),
        ]
        for record in invalid:
            with self.subTest(record=record):
                with self.assertRaises(self.module.JobInvalid):
                    self.store._validate_record(record, job_id)

        valid = [
            terminal("succeeded", "completed", started=True),
            terminal("failed", "operation_failed", started=True),
            terminal("failed", "operation_timed_out", started=True),
            terminal("failed", "launcher_failed"),
            terminal("interrupted", "boot_changed"),
            terminal("interrupted", "runner_interrupted"),
            terminal("interrupted", "runner_interrupted", started=True),
        ]
        for record in valid:
            with self.subTest(record=record):
                self.assertEqual(
                    self.store._validate_record(record, job_id), record
                )

    def test_snapshot_listing_ignores_untrusted_names_and_symlinks(self):
        (self.snapshots / "../ignored").resolve()
        bad = self.snapshots / "20260729-010204-deadbeef"
        try:
            bad.symlink_to(self.snapshots / self.snapshot_id, target_is_directory=True)
        except (OSError, NotImplementedError):
            bad = None
        items = self.store.list_snapshots()
        self.assertEqual([item["id"] for item in items], [self.snapshot_id])

    def test_preexisting_state_symlink_is_rejected_without_chmod_target(self):
        target = self.root / "target"
        target.mkdir()
        os.chmod(target, 0o755)
        link = self.root / "linked-state"
        try:
            link.symlink_to(target, target_is_directory=True)
        except (OSError, NotImplementedError):
            self.skipTest("directory symlinks unavailable")
        before = stat.S_IMODE(target.stat().st_mode)
        with self.assertRaises(self.module.JobInvalid):
            self.module.JobStore(
                state_dir=str(link), snapshot_dir=str(self.snapshots),
                enforce_root_owner=False)
        self.assertEqual(stat.S_IMODE(target.stat().st_mode), before)

    @unittest.skipIf(os.name == "nt", "POSIX ownership contract")
    def test_non_root_owned_records_and_snapshots_are_rejected(self):
        record = self.store.start("software-update")
        os.chmod(self.store._record_path(record["id"]), 0o660)
        os.chmod(self.snapshots, 0o770)
        self.store._enforce_root_owner = True
        with self.assertRaises(self.module.JobInvalid):
            self.store._read_record(record["id"])
        with self.assertRaises(self.module.JobInvalid):
            self.store.list_snapshots()


if __name__ == "__main__":
    unittest.main(verbosity=2)

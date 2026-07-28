#!/usr/bin/env python3
"""Black-box contract and security tests for the native PDG Web API."""
from __future__ import annotations

import base64
import copy
import hashlib
import http.client
import importlib.util
import json
import os
import pathlib
import socket
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

    def load(self):
        return copy.deepcopy(self.model)

    def _rs_meta(self):
        return copy.deepcopy(self.meta)

    def exit_tags(self, model):
        allowed = self.PROXY_TYPES + ("direct", "urltest")
        return [
            item["tag"]
            for item in model.get("outbounds", [])
            if item.get("type") in allowed
        ]

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
        }
        try:
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

    def add_group(self, tag, members):
        self.wrapper_calls.append(("add_group", tag, tuple(members)))
        allowed = set(self.concrete_tags(self.model))
        if not set(members).issubset(allowed):
            return False, "unknown member"
        for item in self.model["outbounds"]:
            if item.get("tag") == tag:
                if item.get("type") != "urltest":
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

    @staticmethod
    def clash_get(path):
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
        self.control = pdgcontrol.PDGControl(self.fake)
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
        rollback_argv = [
            "systemd-run",
            "--collect",
            "--unit=pdg-web-rollback.service",
            "--",
            "/usr/local/bin/pdg",
            "rollback",
            "0",
        ]
        self.assertIn(rollback_argv, self.fake.sh_calls)
        self.assertNotIn(
            ["/usr/local/bin/pdg", "rollback", "0"],
            self.fake.sh_calls,
        )
        self.assertLess(
            self.fake.wrapper_calls.index(("update_check",)),
            self.fake.wrapper_calls.index(("start_update",)),
        )

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
            ("PUT", "/api/v1/dns/remote", {"upstreams": ["udp://1.1.1.1"]}),
            ("PUT", "/api/v1/settings/tfo", {"enabled": 1}),
            ("POST", "/api/v1/actions/restart", {"confirm": True}),
            ("POST", "/api/v1/actions/rollback", {"index": -1}),
            ("POST", "/api/v1/actions/rollback", {"index": True}),
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
                before = self.fake.wrapper_calls.count(("start_update",))
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
                    self.fake.wrapper_calls.count(("start_update",)), before
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
            [("update_check",), ("start_update",)],
        )
        self.assertNotIn(PLAIN_SECRET, response["text"])

    def test_rollback_uses_fixed_transient_unit_argv_without_direct_cli(self):
        self.login()
        self.fake.sh_calls.clear()
        response = self.request(
            "POST", "/api/v1/actions/rollback", {"index": 7}
        )
        self.assertEqual(response["status"], 202, response["text"])
        self.assertEqual(
            response["json"]["data"],
            {"action": "rollback", "accepted": True},
        )
        self.assertEqual(
            self.fake.sh_calls,
            [[
                "systemd-run",
                "--collect",
                "--unit=pdg-web-rollback.service",
                "--",
                "/usr/local/bin/pdg",
                "rollback",
                "7",
            ]],
        )
        self.assertFalse(
            any(
                call[:2] == ["/usr/local/bin/pdg", "rollback"]
                for call in self.fake.sh_calls
            )
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


if __name__ == "__main__":
    unittest.main(verbosity=2)

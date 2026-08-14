#!/usr/bin/env python3
"""Canonical policy-group schema-v3 migration, closure and rendering regressions."""
from __future__ import annotations

import copy
import json
import sys
import types
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "deploy" / "bot"))
sys.path.insert(0, str(ROOT / "deploy" / "web"))

import pdgconfigio  # noqa: E402
import pdgmodel  # noqa: E402
import sb2mihomo  # noqa: E402
try:  # pdgtx uses POSIX locking in production; this validator test does not.
    import fcntl  # noqa: F401,E402
except ImportError:  # pragma: no cover - Windows developer workstation only
    fcntl_stub = types.ModuleType("fcntl")
    fcntl_stub.LOCK_EX = 2
    fcntl_stub.LOCK_NB = 4
    fcntl_stub.LOCK_UN = 8
    fcntl_stub.flock = lambda *_args, **_kwargs: None
    sys.modules["fcntl"] = fcntl_stub
import pdgtx  # noqa: E402


def v3_model() -> dict:
    return pdgmodel.migrate({
        "outbounds": [
            {"type": "direct", "tag": "KFC_JP"},
            {"type": "shadowsocks", "tag": "hk", "server": "hk.example",
             "server_port": 443, "method": "aes-128-gcm", "password": "x"},
            {"type": "shadowsocks", "tag": "tw", "server": "tw.example",
             "server_port": 443, "method": "aes-128-gcm", "password": "x"},
        ],
        "route": {"rules": [], "final": "KFC_JP"},
    })


class MigrationTests(unittest.TestCase):
    def legacy(self) -> dict:
        return {
            "outbounds": [
                {"type": "direct", "tag": "JP"},
                {"type": "shadowsocks", "tag": "hk"},
                {"type": "selector", "tag": "choice",
                 "outbounds": ["JP", "hk"]},
            ],
            "route": {"rules": [{"domain_suffix": ["x.example"],
                                    "outbound": "choice"}], "final": "choice"},
            "_pdg": {"schema": 2, "mihomo": {
                "proxy-groups": [
                    {"name": "fail", "type": "fallback",
                     "proxies": ["choice", "JP"], "use": [],
                     "url": "https://www.gstatic.com/generate_204", "interval": 120},
                    {"name": "choice", "type": "select",
                     "proxies": ["JP", "hk"], "use": [], "lazy": True},
                ],
                "proxy-providers": {}, "rule-providers": {},
                "advanced": {"tcp-concurrent": True}, "managed-files": {},
            }},
        }

    def test_v2_mirrors_merge_to_one_ordered_first_class_representation(self):
        result = pdgmodel.migrate(self.legacy())
        self.assertEqual(result["_pdg"]["schema"], 3)
        self.assertEqual([item["name"] for item in result["_pdg"]["policy-groups"]],
                         ["fail", "choice"])
        self.assertTrue(result["_pdg"]["policy-groups"][1]["lazy"])
        self.assertFalse(any(item.get("type") in {"selector", "urltest"}
                             for item in result["outbounds"]))
        self.assertNotIn("proxy-groups", result["_pdg"]["mihomo"])

    def test_v2_disagreement_and_missing_mirror_fail_closed(self):
        mutations = []
        bad = self.legacy()
        bad["_pdg"]["mihomo"]["proxy-groups"][1]["proxies"] = ["hk", "JP"]
        mutations.append(bad)
        bad = self.legacy()
        bad["_pdg"]["mihomo"]["proxy-groups"][1]["type"] = "url-test"
        mutations.append(bad)
        bad = self.legacy()
        bad["outbounds"] = [item for item in bad["outbounds"]
                            if item.get("tag") != "choice"]
        bad["route"] = {"rules": [], "final": "JP"}
        mutations.append(bad)
        bad = self.legacy()
        bad["_pdg"]["mihomo"]["proxy-groups"] = [
            item for item in bad["_pdg"]["mihomo"]["proxy-groups"]
            if item.get("name") != "choice"]
        mutations.append(bad)
        for candidate in mutations:
            with self.subTest(candidate=candidate), self.assertRaises(pdgmodel.ModelError):
                pdgmodel.migrate(candidate)

    def test_schema1_canonical_only_group_remains_compatible(self):
        candidate = self.legacy()
        candidate["_pdg"] = {"schema": 1, "mihomo": {}}
        result = pdgmodel.migrate(candidate)
        self.assertEqual(result["_pdg"]["schema"], 3)
        self.assertEqual(result["_pdg"]["policy-groups"], [{
            "name": "choice", "type": "select",
            "proxies": ["JP", "hk"], "use": [],
        }])

    def test_v3_rejects_every_legacy_mirror(self):
        candidate = v3_model()
        candidate["_pdg"]["mihomo"]["proxy-groups"] = []
        with self.assertRaises(pdgmodel.ModelError):
            pdgmodel.migrate(candidate)

    def test_declared_v3_envelope_is_exact_before_normalization(self):
        base = v3_model()
        malformed = []
        for key in ("schema", "policy-groups", "mihomo"):
            item = copy.deepcopy(base)
            item["_pdg"].pop(key)
            if key == "schema":
                item["_pdg"]["schema"] = 3
                item["_pdg"].pop("policy-groups")
            malformed.append(item)
        item = copy.deepcopy(base)
        item["_pdg"]["extra"] = {}
        malformed.append(item)
        item = copy.deepcopy(base)
        item["_pdg"]["policy-groups"] = {}
        malformed.append(item)
        for key in pdgmodel.V3_MIHOMO_FIELDS:
            item = copy.deepcopy(base)
            item["_pdg"]["mihomo"].pop(key)
            malformed.append(item)
            item = copy.deepcopy(base)
            item["_pdg"]["mihomo"][key] = []
            malformed.append(item)
        item = copy.deepcopy(base)
        item["_pdg"]["mihomo"]["unknown"] = {}
        malformed.append(item)
        for candidate in malformed:
            with self.subTest(candidate=candidate), self.assertRaises(
                    pdgmodel.ModelError):
                pdgmodel.migrate(candidate)


class ValidationTests(unittest.TestCase):
    def test_unicode_names_normalize_once_and_preserve_every_reference(self):
        candidate = v3_model()
        candidate["outbounds"][1]["tag"] = "  🇭🇰 香港 · IEPL #1  "
        candidate["outbounds"][2]["tag"] = "Cafe\u0301 / 主用"
        candidate["_pdg"]["mihomo"]["proxy-providers"] = {
            " 机场 Provider｜香港 ": {
                "type": "http",
                "url": "https://provider.example/sub.yaml",
                "path": "/etc/mihomo/providers/unicode.yaml",
                "interval": 3600,
            }
        }
        candidate["_pdg"]["policy-groups"] = [{
            "name": "东京/Reality｜主用",
            "type": "select",
            "proxies": ["  🇭🇰 香港 · IEPL #1  ", "Cafe\u0301 / 主用"],
            "use": [" 机场 Provider｜香港 "],
        }]
        candidate["route"]["final"] = "东京/Reality｜主用"

        result = pdgmodel.migrate(candidate)
        self.assertEqual(
            [item["tag"] for item in result["outbounds"][1:]],
            ["🇭🇰 香港 · IEPL #1", "Café / 主用"],
        )
        group = result["_pdg"]["policy-groups"][0]
        self.assertEqual(group["name"], "东京/Reality｜主用")
        self.assertEqual(group["proxies"], ["🇭🇰 香港 · IEPL #1", "Café / 主用"])
        self.assertEqual(group["use"], ["机场 Provider｜香港"])
        self.assertIn("机场 Provider｜香港", result["_pdg"]["mihomo"]["proxy-providers"])

    def test_nfc_equivalent_names_collide_in_the_canonical_namespace(self):
        candidate = v3_model()
        candidate["outbounds"][1]["tag"] = "Café"
        candidate["outbounds"][2]["tag"] = "Cafe\u0301"
        candidate["route"]["final"] = "Café"
        with self.assertRaises(pdgmodel.ModelError):
            pdgmodel.migrate(candidate)

    def test_name_contract_rejects_controls_and_keeps_emoji_zwj(self):
        accepted = (
            "🇭🇰 香港 · IEPL #1",
            "东京/Reality｜主用",
            "空 格 / % # ? < > &",
            "家庭 👨\u200d👩\u200d👧\u200d👦",
            "界" * 64,
            "😀" * 64,
        )
        for value in accepted:
            with self.subTest(accepted=value):
                self.assertEqual(pdgmodel.validate_name(value), value)

        rejected = (
            "", "   ", "line\nbreak", "trailing\n", "\tleading",
            "nul\x00name", "c1\x85name",
            "bidi\u202eoverride", "isolate\u2066name", "zero\u200bwidth",
            "nonjoin\u200cname", "tag\U000e0001name",
            "bom\ufeffname", "a" * 65, "😀" * 65,
        )
        for value in rejected:
            with self.subTest(rejected=repr(value)), self.assertRaises(
                    pdgmodel.NameValidationError) as raised:
                pdgmodel.normalize_name(value)
            self.assertIn(raised.exception.reason,
                          {"type", "encoding", "length", "unsafe", "canonical"})

        self.assertEqual(pdgmodel.normalize_name("  Cafe\u0301  "), "Café")

    def test_namespace_member_provider_and_route_target_closure(self):
        candidates = []
        base = v3_model()
        bad = copy.deepcopy(base)
        bad["_pdg"]["policy-groups"] = [
            {"name": "hk", "type": "select", "proxies": ["KFC_JP"], "use": []}]
        candidates.append(bad)
        bad = copy.deepcopy(base)
        bad["_pdg"]["policy-groups"] = [
            {"name": "g", "type": "select", "proxies": ["missing"], "use": []}]
        candidates.append(bad)
        bad = copy.deepcopy(base)
        bad["_pdg"]["policy-groups"] = [
            {"name": "g", "type": "select", "proxies": [], "use": ["missing"]}]
        candidates.append(bad)
        bad = copy.deepcopy(base)
        bad["route"]["final"] = "missing"
        candidates.append(bad)
        for candidate in candidates:
            with self.subTest(candidate=candidate), self.assertRaises(pdgmodel.ModelError):
                pdgmodel.migrate(candidate)

    def test_nested_group_dag_accepts_closure_and_rejects_cycles(self):
        candidate = v3_model()
        candidate["_pdg"]["policy-groups"] = [
            {"name": "leaf", "type": "select",
             "proxies": ["KFC_JP", "hk"], "use": []},
            {"name": "root", "type": "fallback", "proxies": ["leaf", "tw"],
             "use": [], "url": "https://www.gstatic.com/generate_204", "interval": 180},
        ]
        candidate["route"]["final"] = "root"
        pdgmodel.validate(candidate)
        candidate["_pdg"]["policy-groups"][0]["proxies"] = ["root", "hk"]
        with self.assertRaisesRegex(pdgmodel.ModelError, "cycle"):
            pdgmodel.validate(candidate)

    def test_type_specific_whitelists_reject_machine_fields(self):
        for typ, field in (("select", "interface-name"),
                           ("url-test", "strategy"),
                           ("fallback", "tolerance"),
                           ("load-balance", "routing-mark")):
            candidate = v3_model()
            group = {"name": "g", "type": typ, "proxies": ["hk"], "use": [],
                     field: "unsafe"}
            if typ != "select":
                group.update(url="https://www.gstatic.com/generate_204", interval=180)
            candidate["_pdg"]["policy-groups"] = [group]
            with self.subTest(typ=typ), self.assertRaises(pdgmodel.ModelError):
                pdgmodel.validate(candidate)

    def test_machine_outbounds_are_not_routable_but_block_is(self):
        candidate = v3_model()
        candidate["outbounds"].extend([
            {"type": "dns", "tag": "dns-out"},
            {"type": "block", "tag": "deny"},
        ])
        candidate["_pdg"]["policy-groups"] = [{
            "name": "g", "type": "select", "proxies": ["deny", "hk"], "use": [],
        }]
        candidate["route"]["final"] = "deny"
        pdgmodel.validate(candidate)
        self.assertIn("deny", pdgmodel.routable_tags(candidate))
        self.assertNotIn("dns-out", pdgmodel.routable_tags(candidate))
        for mutation in ("group", "final", "rule"):
            bad = copy.deepcopy(candidate)
            if mutation == "group":
                bad["_pdg"]["policy-groups"][0]["proxies"][0] = "dns-out"
            elif mutation == "final":
                bad["route"]["final"] = "dns-out"
            else:
                bad["route"]["rules"] = [{"domain_suffix": ["x"],
                                            "outbound": "dns-out"}]
            with self.subTest(mutation=mutation), self.assertRaises(pdgmodel.ModelError):
                pdgmodel.validate(bad)

        ambiguous = copy.deepcopy(candidate)
        ambiguous["_pdg"]["policy-groups"][0]["proxies"] = ["deny", "REJECT"]
        with self.assertRaisesRegex(pdgmodel.ModelError, "ambiguous REJECT"):
            pdgmodel.validate(ambiguous)

    def test_all_mihomo_builtin_names_are_reserved(self):
        for reserved in sorted(pdgmodel.RESERVED_TARGETS):
            candidate = v3_model()
            candidate["_pdg"]["policy-groups"] = [{
                "name": reserved, "type": "select",
                "proxies": ["hk"], "use": [],
            }]
            with self.subTest(reserved=reserved), self.assertRaises(
                    pdgmodel.ModelError):
                pdgmodel.validate(candidate)

    def test_ruleset_keys_share_the_entire_mihomo_namespace(self):
        base = v3_model()
        base["outbounds"].append({"type": "block", "tag": "deny"})
        base["_pdg"]["policy-groups"] = [{
            "name": "choice", "type": "select", "proxies": ["hk"], "use": []}]
        base["_pdg"]["mihomo"]["proxy-providers"] = {"airport": {}}
        base["_pdg"]["mihomo"]["rule-providers"] = {"remote-rule": {}}
        pdgmodel.validate(base)
        for name in ("DIRECT", "REJECT", "KFC_JP", "hk", "deny", "choice",
                     "airport", "remote-rule"):
            with self.subTest(name=name), self.assertRaises(pdgmodel.ModelError):
                pdgmodel.validate_ruleset_namespace(base, {name})
        pdgmodel.validate_ruleset_namespace(base, {"rs_safe"})
        pdgmodel.validate_ruleset_namespace(base, {"规则集 / 香港 #1"})
        with self.assertRaisesRegex(pdgmodel.ModelError, "Unicode normalization"):
            pdgmodel.validate_ruleset_namespace(base, ["é", "e\u0301"])

    def test_unicode_ruleset_provider_keeps_name_and_uses_safe_cache_leaf(self):
        self.assertEqual(pdgtx._pdg_ruleset_cache_stem("rs_safe"), "rs_safe")
        name = "规则集 / 香港 #1"
        stem = pdgtx._pdg_ruleset_cache_stem(name)
        self.assertRegex(stem, r"^u-[0-9a-f]{64}$")
        self.assertEqual(stem, pdgtx._pdg_ruleset_cache_stem(name))
        self.assertNotIn(name, stem)
        with self.assertRaises(ValueError):
            pdgtx._pdg_ruleset_cache_stem("e\u0301")
        with self.assertRaises(pdgmodel.NameValidationError):
            pdgtx._pdg_ruleset_cache_stem("bad\u202ename")

    def test_transaction_validator_closes_ruleset_route_targets(self):
        candidate = v3_model()
        candidate["outbounds"].extend([
            {"type": "dns", "tag": "dns-out"},
            {"type": "block", "tag": "deny"},
        ])
        encoded = json.dumps(candidate).encode("utf-8")

        def validate_target(target):
            metadata = {"rs_11111111": {
                "url": "https://example.invalid/rules.txt",
                "outbound": target,
            }}
            ctx = types.SimpleNamespace(targets={"rs_meta": {
                "data": json.dumps(metadata).encode("utf-8")}})
            return pdgtx._v_json_model("config.json", encoded, ctx)

        for target in ("KFC_JP", "deny", "direct"):
            with self.subTest(valid=target):
                ok, error = validate_target(target)
                self.assertTrue(ok, error)
        for target in ("dns-out", "missing", "REJECT"):
            with self.subTest(invalid=target):
                ok, error = validate_target(target)
                self.assertFalse(ok)
                self.assertIn("不可路由", error)


class RenderingAndImportTests(unittest.TestCase):
    def test_unicode_names_render_without_rewriting_or_splitting(self):
        candidate = v3_model()
        candidate["outbounds"][1]["tag"] = "🇭🇰 香港 · IEPL #1"
        candidate["outbounds"][2]["tag"] = "东京/Reality｜主用"
        candidate["_pdg"]["mihomo"]["proxy-providers"] = {
            "机场 Provider｜香港": {
                "type": "http",
                "url": "https://provider.example/sub.yaml",
                "path": "/etc/mihomo/providers/unicode.yaml",
                "interval": 3600,
            }
        }
        candidate["_pdg"]["policy-groups"] = [{
            "name": "精选 / 自动 #1",
            "type": "select",
            "proxies": ["🇭🇰 香港 · IEPL #1", "东京/Reality｜主用"],
            "use": ["机场 Provider｜香港"],
        }]
        candidate["route"]["final"] = "精选 / 自动 #1"

        rendered, _metadata = sb2mihomo.singbox_to_mihomo(pdgmodel.migrate(candidate))
        self.assertEqual(
            [item["name"] for item in rendered["proxies"]],
            ["🇭🇰 香港 · IEPL #1", "东京/Reality｜主用"],
        )
        group = next(item for item in rendered["proxy-groups"]
                     if item["name"] == "精选 / 自动 #1")
        self.assertEqual(group["proxies"], ["🇭🇰 香港 · IEPL #1", "东京/Reality｜主用"])
        self.assertEqual(group["use"], ["机场 Provider｜香港"])
        self.assertEqual(rendered["rules"][-1], "MATCH,精选 / 自动 #1")

    def test_all_four_group_types_nested_provider_and_reserved_targets_render(self):
        candidate = v3_model()
        candidate["outbounds"].insert(1, {"type": "block", "tag": "block"})
        candidate["_pdg"]["mihomo"]["proxy-providers"] = {
            "remote": {"type": "http", "url": "https://provider.example/sub.yaml",
                       "path": "/etc/mihomo/providers/remote.yaml", "interval": 3600}}
        candidate["_pdg"]["policy-groups"] = [
            {"name": "choice", "type": "select",
             "proxies": ["KFC_JP", "hk"], "use": []},
            {"name": "fast", "type": "url-test", "proxies": ["choice", "tw"],
             "use": [], "url": "https://probe.example/204", "interval": 120,
             "tolerance": 25},
            {"name": "fail", "type": "fallback", "proxies": ["fast", "KFC_JP"],
             "use": [], "url": "https://probe.example/204", "interval": 180},
            {"name": "balanced", "type": "load-balance",
             "proxies": ["fail", "REJECT"], "use": ["remote"],
             "url": "https://probe.example/204", "interval": 300,
             "strategy": "round-robin"},
        ]
        candidate["route"] = {
            "rules": [{"domain_suffix": ["x.example"], "outbound": "balanced"}],
            "final": "choice",
        }
        rendered, _metadata = sb2mihomo.singbox_to_mihomo(candidate)
        groups = {item["name"]: item for item in rendered["proxy-groups"]}
        self.assertEqual(set(groups), {"choice", "fast", "fail", "balanced"})
        self.assertEqual(groups["choice"]["proxies"], ["DIRECT", "hk"])
        self.assertEqual(groups["fail"]["proxies"], ["fast", "DIRECT"])
        self.assertEqual(groups["balanced"]["proxies"], ["fail", "REJECT"])
        self.assertEqual(groups["balanced"]["use"], ["remote"])
        self.assertEqual(groups["balanced"]["strategy"], "round-robin")
        self.assertEqual(rendered["rules"][-1], "MATCH,choice")

    def test_mihomo_import_binds_direct_to_current_machine_and_has_no_mirror(self):
        document = {
            "proxies": [
                {"name": "hk", "type": "socks5", "server": "hk.example", "port": 1080}],
            "proxy-providers": {}, "rule-providers": {},
            "proxy-groups": [
                {"name": "choice", "type": "select", "proxies": ["DIRECT", "hk"]},
                {"name": "fail", "type": "fallback", "proxies": ["choice", "DIRECT"],
                 "url": "https://www.gstatic.com/generate_204", "interval": 180},
            ],
            "rules": ["MATCH,fail"],
        }
        imported, _warnings = pdgconfigio.mihomo_to_model(
            document, v3_model(), archive=None, config_name="config.yaml")
        self.assertEqual(imported["_pdg"]["schema"], 3)
        self.assertNotIn("proxy-groups", imported["_pdg"]["mihomo"])
        self.assertFalse(any(item.get("type") in {"selector", "urltest"}
                             for item in imported["outbounds"]))
        self.assertEqual(imported["_pdg"]["policy-groups"][0]["proxies"],
                         ["KFC_JP", "hk"])
        self.assertEqual(imported["_pdg"]["policy-groups"][1]["proxies"],
                         ["choice", "KFC_JP"])


if __name__ == "__main__":
    unittest.main(verbosity=2)

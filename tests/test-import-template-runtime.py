#!/usr/bin/env python3
"""Prepare both repository import templates through the real production stack."""
from __future__ import annotations

import base64
import copy
import hashlib
import importlib.util
import json
import os
import pathlib
import sys

import yaml

ROOT = pathlib.Path(__file__).resolve().parents[1]
BOT_DIR = (ROOT / "deploy" / "bot").resolve()
WORK = pathlib.Path(sys.argv[1]).resolve()

# These production modules use ordinary sibling imports (not a Python
# package).  Mirror their installed /opt/pdg-bot layout with one exact,
# highest-priority repository path before executing any of them by filename.
bot_path = str(BOT_DIR)
if not sys.path or sys.path[0] != bot_path:
    sys.path.insert(0, bot_path)


def load(name: str, path: pathlib.Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    assert spec.loader
    spec.loader.exec_module(module)
    return module


cio = load("pdgconfigio_runtime", ROOT / "deploy/web/pdgconfigio.py")
sb2 = load("sb2mihomo_runtime", ROOT / "deploy/bot/sb2mihomo.py")
tx = None if os.name == "nt" else load("pdgtx_runtime", ROOT / "deploy/bot/pdgtx.py")
shared_model = sys.modules.get("pdgmodel")
if (shared_model is None
        or pathlib.Path(shared_model.__file__).resolve().parent != BOT_DIR):
    raise RuntimeError("shared pdgmodel was not loaded from the repository Bot directory")

stage = WORK / "stage"
providers = WORK / "providers"
rules = WORK / "rules"
certs = WORK / "certs"
for directory in (stage, providers, rules, certs):
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)

model = {
    "outbounds": [{"type": "direct", "tag": "JP"}],
    "route": {"rules": [], "final": "JP"},
    "_pdg": {"schema": 2, "mihomo": {
        "proxy-providers": {}, "rule-providers": {}, "proxy-groups": [],
        "advanced": {}, "managed-files": {},
    }},
}

current_mosdns = (ROOT / "deploy/mosdns/config.yaml").read_text(encoding="utf-8")
identity = {
    "__SERVER_IP__": "203.0.113.25",
    "__INTERNAL_CIDR__": "192.0.2.0/24",
    "__CERT_DIR__": certs.as_posix(),
    "__HIJACK_SET_FILE__": "geosite_gfw.txt",
    "__MOSDNS_CACHE__": "1024",
}
for old, new in identity.items():
    current_mosdns = current_mosdns.replace(old, new)
current_mosdns = current_mosdns.replace("/etc/mosdns/rules/", rules.as_posix() + "/")
mosdns_path = WORK / "current-mosdns.yaml"
mosdns_path.write_text(current_mosdns, encoding="utf-8")
model_path = WORK / "model.json"
model_path.write_text(json.dumps(model), encoding="utf-8")
ruleset_meta = WORK / "rulesets.json"
ruleset_meta.write_text("{}\n", encoding="utf-8")

cio.MODEL_PATH = str(model_path)
cio.MOSDNS_PATH = str(mosdns_path)
cio.MIHOMO_PROVIDER_DIR = str(providers)
cio.RULESET_META_PATH = str(ruleset_meta)
cio.MOSDNS_RULE_DIR = rules.as_posix()
cio.MOSDNS_CERT_DIR = certs.as_posix()


class Bot:
    def load(self):
        return json.loads(model_path.read_text(encoding="utf-8"))


manager = cio.ConfigIO(bot=Bot(), staging_dir=str(stage), enforce_root_owner=False)

# Repository bytes -> strict preview -> staged candidate -> production renderer.
mihomo_raw = (ROOT / "deploy/web/static/templates/mihomo-import.example.yaml").read_bytes()
mihomo_preview = manager.preview("mihomo", mihomo_raw, "application/yaml")
mihomo_record = manager._record(mihomo_preview["importId"])
candidate_model = cio.normalize_model(mihomo_record["candidate"]["model"])
if tx is not None:
    valid, error = tx._v_json_model(
        "model.json", json.dumps(candidate_model).encode("utf-8"), None)
    if not valid:
        raise RuntimeError("pdgtx rejected Mihomo candidate: " + error)
rendered, metadata = sb2.singbox_to_mihomo(
    candidate_model, redir_port=17893, controller="127.0.0.1:19090",
    rulesets={})
if metadata.get("dropped") or metadata.get("unknown_proxies"):
    raise RuntimeError("Mihomo template lost canonical content")
standalone_rendered = copy.deepcopy(rendered)
for kind, field in (("proxy", "proxy-providers"), ("rule", "rule-providers")):
    for provider in (standalone_rendered.get(field) or {}).values():
        leaf = pathlib.Path(provider["path"]).name
        target = providers / leaf
        target.write_text(
            "proxies: []\n" if kind == "proxy" else "payload:\n  - '+.example.org'\n",
            encoding="utf-8")
        provider["path"] = str(target)
(WORK / "mihomo.yaml").write_text(
    json.dumps(standalone_rendered, ensure_ascii=False, indent=2), encoding="utf-8")

# Repository bytes -> strict full-graph contract -> five-value machine rebind.
mosdns_raw = (ROOT / "deploy/web/static/templates/mosdns-import.example.yaml").read_bytes()
mosdns_preview = manager.preview("mosdns", mosdns_raw, "application/yaml")
mosdns_record = manager._record(mosdns_preview["importId"])
managed = yaml.safe_load(base64.b64decode(mosdns_record["candidate"]["mosdns"]))
serialized = yaml.safe_dump(managed, allow_unicode=True, sort_keys=False)
for expected in identity.values():
    if expected not in serialized:
        raise RuntimeError("MosDNS identity was not rebound: " + expected)
if "__" in serialized:
    raise RuntimeError("MosDNS candidate retains a placeholder")
for plugin in managed["plugins"]:
    if plugin.get("tag") in {"udp_server", "tcp_server"}:
        plugin["args"]["listen"] = "127.0.0.1:15353"
    elif plugin.get("tag") == "dot_server":
        plugin["args"]["listen"] = "127.0.0.1:15853"
(WORK / "config.yaml").write_text(
    yaml.safe_dump(managed, allow_unicode=True, sort_keys=False), encoding="utf-8")

for leaf in {
        "unlock.txt", "geosite_cn.txt", "geosite_apple.txt", "custom_direct.txt",
        "ruleset_direct.txt", "geosite_gfw.txt", "custom_hijack.txt", "ruleset_hijack.txt",
        "mitm_hijack.txt"}:
    (rules / leaf).write_text("", encoding="utf-8")

if tx is not None:
    class CandidateContext:
        def __init__(self, candidate, rs_meta=None, extra_targets=None):
            self.targets = {"model": {
                "data": json.dumps(candidate, ensure_ascii=False).encode("utf-8")}}
            if rs_meta is not None:
                self.targets["rs_meta"] = {
                    "data": json.dumps(rs_meta, ensure_ascii=False).encode("utf-8")}
            self.targets.update(extra_targets or {})

    original_run = tx._run
    observed_provider_paths = []
    runner_calls = []

    def isolated_run(argv, *args, **kwargs):
        runner_calls.append(argv)
        if argv and pathlib.Path(argv[0]).name == "mihomo" and "-f" in argv:
            config_path = pathlib.Path(argv[argv.index("-f") + 1])
            checked = json.loads(config_path.read_text(encoding="utf-8"))
            for field in ("proxy-providers", "rule-providers"):
                for provider in (checked.get(field) or {}).values():
                    path = pathlib.Path(provider["path"]).resolve()
                    if "/etc/mihomo/providers" in path.as_posix():
                        raise RuntimeError("production validator consulted a live provider path")
                    if path.parent.name != "providers" or not path.is_file():
                        raise RuntimeError("production validator did not materialize a provider")
                    observed_provider_paths.append(path)
        return original_run(argv, *args, **kwargs)

    tx._run = isolated_run
    good_mihomo = json.dumps(rendered, ensure_ascii=False, indent=2).encode("utf-8")
    try:
        valid, error = tx._v_mihomo_check(
            "mihomo.yaml", good_mihomo, CandidateContext(candidate_model))
        if not valid:
            raise RuntimeError("production Mihomo validator rejected candidate: " + error)
        if not observed_provider_paths:
            raise RuntimeError("production validator did not inspect isolated providers")

        # Model-only transactions must also materialize embedded local
        # provider bytes; no live cache may complete the candidate by accident.
        local_model = copy.deepcopy(candidate_model)
        local_raw = b"proxies: []\n"
        local_leaf = hashlib.sha256(local_raw).hexdigest() + ".yaml"
        local_meta = local_model["_pdg"]["mihomo"]
        local_meta["proxy-providers"]["runtime-local"] = {
            "type": "file", "path": "/etc/mihomo/providers/" + local_leaf}
        local_meta["managed-files"][local_leaf] = base64.b64encode(local_raw).decode("ascii")
        local_model = cio.normalize_model(local_model)
        local_rendered, _ = sb2.singbox_to_mihomo(local_model, rulesets={})
        valid, error = tx._v_mihomo_check(
            "mihomo-local.yaml",
            json.dumps(local_rendered, ensure_ascii=False).encode("utf-8"),
            CandidateContext(local_model))
        if not valid:
            raise RuntimeError("production Mihomo validator rejected local provider: " + error)

        # PDG-owned HTTP rule-providers intentionally keep the stable
        # ./ruleset/<name> cache ABI.  They are allowed only when every field is
        # derived exactly from candidate rulesets.json, and their probe cache is
        # materialized outside the production tree.
        pdg_meta = {"runtime-pdg": {
            "url": "https://example.invalid/runtime-pdg.json",
            "outbound": "JP", "format": "source",
        }}
        pdg_rendered = copy.deepcopy(rendered)
        pdg_rendered.setdefault("rule-providers", {})["runtime-pdg"] = {
            "type": "http",
            "url": "https://example.invalid/runtime-pdg.json",
            "behavior": "classical", "format": "text",
            "path": "./ruleset/runtime-pdg.txt", "interval": 86400,
        }

        for bad_url in (
                "file:///etc/shadow", "missing-scheme.example/rules.txt",
                "https://example.invalid/has whitespace.txt",
                "https://example.invalid/nul\x00suffix",
                "https://" + "a" * (8193 - len("https://"))):
            invalid_meta = copy.deepcopy(pdg_meta)
            invalid_meta["runtime-pdg"]["url"] = bad_url
            calls_before_invalid_url = len(runner_calls)
            valid, _error = tx._v_mihomo_check(
                "mihomo-invalid-candidate-ruleset-url.yaml",
                json.dumps(pdg_rendered, ensure_ascii=False).encode("utf-8"),
                CandidateContext(candidate_model, invalid_meta))
            if valid or len(runner_calls) != calls_before_invalid_url:
                raise RuntimeError(
                    "production validator ran mihomo for invalid candidate ruleset URL")

        invalid_direct_meta = {"runtime-direct": {
            "url": "file:///etc/shadow", "outbound": "direct", "format": "source",
        }}
        calls_before_invalid_direct = len(runner_calls)
        valid, _error = tx._v_mihomo_check(
            "mihomo-invalid-direct-ruleset-url.yaml",
            json.dumps(rendered, ensure_ascii=False).encode("utf-8"),
            CandidateContext(candidate_model, invalid_direct_meta))
        if valid or len(runner_calls) != calls_before_invalid_direct:
            raise RuntimeError(
                "production validator ran mihomo for invalid direct ruleset URL")

        boundary_url = "http://" + "a" * (8192 - len("http://"))
        boundary_meta = copy.deepcopy(pdg_meta)
        boundary_meta["runtime-pdg"]["url"] = boundary_url
        boundary_ok, _boundary_providers, _boundary_sources, boundary_error = (
            tx._pdg_mihomo_rule_providers(
                CandidateContext(candidate_model, boundary_meta)))
        if not boundary_ok:
            raise RuntimeError(
                "production validator rejected 8192-byte HTTP ruleset URL: "
                + boundary_error)

        # Legacy MRS metadata may lack behavior.  Mirror the Bot by proving it
        # from the staged managed source, then use those exact bytes as the
        # isolated probe cache.
        mrs_raw = (ROOT / "tests/fixtures/ruleset-domain.mrs").read_bytes()
        mrs_meta = {"runtime-mrs": {
            "url": "https://example.invalid/runtime.mrs", "outbound": "JP",
            "format": "mrs", "path": "/etc/sing-box/rs/runtime-mrs.mrs",
        }}
        mrs_rendered = copy.deepcopy(rendered)
        mrs_rendered.setdefault("rule-providers", {})["runtime-mrs"] = {
            "type": "http", "url": "https://example.invalid/runtime.mrs",
            "behavior": "domain", "format": "mrs",
            "path": "./ruleset/runtime-mrs.mrs", "interval": 86400,
        }
        valid, error = tx._v_mihomo_check(
            "mihomo-pdg-mrs.yaml",
            json.dumps(mrs_rendered, ensure_ascii=False).encode("utf-8"),
            CandidateContext(candidate_model, mrs_meta, {
                "ruleset:runtime-mrs.mrs": {"data": mrs_raw}}))
        if not valid:
            raise RuntimeError("production validator rejected staged legacy MRS: " + error)

        live_root = WORK / "pdgtx-live"
        (live_root / "opt/pdg-bot").mkdir(parents=True, exist_ok=True)
        live_meta = {"live-pdg": {
            "url": "https://example.invalid/live-pdg.json",
            "outbound": "JP", "format": "source",
        }, "live-mrs": {
            "url": "https://example.invalid/live.mrs", "outbound": "JP",
            "format": "mrs", "path": "/etc/sing-box/rs/live-mrs.mrs",
        }}
        (live_root / "opt/pdg-bot/rulesets.json").write_text(
            json.dumps(live_meta), encoding="utf-8")
        (live_root / "etc/sing-box/rs").mkdir(parents=True, exist_ok=True)
        (live_root / "etc/sing-box/rs/live-mrs.mrs").write_bytes(mrs_raw)
        # A poisoned production Mihomo cache must never affect validation.
        (live_root / "etc/mihomo/ruleset").mkdir(parents=True, exist_ok=True)
        (live_root / "etc/mihomo/ruleset/live-pdg.txt").write_bytes(b"poison")
        original_fsroot = tx.FSROOT
        tx.FSROOT = str(live_root)
        try:
            # Candidate metadata wins over conflicting live metadata.
            valid, error = tx._v_mihomo_check(
                "mihomo-pdg-ruleset.yaml",
                json.dumps(pdg_rendered, ensure_ascii=False).encode("utf-8"),
                CandidateContext(candidate_model, pdg_meta))
            if not valid:
                raise RuntimeError("production validator rejected PDG rule-provider: " + error)

            live_rendered = copy.deepcopy(rendered)
            live_rendered.setdefault("rule-providers", {})["live-pdg"] = {
                "type": "http", "url": "https://example.invalid/live-pdg.json",
                "behavior": "classical", "format": "text",
                "path": "./ruleset/live-pdg.txt", "interval": 86400,
            }
            live_rendered["rule-providers"]["live-mrs"] = {
                "type": "http", "url": "https://example.invalid/live.mrs",
                "behavior": "domain", "format": "mrs",
                "path": "./ruleset/live-mrs.mrs", "interval": 86400,
            }
            valid, error = tx._v_mihomo_check(
                "mihomo-live-pdg-ruleset.yaml",
                json.dumps(live_rendered, ensure_ascii=False).encode("utf-8"),
                CandidateContext(candidate_model))
            if not valid:
                raise RuntimeError("production validator rejected live PDG metadata: " + error)

            for bad_url in (
                    "file:///etc/shadow", "missing-scheme.example/rules.txt",
                    "https://example.invalid/has whitespace.txt",
                    "https://example.invalid/nul\x00suffix",
                    "https://" + "a" * (8193 - len("https://"))):
                invalid_live_meta = copy.deepcopy(live_meta)
                invalid_live_meta["live-pdg"]["url"] = bad_url
                (live_root / "opt/pdg-bot/rulesets.json").write_text(
                    json.dumps(invalid_live_meta), encoding="utf-8")
                calls_before_invalid_url = len(runner_calls)
                valid, _error = tx._v_mihomo_check(
                    "mihomo-invalid-live-ruleset-url.yaml",
                    json.dumps(live_rendered, ensure_ascii=False).encode("utf-8"),
                    CandidateContext(candidate_model))
                if valid or len(runner_calls) != calls_before_invalid_url:
                    raise RuntimeError(
                        "production validator ran mihomo for invalid live ruleset URL")
            invalid_live_direct = {"live-direct": {
                "url": "file:///etc/shadow", "outbound": "direct", "format": "source",
            }}
            (live_root / "opt/pdg-bot/rulesets.json").write_text(
                json.dumps(invalid_live_direct), encoding="utf-8")
            calls_before_invalid_direct = len(runner_calls)
            valid, _error = tx._v_mihomo_check(
                "mihomo-invalid-live-direct-ruleset-url.yaml",
                json.dumps(rendered, ensure_ascii=False).encode("utf-8"),
                CandidateContext(candidate_model))
            if valid or len(runner_calls) != calls_before_invalid_direct:
                raise RuntimeError(
                    "production validator ran mihomo for invalid live direct ruleset URL")
            (live_root / "opt/pdg-bot/rulesets.json").write_text(
                json.dumps(live_meta), encoding="utf-8")

            for field, bad_value in (
                    ("url", "https://example.invalid/tampered.json"),
                    ("behavior", "domain"),
                    ("path", "../ruleset/runtime-pdg.txt"),
                    ("interval", 1)):
                tampered_pdg = copy.deepcopy(pdg_rendered)
                tampered_pdg["rule-providers"]["runtime-pdg"][field] = bad_value
                calls_before_tampered_pdg = len(runner_calls)
                valid, _error = tx._v_mihomo_check(
                    "mihomo-tampered-pdg-%s.yaml" % field,
                    json.dumps(tampered_pdg, ensure_ascii=False).encode("utf-8"),
                    CandidateContext(candidate_model, pdg_meta))
                if valid or len(runner_calls) != calls_before_tampered_pdg:
                    raise RuntimeError(
                        "production validator ran mihomo for tampered PDG field: " + field)

            unowned = copy.deepcopy(rendered)
            unowned.setdefault("rule-providers", {})["unowned"] = {
                "type": "http", "url": "https://example.invalid/unowned.txt",
                "behavior": "classical", "format": "text",
                "path": "./ruleset/unowned.txt", "interval": 86400,
            }
            calls_before_unowned = len(runner_calls)
            valid, _error = tx._v_mihomo_check(
                "mihomo-unowned-ruleset.yaml",
                json.dumps(unowned, ensure_ascii=False).encode("utf-8"),
                CandidateContext(candidate_model, {}))
            if valid or len(runner_calls) != calls_before_unowned:
                raise RuntimeError("production validator ran mihomo for unowned ./ruleset path")
        finally:
            tx.FSROOT = original_fsroot

        calls_before_bad_candidates = len(runner_calls)
        for bad_name, bad_data in (
                ("non-utf8-mihomo.yaml", b"\xff\xfe"),
                ("non-json-mihomo.yaml", b"{not-json"),
                ("non-object-mihomo.yaml", b"[]")):
            valid, _error = tx._v_mihomo_check(bad_name, bad_data, None)
            if valid:
                raise RuntimeError(
                    "production Mihomo validator accepted broken candidate: " + bad_name)
        if len(runner_calls) != calls_before_bad_candidates:
            raise RuntimeError("production Mihomo validator ran mihomo for malformed bytes")
    finally:
        tx._run = original_run

    # Exercise the same wrapper used by pdgtx.  Port mode is deterministic in
    # unprivileged CI and still starts the pinned real MosDNS binary after
    # rewriting only the known managed listener fields on a candidate copy.
    os.environ["PDG_TX_MOSDNS_PROBE_MODE"] = "port"
    os.environ["PDG_TX_MOSDNS_PROBE_SECS"] = "1"
    good_mosdns = (WORK / "config.yaml").read_bytes()
    valid, error = tx._v_mosdns_probe("config.yaml", good_mosdns, None)
    if not valid:
        raise RuntimeError("production MosDNS validator rejected candidate: " + error)
    bad_mosdns = b"log:\n  level: info\nplugins:\n  - tag: broken\n    type: definitely-not-a-plugin\n"
    valid, _error = tx._v_mosdns_probe("bad-mosdns.yaml", bad_mosdns, None)
    if valid:
        raise RuntimeError("production MosDNS validator accepted a broken candidate")

if tx is None:
    print("[OK] templates passed ConfigIO preview and rendering; "
          "pdgtx runtime probes require POSIX")
else:
    print("[OK] templates passed ConfigIO, pdgtx wrappers, negative probes and rendering")

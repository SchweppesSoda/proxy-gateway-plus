#!/usr/bin/env python3
"""Linux hermetic E2E driver for the managed configuration-import pipeline.

This is intentionally not a mock-level unit test.  Raw HTTP framing, auth,
Origin and CSRF are already exhaustively covered by test-web-api.py; beginning
at ConfigIO.preview keeps this root namespace focused on the write pipeline:
prepare_apply -> durable JobStore runner -> ConfigIO.apply -> bot -> pdgtx.
The shell harness supplies SHA-pinned real Mihomo and MosDNS binaries and an
isolated systemctl implementation.
"""
from __future__ import annotations

import copy
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import tarfile

import yaml


WEB = Path("/opt/pdg-web")
STAGE = Path("/var/lib/privdns-gateway/web-imports")
JOBS = Path("/var/lib/privdns-gateway/web-jobs")
MODEL = Path("/etc/sing-box/config.json")
MOSDNS = Path("/etc/mosdns/config.yaml")
PROVIDERS = Path("/etc/mihomo/providers")
MOSDNS_RULES = Path("/etc/mosdns/rules")
RS_META = Path("/opt/pdg-bot/rulesets.json")
RS_DIR = Path("/etc/sing-box/rs")
MOSDNS_ATTESTATION = Path("/etc/privdns-gateway/mosdns-build.env")
TX_AUDIT = Path("/var/lib/privdns-gateway/tx/index.jsonl")


def load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise AssertionError("cannot load " + str(path))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


cio = load("pdgconfigio_e2e", WEB / "pdgconfigio.py")
jobs = load("pdg_web_job_e2e", WEB / "pdg-web-job.py")


def check(value: bool, message: str) -> None:
    if not value:
        raise AssertionError(message)
    print("[CASE] " + message, flush=True)


def tags() -> set[str]:
    data = json.loads(MODEL.read_text(encoding="utf-8"))
    return {
        item["tag"] for item in data.get("outbounds", [])
        if isinstance(item, dict) and isinstance(item.get("tag"), str)
    }


def model() -> dict:
    return json.loads(MODEL.read_text(encoding="utf-8"))


def choices(preview: dict, value: str | None = None) -> dict[str, str]:
    return {
        item["conflictId"]: value or item["default"]
        for item in preview.get("conflicts", [])
    }


def transaction_audit_line_count() -> int:
    try:
        return len(TX_AUDIT.read_text(encoding="utf-8").splitlines())
    except OSError:
        return 0


def transaction_diagnostic(expected_op: str, start_line: int) -> str:
    """Return only pdgtx's already-redacted audit fields for CI failures."""
    try:
        lines = TX_AUDIT.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        return "audit unavailable (" + type(exc).__name__ + ")"
    if len(lines) < start_line:
        return "audit rotated before the failed job could be diagnosed"
    for line in reversed(lines[start_line:]):
        try:
            record = json.loads(line)
        except (TypeError, ValueError):
            continue
        if not isinstance(record, dict) or record.get("op") != expected_op:
            continue
        safe = {
            key: record.get(key)
            for key in (
                "txid", "op", "state", "error_class", "error",
                "targets", "services", "warnings",
            )
        }
        return json.dumps(safe, ensure_ascii=False, sort_keys=True)
    return "no matching transaction audit"


def claim(manager, preview: dict, mode: str, value: str | None = None) -> None:
    manager.prepare_apply(preview["importId"], {
        "confirm": True,
        "mode": mode,
        "conflicts": choices(preview, value),
    })


def mihomo(name: str) -> bytes:
    document = {
        "proxies": [{
            "name": name,
            "type": "ss",
            "server": "192.0.2.10",
            "port": 1443,
            "cipher": "aes-128-gcm",
            "password": "e2e-password",
        }],
        "proxy-groups": [{
            "name": "E2E-" + name,
            "type": "select",
            "proxies": [name, "DIRECT"],
        }],
        "rules": ["DOMAIN-SUFFIX," + name + ".invalid,E2E-" + name,
                  "MATCH,DIRECT"],
    }
    return yaml.safe_dump(document, sort_keys=False).encode("utf-8")


def mihomo_live_merge() -> bytes:
    """A later generation with both a same-name conflict and live-only items."""
    document = {
        "proxies": [{
            "name": "plain-node",
            "type": "ss",
            "server": "192.0.2.99",
            "port": 9443,
            "cipher": "aes-128-gcm",
            "password": "live-conflict-password",
        }, {
            "name": "live-only-node",
            "type": "ss",
            "server": "192.0.2.100",
            "port": 10443,
            "cipher": "aes-128-gcm",
            "password": "live-only-password",
        }],
        "proxy-groups": [{
            "name": "E2E-plain-node",
            "type": "select",
            "proxies": ["plain-node", "live-only-node", "DIRECT"],
        }, {
            "name": "Live-Only-Group",
            "type": "select",
            "proxies": ["live-only-node", "DIRECT"],
        }],
        "rules": ["DOMAIN-SUFFIX,live-only.invalid,Live-Only-Group",
                  "MATCH,DIRECT"],
    }
    return yaml.safe_dump(document, sort_keys=False).encode("utf-8")


def archive_mihomo() -> tuple[bytes, bytes]:
    provider = yaml.safe_dump({
        "proxies": [{
            "name": "provider-node",
            "type": "ss",
            "server": "192.0.2.20",
            "port": 2443,
            "cipher": "aes-128-gcm",
            "password": "provider-password",
        }]
    }, sort_keys=False).encode("utf-8")
    config = yaml.safe_dump({
        "proxy-providers": {
            "local-e2e": {"type": "file", "path": "./providers/local.yaml"},
        },
        "proxy-groups": [{
            "name": "Local-E2E",
            "type": "select",
            "use": ["local-e2e"],
        }],
        "rules": ["DOMAIN-SUFFIX,archive.invalid,Local-E2E", "MATCH,DIRECT"],
    }, sort_keys=False).encode("utf-8")
    out = io.BytesIO()
    with tarfile.open(fileobj=out, mode="w:gz") as archive:
        for name, data in (("config.yaml", config),
                           ("providers/local.yaml", provider)):
            info = tarfile.TarInfo(name)
            info.size = len(data)
            info.mode = 0o600
            archive.addfile(info, io.BytesIO(data))
    return out.getvalue(), provider


def install_nonmodel_generation(bot, prefix: str, proxy_outbound: str) -> dict:
    """Install a coherent ruleset/MosDNS-rules generation for export/restore."""
    RS_DIR.mkdir(parents=True, exist_ok=True)
    for old in RS_DIR.glob("e2e-*.json"):
        old.unlink()
    direct_leaf = "e2e-" + prefix + "-direct.json"
    proxy_leaf = "e2e-" + prefix + "-proxy.json"
    direct_data = json.dumps({
        "version": 1,
        "rules": [{"domain": [prefix + "-direct.example"]}],
    }, sort_keys=True, separators=(",", ":")).encode("utf-8") + b"\n"
    proxy_data = json.dumps({
        "version": 1,
        "rules": [{"domain_suffix": [prefix + "-proxy.example"]}],
    }, sort_keys=True, separators=(",", ":")).encode("utf-8") + b"\n"
    metadata = {
        prefix + "-direct": {
            "url": "https://example.invalid/" + direct_leaf,
            "outbound": "direct",
            "format": "source",
            "path": "/etc/sing-box/rs/" + direct_leaf,
            "count": 1,
        },
        prefix + "-proxy": {
            "url": "https://example.invalid/" + proxy_leaf,
            "outbound": proxy_outbound,
            "format": "source",
            "path": "/etc/sing-box/rs/" + proxy_leaf,
            "count": 1,
        },
    }
    metadata_data = json.dumps(
        metadata, sort_keys=True, separators=(",", ":")).encode("utf-8") + b"\n"
    staged = {
        "ruleset:" + direct_leaf: direct_data,
        "ruleset:" + proxy_leaf: proxy_data,
    }
    direct_aggregate = bot._ruleset_direct_bytes(metadata, staged, {})
    hijack_aggregate = bot._ruleset_hijack_bytes(metadata, staged, {})
    files = {
        MOSDNS_RULES / "custom_direct.txt":
            ("domain:" + prefix + "-custom-direct.example\n").encode("ascii"),
        MOSDNS_RULES / "custom_hijack.txt":
            ("domain:" + prefix + "-custom-hijack.example\n").encode("ascii"),
        MOSDNS_RULES / "ruleset_direct.txt": direct_aggregate,
        MOSDNS_RULES / "ruleset_hijack.txt": hijack_aggregate,
        RS_META: metadata_data,
        RS_DIR / direct_leaf: direct_data,
        RS_DIR / proxy_leaf: proxy_data,
    }
    for path, data in files.items():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
    return {"files": files, "leaves": {direct_leaf, proxy_leaf}}


def store() -> object:
    # /bin/true acknowledges publication without starting a second process.
    # The test invokes run() itself so the exact persistent record and runner
    # path are still exercised deterministically.
    return jobs.JobStore(
        state_dir=str(JOBS),
        snapshot_dir="/var/lib/privdns-gateway/backups",
        cli="/usr/local/bin/pdg",
        runner=str(WEB / "pdg-web-job.py"),
        config_io_runner=str(WEB / "pdgconfigio.py"),
        systemd_run="/bin/true",
        python="/usr/bin/python3",
    )


def main() -> int:
    STAGE.mkdir(parents=True, exist_ok=True)
    JOBS.mkdir(parents=True, exist_ok=True)
    PROVIDERS.mkdir(parents=True, exist_ok=True)
    manager = cio.ConfigIO(staging_dir=str(STAGE))
    job_store = store()
    check(os.environ.get("PDG_E2E_STOCK_MOSDNS_ABI_ONLY") == "1" and
          not MOSDNS_ATTESTATION.exists(),
          "stock MosDNS is ABI-only and is not attested as production patched flavor")

    def apply_job(preview: dict, mode: str, value: str | None = None,
                  *, succeeds: bool = True, claimed: bool = False) -> dict:
        if not claimed:
            claim(manager, preview, mode, value)
        audit_start = transaction_audit_line_count()
        queued = job_store.start("config-import", import_id=preview["importId"])
        return_code = job_store.run(queued["id"])
        terminal = job_store.get(queued["id"])
        if succeeds:
            if return_code != 0 or terminal["status"] != "succeeded":
                print("[DIAG] unexpected config-import job result: " + json.dumps(
                    terminal, ensure_ascii=False, sort_keys=True), flush=True)
                expected_op = (
                    "restore" if preview["kind"] == "pdg"
                    else "web_import_" + preview["kind"])
                print("[DIAG] transaction: " + transaction_diagnostic(
                    expected_op, audit_start), flush=True)
            check(return_code == 0 and terminal["status"] == "succeeded",
                  preview["kind"] + " config-import job succeeds")
        else:
            check(return_code != 0 and terminal["status"] == "failed",
                  preview["kind"] + " config-import job fails closed")
        check(not any(STAGE.glob(preview["importId"] + ".*")),
              preview["kind"] + " terminal job removes staged secrets")
        return terminal

    # Ordinary Mihomo import is applied through the durable config-import job
    # runner, not by calling the transaction backend directly.
    preview = manager.preview("mihomo", mihomo("plain-node"), "application/yaml")
    apply_job(preview, "merge")
    check("plain-node" in tags(), "ordinary Mihomo merge reaches canonical model")

    # Archive import installs the referenced provider under its content hash.
    archive, provider = archive_mihomo()
    leaf = hashlib.sha256(provider).hexdigest() + ".yaml"
    preview = manager.preview("mihomo", archive, "application/gzip")
    apply_job(preview, "merge")
    check((PROVIDERS / leaf).read_bytes() == provider,
          "archive provider is atomically installed by content hash")
    current = model()
    check("plain-node" in tags() and leaf in current["_pdg"]["mihomo"]["managed-files"],
          "merge retains existing proxy and adds provider metadata")

    # Export the generation containing both imports.  Replacing it with a
    # plain config must delete its provider; re-importing the v2 export must
    # restore the exact managed provider closure.
    bot = manager._load_bot()
    exported_components = install_nonmodel_generation(bot, "bundle-a", "plain-node")
    exported_model = copy.deepcopy(current)
    live_mosdns_at_export = MOSDNS.read_bytes()
    bundle, filename, media_type = manager.export("pdg")
    check(filename == "pdg-config-v2.tar.gz" and media_type == "application/gzip",
          "PDG v2 export returns the stable archive contract")
    with tarfile.open(fileobj=io.BytesIO(bundle), mode="r:gz") as archive_file:
        names = set(archive_file.getnames())
        archived_mosdns_file = archive_file.extractfile("etc/mosdns/config.yaml")
        check(archived_mosdns_file is not None,
              "PDG v2 export contains the managed MosDNS configuration")
        archived_mosdns_bytes = archived_mosdns_file.read()
    check(archived_mosdns_bytes == live_mosdns_at_export,
          "PDG v2 export captures the exact live MosDNS bytes")
    exported_mosdns = yaml.safe_load(archived_mosdns_bytes)
    exported_internal_sequence = next(
        item["args"] for item in exported_mosdns["plugins"]
        if item.get("tag") == "internal_sequence")
    check(not any(
        item.get("matches") == "!qname $hijack_set"
        for item in exported_internal_sequence),
        "PDG E2E archive contains the managed all-mode MosDNS shape")
    check("manifest.json" in names and "etc/mihomo/providers/" + leaf in names,
          "PDG v2 manifest archive covers the local provider")
    check({
        "etc/mosdns/rules/custom_direct.txt",
        "etc/mosdns/rules/custom_hijack.txt",
        "etc/mosdns/rules/ruleset_direct.txt",
        "etc/mosdns/rules/ruleset_hijack.txt",
        "opt/pdg-bot/rulesets.json",
        *{"etc/sing-box/rs/" + item for item in exported_components["leaves"]},
    } <= names, "PDG v2 export contains MosDNS rules and managed ruleset closure")

    # Install a distinct non-model generation before replacing the model.  The
    # replacement job derives Mihomo against this generation, so the live state
    # is coherent and demonstrably different from the exported bundle.
    replaced_components = install_nonmodel_generation(
        bot, "bundle-b", "replacement-node")

    preview = manager.preview("mihomo", mihomo("replacement-node"), "application/yaml")
    staged = manager._record(preview["importId"])
    derived_model = cio._merge_model(
        model(), staged["candidate"]["model"], "replace", {})
    derived_bytes, derived_meta = bot._render_mihomo_bytes(derived_model)
    derived_mihomo = json.loads(derived_bytes.decode("utf-8"))
    check(
        derived_mihomo.get("rule-providers", {}).get("bundle-b-proxy") == {
            "type": "http",
            "url": "https://example.invalid/e2e-bundle-b-proxy.json",
            "behavior": "classical",
            "format": "text",
            "path": "./ruleset/bundle-b-proxy.txt",
            "interval": 86400,
        }
        and "bundle-b-direct" not in derived_mihomo.get("rule-providers", {})
        and derived_meta == {"dropped": [], "unknown_proxies": []},
        "Mihomo replace candidate includes the bundle-b PDG HTTP ruleset cache",
    )
    apply_job(preview, "replace", "incoming")
    replacement = model()
    replacement_proxies = {
        item["tag"] for item in replacement["outbounds"]
        if isinstance(item, dict) and item.get("type") not in {
            "direct", "selector", "urltest"
        }
    }
    replacement_groups = {
        item["tag"] for item in replacement["outbounds"]
        if isinstance(item, dict) and item.get("type") in {"selector", "urltest"}
    }
    replacement_meta = replacement["_pdg"]["mihomo"]
    check(replacement_proxies == {"replacement-node"},
          "Mihomo replace leaves the exact canonical proxy set")
    check(replacement_groups == {"E2E-replacement-node"} and {
        item["name"] for item in replacement_meta["proxy-groups"]
    } == {"E2E-replacement-node"},
          "Mihomo replace leaves the exact canonical group set")
    check(replacement_meta["proxy-providers"] == {} and
          replacement_meta["rule-providers"] == {} and
          replacement_meta["managed-files"] == {} and
          {item.name for item in PROVIDERS.iterdir()} == set(),
          "Mihomo replace leaves the exact empty provider set on model and disk")

    preview = manager.preview("pdg", bundle, "application/gzip")
    apply_job(preview, "replace", "incoming")
    restored = model()
    check(cio.normalize_model(restored) == cio.normalize_model(exported_model),
          "PDG v2 export-preview-apply roundtrip restores canonical model")
    check((PROVIDERS / leaf).read_bytes() == provider,
          "PDG v2 roundtrip restores provider payload")
    restored_mosdns = yaml.safe_load(MOSDNS.read_bytes())
    restored_internal_sequence = next(
        item["args"] for item in restored_mosdns["plugins"]
        if item.get("tag") == "internal_sequence")
    check(restored_internal_sequence == exported_internal_sequence,
          "PDG v2 roundtrip preserves the live managed MosDNS hijack mode")
    for path, expected in exported_components["files"].items():
        check(path.read_bytes() == expected,
              "PDG v2 roundtrip restores non-model bytes: " + str(path))
    for replaced_leaf in replaced_components["leaves"]:
        check(not (RS_DIR / replaced_leaf).exists(),
              "PDG v2 roundtrip deletes later managed ruleset: " + replaced_leaf)

    # Exercise native PDG's default mode rather than merely passing the word
    # "merge" explicitly.  First create a coherent live-only model generation,
    # a different valid MosDNS generation, and different managed rule files.
    # The old exported bundle then has both a same-name model conflict and
    # incoming non-model components that default to keeping the live side.
    preview = manager.preview(
        "mihomo", mihomo_live_merge(), "application/yaml")
    apply_job(preview, "merge")
    live_model_before_merge = model()
    live_plain_before_merge = next(
        item for item in live_model_before_merge["outbounds"]
        if isinstance(item, dict) and item.get("tag") == "plain-node")
    live_mos = yaml.safe_load(MOSDNS.read_bytes())
    live_mos.setdefault("log", {})["level"] = "error"
    preview = manager.preview(
        "mosdns", yaml.safe_dump(live_mos, sort_keys=False).encode("utf-8"),
        "application/yaml")
    apply_job(preview, "replace")
    live_mos_before_merge = MOSDNS.read_bytes()
    live_components = install_nonmodel_generation(
        bot, "merge-live", "live-only-node")

    preview = manager.preview("pdg", bundle, "application/gzip")
    conflict_shape = {
        (item["kind"], item["name"]): item["default"]
        for item in preview["conflicts"]
    }
    check(conflict_shape.get(("name", "plain-node")) == "incoming" and
          conflict_shape.get(("name", "E2E-plain-node")) == "incoming",
          "PDG merge preview exposes both unified name conflicts")
    check(conflict_shape.get(("component", "mosdns")) == "existing" and
          conflict_shape.get(("component", "rulesets")) == "existing",
          "PDG merge preview defaults incoming components to existing")
    merge_choices = choices(preview)
    for item in preview["conflicts"]:
        if (item["kind"], item["name"]) in {
                ("name", "plain-node"),
                ("name", "E2E-plain-node")}:
            merge_choices[item["conflictId"]] = "existing"
    # Deliberately omit mode: prepare_apply's public contract must persist the
    # native PDG default of merge into the claim consumed by the job runner.
    manager.prepare_apply(preview["importId"], {
        "confirm": True,
        "conflicts": merge_choices,
    })
    apply_job(preview, "merge", claimed=True)
    merged = model()
    merged_tags = {
        item["tag"] for item in merged["outbounds"]
        if isinstance(item, dict) and isinstance(item.get("tag"), str)
    }
    merged_groups = {
        item["name"] for item in merged["_pdg"]["mihomo"]["proxy-groups"]
    }
    check({"live-only-node", "Live-Only-Group"} <= merged_tags and
          "Live-Only-Group" in merged_groups,
          "PDG default merge preserves live-only proxy and group")
    merged_plain = next(
        item for item in merged["outbounds"]
        if isinstance(item, dict) and item.get("tag") == "plain-node")
    check(merged_plain == live_plain_before_merge,
          "PDG merge honors existing for a same-name outbound conflict")
    check(MOSDNS.read_bytes() == live_mos_before_merge,
          "PDG merge default existing does not overwrite live MosDNS")
    for path, expected in live_components["files"].items():
        check(path.read_bytes() == expected,
              "PDG merge default existing preserves live component: " + str(path))
    for incoming_leaf in exported_components["leaves"]:
        check(not (RS_DIR / incoming_leaf).exists(),
              "PDG merge does not install incoming ruleset by default: " + incoming_leaf)

    # Provider preview-era CAS: mutate the existing content-addressed file
    # after confirmation.  The failed job must preserve that exact external
    # drift and leave every other production file untouched.
    preview = manager.preview(
        "mihomo", mihomo("provider-cas-must-not-land"), "application/yaml")
    claim(manager, preview, "merge")
    provider_before_cas = (PROVIDERS / leaf).read_bytes()
    provider_drift = provider_before_cas + b"# external-provider-drift\n"
    model_before_provider_cas = MODEL.read_bytes()
    mihomo_before_provider_cas = Path("/etc/mihomo/config.yaml").read_bytes()
    (PROVIDERS / leaf).write_bytes(provider_drift)
    apply_job(preview, "merge", succeeds=False, claimed=True)
    check((PROVIDERS / leaf).read_bytes() == provider_drift,
          "provider CAS failure does not overwrite external drift")
    check(MODEL.read_bytes() == model_before_provider_cas and
          Path("/etc/mihomo/config.yaml").read_bytes() == mihomo_before_provider_cas,
          "provider CAS failure leaves model and derived config unchanged")
    (PROVIDERS / leaf).write_bytes(provider_before_cas)

    # MosDNS is replace-only.  Deliberately submit foreign local identity;
    # contract rebinding must keep the live address, CIDR, cert and rule paths.
    before_mos = yaml.safe_load(MOSDNS.read_bytes())
    incoming_mos = copy.deepcopy(before_mos)
    incoming_mos.setdefault("log", {})["level"] = "info"
    for plugin in incoming_mos["plugins"]:
        if plugin.get("tag") == "npn_clients":
            plugin["args"]["ips"] = ["198.51.100.0/24"]
        if plugin.get("tag") == "dot_server":
            plugin["args"]["cert"] = "/tmp/foreign-cert.pem"
            plugin["args"]["key"] = "/tmp/foreign-key.pem"
        if plugin.get("type") == "domain_set":
            plugin.setdefault("args", {})["files"] = ["/tmp/foreign-rules.txt"]
        if plugin.get("type") == "sequence":
            for item in plugin.get("args") or []:
                if isinstance(item, dict) and str(item.get("exec", "")).startswith("black_hole "):
                    item["exec"] = "black_hole 198.51.100.99"
    preview = manager.preview(
        "mosdns", yaml.safe_dump(incoming_mos, sort_keys=False).encode("utf-8"),
        "application/yaml")
    apply_job(preview, "replace")
    after_mos = yaml.safe_load(MOSDNS.read_bytes())
    check(after_mos["log"]["level"] == "info", "MosDNS replace commits allowed data")
    before_by_tag = {item["tag"]: item for item in before_mos["plugins"]}
    after_by_tag = {item["tag"]: item for item in after_mos["plugins"]}
    check(after_by_tag["npn_clients"]["args"] == before_by_tag["npn_clients"]["args"],
          "MosDNS replace rebinds current internal CIDR")
    check(after_by_tag["dot_server"]["args"] == before_by_tag["dot_server"]["args"],
          "MosDNS replace rebinds listeners and certificate identity")
    def black_holes(by_tag: dict) -> list[str]:
        return sorted(
            item["exec"] for plugin in by_tag.values()
            if plugin.get("type") == "sequence"
            for item in (plugin.get("args") or [])
            if isinstance(item, dict) and
            str(item.get("exec", "")).startswith("black_hole ")
        )
    check(black_holes(after_by_tag) == black_holes(before_by_tag),
          "MosDNS replace rebinds current gateway address")
    for tag, old in before_by_tag.items():
        if old.get("type") == "domain_set":
            check(after_by_tag[tag]["args"] == old["args"],
                  "MosDNS replace rebinds managed rule path " + tag)

    # MosDNS preview-era CAS uses a semantic no-op comment as the external
    # drift.  Applying a different requested log level must fail and preserve
    # the exact drift bytes rather than silently overwriting it.
    cas_mos = copy.deepcopy(after_mos)
    cas_mos.setdefault("log", {})["level"] = "debug"
    preview = manager.preview(
        "mosdns", yaml.safe_dump(cas_mos, sort_keys=False).encode("utf-8"),
        "application/yaml")
    claim(manager, preview, "replace")
    mos_before_cas = MOSDNS.read_bytes()
    mos_drift = mos_before_cas + b"\n# external-mosdns-drift\n"
    model_before_mos_cas = MODEL.read_bytes()
    provider_before_mos_cas = (PROVIDERS / leaf).read_bytes()
    mihomo_before_mos_cas = Path("/etc/mihomo/config.yaml").read_bytes()
    MOSDNS.write_bytes(mos_drift)
    apply_job(preview, "replace", succeeds=False, claimed=True)
    check(MOSDNS.read_bytes() == mos_drift and
          yaml.safe_load(MOSDNS.read_bytes())["log"]["level"] == "info",
          "MosDNS CAS failure preserves exact external drift, not imported data")
    check(MODEL.read_bytes() == model_before_mos_cas and
          (PROVIDERS / leaf).read_bytes() == provider_before_mos_cas and
          Path("/etc/mihomo/config.yaml").read_bytes() == mihomo_before_mos_cas,
          "MosDNS CAS failure leaves other production components unchanged")
    MOSDNS.write_bytes(mos_before_cas)

    # Semantic state stays equal while raw model bytes drift.  That passes the
    # outer semantic check and is rejected by the real lock-held pdgtx CAS.
    preview = manager.preview("mihomo", mihomo("cas-must-not-land"), "application/yaml")
    claim(manager, preview, "merge")
    raw_before_drift = MODEL.read_bytes()
    semantic_before = cio._sha(cio._model_bytes(cio.normalize_model(
        json.loads(raw_before_drift.decode("utf-8")))))
    MODEL.write_bytes(raw_before_drift + b"\n")
    semantic_after = cio._sha(cio._model_bytes(cio.normalize_model(
        json.loads(MODEL.read_text(encoding="utf-8")))))
    check(semantic_after == semantic_before,
          "CAS fixture changes raw bytes without changing semantic model")
    apply_job(preview, "merge", succeeds=False, claimed=True)
    check("cas-must-not-land" not in tags(), "lock-held raw-file CAS rejects preview drift")
    MODEL.write_bytes(raw_before_drift)

    # An operation-time service crash happens after candidates are installed.
    # pdgtx must put model and providers back byte-for-byte.
    rollback_model = MODEL.read_bytes()
    rollback_provider = (PROVIDERS / leaf).read_bytes()
    rollback_mihomo = Path("/etc/mihomo/config.yaml").read_bytes()
    preview = manager.preview("mihomo", mihomo("rollback-must-not-land"), "application/yaml")
    claim(manager, preview, "replace", "incoming")
    Path("/tmp/e2e-svc/mihomo.fail").touch()
    try:
        apply_job(preview, "replace", "incoming", succeeds=False, claimed=True)
    finally:
        Path("/tmp/e2e-svc/mihomo.fail").unlink(missing_ok=True)
        Path("/tmp/e2e-svc/mihomo.ac").write_text("1\n", encoding="ascii")
    check(MODEL.read_bytes() == rollback_model,
          "transaction failure rolls canonical model back byte-for-byte")
    check((PROVIDERS / leaf).read_bytes() == rollback_provider,
          "transaction failure rolls provider set back byte-for-byte")
    check(Path("/etc/mihomo/config.yaml").read_bytes() == rollback_mihomo,
          "transaction failure rolls derived Mihomo config back byte-for-byte")

    # Publish a queued import without running it, then emulate a reboot by
    # changing its persisted boot id.  A freshly constructed JobStore must
    # reconcile it to interrupted and discard all staged secrets.
    preview = manager.preview("mihomo", mihomo("interrupted-must-not-land"), "application/yaml")
    claim(manager, preview, "merge")
    record = job_store.start("config-import", import_id=preview["importId"])
    record_path = JOBS / (record["id"] + ".json")
    persisted = json.loads(record_path.read_text(encoding="utf-8"))
    persisted["bootId"] = "00000000-0000-0000-0000-000000000000"
    record_path.write_text(json.dumps(persisted, sort_keys=True, separators=(",", ":")),
                           encoding="utf-8")
    os.chmod(record_path, 0o600)
    restarted_store = store()
    reconciled = restarted_store.get(record["id"])
    check(reconciled["status"] == "interrupted" and
          reconciled["result"] == "runner_interrupted",
          "JobStore restart reconciles orphaned config-import")
    check(not any(STAGE.glob(preview["importId"] + ".*")),
          "reconcile removes orphaned preview upload and claim")
    check("interrupted-must-not-land" not in tags(),
          "reconcile cleanup never applies interrupted input")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

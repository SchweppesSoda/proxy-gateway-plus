#!/usr/bin/env python3
"""Literal ruleset target=direct: phone-local DNS semantics and atomic lifecycle."""
from __future__ import annotations

import importlib
import importlib.util
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import tarfile
import tempfile
import types


ROOT = Path(__file__).resolve().parents[1]
BOT_DIR = ROOT / "deploy/bot"
os.sys.path.insert(0, str(BOT_DIR))
if os.name == "nt" and not hasattr(os, "O_NOFOLLOW"):
    os.O_NOFOLLOW = 0
if os.name == "nt" and not hasattr(os, "chown"):
    os.chown = lambda *args: None
if "fcntl" not in os.sys.modules:
    try:
        import fcntl  # noqa: F401
    except ImportError:
        os.sys.modules["fcntl"] = types.SimpleNamespace(
            LOCK_EX=1, LOCK_NB=2, LOCK_UN=8, flock=lambda *args: None
        )
spec = importlib.util.spec_from_file_location("pdg_bot_phone_direct", BOT_DIR / "pdg-bot.py")
bot = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(bot)

SAMPLE = {
    "experimental": {"clash_api": {"external_controller": "127.0.0.1:9090"}},
    "outbounds": [
        {"type": "shadowsocks", "tag": "hk", "server": "1.1.1.1",
         "server_port": 8388, "method": "aes-256-gcm", "password": "pw"},
        {"type": "direct", "tag": "jp"},
    ],
    "route": {
        "rules": [{"ip_cidr": ["127.0.0.0/8"], "action": "reject"}],
        "final": "jp",
    },
}
MOSDNS_TEMPLATE = (ROOT / "deploy/mosdns/config.yaml").read_text(encoding="utf-8")
# ``origin`` v1.6.4 is this fork's supported historical backup boundary.  Pin
# the complete managed graph so a future HEAD edit cannot silently redefine
# what this compatibility regression claims to exercise.
assert hashlib.sha256(MOSDNS_TEMPLATE.encode("utf-8")).hexdigest() == (
    "eee9a07dfb599708f47e523941a42bd9151cf6eb1f1da5edef48a4c2d9f01574"
)
MOSDNS_SHAPE = (
    MOSDNS_TEMPLATE
    .replace("__SERVER_IP__", "203.0.113.10")
    .replace("__INTERNAL_CIDR__", "10.0.0.0/24")
    .replace("__CERT_DIR__", "/etc/mosdns/certs")
    .replace("__HIJACK_SET_FILE__", "geosite_geolocation-!cn.txt")
    .replace("__MOSDNS_CACHE__", "8192")
)

PROFILE_SENTINEL_TLS_PORTS = [443, 10443]
PROFILE_SHAPE = """\
PDG_PLATFORM=android
PDG_QUIC_MODE=tproxy
PDG_HIJACK_TLS_TCP_PORTS=443,10443
PDG_HIJACK_HTTP_TCP_PORTS=80
PDG_QUIC_MARK=0x504447
PDG_QUIC_MARK_MASK=0xffffffff
PDG_QUIC_ROUTE_TABLE=7895
PDG_QUIC_RULE_PRIORITY=17895
"""


def setup_box(root: str):
    for directory in (
        "/etc/sing-box/rs", "/etc/mihomo", "/etc/mosdns/rules",
        "/etc/privdns-gateway", "/run",
        "/var/lib/privdns-gateway", "/opt/pdg-bot",
    ):
        os.makedirs(root + directory, exist_ok=True)
    os.environ["PDG_TX_FSROOT"] = root
    os.environ["PDG_TX_ROOT"] = root + "/var/lib/privdns-gateway/tx"
    os.environ["PDG_LOCKFILE"] = root + "/run/pdg.lock"
    os.environ["PDG_STABLE_SAMPLES"] = "1"
    for name in list(os.sys.modules):
        if name == "pdgtx":
            del os.sys.modules[name]
    tx = importlib.import_module("pdgtx")
    # Bot production code pins the sibling bundle in _PDGTX_MODULE. Pin this
    # temporary FSROOT-aware instance too; this test runs in its own process.
    bot._PDGTX_MODULE = tx
    # Windows cannot open a directory with os.open(O_RDONLY); directory fsync is
    # exercised on Linux CI, while this shim keeps the desktop Python regression runnable.
    if os.name == "nt":
        tx._fsync_dir = lambda path: None
    tx.svc_stable = lambda unit, **kwargs: (True, "")
    tx.health_snapshot = lambda services, relax_units=(): {
        "svc:" + unit: True for unit in services
    }
    tx._svc_prop_ex = lambda unit, prop: (
        {"ActiveState": "active", "UnitFileState": "enabled", "NRestarts": "0"}.get(
            prop, ""
        ),
        True,
    )
    tx._run = lambda cmd, timeout=60: (0, "")
    tx.VALIDATORS["mihomo_check"] = lambda path, data, ctx: (True, "")
    tx.VALIDATORS["mosdns_probe"] = lambda path, data, ctx: (True, "")

    bot.SB = root + "/etc/sing-box/config.json"
    # Metadata uses the production POSIX path even on Windows; pdgtx maps it below FSROOT.
    bot.RS_DIR = "/etc/sing-box/rs"
    bot.RS_META = root + "/opt/pdg-bot/rulesets.json"
    bot.MIHOMO_DIR = root + "/etc/mihomo"
    bot.MIHOMO_CFG = root + "/etc/mihomo/config.yaml"
    bot.MOSDNS_CONF = root + "/etc/mosdns/config.yaml"
    bot.MOSDNS_DIRECT = root + "/etc/mosdns/rules/custom_direct.txt"
    bot.MOSDNS_HIJACK = root + "/etc/mosdns/rules/custom_hijack.txt"
    bot.MOSDNS_RULESET_DIRECT = root + "/etc/mosdns/rules/ruleset_direct.txt"
    bot.MOSDNS_RULESET_HIJACK = root + "/etc/mosdns/rules/ruleset_hijack.txt"
    bot.BACKEND_MARKER = root + "/etc/privdns-gateway/backend"
    bot.PROFILE_ENV = root + "/etc/privdns-gateway/profile.env"
    bot.LOCKFILE = os.environ["PDG_LOCKFILE"]
    with open(bot.SB, "w", encoding="utf-8") as stream:
        json.dump(SAMPLE, stream)
    with open(bot.MOSDNS_CONF, "w", encoding="utf-8") as stream:
        stream.write(MOSDNS_SHAPE)
    with open(bot.PROFILE_ENV, "w", encoding="utf-8") as stream:
        stream.write(PROFILE_SHAPE)
    # Resolver/platform reads must stay inside this temporary world even when the
    # test itself runs on an already-deployed Linux host.
    bot._platform = lambda: "android"
    bot.sh = lambda cmd: types.SimpleNamespace(returncode=0, stdout="", stderr="")
    bot._svc_active = lambda unit, **kwargs: True
    return tx


def aggregate(root: str) -> str:
    return Path(root + "/etc/mosdns/rules/ruleset_direct.txt").read_text(
        encoding="utf-8"
    )


def hijack_aggregate(root: str) -> str:
    return Path(root + "/etc/mosdns/rules/ruleset_hijack.txt").read_text(
        encoding="utf-8"
    )


def ruleset_path(root: str, metadata_path: str) -> Path:
    return Path(root + metadata_path.replace("\\", "/"))


def backup_blob(entries, *, manifest=False) -> bytes:
    entries = list(entries)
    if manifest:
        inventory = [
            {"path": name, "size": len(data),
             "sha256": hashlib.sha256(data).hexdigest()}
            for name, data in sorted(entries)
        ]
        manifest_data = json.dumps({
            "version": 2,
            "createdAt": "2026-08-11T00:00:00Z",
            "files": inventory,
        }, ensure_ascii=True, sort_keys=True, indent=2).encode("utf-8") + b"\n"
        entries.append(("manifest.json", manifest_data))
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
        for name, data in entries:
            info = tarfile.TarInfo(name)
            info.size = len(data)
            archive.addfile(info, io.BytesIO(data))
    return buffer.getvalue()


def main():
    with tempfile.TemporaryDirectory(prefix="pdg-phone-direct-") as root:
        setup_box(root)
        assert Path(bot.PROFILE_ENV).resolve() == (
            Path(root) / "etc/privdns-gateway/profile.env"
        ).resolve()
        assert (
            bot._mihomo_dataplane_args()["tls_ports"]
            == PROFILE_SENTINEL_TLS_PORTS
        ), "Mihomo resolver did not consume the temporary profile sentinel"
        # Rule files use the same old-bytes SHA contract as rs_meta. Simulate a
        # competing writer after add_rule/del_rule parsed the file but before tx stage.
        real_tx_apply = bot.tx_apply

        def concurrent_add(op, **kwargs):
            if op == "rule_add_direct":
                Path(bot.MOSDNS_DIRECT).write_bytes(
                    bot._direct_text(["competing-add.example"])
                )
            return real_tx_apply(op, **kwargs)

        bot.tx_apply = concurrent_add
        try:
            ok, msg = bot.add_rule("ours-add.example", "direct")
        finally:
            bot.tx_apply = real_tx_apply
        assert not ok and "PRECONDITION_FAILED" in msg
        assert bot._read_direct() == ["competing-add.example"]

        ok, msg = bot.add_rule("delete-me.example", "direct")
        assert ok, msg
        before_delete = bot._read_direct()

        def concurrent_delete(op, **kwargs):
            if op == "rule_del_direct":
                Path(bot.MOSDNS_DIRECT).write_bytes(
                    bot._direct_text(before_delete + ["competing-delete.example"])
                )
            return real_tx_apply(op, **kwargs)

        bot.tx_apply = concurrent_delete
        try:
            ok, msg = bot.del_rule("delete-me.example")
        finally:
            bot.tx_apply = real_tx_apply
        assert not ok and "PRECONDITION_FAILED" in msg
        assert "delete-me.example" in bot._read_direct()
        assert "competing-delete.example" in bot._read_direct()

        sources = {
            "https://x/one.list": (
                ["api.example.com"], ["example.com"], ["video"], []
            ),
            "https://x/two.list": (
                ["api.example.com", "other.example"],
                ["example.com", "corp.cn"],
                [],
                [],
            ),
            "https://x/three.list": ([], [], ["old-keyword"], []),
            "https://x/proxy.list": (["proxy.only.example"], [], [], []),
            "https://x/conflict.list": (["conflict.example"], [], [], []),
            "https://x/meta-race.list": (["meta-race.example"], [], [], []),
            "https://x/config-race.list": (["config-race.example"], [], [], []),
        }
        bot._fetch_surge = lambda url, **kwargs: sources[url]

        ok, msg = bot.add_ruleset("https://x/one.list", "direct", "one")
        assert ok, msg
        meta = json.loads(Path(bot.RS_META).read_text(encoding="utf-8"))
        name_one = next(iter(meta))
        assert meta[name_one]["outbound"] == "direct"
        model = json.loads(Path(bot.SB).read_text(encoding="utf-8"))
        assert not any(r.get("rule_set") == name_one for r in model["route"]["rules"])
        assert name_one not in {
            r.get("tag") for r in model["route"].get("rule_set", [])
        }
        text = aggregate(root)
        assert "full:api.example.com\n" in text
        assert "domain:example.com\n" in text
        assert "keyword:video\n" in text

        ok, msg = bot.add_ruleset("https://x/two.list", "direct", "two")
        assert ok, msg
        text = aggregate(root)
        assert text.count("full:api.example.com\n") == 1
        assert text.count("domain:example.com\n") == 1
        assert "full:other.example\n" in text
        assert "domain:corp.cn\n" in text

        ok, msg = bot.del_ruleset(name_one)
        assert ok, msg
        text = aggregate(root)
        assert "keyword:video\n" not in text
        assert "domain:example.com\n" in text

        ok, msg = bot.add_ruleset("https://x/three.list", "direct", "three")
        assert ok, msg
        current_meta = json.loads(Path(bot.RS_META).read_text(encoding="utf-8"))
        two_name = next(
            name for name, info in current_meta.items()
            if info["url"] == "https://x/two.list"
        )
        three_name = next(
            name for name, info in current_meta.items()
            if info["url"] == "https://x/three.list"
        )

        # Partial refresh: failed direct source remains watched at its old bytes while
        # another direct source and the aggregate commit together.
        def partial(url, **kwargs):
            if url == "https://x/two.list":
                raise ValueError("two unavailable")
            if url == "https://x/three.list":
                return [], [], ["new-keyword"], []
            return sources[url]

        bot._fetch_surge = partial
        count, failed = bot.refresh_rulesets()
        assert count == 1 and any(two_name in item or "two" in item for item in failed)
        text = aggregate(root)
        assert "full:other.example\n" in text
        assert "keyword:new-keyword\n" in text
        assert "keyword:old-keyword\n" not in text

        # A normal provider keeps the existing model/Mihomo path and never enters the
        # phone-local aggregate.
        bot._fetch_surge = lambda url, **kwargs: sources[url]
        ok, msg = bot.add_ruleset("https://x/proxy.list", "hk", "proxy")
        assert ok, msg
        proxy_name = next(
            name for name, info in json.loads(Path(bot.RS_META).read_text()).items()
            if info["url"] == "https://x/proxy.list"
        )
        model = json.loads(Path(bot.SB).read_text(encoding="utf-8"))
        assert any(r.get("rule_set") == proxy_name for r in model["route"]["rules"])
        assert "proxy.only.example" not in aggregate(root)
        assert "full:proxy.only.example\n" in hijack_aggregate(root)

        # target 变更必须同时收敛 model/meta/direct+hijack；direct-type tag 与 literal
        # direct 仍是两套语义。Bot 的通用 reassign 也必须复用同一个核心入口。
        ok, msg = bot.set_ruleset_target(two_name, "hk")
        assert ok, msg
        current_meta = json.loads(Path(bot.RS_META).read_text(encoding="utf-8"))
        assert current_meta[two_name]["outbound"] == "hk"
        model = json.loads(Path(bot.SB).read_text(encoding="utf-8"))
        matching_rules = [
            item for item in model["route"]["rules"]
            if item.get("rule_set") == two_name
        ]
        assert matching_rules == [{"rule_set": two_name, "outbound": "hk"}]
        assert sum(
            item.get("tag") == two_name
            for item in model["route"].get("rule_set", [])
        ) == 1
        assert "full:other.example\n" not in aggregate(root)
        assert "full:other.example\n" in hijack_aggregate(root)
        assert "domain:corp.cn\n" not in aggregate(root)
        assert "domain:corp.cn\n" in hijack_aggregate(root)

        idx = next(
            index for index, item in enumerate(model["route"]["rules"])
            if item.get("rule_set") == two_name
        )
        ok, msg = bot.reassign_rule(idx, "jp")
        assert ok, msg
        current_meta = json.loads(Path(bot.RS_META).read_text(encoding="utf-8"))
        assert current_meta[two_name]["outbound"] == "jp"

        ok, msg = bot.set_ruleset_target(two_name, "direct")
        assert ok, msg
        current_meta = json.loads(Path(bot.RS_META).read_text(encoding="utf-8"))
        assert current_meta[two_name]["outbound"] == "direct"
        model = json.loads(Path(bot.SB).read_text(encoding="utf-8"))
        assert not any(
            item.get("rule_set") == two_name
            for item in model["route"]["rules"]
        )
        assert "full:other.example\n" in aggregate(root)
        assert "full:other.example\n" not in hijack_aggregate(root)
        assert "domain:corp.cn\n" in aggregate(root)
        assert "domain:corp.cn\n" not in hijack_aggregate(root)

        # 同值请求也会修复历史 model/meta 漂移，不能只看 meta 后早退。
        model["route"].setdefault("rule_set", []).append({
            "tag": two_name,
            "type": "local",
            "format": "source",
            "path": current_meta[two_name]["path"],
        })
        model["route"]["rules"].append({
            "rule_set": two_name,
            "outbound": "hk",
        })
        Path(bot.SB).write_text(json.dumps(model), encoding="utf-8")
        ok, msg = bot.set_ruleset_target(two_name, "direct")
        assert ok, msg
        model = json.loads(Path(bot.SB).read_text(encoding="utf-8"))
        assert not any(
            item.get("rule_set") == two_name
            for item in model["route"]["rules"]
        )
        assert not any(
            item.get("tag") == two_name
            for item in model["route"].get("rule_set", [])
        )

        # Mutate a watched direct source after candidate assembly. PRECONDITION_FAILED
        # must leave model/meta/aggregate untouched (the simulated competing source write
        # itself is external and restored after the assertion).
        direct_info = json.loads(Path(bot.RS_META).read_text())[two_name]
        watched_path = ruleset_path(root, direct_info["path"])
        watched_old = watched_path.read_bytes()
        model_old = Path(bot.SB).read_bytes()
        meta_old = Path(bot.RS_META).read_bytes()
        aggregate_old = aggregate(root)
        real_derive = bot._mihomo_derive

        def race(staged):
            watched_path.write_bytes(watched_old + b"\n")
            return real_derive(staged)

        bot._mihomo_derive = race
        try:
            ok, msg = bot.add_ruleset(
                "https://x/conflict.list", "direct", "conflict"
            )
        finally:
            bot._mihomo_derive = real_derive
        assert not ok and "PRECONDITION_FAILED" in msg
        assert Path(bot.SB).read_bytes() == model_old
        assert Path(bot.RS_META).read_bytes() == meta_old
        assert aggregate(root) == aggregate_old
        watched_path.write_bytes(watched_old)

        # rs_meta itself is an optimistic-concurrency dependency. A competing metadata
        # commit after our snapshot must survive; our candidate must not overwrite it.
        model_old = Path(bot.SB).read_bytes()
        meta_old = Path(bot.RS_META).read_bytes()
        aggregate_old = aggregate(root)
        competing = json.loads(meta_old.decode("utf-8"))
        competing["rs_competing"] = {
            "url": "https://x/competing.list",
            "outbound": "hk",
            "format": "source",
            "path": "/etc/sing-box/rs/rs_competing.json",
            "count": 1,
        }
        competing_raw = json.dumps(competing, ensure_ascii=False, indent=2).encode()
        real_derive = bot._mihomo_derive

        def meta_race(staged):
            Path(bot.RS_META).write_bytes(competing_raw)
            return real_derive(staged)

        bot._mihomo_derive = meta_race
        try:
            ok, msg = bot.add_ruleset(
                "https://x/meta-race.list", "direct", "meta-race"
            )
        finally:
            bot._mihomo_derive = real_derive
        assert not ok and "PRECONDITION_FAILED" in msg
        assert Path(bot.SB).read_bytes() == model_old
        assert Path(bot.RS_META).read_bytes() == competing_raw
        assert aggregate(root) == aggregate_old
        Path(bot.RS_META).write_bytes(meta_old)

        # The MosDNS interface is watched in the same transaction, not merely checked
        # before it starts. A concurrent config replacement blocks the commit.
        config_old = Path(bot.MOSDNS_CONF).read_bytes()
        model_old = Path(bot.SB).read_bytes()
        meta_old = Path(bot.RS_META).read_bytes()
        aggregate_old = aggregate(root)

        def config_race(staged):
            Path(bot.MOSDNS_CONF).write_bytes(config_old + b"\n# concurrent change\n")
            return real_derive(staged)

        bot._mihomo_derive = config_race
        try:
            ok, msg = bot.add_ruleset(
                "https://x/config-race.list", "direct", "config-race"
            )
        finally:
            bot._mihomo_derive = real_derive
        assert not ok and "PRECONDITION_FAILED" in msg
        assert Path(bot.SB).read_bytes() == model_old
        assert Path(bot.RS_META).read_bytes() == meta_old
        assert aggregate(root) == aggregate_old
        Path(bot.MOSDNS_CONF).write_bytes(config_old)

        before_info = next(iter(json.loads(Path(bot.RS_META).read_text()).values()))
        before_source = ruleset_path(root, before_info["path"]).read_bytes()
        before_aggregate = aggregate(root)
        bot._fetch_surge = lambda url, **kwargs: (_ for _ in ()).throw(
            ValueError("upstream failed")
        )
        count, failed = bot.refresh_rulesets()
        assert count == 0 and failed
        after_info = next(iter(json.loads(Path(bot.RS_META).read_text()).values()))
        assert ruleset_path(root, after_info["path"]).read_bytes() == before_source
        assert aggregate(root) == before_aggregate

        refused = importlib.import_module("pdgtx").TxRefused
        try:
            bot._phone_direct_entries(
                b'{"version":1,"rules":[{"ip_cidr":["1.1.1.0/24"]}]}', "ip"
            )
        except refused:
            pass
        else:
            raise AssertionError("phone-direct source containing ip_cidr was accepted")
        proxy_dns = bot._ruleset_hijack_bytes(
            {
                "rs_ip": {
                    "url": "https://x/ip.list",
                    "outbound": "hk",
                    "format": "source",
                    "path": "/etc/sing-box/rs/rs_ip.json",
                },
                "rs_mrs": {
                    "url": "https://x/domain.mrs",
                    "outbound": "hk",
                    "format": "mrs",
                    "path": "/etc/sing-box/rs/rs_mrs.mrs",
                },
            },
            {
                "ruleset:rs_ip.json": (
                    b'{"version":1,"rules":[{"ip_cidr":["192.0.2.0/24"]}]}'
                )
            },
            {},
        ).decode()
        assert "IP-CIDR" in proxy_dns and "未猜测" in proxy_dns
        assert "binary provider" in proxy_dns
        assert not any(
            line.startswith(("full:", "domain:", "keyword:"))
            for line in proxy_dns.splitlines()
        )
        try:
            bot._ruleset_hijack_bytes(
                {
                    "rs_conditional": {
                        "url": "https://x/conditional.list",
                        "outbound": "hk",
                        "format": "source",
                        "path": "/etc/sing-box/rs/rs_conditional.json",
                    }
                },
                {
                    "ruleset:rs_conditional.json": (
                        b'{"version":1,"rules":[{"domain":["x.example"],'
                        b'"network":["tcp"]}]}'
                    )
                },
                {},
            )
        except refused as exc:
            assert "不可展开字段" in str(exc)
        else:
            raise AssertionError(
                "proxy source containing conditional/unknown fields was not fail-closed"
            )
        for suffix in (".mrs", ".srs"):
            ok, msg = bot.add_ruleset("https://x/list" + suffix, "direct")
            assert not ok and "direct" in msg

        # Bot restore must accept both the repository's compact YAML and the
        # block-style YAML rendered by the Web importer, while binding checks
        # to the actual top-level plugins list.  Strict parser failures and a
        # duplicated broad rule before the explicit override all fail closed.
        bot._ruleset_direct_interface_bytes(MOSDNS_SHAPE.encode())
        config_io = bot._pdg_config_io()
        assert Path(config_io.__file__).resolve() == (
            ROOT / "deploy/web/pdgconfigio.py").resolve()
        block_yaml = config_io._safe_yaml_dump(
            config_io._safe_yaml_load(MOSDNS_SHAPE.encode()))
        bot._ruleset_direct_interface_bytes(block_yaml)
        original_isfile = bot.os.path.isfile
        bot._PDG_CONFIG_IO_MODULE = None
        bot.os.path.isfile = lambda _path: False
        try:
            try:
                bot._pdg_config_io()
            except ModuleNotFoundError:
                pass
            else:
                raise AssertionError("missing strict YAML parser was accepted")
        finally:
            bot.os.path.isfile = original_isfile
            bot._PDG_CONFIG_IO_MODULE = config_io
        original_bot_file = bot.__file__
        original_abspath = bot.os.path.abspath
        production_candidates = []
        bot._PDG_CONFIG_IO_MODULE = None
        bot.__file__ = "/opt/pdg-bot/bot.py"
        bot.os.path.abspath = lambda path: path
        bot.os.path.isfile = lambda path: (
            production_candidates.append(path) or False)
        try:
            try:
                bot._pdg_config_io()
            except ModuleNotFoundError:
                pass
            else:
                raise AssertionError("missing production YAML parser was accepted")
        finally:
            bot.os.path.isfile = original_isfile
            bot.os.path.abspath = original_abspath
            bot.__file__ = original_bot_file
            bot._PDG_CONFIG_IO_MODULE = config_io
        assert production_candidates == ["/opt/pdg-web/pdgconfigio.py"]
        explicit_rule = (
            "      - matches: qname $explicit_hijack\n"
            "        exec: goto force_hijack_seq\n"
        )
        broad_rule = (
            "      - matches: qname $geosite_cn\n"
            "        exec: $local_upstream\n"
        )
        unsafe_interfaces = {
            "nested fake plugins": MOSDNS_SHAPE.replace(
                "plugins:\n", "plugins: []\nevil:\n", 1),
            "duplicate plugin tag": MOSDNS_SHAPE.replace(
                "  - tag: explicit_hijack\n",
                "  - tag: geosite_cn\n", 1),
            "duplicate broad rule": MOSDNS_SHAPE.replace(
                explicit_rule, broad_rule + explicit_rule, 1),
            "unexpected broad execution": MOSDNS_SHAPE.replace(
                explicit_rule,
                "      - matches: qname $geosite_cn\n"
                "        exec: $remote_upstream\n" + explicit_rule, 1),
            "shadow explicit execution": MOSDNS_SHAPE.replace(
                explicit_rule,
                "      - matches: qname $explicit_hijack\n"
                "        exec: $remote_upstream\n" + explicit_rule, 1),
            "second black hole": MOSDNS_SHAPE.replace(
                "        exec: black_hole 203.0.113.10\n",
                "        exec: black_hole 203.0.113.10\n"
                "      - exec: black_hole not-an-ip\n", 1),
            "duplicate YAML key": MOSDNS_SHAPE.replace(
                "plugins:\n", "plugins:\nplugins:\n", 1),
            "YAML alias": b"plugins: &p []\ncopy: *p\n",
            "YAML tag": b"plugins: !unsafe []\n",
            "multiple YAML documents": b"plugins: []\n---\nplugins: []\n",
        }
        for label, unsafe in unsafe_interfaces.items():
            payload = unsafe.encode() if isinstance(unsafe, str) else unsafe
            try:
                bot._ruleset_direct_interface_bytes(payload)
            except refused:
                pass
            else:
                raise AssertionError(label + " MosDNS interface was accepted")

        for actual, marker, path_in_comment in (
            (
                ',"/etc/mosdns/rules/ruleset_direct.txt"',
                "  - tag: geosite_cn\n",
                "/etc/mosdns/rules/ruleset_direct.txt",
            ),
            (
                '"/etc/mosdns/rules/custom_hijack.txt",',
                "  - tag: explicit_hijack\n",
                "/etc/mosdns/rules/custom_hijack.txt",
            ),
            (
                ',"/etc/mosdns/rules/ruleset_hijack.txt"',
                "  - tag: explicit_hijack\n",
                "/etc/mosdns/rules/ruleset_hijack.txt",
            ),
        ):
            comment_only = MOSDNS_SHAPE.replace(actual, "", 1).replace(
                marker,
                marker + "    # comment-only " + path_in_comment + "\n",
                1,
            )
            try:
                bot._ruleset_direct_interface_bytes(comment_only.encode())
            except refused:
                pass
            else:
                raise AssertionError("comment-only MosDNS path was accepted")
        try:
            bot._register_ruleset_direct_derive(
                types.SimpleNamespace(), {"rs_meta": b"{}", "mosdns_conf": None}
            )
        except refused:
            pass
        else:
            raise AssertionError("staged deletion of MosDNS config was accepted")
        try:
            bot.parse_link("http://user:password@example.com:8080#direct")
        except ValueError:
            pass
        else:
            raise AssertionError("proxy outbound tag literal direct was accepted")
        ok, msg = bot.add_group("direct", ["hk", "jp"])
        assert not ok and "保留字" in msg

        # Restore treats archived aggregate as untrusted cache and derives it from the
        # archived source JSON + metadata inside the same repair transaction.  The
        # supported fork boundary is v1.6.4, whose compact managed graph is byte-for-
        # byte the current template; this legacy no-manifest package must remain valid.
        restore_meta = {
            "rs_restore": {
                "url": "https://x/restore.list",
                "outbound": "direct",
                "format": "source",
                "path": "/etc/sing-box/rs/rs_restore.json",
                "count": 1,
            }
        }
        restored_source = b'{"version":1,"rules":[{"domain":["restored.example"]}]}'

        def restore_entries(mosdns):
            return [
                ("etc/sing-box/config.json", json.dumps(SAMPLE).encode()),
                ("etc/mosdns/config.yaml", mosdns),
                ("etc/mosdns/rules/ruleset_direct.txt",
                 b"domain:poison.example\n"),
                ("opt/pdg-bot/rulesets.json", json.dumps(restore_meta).encode()),
                ("etc/sing-box/rs/rs_restore.json", restored_source),
            ]

        data = backup_blob(restore_entries(MOSDNS_SHAPE.encode()))
        ok, msg = bot.restore_from(data)
        assert ok, msg
        text = aggregate(root)
        assert "full:restored.example\n" in text
        assert "poison.example" not in text

        # Web preview renders a v2 candidate in block style.  Exercise the strict
        # manifest path and prove every machine-owned identity is rebound from the
        # CAS-protected live graph.  An incoming local path is allowed only because
        # the contract removes it before the candidate is staged.
        foreign = config_io._safe_yaml_load(MOSDNS_SHAPE.encode())
        foreign_plugins = {item["tag"]: item for item in foreign["plugins"]}
        foreign_plugins["npn_clients"]["args"]["ips"] = ["172.31.0.0/24"]
        foreign_plugins["lazy_cache"]["args"]["size"] = 2048
        foreign_plugins["geosite_cn"]["args"]["files"].append("/etc/shadow")
        for tag, listen in (("udp_server", "127.0.0.1:1053"),
                            ("tcp_server", "127.0.0.1:1053"),
                            ("dot_server", "127.0.0.1:1853")):
            foreign_plugins[tag]["args"]["listen"] = listen
        foreign_plugins["dot_server"]["args"].update({
            "cert": "/foreign/fullchain.pem", "key": "/foreign/privkey.pem",
        })
        for plugin in foreign["plugins"]:
            if plugin["type"] == "sequence":
                for item in plugin["args"]:
                    if item.get("exec", "").startswith("black_hole "):
                        item["exec"] = "black_hole 198.51.100.44"
        foreign_block_yaml = config_io._safe_yaml_dump(foreign)
        data = backup_blob(restore_entries(foreign_block_yaml), manifest=True)
        ok, msg = bot.restore_from(data)
        assert ok, msg
        restored_mosdns = config_io._safe_yaml_load(
            Path(bot.MOSDNS_CONF).read_bytes())
        restored_plugins = {
            item["tag"]: item for item in restored_mosdns["plugins"]
        }
        local = config_io._safe_yaml_load(MOSDNS_SHAPE.encode())
        local_plugins = {item["tag"]: item for item in local["plugins"]}
        for tag, plugin in local_plugins.items():
            if plugin["type"] == "domain_set":
                assert restored_plugins[tag]["args"]["files"] == plugin["args"]["files"]
        assert "/etc/shadow" not in json.dumps(restored_mosdns)
        assert restored_plugins["npn_clients"]["args"] == local_plugins[
            "npn_clients"]["args"]
        assert restored_plugins["lazy_cache"]["args"]["size"] == 8192
        for tag in ("udp_server", "tcp_server", "dot_server"):
            assert restored_plugins[tag]["args"] == local_plugins[tag]["args"]
        restored_black_holes = {
            item["exec"] for plugin in restored_plugins.values()
            if plugin["type"] == "sequence" for item in plugin["args"]
            if item.get("exec", "").startswith("black_hole ")
        }
        assert restored_black_holes == {"black_hole 203.0.113.10"}

        # A valid MosDNS process is not necessarily a PDG-managed graph.  These
        # takeover attempts all travel through the real v2 restore envelope and
        # must fail before any production target changes.
        takeover_docs = {}
        doc = config_io._safe_yaml_load(MOSDNS_SHAPE.encode())
        doc["api"] = {"http": "0.0.0.0:8080"}
        takeover_docs["top-level API"] = doc
        doc = config_io._safe_yaml_load(MOSDNS_SHAPE.encode())
        doc["plugins"].append({
            "tag": "attacker", "type": "domain_set",
            "args": {"files": ["/etc/shadow"]},
        })
        takeover_docs["extra file-reading plugin"] = doc
        doc = config_io._safe_yaml_load(MOSDNS_SHAPE.encode())
        force = next(item for item in doc["plugins"]
                     if item["tag"] == "force_hijack_seq")
        black_hole = next(item for item in force["args"]
                          if item.get("exec", "").startswith("black_hole "))
        black_hole["matches"] = "qtype 28"
        takeover_docs["black-hole on qtype 28"] = doc
        doc = config_io._safe_yaml_load(MOSDNS_SHAPE.encode())
        internal = next(item for item in doc["plugins"]
                        if item["tag"] == "internal_sequence")
        explicit_at = next(index for index, item in enumerate(internal["args"])
                           if item.get("matches") == "qname $explicit_hijack")
        internal["args"][explicit_at:explicit_at] = [
            {"exec": "$remote_upstream"}, {"exec": "jump has_resp"},
        ]
        takeover_docs["unconditional pre-explicit response"] = doc
        doc = config_io._safe_yaml_load(MOSDNS_SHAPE.encode())
        internal = next(item for item in doc["plugins"]
                        if item["tag"] == "internal_sequence")
        explicit_at = next(index for index, item in enumerate(internal["args"])
                           if item.get("matches") == "qname $explicit_hijack")
        internal["args"].insert(explicit_at, {
            "matches": "  qname  $geosite_cn  ", "exec": "$local_upstream",
        })
        takeover_docs["whitespace-equivalent shadow broad rule"] = doc
        doc = config_io._safe_yaml_load(MOSDNS_SHAPE.encode())
        internal = next(item for item in doc["plugins"]
                        if item["tag"] == "internal_sequence")
        explicit = next(item for item in internal["args"]
                        if item.get("matches") == "qname $explicit_hijack")
        explicit["matches"] = "  qname  $explicit_hijack  "
        takeover_docs["whitespace-equivalent explicit rule"] = doc

        for label, takeover in takeover_docs.items():
            before = {
                path: Path(path).read_bytes()
                for path in (bot.SB, bot.RS_META, bot.MOSDNS_CONF,
                             bot.MOSDNS_RULESET_DIRECT, bot.MIHOMO_CFG)
            }
            payload = backup_blob(
                restore_entries(config_io._safe_yaml_dump(takeover)),
                manifest=True)
            ok, msg = bot.restore_from(payload)
            assert not ok, label + ": " + msg
            for path, content in before.items():
                assert Path(path).read_bytes() == content, label

        # A restore containing direct metadata cannot pair it with an old MosDNS config
        # that never loads the aggregate. Candidate validation fails before production.
        old_mosdns = """\
plugins:
  - tag: geosite_cn
    type: domain_set
    args: { files: ["/etc/mosdns/rules/geosite_cn.txt"] }
  - tag: internal_sequence
    type: sequence
    args:
      - matches: qname $geosite_cn
        exec: $local_upstream
"""
        before = {
            path: Path(path).read_bytes()
            for path in (bot.SB, bot.RS_META, bot.MOSDNS_CONF,
                         bot.MOSDNS_RULESET_DIRECT, bot.MIHOMO_CFG)
        }
        data = backup_blob([
            ("etc/sing-box/config.json", json.dumps(SAMPLE).encode()),
            ("etc/mosdns/config.yaml", old_mosdns.encode()),
            ("opt/pdg-bot/rulesets.json", json.dumps(restore_meta).encode()),
            ("etc/sing-box/rs/rs_restore.json", restored_source),
        ])
        ok, msg = bot.restore_from(data)
        assert not ok, msg
        for path, content in before.items():
            assert Path(path).read_bytes() == content

        # CLI rollback uses the same trusted candidate-tree deriver and ignores a
        # poisoned archived aggregate.
        candidate = Path(root) / "snapshot-candidate"
        (candidate / "etc/mosdns/rules").mkdir(parents=True)
        (candidate / "etc/sing-box/rs").mkdir(parents=True)
        (candidate / "opt/pdg-bot").mkdir(parents=True)
        (candidate / "etc/mosdns/config.yaml").write_text(
            MOSDNS_SHAPE, encoding="utf-8"
        )
        (candidate / "opt/pdg-bot/rulesets.json").write_text(
            json.dumps(restore_meta), encoding="utf-8"
        )
        (candidate / "etc/sing-box/rs/rs_restore.json").write_bytes(
            restored_source
        )
        candidate_aggregate = (
            candidate / "etc/mosdns/rules/ruleset_direct.txt"
        )
        candidate_aggregate.write_text(
            "domain:poison.example\n", encoding="utf-8"
        )
        assert bot._derive_ruleset_direct_tree(str(candidate))
        candidate_text = candidate_aggregate.read_text(encoding="utf-8")
        assert "full:restored.example\n" in candidate_text
        assert "poison.example" not in candidate_text

        # First-upgrade rollback compatibility: the snapshot's old MosDNS contract
        # loaded ruleset_direct + custom_hijack but predated ruleset_hijack. A new
        # CLI must faithfully rebuild only direct, ignore unrelated proxy metadata,
        # and must not inject/trust a new aggregate member.
        legacy_candidate = Path(root) / "legacy-snapshot-candidate"
        (legacy_candidate / "etc/mosdns/rules").mkdir(parents=True)
        (legacy_candidate / "etc/sing-box/rs").mkdir(parents=True)
        (legacy_candidate / "opt/pdg-bot").mkdir(parents=True)
        legacy_shape = MOSDNS_SHAPE.replace(
            ',"/etc/mosdns/rules/ruleset_hijack.txt"', "", 1
        )
        (legacy_candidate / "etc/mosdns/config.yaml").write_text(
            legacy_shape, encoding="utf-8"
        )
        legacy_meta = {
            **restore_meta,
            "rs_unrelated_proxy": {
                "url": "https://x/proxy.list",
                "outbound": "US",
                "format": "source",
                "path": "/etc/sing-box/rs/rs_unrelated_proxy.json",
                "count": 1,
            },
        }
        (legacy_candidate / "opt/pdg-bot/rulesets.json").write_text(
            json.dumps(legacy_meta), encoding="utf-8"
        )
        (legacy_candidate / "etc/sing-box/rs/rs_restore.json").write_bytes(
            restored_source
        )
        legacy_direct = (
            legacy_candidate / "etc/mosdns/rules/ruleset_direct.txt"
        )
        legacy_hijack = (
            legacy_candidate / "etc/mosdns/rules/ruleset_hijack.txt"
        )
        legacy_direct.write_text("domain:poison.example\n", encoding="utf-8")
        legacy_hijack.write_text("domain:poison.example\n", encoding="utf-8")
        assert bot._derive_ruleset_direct_tree(str(legacy_candidate))
        assert "full:restored.example\n" in legacy_direct.read_text(
            encoding="utf-8"
        )
        assert "poison.example" not in legacy_direct.read_text(encoding="utf-8")
        assert not legacy_hijack.exists()

        # A still older proxy-only snapshot neither needs nor references either
        # aggregate. Poisoned archived caches are removed, no proxy source is
        # required merely to restore that old contract, and the helper reports absent.
        proxy_only_candidate = Path(root) / "legacy-proxy-only-candidate"
        (proxy_only_candidate / "etc/mosdns/rules").mkdir(parents=True)
        (proxy_only_candidate / "etc/sing-box/rs").mkdir(parents=True)
        (proxy_only_candidate / "opt/pdg-bot").mkdir(parents=True)
        proxy_only_shape = legacy_shape.replace(
            ',"/etc/mosdns/rules/ruleset_direct.txt"', "", 1
        )
        (proxy_only_candidate / "etc/mosdns/config.yaml").write_text(
            proxy_only_shape, encoding="utf-8"
        )
        proxy_only_meta = {
            "rs_unrelated_proxy": legacy_meta["rs_unrelated_proxy"]
        }
        (proxy_only_candidate / "opt/pdg-bot/rulesets.json").write_text(
            json.dumps(proxy_only_meta), encoding="utf-8"
        )
        proxy_only_direct = (
            proxy_only_candidate / "etc/mosdns/rules/ruleset_direct.txt"
        )
        proxy_only_hijack = (
            proxy_only_candidate / "etc/mosdns/rules/ruleset_hijack.txt"
        )
        proxy_only_direct.write_text(
            "domain:poison.example\n", encoding="utf-8"
        )
        proxy_only_hijack.write_text(
            "domain:poison.example\n", encoding="utf-8"
        )
        assert not bot._derive_ruleset_direct_tree(
            str(proxy_only_candidate)
        )
        assert not proxy_only_direct.exists()
        assert not proxy_only_hijack.exists()

        # Legacy compatibility is schema-aware, not a validation bypass: explicit
        # hijack must still precede the broad direct collection.
        explicit_block = (
            "      - matches: qname $explicit_hijack\n"
            "        exec: goto force_hijack_seq\n"
        )
        first_broad = (
            "      - matches: qname $geosite_cn\n"
            "        exec: $ecs_china\n"
        )
        bad_legacy = legacy_shape.replace(explicit_block, "", 1).replace(
            first_broad, first_broad + explicit_block, 1)
        assert bad_legacy != legacy_shape
        (legacy_candidate / "etc/mosdns/config.yaml").write_text(
            bad_legacy, encoding="utf-8"
        )
        try:
            bot._derive_ruleset_direct_tree(str(legacy_candidate))
        except bot._pdgtx().TxRefused:
            pass
        else:
            raise AssertionError("旧接口错误优先级必须在落盘前被拒绝")

    template = (ROOT / "deploy/mosdns/config.yaml").read_text(encoding="utf-8")
    assert "/etc/mosdns/rules/ruleset_direct.txt" in template
    assert template.index("qname $explicit_hijack") < template.index(
        "qname $geosite_cn"
    )
    install = (ROOT / "install.sh").read_text(encoding="utf-8")
    lifecycle = (ROOT / "deploy/bot/pdg.sh").read_text(encoding="utf-8")
    source = (ROOT / "deploy/bot/pdg-bot.py").read_text(encoding="utf-8")
    assert ": > /etc/mosdns/rules/ruleset_direct.txt" in install
    assert ": > /etc/mosdns/rules/ruleset_hijack.txt" in install
    assert "etc/mosdns/rules/ruleset_direct.txt" in lifecycle
    assert "etc/mosdns/rules/ruleset_hijack.txt" in lifecycle
    assert "MOSDNS_RULESET_DIRECT" in source
    assert '_register_ruleset_direct_derive(t, staged_for_direct)' in source
    rollback_source = lifecycle[lifecycle.index("cmd_rollback(){"):]
    assert rollback_source.index(
        '_pdg_snapshot_rederive_ruleset_direct "$tree"'
    ) < rollback_source.index(
        '_pdg_apply_snapshot_tree "$tree"'
    )
    migration_source = lifecycle[
        lifecycle.index("migrate_ruleset_phone_direct(){"):
        lifecycle.index("migrate_mosdns_hijack_shape(){")
    ]
    assert '_pdg_ruleset_direct_interface_ready_file "$mc"' in migration_source
    assert 'grep -qF "$agg" "$mc"' not in migration_source
    assert "_core_kernel_stable mosdns" in migration_source
    assert (
        'python3 - "$work/config.candidate" "$agg" "$hijagg"'
        in migration_source
    )
    assert "_pdg_capture_ruleset_migration_before" in migration_source
    assert "_pdg_ruleset_aggregate_candidates" in migration_source
    assert migration_source.count(
        "_pdg_restore_ruleset_migration_before"
    ) >= 4
    assert migration_source.index(
        "_pdg_ruleset_aggregate_candidates"
    ) < migration_source.index(
        '_pdg_atomic_install_file "$work/direct.candidate" "$agg"'
    )
    direct_commit = migration_source.index(
        '_pdg_atomic_install_file "$work/direct.candidate" "$agg"'
    )
    transition_commit = migration_source.index(
        '_pdg_atomic_install_file "$work/hijack.transition" "$hijagg"'
    )
    hijack_commit = migration_source.index(
        '_pdg_atomic_install_file "$work/hijack.candidate" "$hijagg"'
    )
    config_commit = migration_source.index(
        '_pdg_atomic_install_file "$work/config.candidate" "$mc"'
    )
    strict_check = migration_source.index(
        'if ! _pdg_ruleset_direct_interface_ready_file "$mc"; then'
    )
    restart = migration_source.index("if systemctl restart mosdns")
    assert (
        transition_commit < direct_commit < hijack_commit
        < config_commit < strict_check < restart
    )
    journal_publish = migration_source.index('mv "$preparing" "$journal"')
    journal_sync = migration_source.index(
        '_pdg_sync_ruleset_migration_path "$work"'
    )
    assert journal_sync < journal_publish < transition_commit
    assert (
        migration_source.index('work="$journal"')
        < transition_commit
    )
    assert migration_source.index(
        "_pdg_recover_ruleset_migration_journal"
    ) < transition_commit

    # Simulate a kill after each ordered live replace.  An old config does not
    # consume the new aggregate paths until both exist; an already-ready config
    # starts with both paths present.  Therefore every bootable disk state keeps
    # all aggregate paths referenced by its active config present, while the
    # published journal supplies byte-exact recovery on the next migrate.
    legacy_config = (
        MOSDNS_SHAPE
        .replace(',"/etc/mosdns/rules/ruleset_direct.txt"', "", 1)
        .replace(',"/etc/mosdns/rules/ruleset_hijack.txt"', "", 1)
    )
    aggregate_paths = (
        "/etc/mosdns/rules/ruleset_direct.txt",
        "/etc/mosdns/rules/ruleset_hijack.txt",
    )
    for active_config, initial_files in (
        (legacy_config, set()),
        (MOSDNS_SHAPE, set(aggregate_paths)),
    ):
        files = set(initial_files)
        disk_config = active_config
        kill_states = [(disk_config, set(files))]
        files.add(aggregate_paths[1])
        kill_states.append((disk_config, set(files)))
        files.add(aggregate_paths[0])
        kill_states.append((disk_config, set(files)))
        kill_states.append((disk_config, set(files)))
        disk_config = MOSDNS_SHAPE
        kill_states.append((disk_config, set(files)))
        for config_at_kill, files_at_kill in kill_states:
            by_tag = bot._mosdns_plugin_map(config_at_kill.encode())
            geosite = bot._mosdns_managed_plugin(
                by_tag, "geosite_cn", "domain_set")
            explicit = bot._mosdns_managed_plugin(
                by_tag, "explicit_hijack", "domain_set")
            referenced = {
                path
                for plugin, label, path in (
                    (geosite, "geosite_cn", aggregate_paths[0]),
                    (explicit, "explicit_hijack", aggregate_paths[1]),
                )
                if path in bot._mosdns_domain_set_files(plugin, label)
            }
            assert referenced <= files_at_kill
    restore_source = lifecycle[
        lifecycle.index("_pdg_restore_ruleset_migration_before(){"):
        lifecycle.index("_pdg_legacy_snapshot_mihomo_prove(){")
    ]
    for before, target in (
        ("config.before", '"$config"'),
        ("direct.before", '"$direct"'),
        ("hijack.before", '"$hijack"'),
    ):
        assert before in restore_source
        assert target in restore_source
    assert 'rm -f "$direct"' in restore_source
    assert 'rm -f "$hijack"' in restore_source
    generated_tail = migration_source.split("\nRSDIRECTPY", 1)[1]
    assert generated_tail.index(
        'if ! _pdg_ruleset_direct_interface_ready_file "$mc"; then'
    ) < generated_tail.index("if systemctl restart mosdns")
    validation_failure = generated_tail[
        generated_tail.index(
            'if ! _pdg_ruleset_direct_interface_ready_file "$mc"; then'
        ):
        generated_tail.index("if systemctl restart mosdns")
    ]
    assert "_pdg_restore_ruleset_migration_before" in validation_failure
    assert "return 1" in validation_failure
    runtime_failure = generated_tail[
        generated_tail.index(
            'c_y "  [规则集手机直连] MosDNS 重启后未稳定，正在还原三文件 before-image。"'
        ):
    ]
    assert "_pdg_restore_ruleset_migration_before" in runtime_failure

    aggregate_script = lifecycle.split("<<'RSAGGPY'\n", 1)[1].split(
        "\nRSAGGPY", 1
    )[0]
    with tempfile.TemporaryDirectory(prefix="pdg-rsagg-migrate-") as directory:
        box = Path(directory)
        rs_dir = box / "rs"
        rs_dir.mkdir()
        config_path = box / "config.yaml"
        config_path.write_text(MOSDNS_SHAPE, encoding="utf-8")
        direct_source = (
            b'{"version":1,"rules":[{"domain_suffix":'
            b'["corp.example","old-proxy.example"]}]}'
        )
        proxy_source = (
            b'{"version":1,"rules":[{"domain":["ai.example"]}]}'
        )
        (rs_dir / "existing-direct.json").write_bytes(direct_source)
        (rs_dir / "existing-proxy.json").write_bytes(proxy_source)
        metadata = {
            "existing_direct": {
                "outbound": "direct",
                "format": "source",
                "path": "/etc/sing-box/rs/existing-direct.json",
            },
            "existing_proxy": {
                "outbound": "US",
                "format": "source",
                "path": "/etc/sing-box/rs/existing-proxy.json",
            },
        }
        metadata_path = box / "rulesets.json"
        metadata_path.write_text(json.dumps(metadata), encoding="utf-8")
        direct_candidate = box / "direct.candidate"
        hijack_candidate = box / "hijack.candidate"
        transition_candidate = box / "hijack.transition"
        old_hijack = box / "old-hijack.txt"
        old_hijack.write_text(
            "domain:old-proxy.example\n", encoding="utf-8"
        )
        aggregate_input = aggregate_script
        if os.name == "nt":
            aggregate_input = (
                "import sys, types\n"
                "sys.modules['fcntl'] = types.SimpleNamespace("
                "LOCK_EX=1, LOCK_NB=2, LOCK_UN=8, flock=lambda *args: None)\n"
                + aggregate_input
            )
        result = subprocess.run(
            [
                os.sys.executable,
                "-",
                str(BOT_DIR / "pdg-bot.py"),
                str(config_path),
                str(metadata_path),
                str(rs_dir),
                str(direct_candidate),
                str(hijack_candidate),
                str(transition_candidate),
                str(old_hijack),
            ],
            input=aggregate_input,
            text=True,
            encoding="utf-8",
            env={**os.environ, "PYTHONIOENCODING": "utf-8"},
            capture_output=True,
            check=False,
        )
        assert result.returncode == 0, result.stderr
        assert "domain:corp.example\n" in direct_candidate.read_text(
            encoding="utf-8"
        )
        assert "domain:old-proxy.example\n" in direct_candidate.read_text(
            encoding="utf-8"
        )
        assert "full:ai.example\n" in hijack_candidate.read_text(
            encoding="utf-8"
        )
        assert "old-proxy.example" not in hijack_candidate.read_text(
            encoding="utf-8"
        )
        transition = transition_candidate.read_text(encoding="utf-8")
        assert "full:ai.example\n" in transition
        assert "domain:old-proxy.example\n" in transition

    migration_script = lifecycle.split("<<'RSDIRECTPY'\n", 1)[1].split(
        "\nRSDIRECTPY", 1
    )[0]
    with tempfile.TemporaryDirectory(prefix="pdg-rsdirect-migrate-") as directory:
        config_path = Path(directory) / "config.yaml"
        explicit_rule = (
            "      - matches: qname $explicit_hijack\n"
            "        exec: goto force_hijack_seq\n"
        )
        broad_rule = (
            "      - matches: qname $geosite_cn\n"
            "        exec: $local_upstream\n"
        )
        wrong_order = MOSDNS_SHAPE.replace(
            explicit_rule + broad_rule, broad_rule + explicit_rule
        )
        config_path.write_text(wrong_order, encoding="utf-8")
        result = subprocess.run(
            [
                os.sys.executable,
                "-",
                str(config_path),
                "/etc/mosdns/rules/ruleset_direct.txt",
                "/etc/mosdns/rules/ruleset_hijack.txt",
            ],
            input=migration_script,
            text=True,
            encoding="utf-8",
            capture_output=True,
            check=False,
        )
        assert result.returncode == 0, result.stderr
        healed = config_path.read_text(encoding="utf-8")
        internal = healed[healed.index("  - tag: internal_sequence"):]
        assert internal.index("qname $explicit_hijack") < internal.index(
            "qname $geosite_cn"
        )
        comment_only = (
            MOSDNS_SHAPE
            .replace(',"/etc/mosdns/rules/ruleset_direct.txt"', "", 1)
            .replace('"/etc/mosdns/rules/custom_hijack.txt",', "", 1)
            .replace(
                explicit_rule,
                "      # - matches: qname $explicit_hijack\n"
                "      #   exec: goto force_hijack_seq\n",
                1,
            )
            .replace(
                "  - tag: geosite_cn\n",
                "  - tag: geosite_cn\n"
                "    # /etc/mosdns/rules/ruleset_direct.txt\n",
                1,
            )
            .replace(
                "  - tag: explicit_hijack\n",
                "  - tag: explicit_hijack\n"
                "    # /etc/mosdns/rules/custom_hijack.txt\n",
                1,
            )
        )
        config_path.write_text(comment_only, encoding="utf-8")
        result = subprocess.run(
            [
                os.sys.executable,
                "-",
                str(config_path),
                "/etc/mosdns/rules/ruleset_direct.txt",
                "/etc/mosdns/rules/ruleset_hijack.txt",
            ],
            input=migration_script,
            text=True,
            encoding="utf-8",
            capture_output=True,
            check=False,
        )
        assert result.returncode == 0, result.stderr
        migrated = config_path.read_text(encoding="utf-8")
        active = "\n".join(
            line.split("#", 1)[0] for line in migrated.splitlines()
        )
        assert "/etc/mosdns/rules/ruleset_direct.txt" in active
        assert "/etc/mosdns/rules/custom_hijack.txt" in active
        assert "/etc/mosdns/rules/ruleset_hijack.txt" in active
        bot._ruleset_direct_interface_bytes(migrated.encode())
    print("[OK] ruleset literal direct phone-local lifecycle")


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Literal ruleset target=direct: phone-local DNS semantics and atomic lifecycle."""
from __future__ import annotations

import importlib
import importlib.util
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
MOSDNS_SHAPE = """\
plugins:
  - tag: geosite_cn
    type: domain_set
    args: { files: ["/etc/mosdns/rules/geosite_cn.txt","/etc/mosdns/rules/ruleset_direct.txt"] }
  - tag: explicit_hijack
    type: domain_set
    args: { files: ["/etc/mosdns/rules/custom_hijack.txt"] }
  - tag: force_hijack_seq
    type: sequence
    args:
      - matches: qtype 1
        exec: black_hole 203.0.113.10
  - tag: internal_sequence
    type: sequence
    args:
      - matches: qname $explicit_hijack
        exec: goto force_hijack_seq
      - matches: qname $geosite_cn
        exec: $local_upstream
"""

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


def ruleset_path(root: str, metadata_path: str) -> Path:
    return Path(root + metadata_path.replace("\\", "/"))


def backup_blob(entries) -> bytes:
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
                ["api.example.com", "other.example"], ["example.com"], [], []
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
        for suffix in (".mrs", ".srs"):
            ok, msg = bot.add_ruleset("https://x/list" + suffix, "direct")
            assert not ok and "direct" in msg
        for actual, marker, path_in_comment in (
            (
                ',"/etc/mosdns/rules/ruleset_direct.txt"',
                "  - tag: geosite_cn\n",
                "/etc/mosdns/rules/ruleset_direct.txt",
            ),
            (
                '"/etc/mosdns/rules/custom_hijack.txt"',
                "  - tag: explicit_hijack\n",
                "/etc/mosdns/rules/custom_hijack.txt",
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
        # archived source JSON + metadata inside the same repair transaction.
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
        data = backup_blob([
            ("etc/sing-box/config.json", json.dumps(SAMPLE).encode()),
            ("etc/mosdns/config.yaml", MOSDNS_SHAPE.encode()),
            ("etc/mosdns/rules/ruleset_direct.txt", b"domain:poison.example\n"),
            ("opt/pdg-bot/rulesets.json", json.dumps(restore_meta).encode()),
            ("etc/sing-box/rs/rs_restore.json", restored_source),
        ])
        ok, msg = bot.restore_from(data)
        assert ok, msg
        text = aggregate(root)
        assert "full:restored.example\n" in text
        assert "poison.example" not in text

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

    template = (ROOT / "deploy/mosdns/config.yaml").read_text(encoding="utf-8")
    assert "/etc/mosdns/rules/ruleset_direct.txt" in template
    assert template.index("qname $explicit_hijack") < template.index(
        "qname $geosite_cn"
    )
    install = (ROOT / "install.sh").read_text(encoding="utf-8")
    lifecycle = (ROOT / "deploy/bot/pdg.sh").read_text(encoding="utf-8")
    source = (ROOT / "deploy/bot/pdg-bot.py").read_text(encoding="utf-8")
    assert ": > /etc/mosdns/rules/ruleset_direct.txt" in install
    assert "etc/mosdns/rules/ruleset_direct.txt" in lifecycle
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
    assert '_pdg_atomic_restore_file "$bak" "$mc"' in migration_source
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
    assert '_pdg_atomic_restore_file "$bak" "$mc"' in validation_failure
    assert "return 1" in validation_failure
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
            .replace('"/etc/mosdns/rules/custom_hijack.txt"', "", 1)
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
            ],
            input=migration_script,
            text=True,
            encoding="utf-8",
            capture_output=True,
            check=False,
        )
        assert result.returncode == 0, result.stderr
        bot._ruleset_direct_interface_bytes(config_path.read_bytes())
    print("[OK] ruleset literal direct phone-local lifecycle")


if __name__ == "__main__":
    main()

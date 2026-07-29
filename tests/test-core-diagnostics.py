#!/usr/bin/env python3
"""Structured core diagnostics: bounded exit probes and side-effect-safe domain probes."""
from __future__ import annotations

import copy
import importlib.util
import ipaddress
import pathlib
import subprocess
import sys
import tempfile
import threading
import types
import urllib.error

try:
    import fcntl
    HAVE_FCNTL = True
except ModuleNotFoundError:
    HAVE_FCNTL = False
    fcntl = types.SimpleNamespace(
        LOCK_EX=1,
        LOCK_NB=2,
        LOCK_UN=8,
        flock=lambda *_args: None,
    )
    sys.modules["fcntl"] = fcntl


ROOT = pathlib.Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "pdg_bot_core_diagnostics", ROOT / "deploy/bot/pdg-bot.py"
)
bot = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(bot)


MODEL = {
    "outbounds": [
        {"type": "direct", "tag": "JP"},
        {
            "type": "shadowsocks",
            "tag": "US",
            "server": "us.example",
            "server_port": 443,
        },
        {
            "type": "trojan",
            "tag": "HK",
            "server": "hk.example",
            "server_port": 443,
        },
    ],
    "route": {"rules": [], "final": "US"},
}


def result(returncode=0, stdout="", stderr=""):
    return types.SimpleNamespace(
        returncode=returncode, stdout=stdout, stderr=stderr
    )


# Clash probes are concurrent but output remains in model order and direct uses DIRECT.
bot.load = lambda: MODEL
bot.clash_up = lambda: True
bot._core_backend = lambda: "mihomo"
calls = []
calls_lock = threading.Lock()


def clash_get(path):
    with calls_lock:
        calls.append(path)
    if "/HK/" in path:
        raise urllib.error.HTTPError(path, 504, "timeout", {}, None)
    return {"delay": 23 if "/DIRECT/" in path else 47}


bot.clash_get = clash_get
exits = bot.probe_exit_delays(max_workers=2)
assert exits["method"] == "clash"
assert [item["tag"] for item in exits["items"]] == ["JP", "US", "HK"]
assert [item["status"] for item in exits["items"]] == ["ok", "ok", "timeout"]
assert any("/DIRECT/" in path for path in calls)

# Web-safe mode must not fall back to direct endpoint TCP probes.
bot.clash_up = lambda: False
bot.socket.create_connection = lambda *_a, **_k: (_ for _ in ()).throw(
    AssertionError("TCP fallback was disabled")
)
exits = bot.probe_exit_delays(allow_tcp_fallback=False)
assert exits["method"] == "none"
assert exits["error"] == "clash_unavailable"
assert all(item["status"] == "unavailable" for item in exits["items"])
assert bot.probe_exit_delays(
    allow_tcp_fallback=False, timeout_ms="not-an-int"
)["method"] == "none"

# A malformed endpoint is one unavailable item, not an exception that drops the
# whole structured response.
bad_model = copy.deepcopy(MODEL)
bad_model["outbounds"][1]["server_port"] = "broken"
bot.load = lambda: bad_model
exits = bot.probe_exit_delays(
    allow_tcp_fallback=True, timeout_ms="not-an-int"
)
assert exits["method"] == "tcp"
assert exits["items"][0]["status"] == "unreachable"


with tempfile.TemporaryDirectory(prefix="pdg-core-diag.") as temp:
    root = pathlib.Path(temp)
    rules = root / "rules"
    rules.mkdir()
    config = root / "config.yaml"
    config.write_text(
        'args: { ips: ["10.0.0.0/30"] }\n'
        'args: { files: ["/etc/mosdns/rules/geosite_cn.txt"] }\n',
        encoding="utf-8",
    )
    bot.MOSDNS_CONF = str(config)
    bot.SB = str(root / "model.json")
    bot.RS_META = str(root / "rulesets.json")
    bot.MOSDNS_DIRECT = str(rules / "custom_direct.txt")
    bot.MOSDNS_HIJACK = str(rules / "custom_hijack.txt")
    bot.MOSDNS_RULESET_DIRECT = str(rules / "ruleset_direct.txt")
    bot.MOSDNS_RULESET_HIJACK = str(rules / "ruleset_hijack.txt")
    pathlib.Path(bot.SB).write_text("{}", encoding="utf-8")
    pathlib.Path(bot.RS_META).write_text("{}", encoding="utf-8")
    for path in (
        bot.MOSDNS_DIRECT, bot.MOSDNS_HIJACK,
        bot.MOSDNS_RULESET_DIRECT, bot.MOSDNS_RULESET_HIJACK,
        str(rules / "geosite_cn.txt"),
    ):
        pathlib.Path(path).write_text("# initial\n", encoding="utf-8")
    chosen = bot._internal_probe_ip()
    assert ipaddress.ip_address(chosen) in ipaddress.ip_network("10.0.0.0/30")
    assert chosen not in {"10.0.0.0", "10.0.0.3"}

    bot.PROBE_LOCKFILE = str(root / "probe.lock")

    # Changing only a MosDNS-consumed collection invalidates the optimistic token
    # before any interface or DNS side effect.
    bot._server_ip = lambda: "8.8.8.8"

    def mutate_dns_collection():
        pathlib.Path(bot.MOSDNS_HIJACK).write_text(
            "domain:changed.example\n", encoding="utf-8"
        )
        return "10.0.0.2"

    bot._internal_probe_ip = mutate_dns_collection
    bot.sh = lambda _cmd: (_ for _ in ()).throw(
        AssertionError("changed DNS collection reached a side effect")
    )
    assert bot._probe_config_generation() is not None, (
        bot._probe_config_generation_once()
    )
    routed = bot.probe_domain_route("dns-generation.example")
    assert routed["path"] == "unknown"
    assert routed["reason"] == "config_changed", routed

    bot._internal_probe_ip = lambda: "10.0.0.2"
    bot._server_ip = lambda: "8.8.8.8"
    bot.load = lambda: MODEL
    bot._rs_meta = lambda: {}
    commands = []

    # Failed `ip addr add` fails closed and is never paired with delete or dig.
    def preexisting(cmd):
        commands.append(tuple(cmd))
        if cmd[:3] == ["ip", "addr", "add"]:
            return result(2, stderr="exists")
        if cmd and cmd[0] == "dig":
            return result(0, "8.8.8.8\n")
        return result()

    bot.sh = preexisting
    routed = bot.probe_domain_route("example.com")
    assert routed["path"] == "unknown"
    assert routed["reason"] == "probe_unavailable"
    assert routed["dns_verified"] is False
    assert routed["route_confidence"] == "unknown"
    assert not any(cmd[0] == "dig" for cmd in commands)
    assert not any(cmd[:3] == ("ip", "addr", "del") for cmd in commands)

    # Process launch/timeout/cleanup exceptions all degrade to one structured
    # unavailable result. Cleanup failure cannot preserve a successful verdict.
    commands.clear()

    def add_raises(cmd):
        commands.append(tuple(cmd))
        if cmd[:3] == ["ip", "addr", "add"]:
            raise OSError("ip unavailable")
        return result()

    bot.sh = add_raises
    routed = bot.probe_domain_route("add-exception.example")
    assert routed["path"] == "unknown"
    assert routed["reason"] == "probe_unavailable"
    assert not any(cmd[:3] == ("ip", "addr", "del") for cmd in commands)

    commands.clear()

    def dig_raises(cmd):
        commands.append(tuple(cmd))
        if cmd and cmd[0] == "dig":
            raise subprocess.TimeoutExpired(cmd, 2)
        return result()

    bot.sh = dig_raises
    routed = bot.probe_domain_route("dig-exception.example")
    assert routed["path"] == "unknown"
    assert routed["reason"] == "probe_unavailable"
    assert any(cmd[:3] == ("ip", "addr", "del") for cmd in commands)

    commands.clear()

    def delete_raises(cmd):
        commands.append(tuple(cmd))
        if cmd and cmd[0] == "dig":
            return result(0, "8.8.8.8\n")
        if cmd[:3] == ["ip", "addr", "del"]:
            raise OSError("cleanup unavailable")
        return result()

    bot.sh = delete_raises
    routed = bot.probe_domain_route("delete-exception.example")
    assert routed["path"] == "unknown"
    assert routed["reason"] == "probe_unavailable"
    assert routed["verified"] is False

    # The A black-hole proves only that DNS entered the gateway. The selected
    # target remains a local ruleset simulation and must not be labelled verified.
    commands.clear()

    def gateway(cmd):
        commands.append(tuple(cmd))
        if cmd and cmd[0] == "dig":
            return result(0, "8.8.8.8\n")
        return result()

    bot.sh = gateway
    routed = bot.probe_domain_route("example.com")
    assert routed["path"] == "gateway"
    assert routed["target"] == "US"
    assert routed["dns_verified"] is True
    assert routed["route_confidence"] == "simulated"
    assert routed["verified"] is False
    assert routed["confidence"] == "simulated"
    assert sum(cmd[:3] == ("ip", "addr", "del") for cmd in commands) == 1

    # Bot HTML preserves split evidence: gateway DNS is observed, while the target
    # remains a local ruleset simulation.
    domain_probe = bot.probe_domain_route
    bot.probe_domain_route = lambda domain: {
        "domain": domain,
        "path": "gateway",
        "target": "US",
        "reason": "default",
        "dns_verified": True,
        "route_confidence": "simulated",
        "verified": False,
        "confidence": "simulated",
    }
    try:
        formatted = bot.test_domain("example.com")
    finally:
        bot.probe_domain_route = domain_probe
    assert "DNS 已实测进入网关" in formatted
    assert "出口仅依据当前规则推演" in formatted
    assert "没探到 DNS 结果" not in formatted

    # The consistency token is captured before server/probe identity reads, then
    # immediately rechecked. A change there returns before any interface/DNS action.
    generation_probe = bot._probe_config_generation
    server_ip_probe = bot._server_ip
    internal_ip_probe = bot._internal_probe_ip
    order = []
    generations = iter(("before", "after"))

    def ordered_generation():
        order.append("generation")
        return next(generations)

    bot._probe_config_generation = ordered_generation
    bot._server_ip = lambda: order.append("server_ip") or "8.8.8.8"
    bot._internal_probe_ip = lambda: order.append("probe_ip") or "10.0.0.2"
    bot.sh = lambda _cmd: (_ for _ in ()).throw(
        AssertionError("changed derived identity reached a network side effect")
    )
    try:
        routed = bot.probe_domain_route("derived-generation.example")
    finally:
        bot._probe_config_generation = generation_probe
        bot._server_ip = server_ip_probe
        bot._internal_probe_ip = internal_ip_probe
    assert order == ["generation", "server_ip", "probe_ip", "generation"]
    assert routed["path"] == "unknown"
    assert routed["reason"] == "config_changed"

    # A transaction committed between DNS observation and model inference invalidates
    # the stitched answer without ever blocking that writer.
    generation_probe = bot._probe_config_generation
    generations = iter(("before", "before", "before", "after"))
    bot._probe_config_generation = lambda: next(generations)
    commands.clear()
    bot.sh = gateway
    try:
        routed = bot.probe_domain_route("generation-change.example")
    finally:
        bot._probe_config_generation = generation_probe
    assert routed["path"] == "unknown"
    assert routed["reason"] == "config_changed"
    assert routed["dns_verified"] is False
    assert routed["route_confidence"] == "unknown"
    assert routed["verified"] is False
    assert routed["confidence"] == "unknown"

    # Simultaneous gateway black-hole and real A answers are ambiguous, never gateway.
    commands.clear()

    def mixed(cmd):
        commands.append(tuple(cmd))
        if cmd and cmd[0] == "dig":
            return result(0, "8.8.8.8\n1.1.1.1\n")
        return result()

    bot.sh = mixed
    routed = bot.probe_domain_route("mixed.example")
    assert routed["path"] == "unknown"
    assert routed["reason"] == "probe_unavailable"
    assert routed["dns_verified"] is False
    assert routed["route_confidence"] == "unknown"

    # A successful add owns exactly one cleanup.
    commands.clear()

    def owned(cmd):
        commands.append(tuple(cmd))
        if cmd and cmd[0] == "dig":
            return result(0, "198.51.100.8\n")
        return result()

    bot.sh = owned
    routed = bot.probe_domain_route("direct.example")
    assert routed["path"] == "direct"
    assert routed["dns_verified"] is True
    assert routed["route_confidence"] == "verified"
    assert sum(cmd[:3] == ("ip", "addr", "del") for cmd in commands) == 1

    # A missing/non-IP server identity cannot turn an arbitrary A answer into a
    # verified direct result.
    bot._server_ip = lambda: "?"
    commands.clear()
    bot.sh = owned
    routed = bot.probe_domain_route("identity-missing.example")
    assert routed["path"] == "unknown"
    assert routed["reason"] == "probe_unavailable"
    assert routed["verified"] is False

    # A completed query without A records is unknown, including domains that could
    # otherwise look like CN/custom-direct candidates. Local route simulation does
    # not fully evaluate MosDNS sets.
    bot._server_ip = lambda: "8.8.8.8"

    def no_answer(cmd):
        commands.append(tuple(cmd))
        if cmd and cmd[0] == "dig":
            return result(0, "")
        return result()

    for domain in ("www.baidu.cn", "custom-direct.example"):
        commands.clear()
        bot.sh = no_answer
        routed = bot.probe_domain_route(domain)
        assert routed["path"] == "unknown"
        assert routed["reason"] == "dns_no_answer"
        assert routed["dns_verified"] is False
        assert routed["route_confidence"] == "unknown"

    # A dig process failure is also unavailable, not a simulated gateway path.
    commands.clear()

    def dig_failed(cmd):
        commands.append(tuple(cmd))
        if cmd and cmd[0] == "dig":
            return result(9, stderr="failed")
        return result()

    bot.sh = dig_failed
    routed = bot.probe_domain_route("dig-failed.example")
    assert routed["path"] == "unknown"
    assert routed["reason"] == "probe_unavailable"

    # Another process holding the probe lock causes a structured busy result and
    # absolutely no network/interface side effects.
    if HAVE_FCNTL:
        lock = open(bot.PROBE_LOCKFILE, "w")
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        commands.clear()
        bot.sh = lambda cmd: (_ for _ in ()).throw(
            AssertionError("busy probe performed a side effect")
        )
        try:
            routed = bot.probe_domain_route("busy.example")
        finally:
            fcntl.flock(lock, fcntl.LOCK_UN)
            lock.close()
        assert routed["path"] == "unknown"
        assert routed["reason"] == "probe_busy"


# An unexpandable MRS before final is uncertainty, not a false default-route hit.
bot._internal_probe_ip = lambda: ""
bot.load = lambda: {
    **MODEL,
    "route": {
        "rules": [{"rule_set": "rs_binary", "outbound": "HK"}],
        "final": "US",
    },
}
bot._rs_meta = lambda: {
    "rs_binary": {
        "format": "mrs",
        "path": "/etc/sing-box/rs/rs_binary.mrs",
        "label": "Binary",
    }
}
routed = bot.probe_domain_route("maybe.example")
assert routed["path"] == "unknown"
assert routed["reason"] == "probe_unavailable"
assert routed["confidence"] == "unknown"
target, reason, label, certain = bot._singbox_route_info("maybe.example")
assert target is None
assert reason == "probe_unavailable"
assert label == "Binary"
assert certain is False

# A textually matching explicit domain rule with packet-context conditions is not
# an unconditional route match.
bot.load = lambda: {
    "outbounds": [],
    "route": {
        "rules": [{
            "domain_suffix": ["example.com"],
            "network": ["tcp"],
            "outbound": "US",
        }],
        "final": "JP",
    },
}
bot._rs_meta = lambda: {}
target, reason, label, certain = bot._singbox_route_info("www.example.com")
assert target is None
assert reason == "probe_unavailable"
assert label == "条件域名规则"
assert certain is False

# Conditional source fields cannot be evaluated without packet context. Even if
# their domain text appears to match, local route diagnostics must report unknown
# rather than claiming that rule or a later/default route.
with tempfile.TemporaryDirectory(prefix="pdg-core-source.") as temp:
    source = pathlib.Path(temp) / "conditional.json"
    source.write_text(
        '{"version":1,"rules":[{"domain_suffix":["example.com"],'
        '"network":["tcp"]}]}',
        encoding="utf-8",
    )
    bot.load = lambda: {
        "outbounds": [],
        "route": {
            "rules": [
                {"rule_set": "conditional", "outbound": "US"},
                {"domain_suffix": ["example.com"], "outbound": "JP"},
            ],
            "final": "US",
        },
    }
    bot._rs_meta = lambda: {
        "conditional": {
            "format": "source",
            "path": str(source),
            "outbound": "US",
        }
    }
    target, reason, label, certain = bot._singbox_route_info(
        "www.example.com"
    )
    assert target is None
    assert reason == "probe_unavailable"
    assert label == "conditional"
    assert certain is False

# Domain-bearing non-outbound actions may intercept before any later/default route.
bot.load = lambda: {
    "route": {
        "rules": [{
            "action": "reject",
            "domain_suffix": ["example.com"],
        }],
        "final": "US",
    }
}
bot._rs_meta = lambda: {}
target, reason, label, certain = bot._singbox_route_info("www.example.com")
assert target is None
assert reason == "probe_unavailable"
assert label == "域名动作规则"
assert certain is False

with tempfile.TemporaryDirectory(prefix="pdg-core-action-rs.") as temp:
    source = pathlib.Path(temp) / "reject.json"
    source.write_text(
        '{"version":1,"rules":[{"domain_suffix":["example.com"]}]}',
        encoding="utf-8",
    )
    bot.load = lambda: {
        "route": {
            "rules": [{"action": "reject", "rule_set": "reject_set"}],
            "final": "US",
        }
    }
    bot._rs_meta = lambda: {
        "reject_set": {
            "format": "source",
            "path": str(source),
            "label": "Reject Set",
        }
    }
    target, reason, label, certain = bot._singbox_route_info(
        "www.example.com"
    )
    assert target is None
    assert reason == "probe_unavailable"
    assert label == "Reject Set"
    assert certain is False

# Malformed model and a meta failure on the second label lookup must be structured
# unknown results, not exceptions that become Web 500 responses.
bot.load = lambda: {"route": {"rules": None}}
target, reason, label, certain = bot._singbox_route_info("bad.example")
assert target is None
assert reason == "probe_unavailable"
assert label == "配置不可读取"
assert certain is False

with tempfile.TemporaryDirectory(prefix="pdg-core-flaky-meta.") as temp:
    source = pathlib.Path(temp) / "matching.json"
    source.write_text(
        '{"version":1,"rules":[{"domain_suffix":["example.com"]}]}',
        encoding="utf-8",
    )
    bot.load = lambda: {
        "route": {
            "rules": [{"rule_set": "matching", "outbound": "US"}],
            "final": "JP",
        }
    }
    meta_calls = [0]

    def flaky_meta():
        meta_calls[0] += 1
        if meta_calls[0] == 1:
            return {
                "matching": {
                    "format": "source",
                    "path": str(source),
                    "outbound": "US",
                }
            }
        raise ValueError("metadata changed or malformed")

    bot._rs_meta = flaky_meta
    target, reason, label, certain = bot._singbox_route_info(
        "www.example.com"
    )
    assert target is None
    assert reason == "probe_unavailable"
    assert label == "配置不可读取"
    assert certain is False

print("[OK] core structured diagnostics")

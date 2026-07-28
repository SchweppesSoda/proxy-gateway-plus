#!/usr/bin/env python3
"""Mihomo data-plane 参数与 Bot 持久 profile 透传回归。"""
import importlib.util
import json
import os
import sys
import tempfile
import types
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BOT_DIR = ROOT / "deploy" / "bot"
sys.path.insert(0, str(BOT_DIR))

import sb2mihomo  # noqa: E402

if "fcntl" not in sys.modules:
    try:
        import fcntl  # noqa: F401
    except ImportError:
        sys.modules["fcntl"] = types.SimpleNamespace(
            LOCK_EX=1, LOCK_NB=2, LOCK_UN=8, flock=lambda *args: None)

spec = importlib.util.spec_from_file_location("pdg_bot_dataplane", BOT_DIR / "pdg-bot.py")
bot = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bot)

MODEL = {
    "outbounds": [{"type": "direct", "tag": "direct"}],
    "route": {"rules": [], "final": "direct"},
}


def assert_raises(exc_type, fn, *args, **kwargs):
    try:
        fn(*args, **kwargs)
    except exc_type:
        return
    raise AssertionError("%s was not raised" % exc_type.__name__)


def main():
    # 纯十进制、安全范围、去重和数值稳定排序。
    assert sb2mihomo.parse_port_list("8443, 443 8443,80", name="TLS") == [80, 443, 8443]
    assert sb2mihomo.parse_port_list([8443, 443, 8443], name="TLS") == [443, 8443]
    for bad in ("", "0", "65536", "443-445", "443;8443", "+443", "４４３",
                "443,", "443,,8443", "443, ,8443"):
        assert_raises(ValueError, sb2mihomo.parse_port_list, bad, name="TLS")
    for bad in ([True, 443], [443.0], [0], [65536]):
        assert_raises(ValueError, sb2mihomo.parse_port_list, bad, name="TLS")

    # 此 fork 缺省是原生 tproxy；reject 是显式安全回退。
    default, _ = sb2mihomo.singbox_to_mihomo(MODEL)
    assert default["tproxy-port"] == 7895
    assert default["sniffer"]["sniff"]["QUIC"]["ports"] == [443]
    reject, _ = sb2mihomo.singbox_to_mihomo(MODEL, quic_mode="reject")
    assert "tproxy-port" not in reject
    assert "QUIC" not in reject["sniffer"]["sniff"]
    assert reject["sniffer"]["sniff"]["TLS"]["ports"] == [443, 5228, 5229, 5230]
    assert reject["sniffer"]["sniff"]["HTTP"]["ports"] == [80]
    assert 10443 not in reject["sniffer"]["sniff"]["TLS"]["ports"]

    # tproxy 只改变 UDP/QUIC 能力；TCP redir 与原始目的端口嗅探配置仍共用同一份端口模型。
    tproxy, _ = sb2mihomo.singbox_to_mihomo(
        MODEL,
        quic_mode="tproxy",
        tproxy_port=7895,
        tls_ports="10443,443,10443",
        http_ports="8080,80",
    )
    assert tproxy["redir-port"] == 7893
    assert tproxy["tproxy-port"] == 7895
    assert tproxy["sniffer"]["override-destination"] is True
    assert tproxy["sniffer"]["sniff"]["TLS"]["ports"] == [443, 10443]
    assert tproxy["sniffer"]["sniff"]["HTTP"]["ports"] == [80, 8080]
    assert tproxy["sniffer"]["sniff"]["QUIC"]["ports"] == [443]
    assert_raises(ValueError, sb2mihomo.singbox_to_mihomo, MODEL, quic_mode="auto")
    assert_raises(ValueError, sb2mihomo.singbox_to_mihomo, MODEL, quic_mode="tproxy",
                  tproxy_port=0)

    with tempfile.TemporaryDirectory() as tmp:
        profile = os.path.join(tmp, "profile.env")
        bot.PROFILE_ENV = profile
        bot._platform = lambda: "android"
        with open(profile, "w", encoding="utf-8") as f:
            f.write(
                "PDG_QUIC_MODE=tproxy\n"
                "PDG_HIJACK_TLS_TCP_PORTS=10443,443,10443\n"
                "PDG_HIJACK_HTTP_TCP_PORTS=8080,80\n"
            )

        args = bot._mihomo_dataplane_args()
        assert args == {
            "quic_mode": "tproxy",
            "tproxy_port": 7895,
            "tls_ports": [443, 10443],
            "http_ports": [80, 8080],
        }
        data, _ = bot._render_mihomo_bytes(MODEL, rs_meta={})
        rendered = json.loads(data)
        assert rendered["tproxy-port"] == 7895
        assert rendered["sniffer"]["sniff"]["TLS"]["ports"] == [443, 10443]
        assert rendered["sniffer"]["sniff"]["HTTP"]["ports"] == [80, 8080]
        assert rendered["sniffer"]["sniff"]["QUIC"]["ports"] == [443]

        # 文件渲染与事务派生调用同一个持久参数读取器，不能抹回默认端口或 reject。
        bot.SB = os.path.join(tmp, "model.json")
        bot.MIHOMO_DIR = os.path.join(tmp, "mihomo")
        bot.MIHOMO_CFG = os.path.join(bot.MIHOMO_DIR, "config.yaml")
        bot.RS_META = os.path.join(tmp, "missing-rulesets.json")
        bot.MITM_HIJACK_FILE = os.path.join(tmp, "missing-mitm.txt")
        with open(bot.SB, "w", encoding="utf-8") as f:
            json.dump(MODEL, f)
        bot._render_mihomo_file()
        file_cfg = json.load(open(bot.MIHOMO_CFG, encoding="utf-8"))
        assert file_cfg["tproxy-port"] == 7895
        assert file_cfg["sniffer"]["sniff"]["TLS"]["ports"] == [443, 10443]
        assert json.loads(bot._mihomo_derive({"model": json.dumps(MODEL).encode()}))[
            "sniffer"]["sniff"]["TLS"]["ports"] == [443, 10443]

        # 已存在但非法/未知的持久值必须 fail closed；不得静默降级成半份默认配置。
        for text in (
            "PDG_QUIC_MODE=unknown\n",
            "PDG_HIJACK_TLS_TCP_PORTS=443-445\n",
            "PDG_HIJACK_HTTP_TCP_PORTS=80,\n",
            "PDG_QUIC_MODE=reject\nPDG_QUIC_MODE=tproxy\n",
        ):
            with open(profile, "w", encoding="utf-8") as f:
                f.write(text)
            assert_raises(ValueError, bot._mihomo_dataplane_args)
            assert_raises(ValueError, bot._render_mihomo_bytes, MODEL, {})
            assert_raises(
                ValueError, bot._mihomo_derive,
                {"model": json.dumps(MODEL).encode("utf-8")})

        # profile 缺键时保留现有平台默认，且始终显式传入 generator。
        with open(profile, "w", encoding="utf-8") as f:
            f.write("PDG_LOWMEM=0\n")
        assert bot._mihomo_dataplane_args() == {
            "quic_mode": "tproxy",
            "tproxy_port": 7895,
            "tls_ports": [443, 5228, 5229, 5230],
            "http_ports": [80],
        }
        bot._platform = lambda: "ios"
        assert bot._mihomo_dataplane_args()["tls_ports"] == [443]

    print("[OK] Mihomo data-plane 参数与持久 profile 透传全部断言通过")


if __name__ == "__main__":
    main()

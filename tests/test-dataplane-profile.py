#!/usr/bin/env python3
"""Strict profile and doctor cross-component data-plane regression tests."""
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
BOT = ROOT / "deploy" / "bot"
sys.path.insert(0, str(BOT))

import checks  # noqa: E402
import nftmerge  # noqa: E402
import pdgprofile  # noqa: E402
import sb2mihomo  # noqa: E402

TEMPLATE = ROOT / "deploy" / "firewall" / "nftables-mihomo.conf"
MODEL = {
    "outbounds": [{"type": "direct", "tag": "direct"}],
    "route": {"rules": [], "final": "direct"},
}


def raises(fn, *args, **kwargs):
    try:
        fn(*args, **kwargs)
    except ValueError:
        return
    raise AssertionError("ValueError was not raised")


def profile_text(*, mode="managed", platform="android", quic="tproxy",
                 cidr="172.22.0.0/16", tls=None, http="80",
                 mark="0x504447", mask="0xffffffff", table="7895",
                 priority="17895"):
    if tls is None:
        tls = "443,5228,5229,5230" if platform == "android" else "443"
    return (
        f"PDG_FIREWALL_MODE={mode}\n"
        f"PDG_PLATFORM={platform}\n"
        f"PDG_INTERNAL_CIDR={cidr}\n"
        "PDG_SSH_PORT=22\n"
        f"PDG_QUIC_MODE={quic}\n"
        f"PDG_HIJACK_TLS_TCP_PORTS={tls}\n"
        f"PDG_HIJACK_HTTP_TCP_PORTS={http}\n"
        f"PDG_QUIC_MARK={mark}\n"
        f"PDG_QUIC_MARK_MASK={mask}\n"
        f"PDG_QUIC_ROUTE_TABLE={table}\n"
        f"PDG_QUIC_RULE_PRIORITY={priority}\n"
    )


def materialize(td, text):
    profile = td / "profile.env"
    platform = td / "platform"
    marker = td / "firewall-mode"
    mos = td / "mosdns.yaml"
    nft = td / "nftables.conf"
    mihomo = td / "config.yaml"
    helper = td / "quic-helper"
    profile.write_text(text, encoding="utf-8")
    values = pdgprofile.read_values(profile, missing_ok=False)
    platform.write_text(values["PDG_PLATFORM"] + "\n", encoding="utf-8")
    marker.write_text(values["PDG_FIREWALL_MODE"] + "\n", encoding="utf-8")
    mos.write_text(
        'plugins:\n  - tag: npn_clients\n    args:\n'
        f'      ips: ["{values["PDG_INTERNAL_CIDR"]}"]\n',
        encoding="utf-8",
    )
    cfg = pdgprofile.resolve(
        profile, platform=values["PDG_PLATFORM"], environ={},
        ssh_port=values["PDG_SSH_PORT"])
    rendered = pdgprofile.render_nft(
        TEMPLATE, cfg, internal_cidr=values["PDG_INTERNAL_CIDR"],
        ssh_port=values["PDG_SSH_PORT"],
        firewall_mode=values["PDG_FIREWALL_MODE"])
    rendered = nftmerge._render_mode(rendered, values["PDG_FIREWALL_MODE"])
    nft.write_text(rendered, encoding="utf-8")
    mc, _ = sb2mihomo.singbox_to_mihomo(
        MODEL, quic_mode=cfg["quic_mode"], tproxy_port=cfg["tproxy_port"],
        tls_ports=cfg["tls_ports"], http_ports=cfg["http_ports"])
    mihomo.write_text(json.dumps(mc), encoding="utf-8")
    helper.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    helper.chmod(helper.stat().st_mode | stat.S_IXUSR)
    checks.PROFILE_ENV = str(profile)
    checks.PLATFORM_FILE = str(platform)
    checks.FIREWALL_MODE_FILE = str(marker)
    checks.MOSDNS_CONF = str(mos)
    checks.NFT_CONF = str(nft)
    checks.MIHOMO_CFG = str(mihomo)
    checks.QUIC_HELPER = str(helper)
    return cfg, nft, mihomo


def main():
    # Parser rejects nft injection/public/all-network/noncanonical profile
    # values; render CLI input is canonicalized and checked again.
    for bad in (
        "172.22.0.0/16; delete table inet filter",
        "0.0.0.0/0",
        "2001:db8::/64",
    ):
        raises(pdgprofile.canonical_ipv4_cidr, bad)
    assert pdgprofile.canonical_ipv4_cidr("172.22.4.9/16") == "172.22.0.0/16"
    with tempfile.TemporaryDirectory() as raw:
        td = Path(raw)
        p = td / "p"
        p.write_text(profile_text(cidr="172.22.4.9/16"), encoding="utf-8")
        raises(pdgprofile.resolve, p, environ={})
        p.write_text(profile_text(), encoding="utf-8")
        raises(pdgprofile.resolve, p, platform="ios", environ={})
        # Original destination 80/443 are valid, local listeners are not.
        ok = pdgprofile.resolve(
            p, environ={"PDG_HIJACK_TLS_TCP_PORTS": "443,10443",
                        "PDG_HIJACK_HTTP_TCP_PORTS": "80"})
        assert ok["tcp_ports"] == [80, 443, 10443]
        raises(
            pdgprofile.resolve, p,
            environ={"PDG_HIJACK_TLS_TCP_PORTS": "443,10443",
                     "PDG_HIJACK_HTTP_TCP_PORTS": "80"},
            occupied_tcp_ports={10443})
        # Intentional original destinations remain valid even when services
        # currently listen on them.
        pdgprofile.resolve(
            p, environ={}, occupied_tcp_ports={80, 443, 7893, 7895})
        for local in ("53", "853", "7893", "7895", "8445", "9090"):
            raises(
                pdgprofile.resolve, p,
                environ={"PDG_HIJACK_TLS_TCP_PORTS": local})
        for bad_ip in (
            "0.0.0.0", "127.0.0.1", "169.254.1.1", "224.0.0.1",
            "255.255.255.255", "203.0.113.7;touch /tmp/pwn",
            "203.000.113.7",
        ):
            raises(pdgprofile.canonical_ipv4_address, bad_ip)
        assert pdgprofile.canonical_ipv4_address("203.0.113.7") == "203.0.113.7"
        for bad_host in (
            "Dot.Example.com", "dot.example.com.", "localhost",
            "dot_example.com", "-dot.example.com", "203.0.113.7",
            "dot.example.com;touch",
        ):
            raises(pdgprofile.canonical_hostname, bad_host)
        assert pdgprofile.canonical_hostname("dot.example.com") == "dot.example.com"

    with tempfile.TemporaryDirectory() as raw:
        td = Path(raw)
        cfg, nft_path, _mihomo = materialize(td, profile_text())
        live = nft_path.read_text(encoding="utf-8")

        def fake_run(cmd, t=10):
            del t
            if cmd[-5:] == ["nft", "list", "table", "inet", "pdg"] \
                    or cmd[-4:] == ["list", "table", "inet", "pdg"]:
                return (0, fake_run.live, "")
            if cmd[0] == checks.QUIC_HELPER and cmd[1:] == ["status"]:
                return (0, "tproxy exact", "")
            return (1, "", "unexpected command: " + " ".join(cmd))

        fake_run.live = live
        old_run, old_nft_bin = checks._run, checks.nftscan.nft_bin
        checks._run = fake_run
        checks.nftscan.nft_bin = lambda: "nft"
        try:
            assert checks.check_dataplane_profile()[0] == "ok"

            # nft may optimize a full-mask live expression to direct set.
            bitwise = (
                "meta mark set ((meta mark & 0x0) | 0x504447) "
                "tproxy ip to :7895 accept")
            fake_run.live = live.replace(
                bitwise, "meta mark set 0x504447 tproxy ip to :7895 accept")
            assert checks.check_dataplane_profile()[0] == "ok"

            # nft's live canonical form may retain the forced mark bits in A.
            fake_run.live = live.replace(
                bitwise,
                "meta mark set meta mark & 0x00504447 | 0x00504447 "
                "tproxy ip to :7895 accept")
            assert checks.check_dataplane_profile()[0] == "ok"

            # Preserving an unforced bit or forcing a different constant is not
            # semantically equivalent, despite having the same expression shape.
            fake_run.live = live.replace(
                bitwise,
                "meta mark set meta mark & 0x0050444f | 0x00504447 "
                "tproxy ip to :7895 accept")
            assert checks.check_dataplane_profile()[0] == "fail"
            fake_run.live = live.replace(
                bitwise,
                "meta mark set meta mark & 0x00504447 | 0x00504446 "
                "tproxy ip to :7895 accept")
            assert checks.check_dataplane_profile()[0] == "fail"
            fake_run.live = live.replace(
                bitwise, "meta mark set 0x00504446 "
                "tproxy ip to :7895 accept")
            assert checks.check_dataplane_profile()[0] == "fail"

            fake_run.live = ""
            assert checks.check_dataplane_profile()[0] == "fail"

            fake_run.live = live.replace(
                "elements = { 443, 5228, 5229, 5230 }",
                "elements = { 443 }", 1)
            assert checks.check_dataplane_profile()[0] == "fail"

            fake_run.live = live.replace("tproxy ip to :7895", "tproxy to :7895")
            assert checks.check_dataplane_profile()[0] == "fail"

            fake_run.live = live.replace(
                "ip saddr 172.22.0.0/16 udp dport 443 meta mark",
                "ip saddr 172.23.0.0/16 udp dport 443 meta mark", 1)
            assert checks.check_dataplane_profile()[0] == "fail"

            # Missing source-scoped 7893/local listener acceptance cannot green.
            broken = live.replace(
                "53, 853, 7893, 8445", "53, 853, 8445")
            nft_path.write_text(broken, encoding="utf-8")
            fake_run.live = broken
            assert checks.check_dataplane_profile()[0] == "fail"
        finally:
            checks._run = old_run
            checks.nftscan.nft_bin = old_nft_bin

    # Partial masks retain non-owned mark bits in both template and live check.
    with tempfile.TemporaryDirectory() as raw:
        td = Path(raw)
        cfg, nft_path, _ = materialize(
            td, profile_text(mark="0x4400", mask="0xff00"))
        text = nft_path.read_text(encoding="utf-8")
        assert "meta mark & 0xffff00ff" in text
        assert "| 0x4400" in text
        values = pdgprofile.read_values(td / "profile.env", missing_ok=False)

        optimizer = text.replace(
            "meta mark set ((meta mark & 0xffff00ff) | 0x4400)",
            "meta mark set meta mark & 0xffff44ff | 0x00004400")
        checks._validate_profile_nft(
            optimizer, values, cfg, "managed", "live", runtime=True)

        bad_preserve = text.replace(
            "meta mark set ((meta mark & 0xffff00ff) | 0x4400)",
            "meta mark set meta mark & 0xffff45ff | 0x00004400")
        raises(
            checks._validate_profile_nft,
            bad_preserve, values, cfg, "managed", "live", runtime=True)

        # A direct constant cannot represent a partial-mask update.
        partial_constant = text.replace(
            "meta mark set ((meta mark & 0xffff00ff) | 0x4400)",
            "meta mark set 0x00004400")
        raises(
            checks._validate_profile_nft,
            partial_constant, values, cfg, "managed", "live", runtime=True)

    # Reject removes TPROXY and changes only the managed UDP/443 input action.
    with tempfile.TemporaryDirectory() as raw:
        td = Path(raw)
        _cfg, nft_path, mihomo = materialize(td, profile_text(quic="reject"))
        nft = nft_path.read_text(encoding="utf-8")
        mc = json.loads(mihomo.read_text(encoding="utf-8"))
        assert "pdg_quic_prerouting" not in nft
        assert "udp dport 443 reject" in nft
        assert "tproxy-port" not in mc

    # External mode owns no input policy; generic nonstandard TLS is opt-in and
    # appears identically in nft named sets and Mihomo sniffer.
    with tempfile.TemporaryDirectory() as raw:
        td = Path(raw)
        cfg, nft_path, mihomo = materialize(
            td, profile_text(mode="external", tls="443,10443"))
        nft = nft_path.read_text(encoding="utf-8")
        mc = json.loads(mihomo.read_text(encoding="utf-8"))
        assert "chain input {" not in nft
        assert "hook input" not in nft
        assert cfg["tls_ports"] == [443, 10443]
        assert mc["sniffer"]["sniff"]["TLS"]["ports"] == [443, 10443]
        assert checks._nft_set_ports(nft, "pdg_tls_tcp_ports") == [443, 10443]

    # Duplicate render-driving keys and state/profile mismatches fail closed.
    with tempfile.TemporaryDirectory() as raw:
        td = Path(raw)
        text = profile_text() + "PDG_QUIC_MODE=reject\n"
        p = td / "p"
        p.write_text(text, encoding="utf-8")
        raises(pdgprofile.resolve, p, environ={})

    # External doctor wording is explicit about external ownership.
    old_mode, old_scan = checks.nftscan.persisted_mode, checks.nftscan.scan
    checks.nftscan.persisted_mode = lambda: "external"
    checks.nftscan.scan = lambda: ([], True)
    try:
        level, _, detail = checks.check_nft_input_chains()
        assert level == "ok" and "PDG 无 input hook" in detail
    finally:
        checks.nftscan.persisted_mode, checks.nftscan.scan = old_mode, old_scan

    # CI's four-combination gate must count only actual nft statements, never
    # template comments that happen to mention tproxy.
    actual_tproxy = re.compile(
        r"^\s*ip\s+saddr\s+\S+\s+udp\s+dport\s+443\b.*"
        r"\stproxy\s+ip\s+to\s+:7895(?:\s|$)")
    for firewall_mode in ("managed", "external"):
        for quic_mode in ("tproxy", "reject"):
            with tempfile.TemporaryDirectory() as raw:
                td = Path(raw)
                _, nft_path, _ = materialize(
                    td, profile_text(mode=firewall_mode, quic=quic_mode))
                statements = [
                    line for line in nft_path.read_text(encoding="utf-8").splitlines()
                    if not line.lstrip().startswith("#")
                    and actual_tproxy.search(line)
                ]
                assert len(statements) == (1 if quic_mode == "tproxy" else 0), (
                    firewall_mode, quic_mode, statements)

    print("[OK] strict profile + live/persistent/Mihomo/route doctor consistency")


if __name__ == "__main__":
    main()

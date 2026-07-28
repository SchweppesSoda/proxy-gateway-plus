#!/usr/bin/env python3
"""Firewall mode, ownership, merge, and removal regression tests."""
import importlib.util
import os
from pathlib import Path
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
SCAN = ROOT / "deploy" / "bot" / "nftscan.py"
MERGE = ROOT / "deploy" / "bot" / "nftmerge.py"
TEMPLATE = ROOT / "deploy" / "firewall" / "nftables-mihomo.conf"

spec = importlib.util.spec_from_file_location("nftscan_firewall_test", SCAN)
nftscan = importlib.util.module_from_spec(spec)
spec.loader.exec_module(nftscan)


def rendered(mode):
    text = TEMPLATE.read_text(encoding="utf-8")
    text = text.replace("__INTERNAL_CIDR__", "192.0.2.0/24")
    text = text.replace("__SSH_PORT__", "22")
    with tempfile.TemporaryDirectory() as td:
        src = Path(td) / "src.nft"
        target = Path(td) / "target.nft"
        out = Path(td) / "out.nft"
        src.write_text(text, encoding="utf-8")
        target.write_text("#!/usr/sbin/nft -f\n", encoding="utf-8")
        proc = subprocess.run(
            [sys.executable, str(MERGE), "--mode", mode, str(src), str(target), str(out)],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        assert proc.returncode == 0, proc.stderr
        return out.read_text(encoding="utf-8")


managed = rendered("managed")
external = rendered("external")
assert nftscan.pdg_table_status(managed) == "owned-managed"
assert nftscan.pdg_table_status(external) == "owned-external"
assert "hook input" in managed and "policy drop" in managed
assert "hook input" not in external and "policy drop" not in external
assert "hook prerouting" in external and "redirect to :7893" in external

foreign_input = """table inet filter {
 chain input {
  type filter hook input priority 0; policy drop;
 }
}
"""
assert nftscan.scan_text(foreign_input, "", mode="managed")
assert nftscan.scan_text(foreign_input, "", mode="external") == []

markerless = external.replace(
    'comment "owner=privdns-gateway;schema=1;component=firewall;mode=external"\n', ""
)
assert nftscan.pdg_table_status(markerless) == "foreign"
wrong_shape = external.replace("redirect to :7893", "accept")
assert nftscan.pdg_table_status(wrong_shape) == "foreign"

with tempfile.TemporaryDirectory() as td:
    td = Path(td)
    src = td / "src.nft"
    target = td / "target.nft"
    out = td / "out.nft"
    src.write_text(
        TEMPLATE.read_text(encoding="utf-8")
        .replace("__INTERNAL_CIDR__", "192.0.2.0/24")
        .replace("__SSH_PORT__", "22"),
        encoding="utf-8",
    )
    target.write_text(
        "# before\n" + markerless + "# after\n",
        encoding="utf-8",
    )
    proc = subprocess.run(
        [sys.executable, str(MERGE), "--mode", "managed", str(src), str(target), str(out)],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    assert proc.returncode == 4, (proc.returncode, proc.stderr)
    assert not out.exists()

# Only the exact historical stock markerless shape is a one-way replacement
# migration. It never grants uninstall ownership.
legacy_stock = """table inet pdg {
 chain prerouting {
  type nat hook prerouting priority dstnat; policy accept;
  ip saddr 172.22.0.0/16 tcp dport { 80, 443, 5228-5230 } redirect to :7893
 }
 chain input {
  type filter hook input priority 0; policy drop;
  iif "lo" accept
  ct state established,related accept
  tcp dport { 22 } accept
  ip saddr 172.22.0.0/16 tcp dport { 53, 81, 853, 7893, 8445 } accept
  ip saddr 172.22.0.0/16 udp dport 53 accept
  ip saddr 172.22.0.0/16 udp dport 443 reject
  ip protocol icmp accept
  ip6 nexthdr icmpv6 accept
 }
}
"""
assert nftscan.legacy_stock_pdg_status(legacy_stock) == "managed"
with tempfile.TemporaryDirectory() as td:
    td = Path(td)
    src, target, out = td / "src", td / "target", td / "out"
    src.write_text(
        TEMPLATE.read_text(encoding="utf-8")
        .replace("__INTERNAL_CIDR__", "172.22.0.0/16")
        .replace("__SSH_PORT__", "22"), encoding="utf-8")
    target.write_text("# before\n" + legacy_stock + "# after\n", encoding="utf-8")
    replaced = subprocess.run(
        [sys.executable, str(MERGE), "--mode", "managed",
         str(src), str(target), str(out)],
        text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    assert replaced.returncode == 0, replaced.stderr
    assert nftscan.pdg_table_status(out.read_text(encoding="utf-8")) == "owned-managed"
    removed = subprocess.run(
        [sys.executable, str(MERGE), "--remove", str(target), str(out)],
        text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    assert removed.returncode == 4
    # One extra custom line makes the markerless table foreign and immutable.
    target.write_text(legacy_stock.replace(
        'ip protocol icmp accept', 'tcp dport 10443 accept\n  ip protocol icmp accept'),
        encoding="utf-8")
    rejected = subprocess.run(
        [sys.executable, str(MERGE), "--mode", "managed",
         str(src), str(target), str(out)],
        text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    assert rejected.returncode == 4

with tempfile.TemporaryDirectory() as td:
    td = Path(td)
    target = td / "target.nft"
    out = td / "out.nft"
    target.write_text("# before\n" + managed + "# after\n", encoding="utf-8")
    proc = subprocess.run(
        [sys.executable, str(MERGE), "--remove", str(target), str(out)],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    assert proc.returncode == 0, proc.stderr
    result = out.read_text(encoding="utf-8")
    assert "table inet pdg" not in result
    assert "# before" in result and "# after" in result

install_text = (ROOT / "install.sh").read_text(encoding="utf-8")
uninstall_text = (ROOT / "uninstall.sh").read_text(encoding="utf-8")
assert "PDG_FIREWALL_MODE" in install_text
assert "PDG_FIREWALL_MODE=$FIREWALL_MODE" in install_text
assert ".pdg-orig /etc/nftables.conf" not in uninstall_text
assert "--remove" in uninstall_text
assert 'systemctl disable pdg-quic-routing' in uninstall_text
assert "cleanup-status" in uninstall_text
assert "pdg_nft_atomic_install" in uninstall_text
assert "QUIC_CLEAN" in uninstall_text

print("firewall ownership/mode regression OK")

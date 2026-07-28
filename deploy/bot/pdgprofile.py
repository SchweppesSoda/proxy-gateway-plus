#!/usr/bin/env python3
"""Strict, shared profile parser for the PDG transparent data plane.

The installer, Bot renderer, firewall renderer, QUIC policy-routing helper and
diagnostics all consume the normalized values produced here.  Relevant profile
keys are single-valued: a duplicate is corruption, not "last value wins".
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys

import sb2mihomo

PROFILE_FILE = "/etc/privdns-gateway/profile.env"

DATA_KEYS = (
    "PDG_QUIC_MODE",
    "PDG_HIJACK_TLS_TCP_PORTS",
    "PDG_HIJACK_HTTP_TCP_PORTS",
    "PDG_QUIC_MARK",
    "PDG_QUIC_MARK_MASK",
    "PDG_QUIC_ROUTE_TABLE",
    "PDG_QUIC_RULE_PRIORITY",
)
MODE_KEYS = (
    "PDG_FIREWALL_MODE",
    "PDG_PLATFORM",
    "PDG_INTERNAL_CIDR",
    "PDG_SSH_PORT",
)
AUX_KEYS = (
    "PDG_LOWMEM",
    "PDG_HIJACK_MODE",
    "PDG_TFO",
    "PDG_CERT_DIR",
)
MANAGED_KEYS = frozenset(DATA_KEYS + MODE_KEYS + AUX_KEYS)

DEFAULT_QUIC_MODE = "tproxy"
DEFAULT_HTTP_PORTS = [80]
DEFAULT_TLS_PORTS = {
    "android": [443, 5228, 5229, 5230],
    "ios": [443],
}
DEFAULT_QUIC_MARK = 0x504447
DEFAULT_QUIC_MARK_MASK = 0xFFFFFFFF
DEFAULT_QUIC_ROUTE_TABLE = 7895
DEFAULT_QUIC_RULE_PRIORITY = 17895

COMMON_LOCAL_TCP_PORTS = {
    53: "mosdns DNS",
    853: "mosdns DoT",
    7893: "Mihomo REDIRECT",
    8445: "Telegram mixed listener",
    9090: "Mihomo clash_api",
}
IOS_LOCAL_TCP_PORTS = {
    81: "iOS OnDemand probe",
    7894: "iOS MITM SOCKS listener",
    8443: "iOS profile download hook",
}

_KEY_SHAPE = re.compile(r"^[A-Z][A-Z0-9_]*$")
_UINT = re.compile(r"^(?:0|[1-9][0-9]*)$")
_MARK = re.compile(r"^(?:0[xX][0-9a-fA-F]+|(?:0|[1-9][0-9]*))$")


class ProfileError(ValueError):
    pass


def read_values(path=PROFILE_FILE, *, missing_ok=True):
    """Read managed keys, rejecting malformed or duplicate managed entries."""
    try:
        lines = Path(path).read_text(encoding="utf-8").splitlines()
    except FileNotFoundError:
        if missing_ok:
            return {}
        raise ProfileError("找不到 profile: %s" % path)
    except OSError as error:
        raise ProfileError("无法读取 profile: %s" % path) from error

    found = {}
    for number, raw in enumerate(lines, 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            token = line.split(None, 1)[0] if line else ""
            if token in MANAGED_KEYS:
                raise ProfileError("%s:%d 受管 profile 键格式错误: %s"
                                   % (path, number, token))
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        if key not in MANAGED_KEYS:
            continue
        if not _KEY_SHAPE.fullmatch(key) or not raw.lstrip().startswith(key + "="):
            raise ProfileError("%s:%d 受管 profile 键格式错误: %s"
                               % (path, number, key))
        if key in found:
            raise ProfileError("%s 存在重复键: %s" % (path, key))
        found[key] = value.strip()
    return found


def retarget_platform_text(path, target):
    """Return a strict profile candidate for an Android/iOS transition.

    Only the canonical platform and Android-only GMS TLS ports change.  Unknown
    keys, comments and every other managed value retain their original order.
    """
    target = _choice(target, ("android", "ios"), "PDG_PLATFORM")
    values = read_values(path)
    if "PDG_HIJACK_TLS_TCP_PORTS" in values:
        ports = sb2mihomo.parse_port_list(
            values["PDG_HIJACK_TLS_TCP_PORTS"],
            name="PDG_HIJACK_TLS_TCP_PORTS")
    else:
        ports = list(DEFAULT_TLS_PORTS[target])
    gms = {5228, 5229, 5230}
    if target == "ios":
        ports = [port for port in ports if port not in gms]
    else:
        ports = sorted(set(ports) | gms)
    if not ports:
        raise ProfileError(
            "切换到 iOS 后 TLS 端口集合为空；请先保留至少一个非 GMS 目的端口")

    updates = {
        "PDG_PLATFORM": target,
        "PDG_HIJACK_TLS_TCP_PORTS": ",".join(map(str, ports)),
    }
    try:
        lines = Path(path).read_text(encoding="utf-8").splitlines()
    except FileNotFoundError:
        lines = []
    except OSError as error:
        raise ProfileError("无法读取 profile: %s" % path) from error
    seen = set()
    output = []
    for line in lines:
        stripped = line.lstrip()
        key = stripped.split("=", 1)[0] if "=" in stripped else ""
        if key in updates:
            if key not in seen:
                output.append("%s=%s" % (key, updates[key]))
                seen.add(key)
        else:
            output.append(line)
    for key in ("PDG_PLATFORM", "PDG_HIJACK_TLS_TCP_PORTS"):
        if key not in seen:
            output.append("%s=%s" % (key, updates[key]))
    return "\n".join(output) + "\n"


def _choice(value, choices, name):
    if not isinstance(value, str) or value not in choices:
        raise ProfileError("%s 只能是 %s" % (name, " 或 ".join(choices)))
    return value


def _uint(value, name, *, maximum=0xFFFFFFFF, forbidden=()):
    text = str(value).strip()
    if not _UINT.fullmatch(text):
        raise ProfileError("%s 必须是十进制正整数" % name)
    number = int(text, 10)
    if number < 1 or number > maximum or number in forbidden:
        raise ProfileError("%s 超出安全范围" % name)
    return number


def _mark(value, name):
    text = str(value).strip()
    if not _MARK.fullmatch(text):
        raise ProfileError("%s 必须是十进制或 0x 十六进制整数" % name)
    number = int(text, 0)
    if number < 1 or number > 0xFFFFFFFF:
        raise ProfileError("%s 超出 1..0xffffffff" % name)
    return number


def _env_or_profile(name, values, environ, default):
    return environ[name] if name in environ else values.get(name, default)


def canonical_ipv4_cidr(value, name="PDG_INTERNAL_CIDR"):
    try:
        network = ipaddress.ip_network(str(value).strip(), strict=False)
    except ValueError as error:
        raise ProfileError("%s 必须是合法 IPv4 CIDR" % name) from error
    if network.version != 4 or network.prefixlen == 0:
        raise ProfileError("%s 必须是非全网 IPv4 CIDR" % name)
    return str(network)


def canonical_ipv4_address(value, name="PDG_SERVER_IP"):
    text = str(value)
    if text != text.strip():
        raise ProfileError("%s 必须是 canonical IPv4 地址" % name)
    try:
        address = ipaddress.ip_address(text)
    except ValueError as error:
        raise ProfileError("%s 必须是合法 IPv4 地址" % name) from error
    if address.version != 4 or str(address) != text:
        raise ProfileError("%s 必须是 canonical IPv4 地址" % name)
    if address.is_unspecified or address.is_loopback \
            or address.is_link_local or address.is_multicast \
            or address == ipaddress.IPv4Address("255.255.255.255"):
        raise ProfileError("%s 不是安全的服务器 IPv4 地址" % name)
    return text


def canonical_hostname(value, name="PDG_DOT_DOMAIN"):
    text = str(value)
    if text != text.strip() or text != text.lower() or len(text) > 253 \
            or "." not in text or text.endswith("."):
        raise ProfileError("%s 必须是 lowercase canonical hostname" % name)
    labels = text.split(".")
    if any(not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label)
           for label in labels):
        raise ProfileError("%s 含非法 hostname label" % name)
    try:
        ipaddress.ip_address(text)
    except ValueError:
        return text
    raise ProfileError("%s 必须是 hostname，不能是 IP" % name)


def live_tcp_listener_ports():
    ss = shutil.which("ss")
    if not ss:
        raise ProfileError("找不到 ss，无法执行 authoritative TCP listener preflight")
    try:
        result = subprocess.run(
            [ss, "-H", "-lnt"], text=True, capture_output=True, timeout=10,
            check=False)
    except (OSError, subprocess.SubprocessError) as error:
        raise ProfileError(
            "读不到 live TCP listeners，拒绝跳过 collision preflight") from error
    if result.returncode != 0:
        raise ProfileError("读不到 live TCP listeners，拒绝跳过 collision preflight")
    ports = set()
    for line in result.stdout.splitlines():
        fields = line.split()
        if len(fields) < 4:
            raise ProfileError("ss 返回无法识别的 TCP listener 记录")
        match = re.search(r":([0-9]+)$", fields[3])
        if not match or not (1 <= int(match.group(1)) <= 65535):
            raise ProfileError("ss 返回非法 TCP listener endpoint")
        ports.add(int(match.group(1)))
    return ports


def resolve(path=PROFILE_FILE, *, platform=None, environ=None, ssh_port=None,
            occupied_tcp_ports=None):
    """Resolve and validate the normalized transparent data-plane profile."""
    values = read_values(path)
    environ = os.environ if environ is None else environ
    profile_platform = values.get("PDG_PLATFORM")
    if platform is not None and profile_platform and platform != profile_platform:
        raise ProfileError("CLI/canonical platform 与 profile PDG_PLATFORM 不一致")
    platform = platform or _env_or_profile(
        "PDG_PLATFORM", values, environ, "android")
    platform = _choice(platform, ("android", "ios"), "PDG_PLATFORM")

    quic_mode = sb2mihomo.parse_quic_mode(_env_or_profile(
        "PDG_QUIC_MODE", values, environ, DEFAULT_QUIC_MODE))
    tls_ports = sb2mihomo.parse_port_list(_env_or_profile(
        "PDG_HIJACK_TLS_TCP_PORTS", values, environ,
        DEFAULT_TLS_PORTS[platform]), name="PDG_HIJACK_TLS_TCP_PORTS")
    http_ports = sb2mihomo.parse_port_list(_env_or_profile(
        "PDG_HIJACK_HTTP_TCP_PORTS", values, environ,
        DEFAULT_HTTP_PORTS), name="PDG_HIJACK_HTTP_TCP_PORTS")
    overlap = sorted(set(tls_ports) & set(http_ports))
    if overlap:
        raise ProfileError("TLS/HTTP 劫持端口不能重叠: %s"
                           % ",".join(map(str, overlap)))

    mark = _mark(_env_or_profile(
        "PDG_QUIC_MARK", values, environ, hex(DEFAULT_QUIC_MARK)),
        "PDG_QUIC_MARK")
    mask = _mark(_env_or_profile(
        "PDG_QUIC_MARK_MASK", values, environ, hex(DEFAULT_QUIC_MARK_MASK)),
        "PDG_QUIC_MARK_MASK")
    if mark & mask != mark:
        raise ProfileError("PDG_QUIC_MARK 的置位必须全部包含在 PDG_QUIC_MARK_MASK 内")
    route_table = _uint(_env_or_profile(
        "PDG_QUIC_ROUTE_TABLE", values, environ, str(DEFAULT_QUIC_ROUTE_TABLE)),
        "PDG_QUIC_ROUTE_TABLE", forbidden=(253, 254, 255))
    rule_priority = _uint(_env_or_profile(
        "PDG_QUIC_RULE_PRIORITY", values, environ,
        str(DEFAULT_QUIC_RULE_PRIORITY)), "PDG_QUIC_RULE_PRIORITY")

    local = dict(COMMON_LOCAL_TCP_PORTS)
    if platform == "ios":
        local.update(IOS_LOCAL_TCP_PORTS)
    if quic_mode == "tproxy":
        local[7895] = "Mihomo native QUIC TPROXY"
    configured_ssh = ssh_port
    if configured_ssh is None:
        configured_ssh = _env_or_profile(
            "PDG_SSH_PORT", values, environ, "")
    normalized_ssh = None
    if str(configured_ssh).strip():
        normalized_ssh = _uint(configured_ssh, "PDG_SSH_PORT", maximum=65535)
        if values.get("PDG_SSH_PORT"):
            profile_ssh = _uint(
                values["PDG_SSH_PORT"], "PDG_SSH_PORT", maximum=65535)
            if normalized_ssh != profile_ssh:
                raise ProfileError("CLI/detected SSH port 与 profile PDG_SSH_PORT 不一致")
        local[normalized_ssh] = "SSH listener"

    # 80/443 are deliberately valid original destination ports.  REDIRECT is
    # source-scoped, so external ACME traffic on :80 is not intercepted.
    conflicts = [(port, local[port]) for port in sorted(set(tls_ports + http_ports))
                 if port not in (80, 443) and port in local]
    if conflicts:
        raise ProfileError("劫持端口与本机监听冲突（会自环/截断服务）: %s"
                           % ", ".join("%d(%s)" % item for item in conflicts))
    occupied = set(occupied_tcp_ports or ())
    live_conflicts = sorted(
        port for port in set(tls_ports + http_ports)
        if port not in (80, 443) and port in occupied)
    if live_conflicts:
        raise ProfileError(
            "劫持端口与 authoritative live TCP listener 冲突: %s"
            % ",".join(map(str, live_conflicts)))

    canonical_cidr = None
    if values.get("PDG_INTERNAL_CIDR"):
        canonical_cidr = canonical_ipv4_cidr(values["PDG_INTERNAL_CIDR"])
        if values["PDG_INTERNAL_CIDR"].strip() != canonical_cidr:
            raise ProfileError(
                "profile PDG_INTERNAL_CIDR 必须使用 canonical network CIDR: "
                + canonical_cidr)
    firewall_mode = None
    if values.get("PDG_FIREWALL_MODE"):
        firewall_mode = _choice(
            values["PDG_FIREWALL_MODE"], ("managed", "external"),
            "PDG_FIREWALL_MODE")

    return {
        "platform": platform,
        "firewall_mode": firewall_mode,
        "internal_cidr": canonical_cidr,
        "ssh_port": normalized_ssh,
        "quic_mode": quic_mode,
        "tls_ports": tls_ports,
        "http_ports": http_ports,
        "tcp_ports": sorted(set(tls_ports + http_ports)),
        "tproxy_port": 7895,
        "mark": mark,
        "mark_text": "0x%x" % mark,
        "mask": mask,
        "mask_text": "0x%x" % mask,
        "mark_clear_mask": (~mask) & 0xFFFFFFFF,
        "mark_clear_mask_text": "0x%x" % ((~mask) & 0xFFFFFFFF),
        "route_table": route_table,
        "rule_priority": rule_priority,
        "local_tcp_ports": (
            [53, 81, 853, 7893, 8445]
            if platform == "ios" else [53, 853, 7893, 8445]),
    }


def profile_lines(config):
    return (
        "PDG_QUIC_MODE=%s" % config["quic_mode"],
        "PDG_HIJACK_TLS_TCP_PORTS=%s" % ",".join(map(str, config["tls_ports"])),
        "PDG_HIJACK_HTTP_TCP_PORTS=%s" % ",".join(map(str, config["http_ports"])),
        "PDG_QUIC_MARK=%s" % config["mark_text"],
        "PDG_QUIC_MARK_MASK=%s" % config["mask_text"],
        "PDG_QUIC_ROUTE_TABLE=%d" % config["route_table"],
        "PDG_QUIC_RULE_PRIORITY=%d" % config["rule_priority"],
    )


def render_nft(template, config, *, internal_cidr, ssh_port, firewall_mode):
    """Render all data-plane placeholders and conditional QUIC blocks."""
    firewall_mode = _choice(
        firewall_mode, ("managed", "external"), "PDG_FIREWALL_MODE")
    if config.get("firewall_mode") \
            and config["firewall_mode"] != firewall_mode:
        raise ProfileError("render firewall mode 与 profile 不一致")
    internal_cidr = canonical_ipv4_cidr(internal_cidr)
    if config.get("internal_cidr") \
            and config["internal_cidr"] != internal_cidr:
        raise ProfileError("render internal CIDR 与 profile 不一致")
    ssh_port = _uint(ssh_port, "PDG_SSH_PORT", maximum=65535)
    if config.get("ssh_port") and config["ssh_port"] != ssh_port:
        raise ProfileError("render SSH port 与 profile 不一致")
    text = Path(template).read_text(encoding="utf-8")
    replacements = {
        "__INTERNAL_CIDR__": internal_cidr,
        "__SSH_PORT__": str(ssh_port),
        "__FIREWALL_MODE__": firewall_mode,
        "__HIJACK_TLS_TCP_PORTS__": ", ".join(map(str, config["tls_ports"])),
        "__HIJACK_HTTP_TCP_PORTS__": ", ".join(map(str, config["http_ports"])),
        "__HIJACK_TCP_PORTS__": ", ".join(map(str, config["tcp_ports"])),
        "__PDG_LOCAL_TCP_PORTS__": ", ".join(
            map(str, config["local_tcp_ports"])),
        "__QUIC_INPUT_ACTION__": (
            "accept" if config["quic_mode"] == "tproxy" else "reject"),
        "__QUIC_MARK__": config["mark_text"],
        "__QUIC_MARK_MASK__": config["mask_text"],
        "__QUIC_MARK_CLEAR_MASK__": config["mark_clear_mask_text"],
        "__QUIC_ROUTE_TABLE__": str(config["route_table"]),
        "__QUIC_RULE_PRIORITY__": str(config["rule_priority"]),
    }
    for token, value in replacements.items():
        text = text.replace(token, value)
    begin = "# PDG_QUIC_TPROXY_BEGIN"
    end = "# PDG_QUIC_TPROXY_END"
    if text.count(begin) != 1 or text.count(end) != 1:
        raise ProfileError("nft 模板 QUIC 条件区边界错误")
    before, remainder = text.split(begin, 1)
    conditional, after = remainder.split(end, 1)
    text = before + (conditional if config["quic_mode"] == "tproxy" else "") + after
    unresolved = sorted(set(re.findall(r"__[A-Z0-9_]+__", text)))
    if unresolved:
        raise ProfileError("nft 模板仍有未渲染占位符: %s" % ", ".join(unresolved))
    return text


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--profile", default=PROFILE_FILE)
    parser.add_argument("--platform", choices=("android", "ios"))
    parser.add_argument("--ssh-port")
    parser.add_argument("--profile-only", action="store_true",
                        help="ignore process PDG_* overrides")
    parser.add_argument("--listener-preflight", action="store_true",
                        help="reject hijack ports occupied by live TCP listeners")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("json")
    sub.add_parser("lines")
    cidr = sub.add_parser("canonical-cidr")
    cidr.add_argument("value")
    ipv4 = sub.add_parser("canonical-ipv4")
    ipv4.add_argument("value")
    hostname = sub.add_parser("canonical-hostname")
    hostname.add_argument("value")
    platform = sub.add_parser("retarget-platform")
    platform.add_argument("target", choices=("android", "ios"))
    nft = sub.add_parser("render-nft")
    nft.add_argument("--template", required=True)
    nft.add_argument("--internal-cidr", required=True)
    nft.add_argument("--firewall-mode", required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "canonical-cidr":
            print(canonical_ipv4_cidr(args.value))
            return 0
        if args.command == "canonical-ipv4":
            print(canonical_ipv4_address(args.value))
            return 0
        if args.command == "canonical-hostname":
            print(canonical_hostname(args.value))
            return 0
        if args.command == "retarget-platform":
            print(retarget_platform_text(args.profile, args.target), end="")
            return 0
        occupied = live_tcp_listener_ports() if args.listener_preflight else ()
        config = resolve(
            args.profile, platform=args.platform, ssh_port=args.ssh_port,
            environ={} if args.profile_only else None,
            occupied_tcp_ports=occupied)
        if args.command == "json":
            print(json.dumps(config, sort_keys=True))
        elif args.command == "lines":
            print("\n".join(profile_lines(config)))
        else:
            print(render_nft(
                args.template, config, internal_cidr=args.internal_cidr,
                ssh_port=args.ssh_port,
                firewall_mode=args.firewall_mode), end="")
    except (OSError, ValueError) as error:
        print("profile/data-plane 校验失败: %s" % error, file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())

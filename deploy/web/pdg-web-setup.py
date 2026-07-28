#!/usr/bin/env python3
"""Create and validate the root-only PDG Web configuration.

Passwords are accepted only from getpass(3) or stdin.  They are never accepted
on argv or through an environment variable.
"""
from __future__ import annotations

import argparse
import base64
import getpass
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import ssl
import stat
import sys
import tempfile
import time
import unicodedata
import urllib.parse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from pdgwebconfig import (  # noqa: E402
    ConfigError as RuntimeConfigError,
    MAX_CONFIG_BYTES,
    load_config as runtime_load_config,
    strict_json_loads,
    validate_config as runtime_validate_config,
)


CONFIG_DIR = "/etc/privdns-gateway"
CONFIG_PATH = CONFIG_DIR + "/web.json"
DEFAULT_CONFIG = CONFIG_PATH
DEFAULT_LISTEN = "127.0.0.1"
DEFAULT_PORT = 9091
DEFAULT_CERT = "/etc/mosdns/certs/fullchain.pem"
DEFAULT_KEY = "/etc/mosdns/certs/privkey.pem"
DEFAULT_SESSION_HOURS = 8
PBKDF2_ITERATIONS = 600_000
MAX_TLS_PATH_BYTES = 4096
LOOPBACKS = ("127.0.0.1/32", "::1/128")
DOMAIN_RE = re.compile(
    r"(?=.{1,253}\Z)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?\Z"
)


class ConfigError(ValueError):
    """A user-correctable configuration error."""


def _strict_uint(value, name, minimum, maximum):
    if isinstance(value, bool):
        raise ConfigError("%s 必须是整数" % name)
    if isinstance(value, str):
        if not re.fullmatch(r"(?:0|[1-9][0-9]*)", value):
            raise ConfigError("%s 必须是十进制整数" % name)
        value = int(value, 10)
    if not isinstance(value, int) or not minimum <= value <= maximum:
        raise ConfigError("%s 必须在 %d..%d" % (name, minimum, maximum))
    return value


def validate_listen(value):
    if not isinstance(value, str) or not value or value.strip() != value:
        raise ConfigError("listen 必须是 canonical IP 地址")
    try:
        parsed = ipaddress.ip_address(value)
    except ValueError as exc:
        raise ConfigError("listen 只接受 IP 地址，不接受主机名") from exc
    if str(parsed) != value:
        raise ConfigError("listen 必须使用 canonical 写法: %s" % parsed)
    if parsed.is_multicast:
        raise ConfigError("listen 不能是组播地址")
    return value


def validate_domain(value):
    if not isinstance(value, str) or value.strip() != value:
        raise ConfigError("访问域名格式错误")
    if value.lower() != value or not DOMAIN_RE.fullmatch(value):
        raise ConfigError("访问域名必须是 lowercase canonical hostname")
    return value


def parse_trusted_cidrs(values):
    raw = []
    for value in values or ():
        raw.extend(x for x in re.split(r"[\s,]+", value.strip()) if x)
    networks = []
    for value in raw:
        try:
            network = ipaddress.ip_network(value, strict=True)
        except ValueError as exc:
            raise ConfigError(
                "可信来源必须是 canonical CIDR（不能带 host bits）: %s" % value
            ) from exc
        canonical = str(network)
        if canonical != value:
            raise ConfigError("可信来源必须使用 canonical 写法: %s" % canonical)
        if network.prefixlen == 0:
            raise ConfigError("拒绝把全部互联网（/0）设为可信来源")
        if network.is_multicast:
            raise ConfigError("可信来源不能是组播网段: %s" % value)
        if canonical not in networks:
            networks.append(canonical)
    for loopback in LOOPBACKS:
        if loopback not in networks:
            networks.append(loopback)
    parsed_networks = [ipaddress.ip_network(item) for item in networks]
    for version in (4, 6):
        collapsed = list(ipaddress.collapse_addresses(
            network for network in parsed_networks if network.version == version
        ))
        if any(network.prefixlen == 0 for network in collapsed):
            raise ConfigError(
                "拒绝以多个网段的并集覆盖全部 IPv%d 互联网（等价 /0）" % version
            )
    networks.sort(key=lambda item: (
        ipaddress.ip_network(item).version,
        int(ipaddress.ip_network(item).network_address),
        ipaddress.ip_network(item).prefixlen,
    ))
    if len(networks) > 64:
        raise ConfigError("trusted_cidrs 最多允许 64 项")
    return networks


def validate_trusted_cidrs(values):
    if not isinstance(values, list) or not values or not all(
            isinstance(x, str) for x in values):
        raise ConfigError("trusted_cidrs 必须是非空 CIDR 数组")
    canonical = parse_trusted_cidrs(values)
    if canonical != values:
        raise ConfigError(
            "trusted_cidrs 必须去重、排序并包含精确 loopback CIDR"
        )
    return values


def _host_for(domain, port):
    return domain if port == 443 else "%s:%d" % (domain, port)


def _b64url(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _secure_root_path(value, name):
    """Resolve a root-controlled path without trusting writable parents.

    Certbot's /etc/letsencrypt/live entries are root-owned symlinks into its
    archive, so links are allowed.  Every directory on both the displayed and
    resolved paths must nevertheless be root-owned and not group/world
    writable, and every link itself must be root-owned.
    """
    pending = value
    seen_links = set()
    for _hop in range(41):
        current = os.path.sep
        components = [part for part in Path(pending).parts if part != os.path.sep]
        restarted = False
        for index, component in enumerate(components):
            current = os.path.join(current, component)
            try:
                info = os.lstat(current)
            except OSError as exc:
                raise ConfigError("%s 不存在或不可读取: %s" % (name, value)) from exc
            final = index == len(components) - 1
            if stat.S_ISLNK(info.st_mode):
                if getattr(info, "st_uid", 0) != 0:
                    raise ConfigError("%s 的符号链接链必须由 root 拥有" % name)
                identity = (
                    getattr(info, "st_dev", 0),
                    getattr(info, "st_ino", 0),
                    current,
                )
                if identity in seen_links:
                    raise ConfigError("%s 的符号链接链存在循环" % name)
                seen_links.add(identity)
                try:
                    destination = os.readlink(current)
                except OSError as exc:
                    raise ConfigError("%s 的符号链接无法读取" % name) from exc
                if os.path.isabs(destination):
                    resolved = destination
                else:
                    resolved = os.path.join(os.path.dirname(current), destination)
                remaining = components[index + 1:]
                pending = os.path.normpath(os.path.join(resolved, *remaining))
                if not os.path.isabs(pending):
                    raise ConfigError("%s 的符号链接解析结果不是绝对路径" % name)
                restarted = True
                break
            if not final:
                if not stat.S_ISDIR(info.st_mode):
                    raise ConfigError("%s 的父路径包含非目录组件" % name)
                if getattr(info, "st_uid", 0) != 0 or info.st_mode & 0o022:
                    raise ConfigError(
                        "%s 的全部父目录必须由 root 拥有且不可被 group/world 写入"
                        % name
                    )
            else:
                return info, current
        if not restarted:
            break
    raise ConfigError("%s 的符号链接层数过多" % name)


def validate_path(value, name, *, private=False):
    if not isinstance(value, str) or not value or value.strip() != value:
        raise ConfigError("%s 路径不能为空" % name)
    if "\x00" in value or not os.path.isabs(value):
        raise ConfigError("%s 必须是绝对路径" % name)
    if len(value.encode("utf-8")) > MAX_TLS_PATH_BYTES:
        raise ConfigError("%s 路径过长" % name)
    if ".." in Path(value).parts or os.path.normpath(value) != value:
        raise ConfigError("%s 必须是 normalized 绝对路径" % name)
    info, _resolved = _secure_root_path(value, name)
    if not stat.S_ISREG(info.st_mode):
        raise ConfigError("%s 的最终目标必须是普通文件" % name)
    if getattr(info, "st_uid", 0) != 0:
        raise ConfigError("%s 必须由 root 拥有" % name)
    if info.st_mode & stat.S_IWOTH or info.st_mode & stat.S_IWGRP:
        raise ConfigError("%s 不能允许 group/world 写入" % name)
    if private and info.st_mode & 0o077:
        raise ConfigError("%s 必须是 owner-only 权限（建议 0600）" % name)
    return value


def _parse_dns_san(pattern):
    """Parse one ASCII DNS SAN without supporting legacy wildcard forms."""
    if (
        not isinstance(pattern, str)
        or not pattern
        or pattern.strip() != pattern
    ):
        raise ConfigError("TLS 证书包含格式无效的 DNS SAN")
    try:
        pattern.encode("ascii")
    except UnicodeEncodeError as exc:
        raise ConfigError("TLS 证书 DNS SAN 必须是 ASCII hostname") from exc
    canonical = pattern.lower()
    if "*" not in canonical:
        if not DOMAIN_RE.fullmatch(canonical):
            raise ConfigError("TLS 证书包含格式无效的 DNS SAN")
        return False, canonical
    if canonical.count("*") != 1 or not canonical.startswith("*."):
        raise ConfigError(
            "TLS 证书 wildcard DNS SAN 仅允许完整最左标签 *."
        )
    suffix = canonical[2:]
    if not DOMAIN_RE.fullmatch(suffix):
        raise ConfigError("TLS 证书包含格式无效的 wildcard DNS SAN")
    return True, suffix


def _validate_dns_san_hostname(decoded, domain):
    """Require an exact DNS SAN or a one-label, leftmost wildcard match."""
    if not isinstance(decoded, dict):
        raise ConfigError("TLS 证书解析结果格式无效")
    if (
        not isinstance(domain, str)
        or domain != domain.lower()
        or not DOMAIN_RE.fullmatch(domain)
    ):
        raise ConfigError("访问域名必须是 ASCII lowercase canonical hostname")
    entries = decoded.get("subjectAltName", ())
    if not isinstance(entries, (tuple, list)):
        raise ConfigError("TLS 证书 SAN 字段格式无效")
    parsed = []
    for entry in entries:
        if not isinstance(entry, (tuple, list)) or len(entry) != 2:
            raise ConfigError("TLS 证书 SAN 字段格式无效")
        kind, pattern = entry
        if kind == "DNS":
            parsed.append(_parse_dns_san(pattern))
    if not parsed:
        raise ConfigError("TLS 证书必须包含 DNS SAN（不接受 CN fallback）")
    for wildcard, pattern in parsed:
        if not wildcard and pattern == domain:
            return
        if wildcard:
            suffix_labels = pattern.split(".")
            domain_labels = domain.split(".")
            if (
                len(domain_labels) == len(suffix_labels) + 1
                and domain_labels[1:] == suffix_labels
            ):
                return
    raise ConfigError("TLS 证书 DNS SAN 不覆盖访问域名 %s" % domain)


def validate_certificate(cert, key, domain):
    cert = validate_path(cert, "TLS 证书")
    key = validate_path(key, "TLS 私钥", private=True)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    try:
        context.load_cert_chain(cert, key)
    except (OSError, ssl.SSLError) as exc:
        raise ConfigError("TLS 证书/私钥无法加载或不匹配") from exc
    try:
        decoded = ssl._ssl._test_decode_cert(cert)  # type: ignore[attr-defined]
    except (OSError, ValueError, ssl.SSLError) as exc:
        raise ConfigError("TLS 证书无法解析") from exc
    _validate_dns_san_hostname(decoded, domain)
    try:
        not_before = ssl.cert_time_to_seconds(decoded["notBefore"])
        not_after = ssl.cert_time_to_seconds(decoded["notAfter"])
    except (KeyError, TypeError, ValueError, OverflowError) as exc:
        raise ConfigError("TLS 证书有效期字段无效") from exc
    now = time.time()
    if now < not_before:
        raise ConfigError("TLS 证书尚未生效")
    if now > not_after:
        raise ConfigError("TLS 证书已经过期")


def validate_config(config, *, check_certificate=True):
    try:
        runtime = runtime_validate_config(config, testing=False)
    except (RuntimeConfigError, TypeError, ValueError) as exc:
        raise ConfigError("配置不符合 PDG Web 生产 schema") from exc
    domains = []
    for host in config["allowed_hosts"]:
        parsed = urllib.parse.urlsplit("https://" + host)
        domains.append(parsed.hostname)
    if check_certificate:
        for domain in domains:
            validate_certificate(runtime.cert, runtime.key, domain)
    else:
        validate_path(runtime.cert, "TLS 证书")
        validate_path(runtime.key, "TLS 私钥", private=True)
    return config


def _password_from_user(stdin_mode=False):
    if stdin_mode:
        password = sys.stdin.readline()
        if password == "":
            raise ConfigError("stdin 中没有管理员密码")
        password = password.rstrip("\r\n")
    else:
        password = getpass.getpass("管理员密码（至少 12 个字符）: ")
        confirm = getpass.getpass("再次输入管理员密码: ")
        if not secrets.compare_digest(password, confirm):
            raise ConfigError("两次输入的密码不一致")
    if len(password) < 12 or len(password.encode("utf-8")) > 1024:
        raise ConfigError("管理员密码必须为 12..1024 UTF-8 bytes")
    if password.isspace() or any(
            unicodedata.category(char).startswith("C") for char in password):
        raise ConfigError("管理员密码不能全为空白或包含 Unicode 控制字符")
    return password


def make_auth(password):
    salt = secrets.token_bytes(16)
    password_hash = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt, PBKDF2_ITERATIONS, dklen=32
    )
    return {
        "algorithm": "pbkdf2_sha256",
        "iterations": PBKDF2_ITERATIONS,
        "salt": _b64url(salt),
        "password_hash": _b64url(password_hash),
        "session_secret": _b64url(secrets.token_bytes(32)),
    }


def read_config(path):
    try:
        with open(path, "rb") as stream:
            data = stream.read(MAX_CONFIG_BYTES + 1)
        if not data or len(data) > MAX_CONFIG_BYTES:
            raise ConfigError("配置文件大小必须为 1..%d bytes" % MAX_CONFIG_BYTES)
        value = strict_json_loads(data)
    except ConfigError:
        raise
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise ConfigError("无法读取现有配置 %s" % path) from exc
    return value


def _require_production_config_path(path):
    """Return the dedicated config directory or reject before filesystem I/O."""
    if path != CONFIG_PATH:
        raise ConfigError(
            "PDG Web 配置路径固定为 %s；拒绝其他 --config 路径" % CONFIG_PATH
        )
    parent = os.path.dirname(path)
    if parent != CONFIG_DIR:
        raise ConfigError("PDG Web 配置目录不是预期的专用目录")
    return parent


def validate_config_file_security(path, *, strict_permissions=True):
    """Reject links/non-files and, when requested, enforce root:root 0600/0700."""
    parent = _require_production_config_path(path)
    if os.path.realpath(parent) != parent:
        raise ConfigError("配置目录及其父路径不能经过符号链接")
    try:
        parent_info = os.lstat(parent)
        info = os.lstat(path)
    except OSError as exc:
        raise ConfigError("配置文件或目录不存在: %s" % path) from exc
    if not stat.S_ISDIR(parent_info.st_mode):
        raise ConfigError("配置父路径不是目录")
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        raise ConfigError("配置必须是普通文件，不能是符号链接")
    if strict_permissions:
        if stat.S_IMODE(parent_info.st_mode) != 0o700:
            raise ConfigError("配置目录权限必须精确为 0700")
        if stat.S_IMODE(info.st_mode) != 0o600:
            raise ConfigError("配置文件权限必须精确为 0600")
        if getattr(info, "st_nlink", 1) != 1:
            raise ConfigError("配置文件必须只有一个硬链接")
        if (
            getattr(parent_info, "st_uid", 0) != 0
            or getattr(info, "st_uid", 0) != 0
            or getattr(parent_info, "st_gid", 0) != 0
            or getattr(info, "st_gid", 0) != 0
        ):
            raise ConfigError("配置目录和文件必须由 root:root 拥有")


def _ensure_parent(path):
    """Create or tighten only the dedicated production config directory."""
    parent = _require_production_config_path(path)
    container = os.path.dirname(parent)
    try:
        container_info = os.lstat(container)
    except OSError as exc:
        raise ConfigError("配置目录的父路径不存在或不可读取") from exc
    if (
        stat.S_ISLNK(container_info.st_mode)
        or not stat.S_ISDIR(container_info.st_mode)
        or getattr(container_info, "st_uid", 0) != 0
        or getattr(container_info, "st_gid", 0) != 0
        or container_info.st_mode & 0o022
        or os.path.realpath(container) != container
    ):
        raise ConfigError("配置目录的父路径必须由 root:root 安全控制")

    created = False
    try:
        os.mkdir(parent, mode=0o700)
        created = True
    except FileExistsError:
        pass
    try:
        parent_info = os.lstat(parent)
    except OSError as exc:
        raise ConfigError("配置目录不存在或不可读取") from exc
    if os.path.realpath(parent) != parent:
        raise ConfigError("配置目录及其父路径不能经过符号链接")
    if stat.S_ISLNK(parent_info.st_mode) or not stat.S_ISDIR(parent_info.st_mode):
        raise ConfigError("配置父路径不是目录")
    if not created and (
        getattr(parent_info, "st_uid", 0) != 0
        or getattr(parent_info, "st_gid", 0) != 0
        or parent_info.st_mode & 0o022
    ):
        raise ConfigError(
            "现有配置目录必须先由 root:root 拥有且不可被 group/world 写入"
        )
    if created and hasattr(os, "geteuid") and os.geteuid() == 0:
        os.chown(parent, 0, 0)
    os.chmod(parent, 0o700)
    if os.path.lexists(path):
        info = os.lstat(path)
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
            raise ConfigError("拒绝覆盖符号链接或非普通配置文件")
    return parent


def atomic_write(path, config):
    parent = _ensure_parent(path)
    fd = -1
    temp_path = ""
    try:
        fd, temp_path = tempfile.mkstemp(prefix=".web.json.", dir=parent)
        os.fchmod(fd, 0o600)
        if hasattr(os, "fchown") and hasattr(os, "geteuid") and os.geteuid() == 0:
            os.fchown(fd, 0, 0)
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            fd = -1
            json.dump(config, stream, ensure_ascii=False, indent=2, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        try:
            runtime_load_config(temp_path, testing=False)
        except RuntimeConfigError as exc:
            raise ConfigError(
                "候选配置未通过 PDG Web 生产 loader；拒绝替换现有配置"
            ) from exc
        os.replace(temp_path, path)
        temp_path = ""
        os.chmod(path, 0o600)
        if hasattr(os, "geteuid") and os.geteuid() == 0:
            os.chown(path, 0, 0)
        directory_fd = os.open(parent, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        if fd >= 0:
            os.close(fd)
        if temp_path:
            try:
                os.unlink(temp_path)
            except FileNotFoundError:
                pass


def _prompt(label, default):
    suffix = " [%s]" % default if default else ""
    value = input("%s%s: " % (label, suffix)).strip()
    return value or default


def _detected_domain():
    for path in ("/opt/pdg-bot/dot-domain",):
        try:
            value = Path(path).read_text(encoding="utf-8").strip()
            return validate_domain(value)
        except (OSError, ConfigError):
            pass
    return ""


def _defaults(existing):
    result = {
        "listen": DEFAULT_LISTEN,
        "port": str(DEFAULT_PORT),
        "domain": _detected_domain(),
        "trusted": ",".join(LOOPBACKS),
        "cert": DEFAULT_CERT,
        "key": DEFAULT_KEY,
        "session_hours": str(DEFAULT_SESSION_HOURS),
    }
    if not isinstance(existing, dict):
        return result
    if isinstance(existing.get("listen"), str):
        result["listen"] = existing["listen"]
    if isinstance(existing.get("port"), int):
        result["port"] = str(existing["port"])
    if isinstance(existing.get("trusted_cidrs"), list):
        result["trusted"] = ",".join(
            x for x in existing["trusted_cidrs"] if isinstance(x, str)
        )
    if isinstance(existing.get("session_hours"), int):
        result["session_hours"] = str(existing["session_hours"])
    tls = existing.get("tls")
    if isinstance(tls, dict):
        if isinstance(tls.get("cert"), str):
            result["cert"] = tls["cert"]
        if isinstance(tls.get("key"), str):
            result["key"] = tls["key"]
    hosts = existing.get("allowed_hosts")
    if isinstance(hosts, list) and hosts and isinstance(hosts[0], str):
        host = hosts[0]
        port = existing.get("port")
        if isinstance(port, int) and port != 443 and host.endswith(":%d" % port):
            host = host.rsplit(":", 1)[0]
        result["domain"] = host
    return result


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description="配置 PDG Web 管理面")
    parser.add_argument("--config", default=CONFIG_PATH, help=argparse.SUPPRESS)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--password-only", action="store_true")
    mode.add_argument("--validate-only", action="store_true")
    parser.add_argument("--non-interactive", action="store_true")
    parser.add_argument("--password-stdin", action="store_true")
    parser.add_argument("--listen")
    parser.add_argument("--port")
    parser.add_argument("--domain")
    parser.add_argument("--trusted-cidr", action="append", dest="trusted_cidrs")
    parser.add_argument("--cert")
    parser.add_argument("--key")
    parser.add_argument("--session-hours")
    return parser.parse_args(argv)


def main(argv=None):
    args = parse_args(argv)
    if hasattr(os, "geteuid") and os.geteuid() != 0:
        raise ConfigError("请用 root 运行（配置包含认证密钥）")
    config_path = CONFIG_PATH
    _require_production_config_path(args.config)

    if args.validate_only:
        validate_config_file_security(config_path)
        try:
            runtime_load_config(config_path, testing=False)
        except RuntimeConfigError as exc:
            raise ConfigError("配置未通过 PDG Web 生产 loader") from exc
        validate_config(read_config(config_path))
        print("配置校验通过: %s" % config_path)
        return 0

    if args.password_only:
        if any((args.listen, args.port, args.domain, args.trusted_cidrs,
                args.cert, args.key, args.session_hours, args.non_interactive)):
            raise ConfigError("--password-only 不能同时修改服务参数")
        validate_config_file_security(config_path)
        config = validate_config(read_config(config_path))
        password = _password_from_user(args.password_stdin)
        config["auth"] = make_auth(password)
        password = None
        validate_config(config)
        atomic_write(config_path, config)
        print("管理员密码已更新，现有会话已失效。")
        return 0

    existing = None
    if os.path.exists(config_path):
        validate_config_file_security(config_path, strict_permissions=False)
        try:
            existing = read_config(config_path)
        except ConfigError:
            existing = None
    defaults = _defaults(existing)

    if args.non_interactive:
        if not args.domain or not args.trusted_cidrs or not args.password_stdin:
            raise ConfigError(
                "非交互 setup 必须给 --domain、至少一个 --trusted-cidr、--password-stdin"
            )
        listen = args.listen or defaults["listen"]
        port_text = args.port or defaults["port"]
        domain = args.domain
        trusted_values = args.trusted_cidrs
        cert = args.cert or defaults["cert"]
        key = args.key or defaults["key"]
        hours_text = args.session_hours or defaults["session_hours"]
    else:
        listen = args.listen or _prompt("监听 IP", defaults["listen"])
        port_text = args.port or _prompt("监听端口", defaults["port"])
        domain = args.domain or _prompt("访问域名（TLS 证书必须覆盖）", defaults["domain"])
        trusted_text = (
            ",".join(args.trusted_cidrs) if args.trusted_cidrs
            else _prompt("可信来源 CIDR（逗号分隔；loopback 会自动加入）",
                         defaults["trusted"])
        )
        trusted_values = [trusted_text]
        cert = args.cert or _prompt("TLS 证书路径", defaults["cert"])
        key = args.key or _prompt("TLS 私钥路径", defaults["key"])
        hours_text = args.session_hours or _prompt(
            "会话小时数（1..8）", defaults["session_hours"]
        )

    listen = validate_listen(listen)
    port = _strict_uint(port_text, "port", 1, 65535)
    domain = validate_domain(domain)
    trusted = parse_trusted_cidrs(trusted_values)
    hours = _strict_uint(hours_text, "session_hours", 1, 8)
    validate_certificate(cert, key, domain)
    password = _password_from_user(args.password_stdin)
    host = _host_for(domain, port)
    config = {
        "listen": listen,
        "port": port,
        "trusted_cidrs": trusted,
        "allowed_hosts": [host],
        "allowed_origins": ["https://" + host],
        "session_hours": hours,
        "tls": {"cert": cert, "key": key},
        "auth": make_auth(password),
    }
    password = None
    validate_config(config)
    atomic_write(config_path, config)
    print("配置已安全写入: %s" % config_path)
    interface = "[%s]" % listen if ipaddress.ip_address(listen).version == 6 else listen
    print("服务接口: %s:%d；HTTPS Host: %s" % (interface, port, host))
    print("可信来源: %s" % ", ".join(trusted))
    print("默认仍为禁用状态；确认外部防火墙后执行: pdg web enable")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except ConfigError as error:
        print("[x] %s" % error, file=sys.stderr)
        raise SystemExit(2)

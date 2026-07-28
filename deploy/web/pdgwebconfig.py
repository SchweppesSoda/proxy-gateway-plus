#!/usr/bin/env python3
"""Strict, shared schema loader for the PDG Web management configuration.

This module validates configuration structure and safe file handling only.  TLS
certificate/key loading, hostname coverage, and certificate validity remain
setup/runtime responsibilities at the point where those files are consumed.
"""
from __future__ import annotations

import base64
import dataclasses
import hmac
import ipaddress
import json
import os
import re
import stat
import urllib.parse
from typing import Any


MAX_CONFIG_BYTES = 64 * 1024
_HOST_CHARS_RE = re.compile(r"^[A-Za-z0-9.:[\]_-]+$")
_B64URL_RE = re.compile(r"^[A-Za-z0-9_-]+$")


class ConfigError(RuntimeError):
    pass


@dataclasses.dataclass(frozen=True)
class WebConfig:
    listen: str
    port: int
    trusted_cidrs: tuple[
        ipaddress.IPv4Network | ipaddress.IPv6Network, ...
    ]
    allowed_hosts: frozenset[str]
    allowed_origins: frozenset[str]
    origin_hosts: frozenset[tuple[str, str]]
    session_seconds: int
    cert: str
    key: str
    iterations: int
    salt: bytes
    password_hash: bytes
    session_secret: bytes


def _duplicate_object(pairs):
    out = {}
    for key, value in pairs:
        if key in out:
            raise ValueError("duplicate JSON key")
        out[key] = value
    return out


def _reject_constant(_value):
    raise ValueError("non-finite JSON number")


def strict_json_loads(data: bytes):
    if not isinstance(data, bytes):
        raise TypeError("JSON input must be bytes")
    return json.loads(
        data.decode("utf-8"),
        object_pairs_hook=_duplicate_object,
        parse_constant=_reject_constant,
    )


def _b64url_decode(
        value: Any, field: str, *, minimum: int, maximum: int) -> bytes:
    if not isinstance(value, str) or not _B64URL_RE.fullmatch(value):
        raise ConfigError(f"{field} is invalid")
    try:
        raw = base64.urlsafe_b64decode(
            value.encode("ascii") + b"=" * (-len(value) % 4))
    except Exception as exc:
        raise ConfigError(f"{field} is invalid") from exc
    canonical = base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")
    if not hmac.compare_digest(canonical, value):
        raise ConfigError(f"{field} is invalid")
    if not minimum <= len(raw) <= maximum:
        raise ConfigError(f"{field} is invalid")
    return raw


def normalize_host(value: Any) -> str:
    if not isinstance(value, str) or not 1 <= len(value) <= 300:
        raise ConfigError("allowed host is invalid")
    if value != value.strip() or not _HOST_CHARS_RE.fullmatch(value):
        raise ConfigError("allowed host is invalid")
    if any(ch in value for ch in ("/", "\\", "@", ",", "#", "?", "%")):
        raise ConfigError("allowed host is invalid")
    try:
        parsed = urllib.parse.urlsplit("https://" + value)
        hostname = parsed.hostname
        port = parsed.port
    except (ValueError, UnicodeError) as exc:
        raise ConfigError("allowed host is invalid") from exc
    if not hostname or parsed.username is not None or parsed.password is not None:
        raise ConfigError("allowed host is invalid")
    host = hostname.lower()
    if host.endswith("."):
        raise ConfigError("allowed host is invalid")
    try:
        ip = ipaddress.ip_address(host)
        shown = f"[{ip.compressed}]" if ip.version == 6 else ip.compressed
    except ValueError:
        if not re.fullmatch(
                r"(?=.{1,253}$)"
                r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*"
                r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?",
                host):
            raise ConfigError("allowed host is invalid")
        shown = host
    return shown + (f":{port}" if port is not None else "")


def normalize_origin(value: Any) -> tuple[str, str]:
    if not isinstance(value, str) or not 1 <= len(value) <= 340:
        raise ConfigError("allowed origin is invalid")
    if value != value.strip():
        raise ConfigError("allowed origin is invalid")
    try:
        parsed = urllib.parse.urlsplit(value)
    except (ValueError, UnicodeError) as exc:
        raise ConfigError("allowed origin is invalid") from exc
    if (
            parsed.scheme.lower() != "https" or not parsed.netloc
            or parsed.path or parsed.query or parsed.fragment
            or parsed.username is not None or parsed.password is not None):
        raise ConfigError("allowed origin is invalid")
    host = normalize_host(parsed.netloc)
    return "https://" + host, host


def _validate_keys(value: Any, expected: set[str], where: str):
    if not isinstance(value, dict) or set(value) != expected:
        raise ConfigError(f"{where} has unknown or missing fields")


def validate_config(raw: Any, *, testing: bool = False) -> WebConfig:
    """Validate a decoded configuration mapping and return its frozen form."""

    _validate_keys(
        raw,
        {
            "listen", "port", "trusted_cidrs", "allowed_hosts",
            "allowed_origins", "session_hours", "tls", "auth",
        },
        "web config",
    )
    _validate_keys(raw["tls"], {"cert", "key"}, "tls config")
    _validate_keys(
        raw["auth"],
        {
            "algorithm", "iterations", "salt", "password_hash",
            "session_secret",
        },
        "auth config",
    )

    try:
        listen_ip = ipaddress.ip_address(raw["listen"])
    except (ValueError, TypeError) as exc:
        raise ConfigError("listen must be an IP address") from exc
    if raw["listen"] != listen_ip.compressed or listen_ip.is_multicast:
        raise ConfigError(
            "listen must be a canonical non-multicast IP address")

    port = raw["port"]
    if type(port) is not int or not 1 <= port <= 65535:
        raise ConfigError("port is invalid")

    cidrs_value = raw["trusted_cidrs"]
    if not isinstance(cidrs_value, list) or not 1 <= len(cidrs_value) <= 64:
        raise ConfigError("trusted_cidrs is invalid")
    cidrs = []
    canonical_cidrs = []
    for value in cidrs_value:
        if not isinstance(value, str):
            raise ConfigError("trusted_cidrs is invalid")
        try:
            network = ipaddress.ip_network(value, strict=True)
        except ValueError as exc:
            raise ConfigError("trusted_cidrs is invalid") from exc
        if (
                value != network.with_prefixlen or network.prefixlen == 0
                or network.is_multicast):
            raise ConfigError(
                "trusted_cidrs must be canonical and may not contain "
                "/0 or multicast")
        cidrs.append(network)
        canonical_cidrs.append(value)
    for version in (4, 6):
        collapsed = ipaddress.collapse_addresses(
            network for network in cidrs if network.version == version)
        if any(network.prefixlen == 0 for network in collapsed):
            raise ConfigError(
                "trusted_cidrs union may not cover all IPv%d addresses"
                % version)
    sorted_cidrs = sorted(
        canonical_cidrs,
        key=lambda item: (
            ipaddress.ip_network(item).version,
            int(ipaddress.ip_network(item).network_address),
            ipaddress.ip_network(item).prefixlen,
        ),
    )
    if (
            canonical_cidrs != sorted_cidrs
            or len(set(canonical_cidrs)) != len(canonical_cidrs)):
        raise ConfigError("trusted_cidrs must be sorted and unique")
    if (
            "127.0.0.1/32" not in canonical_cidrs
            or "::1/128" not in canonical_cidrs):
        raise ConfigError(
            "trusted_cidrs must contain exact IPv4 and IPv6 loopbacks")

    hosts_value = raw["allowed_hosts"]
    if not isinstance(hosts_value, list) or not 1 <= len(hosts_value) <= 64:
        raise ConfigError("allowed_hosts is invalid")
    normalized_hosts = [normalize_host(value) for value in hosts_value]
    if normalized_hosts != hosts_value:
        raise ConfigError("allowed_hosts must use canonical spelling")
    hosts = frozenset(normalized_hosts)
    if len(hosts) != len(hosts_value):
        raise ConfigError("allowed_hosts contains duplicates")

    origins_value = raw["allowed_origins"]
    if (
            not isinstance(origins_value, list)
            or not 1 <= len(origins_value) <= 64):
        raise ConfigError("allowed_origins is invalid")
    normalized_origin_pairs = [
        normalize_origin(value) for value in origins_value]
    if [
            origin for origin, _host in normalized_origin_pairs
    ] != origins_value:
        raise ConfigError("allowed_origins must use canonical spelling")
    if origins_value != ["https://" + host for host in hosts_value]:
        raise ConfigError(
            "allowed_origins must correspond exactly to allowed_hosts")
    origin_pairs = frozenset(normalized_origin_pairs)
    if len(origin_pairs) != len(origins_value):
        raise ConfigError("allowed_origins contains duplicates")
    for _origin, host in origin_pairs:
        if host not in hosts:
            raise ConfigError("every allowed origin must have an allowed host")

    hours = raw["session_hours"]
    if type(hours) is not int or not 1 <= hours <= 8:
        raise ConfigError("session_hours is invalid")

    cert = raw["tls"]["cert"]
    key = raw["tls"]["key"]
    if (
            not isinstance(cert, str) or not isinstance(key, str)
            or "\x00" in cert or "\x00" in key
            or not os.path.isabs(cert) or not os.path.isabs(key)
            or os.path.normpath(cert) != cert or os.path.normpath(key) != key
            or len(cert) > 4096 or len(key) > 4096):
        raise ConfigError("TLS paths are invalid")

    auth = raw["auth"]
    if auth["algorithm"] != "pbkdf2_sha256":
        raise ConfigError("unsupported password algorithm")
    iterations = auth["iterations"]
    minimum_iterations = 1000 if testing else 600_000
    if (
            type(iterations) is not int
            or not minimum_iterations <= iterations <= 5_000_000):
        raise ConfigError("PBKDF2 iterations are invalid")
    salt = _b64url_decode(
        auth["salt"], "salt", minimum=16, maximum=64)
    password_hash = _b64url_decode(
        auth["password_hash"], "password_hash", minimum=32, maximum=32)
    session_secret = _b64url_decode(
        auth["session_secret"], "session_secret", minimum=32, maximum=64)

    return WebConfig(
        listen=listen_ip.compressed,
        port=port,
        trusted_cidrs=tuple(cidrs),
        allowed_hosts=hosts,
        allowed_origins=frozenset(
            origin for origin, _host in origin_pairs),
        origin_hosts=origin_pairs,
        session_seconds=hours * 3600,
        cert=cert,
        key=key,
        iterations=iterations,
        salt=salt,
        password_hash=password_hash,
        session_secret=session_secret,
    )


def _read_config_file(path: str, *, testing: bool) -> bytes:
    if not isinstance(path, str) or "\x00" in path:
        raise ConfigError("web config path is invalid")
    if not testing:
        if not os.path.isabs(path) or os.path.normpath(path) != path:
            raise ConfigError(
                "web config path must be normalized and absolute")
        parent = os.path.dirname(path)
        if os.path.realpath(parent) != parent:
            raise ConfigError(
                "web config parent must not traverse symlinks")
        try:
            parent_info = os.lstat(parent)
        except OSError as exc:
            raise ConfigError("cannot inspect web config parent") from exc
        if (
                not stat.S_ISDIR(parent_info.st_mode)
                or stat.S_IMODE(parent_info.st_mode) != 0o700
                or parent_info.st_uid != 0 or parent_info.st_gid != 0):
            raise ConfigError(
                "web config parent must be root:root mode 0700")

    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        raise ConfigError("cannot open web config") from exc
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise ConfigError("web config is not a regular file")
        if (
                not testing
                and (
                    stat.S_IMODE(info.st_mode) != 0o600
                    or info.st_uid != 0 or info.st_gid != 0
                    or info.st_nlink != 1
                )):
            raise ConfigError(
                "web config must be root:root mode 0600 with one link")
        if info.st_size <= 0 or info.st_size > MAX_CONFIG_BYTES:
            raise ConfigError("web config size is invalid")
        chunks = []
        remaining = MAX_CONFIG_BYTES + 1
        while remaining:
            chunk = os.read(fd, min(remaining, 8192))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        data = b"".join(chunks)
        if len(data) > MAX_CONFIG_BYTES:
            raise ConfigError("web config is too large")
        return data
    finally:
        os.close(fd)


def load_config(path: str, *, testing: bool = False) -> WebConfig:
    """Strictly load one configuration file and return its frozen form."""

    try:
        raw = strict_json_loads(_read_config_file(path, testing=testing))
    except ConfigError:
        raise
    except Exception as exc:
        raise ConfigError("web config is not valid JSON") from exc
    return validate_config(raw, testing=testing)

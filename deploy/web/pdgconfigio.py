#!/usr/bin/env python3
"""PDG managed configuration import/export core.

The HTTPS handler only deals with authentication and bounded request bodies.
This module owns parsing, archive safety, canonical-model conversion, secure
preview staging and the final ``pdgtx``-backed apply.  Imported Mihomo and
MosDNS files never become an alternative source of truth: Mihomo is converted
into the PDG model and MosDNS can only replace the validated managed graph.
"""
from __future__ import annotations

import argparse
import base64
import copy
import datetime as dt
import hashlib
import importlib.util
import io
import ipaddress
import json
import math
import os
import pathlib
import re
import secrets
import stat
import struct
import tarfile
import tempfile
import threading
import time
import zipfile
from typing import Any


STAGING_DIR = os.environ.get(
    "PDG_IMPORT_STAGING_DIR", "/var/lib/privdns-gateway/web-imports")
MODEL_PATH = os.environ.get("PDG_MODEL_PATH", "/etc/sing-box/config.json")
MIHOMO_PATH = os.environ.get("PDG_MIHOMO_CONFIG", "/etc/mihomo/config.yaml")
MOSDNS_PATH = os.environ.get("PDG_MOSDNS_CONFIG", "/etc/mosdns/config.yaml")
MIHOMO_PROVIDER_DIR = os.environ.get(
    "PDG_MIHOMO_PROVIDER_DIR", "/etc/mihomo/providers")
BOT_PATH = os.environ.get("PDG_BOT_MODULE", "/opt/pdg-bot/bot.py")
RULESET_META_PATH = os.environ.get("PDG_RULESET_META", "/opt/pdg-bot/rulesets.json")
RULESET_DIR = os.environ.get("PDG_RULESET_DIR", "/etc/sing-box/rs")
MOSDNS_RULE_DIR = os.environ.get("PDG_MOSDNS_RULE_DIR", "/etc/mosdns/rules")
MOSDNS_CERT_DIR = os.environ.get("PDG_MOSDNS_CERT_DIR", "/etc/mosdns/certs")

MAX_ARCHIVE_FILE = 8 * 1024 * 1024
MAX_MODEL_FILE = 24 * 1024 * 1024
MAX_ARCHIVE_TOTAL = 32 * 1024 * 1024
MAX_LEGACY_PDG_TOTAL = 64 * 1024 * 1024
# A default bot backup may contain 32 MiB of incompressible data plus tar/gzip
# framing.  Keep the wire envelope slightly larger so every successful Web
# export is a valid input to Web preview.
MAX_UPLOAD = 36 * 1024 * 1024
MAX_LEGACY_PDG_UPLOAD = 68 * 1024 * 1024
MAX_ARCHIVE_FILES = 512
MAX_RECORD_BYTES = 48 * 1024 * 1024
MAX_YAML_TOKENS = 200_000
MAX_CONFLICTS = 200
PREVIEW_TTL = 30 * 60
# A config-import job is bounded well below this window.  Claims younger than
# this are treated as potentially live even if the Web process has restarted;
# older regular-file claims can be atomically taken over by the janitor.
CLAIM_PROTECTION_TTL = 2 * 60 * 60
_IMPORT_ID_RE = re.compile(r"^imp-[a-f0-9]{32}$")
_MACHINE_TAG_RE = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")
_SAFE_ARCHIVE_LEAF_RE = re.compile(r"^[A-Za-z0-9_.@+ -]{1,128}$")
_HEX64_RE = re.compile(r"^[a-f0-9]{64}$")
_PROVIDER_EXT_RE = re.compile(r"\.(?:ya?ml|json|txt|mrs)$", re.I)


def _reserved_targets() -> frozenset[str]:
    return frozenset(_pdgmodel().RESERVED_TARGETS)


def _archive_member_limit(name: str) -> int:
    return MAX_MODEL_FILE if name in {
        "model.json", "config.json", "etc/sing-box/config.json",
    } or name.endswith("/etc/sing-box/config.json") else MAX_ARCHIVE_FILE


def _upload_limit(kind: str) -> int:
    return MAX_LEGACY_PDG_UPLOAD if kind == "pdg" else MAX_UPLOAD

_PDG_OWNED_MIHOMO = {
    "allow-lan", "bind-address", "dns", "external-controller", "external-ui",
    "external-ui-url", "listeners", "mixed-port", "port", "redir-port", "secret",
    "sniffer", "socks-port", "tproxy-port", "tun", "proxies", "proxy-providers",
    "proxy-groups", "rule-providers", "rules", "mode", "log-level",
}
_MIHOMO_IMPORTED_SECTIONS = {
    "proxies", "proxy-providers", "proxy-groups", "rule-providers", "rules",
}
_SUPPORTED_RULES = {
    "DOMAIN": "domain", "DOMAIN-SUFFIX": "domain_suffix",
    "DOMAIN-KEYWORD": "domain_keyword", "IP-CIDR": "ip_cidr",
    "IP-CIDR6": "ip_cidr", "RULE-SET": "rule_set",
}
_REQUIRED_MOSDNS = {
    "remote_upstream": "forward", "local_upstream": "forward",
    "unlock_upstream": "forward", "geosite_unlock": "domain_set",
    "geosite_cn": "domain_set", "npn_clients": "ip_set",
    "hijack_set": "domain_set", "explicit_hijack": "domain_set",
    "force_hijack": "domain_set", "ecs_china": "ecs_handler",
    "ecs_neutral": "ecs_handler", "has_resp": "sequence",
    "client_limiter": "rate_limiter", "lazy_cache": "cache",
    "force_hijack_seq": "sequence",
    "internal_sequence": "sequence", "main_sequence": "sequence",
    "udp_server": "udp_server", "tcp_server": "tcp_server",
    "dot_server": "tcp_server",
}


class ConfigIOError(RuntimeError):
    pass


class ImportInvalid(ConfigIOError):
    pass


class ImportNotFound(ConfigIOError):
    pass


class ImportExpired(ConfigIOError):
    pass


class ImportConflict(ConfigIOError):
    pass


_PDG_MODEL_MODULE = None


def _pdgmodel():
    """Load the one shared schema-v3 validator from the managed Bot bundle."""
    global _PDG_MODEL_MODULE
    if _PDG_MODEL_MODULE is None:
        candidates = [
            "/opt/pdg-bot/pdgmodel.py",
            os.path.abspath(os.path.join(
                os.path.dirname(__file__), "..", "bot", "pdgmodel.py")),
        ]
        path = next((item for item in candidates
                     if os.path.isfile(item) and not os.path.islink(item)), None)
        if path is None:
            raise ImportInvalid("PDG schema validator is unavailable")
        spec = importlib.util.spec_from_file_location("_pdg_model_v3", path)
        if spec is None or spec.loader is None:
            raise ImportInvalid("PDG schema validator is unavailable")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        if not callable(getattr(module, "migrate", None)):
            raise ImportInvalid("PDG schema validator is unavailable")
        _PDG_MODEL_MODULE = module
    return _PDG_MODEL_MODULE


def _normalize_name(value: Any, label: str) -> str:
    try:
        return _pdgmodel().normalize_name(value, label)
    except (TypeError, ValueError) as exc:
        detail = {
            "length": "must be 1-64 Unicode code points and at most 256 UTF-8 bytes",
            "unsafe": "contains a control, bidirectional, or unsafe invisible character",
            "canonical": "must use NFC and have no surrounding whitespace",
            "encoding": "must be valid UTF-8 text",
            "type": "must be text",
        }.get(getattr(exc, "reason", None), "is invalid")
        raise ImportInvalid(label + " " + detail) from exc


def _valid_name(value: Any) -> bool:
    try:
        return bool(_pdgmodel().is_valid_name(value))
    except (TypeError, ValueError):
        return False


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _strict_json(data: bytes) -> Any:
    def duplicate(pairs):
        out = {}
        for key, value in pairs:
            if key in out:
                raise ValueError("duplicate key")
            out[key] = value
        return out

    return json.loads(
        data.decode("utf-8"), object_pairs_hook=duplicate,
        parse_constant=lambda _value: (_ for _ in ()).throw(ValueError("constant")))


def _yaml_module():
    try:
        import yaml  # type: ignore
    except ImportError as exc:
        raise ConfigIOError("YAML support is unavailable") from exc
    return yaml


def _safe_yaml_load(data: bytes) -> dict[str, Any]:
    if not data or len(data) > MAX_UPLOAD or b"\x00" in data:
        raise ImportInvalid("configuration size is invalid")
    try:
        text = data.decode("utf-8", "strict")
    except UnicodeDecodeError as exc:
        raise ImportInvalid("configuration must be UTF-8") from exc
    yaml = _yaml_module()
    class StrictSafeLoader(yaml.SafeLoader):
        pass

    def construct_mapping(loader, node, deep=False):
        if not isinstance(node, yaml.nodes.MappingNode):
            raise ImportInvalid("YAML mapping is invalid")
        mapping = {}
        for key_node, value_node in node.value:
            if not isinstance(key_node, yaml.nodes.ScalarNode):
                raise ImportInvalid("complex YAML keys are not accepted")
            key = loader.construct_object(key_node, deep=False)
            if not isinstance(key, str) or key in mapping:
                raise ImportInvalid("YAML keys must be unique strings")
            mapping[key] = loader.construct_object(value_node, deep=deep)
        return mapping

    StrictSafeLoader.add_constructor(
        yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, construct_mapping)
    try:
        count = 0
        documents = 0
        for token in yaml.scan(text):
            count += 1
            if count > MAX_YAML_TOKENS:
                raise ImportInvalid("configuration is too complex")
            if isinstance(token, yaml.tokens.DocumentStartToken):
                documents += 1
                if documents > 1:
                    raise ImportInvalid("multiple YAML documents are not accepted")
            if isinstance(token, (yaml.tokens.AnchorToken, yaml.tokens.AliasToken,
                                  yaml.tokens.TagToken)):
                raise ImportInvalid("YAML anchors, aliases and tags are not accepted")
        value = yaml.load(text, Loader=StrictSafeLoader)
    except ImportInvalid:
        raise
    except Exception as exc:
        raise ImportInvalid("configuration is not valid safe YAML") from exc
    if not isinstance(value, dict):
        raise ImportInvalid("configuration root must be a mapping")

    nodes = 0

    def bounded(item, depth=0):
        nonlocal nodes
        nodes += 1
        if nodes > 100_000 or depth > 64:
            raise ImportInvalid("configuration nesting or size is excessive")
        if isinstance(item, dict):
            for key, child in item.items():
                if not isinstance(key, str):
                    raise ImportInvalid("configuration keys must be strings")
                bounded(child, depth + 1)
        elif isinstance(item, list):
            for child in item:
                bounded(child, depth + 1)
        elif isinstance(item, float):
            if not math.isfinite(item):
                raise ImportInvalid("configuration contains a non-finite number")
        elif not isinstance(item, (str, int, bool, type(None))):
            raise ImportInvalid("configuration contains an unsupported value")

    bounded(value)
    return value


def _safe_yaml_dump(value: dict[str, Any]) -> bytes:
    yaml = _yaml_module()
    try:
        return yaml.safe_dump(
            value, allow_unicode=True, sort_keys=False,
            default_flow_style=False).encode("utf-8")
    except Exception as exc:
        raise ImportInvalid("configuration cannot be rendered") from exc


def _normalize_member(name: str) -> str:
    if not isinstance(name, str) or not name or "\\" in name or "\x00" in name:
        raise ImportInvalid("archive contains an invalid member name")
    pure = pathlib.PurePosixPath(name)
    if pure.is_absolute() or any(part in {"", ".", ".."} for part in pure.parts):
        raise ImportInvalid("archive member escapes its root")
    if len(pure.parts) > 12 or len(name) > 512:
        raise ImportInvalid("archive member name is too deep")
    if any(not _SAFE_ARCHIVE_LEAF_RE.fullmatch(part) for part in pure.parts):
        raise ImportInvalid("archive member name is not supported")
    return pure.as_posix()


def _archive_files(
        payload: bytes, *, total_limit: int = MAX_ARCHIVE_TOTAL) -> dict[str, bytes] | None:
    if total_limit not in {MAX_ARCHIVE_TOTAL, MAX_LEGACY_PDG_TOTAL}:
        raise ImportInvalid("archive size limit is invalid")
    files: dict[str, bytes] = {}
    total = 0
    if payload.startswith(b"PK\x03\x04"):
        try:
            # Reject an oversized central directory before ZipFile builds its
            # in-memory ZipInfo table.  ZIP64/multidisk are intentionally out
            # of scope for a bounded configuration bundle.
            eocd = payload.rfind(b"PK\x05\x06", max(0, len(payload) - 65557))
            if eocd < 0 or eocd + 22 > len(payload):
                raise ImportInvalid("ZIP end record is invalid")
            disk, start_disk, disk_entries, total_entries, central_size = struct.unpack_from(
                "<HHHHI", payload, eocd + 4)
            if (disk != 0 or start_disk != 0 or disk_entries != total_entries
                    or total_entries in {0, 0xffff}
                    or total_entries > MAX_ARCHIVE_FILES
                    or central_size > 1024 * 1024):
                raise ImportInvalid("ZIP member table is unsafe")
            with zipfile.ZipFile(io.BytesIO(payload)) as archive:
                infos = archive.infolist()
                if not 1 <= len(infos) <= MAX_ARCHIVE_FILES:
                    raise ImportInvalid("archive member count is invalid")
                for info in infos:
                    if info.is_dir():
                        continue
                    mode = (info.external_attr >> 16) & 0o170000
                    if mode and mode != stat.S_IFREG:
                        raise ImportInvalid("archive contains a non-regular member")
                    name = _normalize_member(info.filename)
                    if name in files or info.file_size < 0:
                        raise ImportInvalid("archive contains a duplicate member")
                    limit = _archive_member_limit(name)
                    if info.file_size > limit:
                        raise ImportInvalid("archive member is too large")
                    if info.compress_size and info.file_size > info.compress_size * 200:
                        raise ImportInvalid("archive compression ratio is unsafe")
                    chunks = []
                    actual = 0
                    with archive.open(info, "r") as stream:
                        while True:
                            chunk = stream.read(64 * 1024)
                            if not chunk:
                                break
                            actual += len(chunk)
                            if actual > info.file_size or actual > limit:
                                raise ImportInvalid("archive member expands beyond its declaration")
                            chunks.append(chunk)
                    if actual != info.file_size:
                        raise ImportInvalid("archive member size is invalid")
                    data = b"".join(chunks)
                    total += len(data)
                    if total > total_limit:
                        raise ImportInvalid("archive expands beyond the size limit")
                    files[name] = data
        except ImportInvalid:
            raise
        except (OSError, ValueError, RuntimeError, zipfile.BadZipFile) as exc:
            raise ImportInvalid("archive is invalid") from exc
        return files
    if payload.startswith(b"\x1f\x8b") or (
            len(payload) >= 262 and payload[257:262] == b"ustar"):
        fileobj = _NamedBytesIO(payload)
        fileobj.seek(0)
        try:
            # Stream mode is deliberate: getmembers() lets a tiny hostile tar
            # allocate an unbounded in-memory member table before our count gate.
            with tarfile.open(fileobj=fileobj, mode="r|*") as archive:
                member_count = 0
                for member in archive:
                    member_count += 1
                    if member_count > MAX_ARCHIVE_FILES:
                        raise ImportInvalid("archive member count is invalid")
                    if member.isdir():
                        continue
                    if not member.isreg() or member.issym() or member.islnk():
                        raise ImportInvalid("archive contains a non-regular member")
                    name = _normalize_member(member.name)
                    limit = _archive_member_limit(name)
                    if name in files or member.size < 0 or member.size > limit:
                        raise ImportInvalid("archive member is invalid")
                    stream = archive.extractfile(member)
                    if stream is None:
                        raise ImportInvalid("archive member cannot be read")
                    chunks = []
                    actual = 0
                    while True:
                        chunk = stream.read(64 * 1024)
                        if not chunk:
                            break
                        actual += len(chunk)
                        if actual > member.size or actual > limit:
                            raise ImportInvalid("archive member expands beyond its declaration")
                        chunks.append(chunk)
                    if actual != member.size:
                        raise ImportInvalid("archive member size is invalid")
                    data = b"".join(chunks)
                    total += len(data)
                    if total > total_limit:
                        raise ImportInvalid("archive expands beyond the size limit")
                    files[name] = data
                if member_count < 1:
                    raise ImportInvalid("archive member count is invalid")
        except ImportInvalid:
            raise
        except (OSError, ValueError, tarfile.TarError) as exc:
            raise ImportInvalid("archive is invalid") from exc
        return files
    return None


class _NamedBytesIO(io.BytesIO):
    """BytesIO accepted by ``tarfile.is_tarfile`` on all supported Pythons."""

    name = "upload.tar"


def _verify_manifest(files: dict[str, bytes]) -> None:
    data = files.get("manifest.json")
    if data is None:
        return
    try:
        manifest = _strict_json(data)
    except Exception as exc:
        raise ImportInvalid("manifest is invalid") from exc
    created_at = manifest.get("createdAt") if isinstance(manifest, dict) else None
    if (not isinstance(manifest, dict) or set(manifest) != {"version", "createdAt", "files"}
            or manifest.get("version") != 2
            or not isinstance(created_at, str)
            or not re.fullmatch(
                r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z",
                created_at)):
        raise ImportInvalid("manifest version is not supported")
    try:
        dt.datetime.strptime(created_at, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError as exc:
        raise ImportInvalid("manifest creation time is invalid") from exc
    entries = manifest.get("files")
    if not isinstance(entries, list) or not entries:
        raise ImportInvalid("manifest file list is invalid")
    seen = set()
    for item in entries:
        if not isinstance(item, dict) or set(item) != {"path", "size", "sha256"}:
            raise ImportInvalid("manifest entry is invalid")
        path = _normalize_member(item.get("path"))
        if path in seen or path == "manifest.json" or path not in files:
            raise ImportInvalid("manifest references an invalid file")
        data = files[path]
        if (type(item.get("size")) is not int
                or not 0 <= item["size"] <= _archive_member_limit(path)
                or item["size"] != len(data) or item.get("sha256") != _sha(data)):
            raise ImportInvalid("manifest integrity check failed")
        seen.add(path)
    if seen != set(files) - {"manifest.json"}:
        raise ImportInvalid("manifest does not cover the complete archive")


_PDG_FIXED_MEMBERS = {
    "manifest.json", "etc/sing-box/config.json", "etc/mosdns/config.yaml",
    "etc/mosdns/rules/custom_direct.txt", "etc/mosdns/rules/ruleset_direct.txt",
    "etc/mosdns/rules/ruleset_hijack.txt", "etc/mosdns/rules/custom_hijack.txt",
    "opt/pdg-bot/rulesets.json",
}


def _verify_pdg_members(files: dict[str, bytes]) -> None:
    """Mirror the bot restore whitelist and require the canonical model member."""
    for name in files:
        if name in _PDG_FIXED_MEMBERS:
            continue
        if re.fullmatch(r"etc/sing-box/rs/[A-Za-z0-9_.-]+\.(?:json|mrs)", name):
            continue
        if re.fullmatch(
                r"etc/mihomo/providers/[a-f0-9]{64}\.(?:ya?ml|json|txt|mrs)",
                name, re.I):
            continue
        raise ImportInvalid("PDG archive contains a member outside the restore whitelist")
    if "etc/sing-box/config.json" not in files:
        raise ImportInvalid("PDG archive is missing the canonical model")


_PROXY_ADVANCED_BLOCKED = {
    "name", "type", "server", "port", "password", "username", "uuid",
    "cipher", "alterId", "flow", "auth", "auth-str", "up", "down",
    "congestion-controller", "udp-relay-mode", "tls", "servername", "sni",
    "skip-cert-verify", "alpn", "reality-opts", "client-fingerprint",
    "network", "ws-opts", "grpc-opts", "tfo",
}
_TOP_RUNTIME_ADVANCED = {"tcp-concurrent", "unified-delay"}
_PROXY_RUNTIME_ADVANCED = {"udp", "packet-encoding"}
_PROVIDER_COMMON = {"type", "url", "path", "interval", "size-limit"}
_PROXY_PROVIDER_FIELDS = _PROVIDER_COMMON | {
    "health-check", "filter", "exclude-filter", "override"}
_RULE_PROVIDER_FIELDS = _PROVIDER_COMMON | {"format", "behavior"}
_PROVIDER_HEALTH_FIELDS = {"enable", "url", "interval", "lazy"}
_PROVIDER_OVERRIDE_FIELDS = {"additional-prefix", "additional-suffix", "udp", "tfo"}
_GROUP_COMMON_FIELDS = {"name", "type", "proxies", "use"}
_GROUP_FIELDS = {
    "select": _GROUP_COMMON_FIELDS | {"lazy", "disable-udp", "hidden"},
    "url-test": _GROUP_COMMON_FIELDS | {
        "url", "interval", "tolerance", "lazy", "disable-udp", "hidden"},
    "fallback": _GROUP_COMMON_FIELDS | {
        "url", "interval", "lazy", "disable-udp", "hidden"},
    "load-balance": _GROUP_COMMON_FIELDS | {
        "url", "interval", "lazy", "disable-udp", "hidden", "strategy"},
}


def _validate_proxy_advanced(value: Any, depth: int = 0, budget: list[int] | None = None) -> None:
    if budget is None:
        budget = [0]
    if depth > 12:
        raise ImportInvalid("per-proxy Mihomo metadata is too deep")
    budget[0] += 1
    if budget[0] > 4096:
        raise ImportInvalid("per-proxy Mihomo metadata is too complex")
    if value is None or isinstance(value, (bool, int)):
        return
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ImportInvalid("per-proxy Mihomo metadata contains a non-finite number")
        return
    if isinstance(value, str):
        if len(value) > 16384 or "\x00" in value:
            raise ImportInvalid("per-proxy Mihomo metadata contains an unsafe value")
        return
    if isinstance(value, list):
        for child in value:
            _validate_proxy_advanced(child, depth + 1, budget)
        return
    if isinstance(value, dict):
        for key, child in value.items():
            if not isinstance(key, str) or not key or len(key) > 128 or "\x00" in key:
                raise ImportInvalid("per-proxy Mihomo metadata contains an unsafe key")
            _validate_proxy_advanced(child, depth + 1, budget)
        return
    raise ImportInvalid("per-proxy Mihomo metadata contains an unsupported value")


def _valid_http_url(value: Any) -> bool:
    return (isinstance(value, str) and len(value) <= 8192
            and re.fullmatch(r"https?://[^\s\x00]+", value, re.I) is not None)


def _validate_provider_schema(collection_name: str, provider: dict[str, Any]) -> None:
    fields = (_PROXY_PROVIDER_FIELDS if collection_name == "proxy-provider"
              else _RULE_PROVIDER_FIELDS)
    if set(provider) - fields:
        raise ImportInvalid(collection_name + " contains unsupported runtime fields")
    interval = provider.get("interval")
    if interval is not None and (type(interval) is not int or not 1 <= interval <= 604800):
        raise ImportInvalid(collection_name + " interval is invalid")
    size_limit = provider.get("size-limit")
    if size_limit is not None and (
            type(size_limit) is not int or not 1 <= size_limit <= 1024 * 1024 * 1024):
        raise ImportInvalid(collection_name + " size limit is invalid")
    for key in ("filter", "exclude-filter"):
        value = provider.get(key)
        if value is not None and (
                not isinstance(value, str) or len(value) > 4096 or "\x00" in value):
            raise ImportInvalid(collection_name + " filter is invalid")
    health = provider.get("health-check")
    if health is not None:
        if (not isinstance(health, dict) or set(health) - _PROVIDER_HEALTH_FIELDS
                or type(health.get("enable", True)) is not bool
                or not _valid_http_url(health.get("url"))
                or type(health.get("interval")) is not int
                or not 1 <= health["interval"] <= 604800
                or ("lazy" in health and type(health["lazy"]) is not bool)):
            raise ImportInvalid(collection_name + " health-check is invalid")
    override = provider.get("override")
    if override is not None:
        if not isinstance(override, dict) or set(override) - _PROVIDER_OVERRIDE_FIELDS:
            raise ImportInvalid(collection_name + " override contains unsafe runtime fields")
        for key in ("additional-prefix", "additional-suffix"):
            value = override.get(key)
            if value is not None and (
                    not isinstance(value, str) or len(value) > 128 or "\x00" in value):
                raise ImportInvalid(collection_name + " override is invalid")
        for key in ("udp", "tfo"):
            if key in override and type(override[key]) is not bool:
                raise ImportInvalid(collection_name + " override is invalid")
    if "format" in provider:
        allowed = {"yaml"} if collection_name == "proxy-provider" else {"yaml", "text", "mrs"}
        if provider["format"] not in allowed:
            raise ImportInvalid(collection_name + " format is invalid")
    if "behavior" in provider and provider["behavior"] not in {"domain", "ipcidr", "classical"}:
        raise ImportInvalid(collection_name + " behavior is invalid")


def _validate_group_schema(group: dict[str, Any]) -> None:
    typ = group.get("type")
    allowed = _GROUP_FIELDS.get(typ)
    if allowed is None or set(group) - allowed:
        raise ImportInvalid("proxy group contains unsupported runtime fields")
    for key in ("lazy", "disable-udp", "hidden"):
        if key in group and type(group[key]) is not bool:
            raise ImportInvalid("proxy group option is invalid")
    if "url" in group and not _valid_http_url(group["url"]):
        raise ImportInvalid("proxy group URL is invalid")
    if "interval" in group and (
            type(group["interval"]) is not int or not 1 <= group["interval"] <= 604800):
        raise ImportInvalid("proxy group interval is invalid")
    if "tolerance" in group and (
            type(group["tolerance"]) is not int or not 0 <= group["tolerance"] <= 65535):
        raise ImportInvalid("proxy group tolerance is invalid")
    if "strategy" in group and group["strategy"] not in {
            "consistent-hashing", "round-robin", "sticky-sessions"}:
        raise ImportInvalid("proxy group strategy is invalid")


def _inactive_advanced_warnings(model: dict[str, Any]) -> list[str]:
    mihomo = ((model.get("_pdg") or {}).get("mihomo") or {})
    top = set((mihomo.get("advanced") or {})) - _TOP_RUNTIME_ADVANCED
    proxy = set()
    for outbound in model.get("outbounds", []):
        metadata = outbound.get("_pdg_mihomo") if isinstance(outbound, dict) else None
        advanced = metadata.get("advanced") if isinstance(metadata, dict) else None
        if isinstance(advanced, dict):
            proxy.update(set(advanced) - _PROXY_RUNTIME_ADVANCED)

    def describe(label: str, keys: set[str]) -> str | None:
        ordered = sorted(keys)
        if not ordered:
            return None
        shown = ordered[:20]
        suffix = f" (+{len(ordered) - len(shown)} more)" if len(ordered) > len(shown) else ""
        return label + "=" + ", ".join(shown) + suffix

    parts = [item for item in (describe("top-level", top), describe("per-proxy", proxy))
             if item is not None]
    return (["Read-only Mihomo fields were retained but not activated: " + "; ".join(parts)]
            if parts else [])


def _validate_runtime_advanced(value: dict[str, Any], *, proxy: bool) -> None:
    if proxy:
        if "udp" in value and type(value["udp"]) is not bool:
            raise ImportInvalid("per-proxy Mihomo udp option is invalid")
        if ("packet-encoding" in value
                and value["packet-encoding"] not in {"packetaddr", "xudp"}):
            raise ImportInvalid("per-proxy Mihomo packet encoding is invalid")
    elif any(key in value and type(value[key]) is not bool
             for key in _TOP_RUNTIME_ADVANCED):
        raise ImportInvalid("top-level Mihomo runtime metadata is invalid")


def normalize_model(model: Any) -> dict[str, Any]:
    try:
        result = _pdgmodel().migrate(model)
    except (TypeError, ValueError) as exc:
        raise ImportInvalid("PDG schema v3 validation failed: " + str(exc)) from exc
    for outbound in result["outbounds"]:
        if not isinstance(outbound, dict):
            continue
        proxy_meta = outbound.get("_pdg_mihomo")
        if proxy_meta is None:
            continue
        if (not isinstance(proxy_meta, dict) or set(proxy_meta) != {"advanced"}
                or not isinstance(proxy_meta.get("advanced"), dict)):
            raise ImportInvalid("per-proxy Mihomo metadata has the wrong shape")
        advanced = proxy_meta["advanced"]
        if set(advanced) & _PROXY_ADVANCED_BLOCKED:
            raise ImportInvalid("per-proxy Mihomo metadata overrides a canonical field")
        _validate_proxy_advanced(advanced)
        _validate_runtime_advanced(advanced, proxy=True)
    meta = result.get("_pdg")
    if meta is None:
        meta = {}
    if not isinstance(meta, dict) or set(meta) != {
            "schema", "policy-groups", "mihomo"}:
        raise ImportInvalid("PDG metadata is invalid")
    schema = meta.get("schema")
    if schema != 3:
        raise ImportInvalid("PDG model schema is not supported")
    mihomo = meta.get("mihomo") or {}
    if not isinstance(mihomo, dict) or set(mihomo) != {
            "proxy-providers", "rule-providers", "advanced", "managed-files"}:
        raise ImportInvalid("PDG Mihomo metadata is invalid")
    normalized = {
        "proxy-providers": copy.deepcopy(mihomo.get("proxy-providers") or {}),
        "rule-providers": copy.deepcopy(mihomo.get("rule-providers") or {}),
        "advanced": copy.deepcopy(mihomo.get("advanced") or {}),
        "managed-files": copy.deepcopy(mihomo.get("managed-files") or {}),
    }
    if not isinstance(normalized["proxy-providers"], dict) or not isinstance(
            normalized["rule-providers"], dict) or not isinstance(
            normalized["advanced"], dict) or not isinstance(
            normalized["managed-files"], dict):
        raise ImportInvalid("PDG Mihomo metadata has the wrong shape")
    if set(normalized["advanced"]) & _PDG_OWNED_MIHOMO:
        raise ImportInvalid("PDG Mihomo metadata overrides a managed runtime field")
    _validate_proxy_advanced(normalized["advanced"])
    _validate_runtime_advanced(normalized["advanced"], proxy=False)
    managed_raw_total = 0
    for leaf, encoded in normalized["managed-files"].items():
        if not isinstance(leaf, str) or not re.fullmatch(
                r"[a-f0-9]{64}\.(?:ya?ml|json|txt|mrs)", leaf, re.I):
            raise ImportInvalid("managed provider file name is invalid")
        try:
            raw = base64.b64decode(encoded, validate=True)
        except Exception as exc:
            raise ImportInvalid("managed provider file is invalid") from exc
        if not raw or len(raw) > MAX_ARCHIVE_FILE or _sha(raw) != leaf.split(".", 1)[0]:
            raise ImportInvalid("managed provider file integrity check failed")
        managed_raw_total += len(raw)
    _validate_native_mihomo_metadata(result, normalized)
    result["_pdg"] = {
        "schema": 3,
        "policy-groups": copy.deepcopy(meta["policy-groups"]),
        "mihomo": normalized,
    }
    encoded_model_size = len(_model_bytes(result))
    if (encoded_model_size > MAX_MODEL_FILE
            or encoded_model_size + managed_raw_total > MAX_ARCHIVE_TOTAL):
        raise ImportInvalid("PDG model and managed providers exceed the restorable limits")
    return result


def _validate_native_mihomo_metadata(model: dict[str, Any], metadata: dict[str, Any]) -> None:
    """Validate native PDG v3 metadata as strictly as the Mihomo importer.

    A native bundle is not a privileged raw takeover channel: provider paths,
    group references and embedded managed-file closure remain PDG-owned.
    """
    local_leaves: set[str] = set()
    direct_tags = {
        item.get("tag") for item in model.get("outbounds", [])
        if isinstance(item, dict) and item.get("type") == "direct"
        and isinstance(item.get("tag"), str)
    }
    if direct_tags & _reserved_targets():
        raise ImportInvalid("direct tag collides with a reserved Mihomo target")
    providers = metadata["proxy-providers"]
    rule_providers = metadata["rule-providers"]
    for collection_name, collection in (("proxy-provider", providers),
                                        ("rule-provider", rule_providers)):
        for name, provider in collection.items():
            if (not _valid_name(name)
                    or not isinstance(provider, dict)
                    or not _validate_safe_value(provider)):
                raise ImportInvalid(collection_name + " metadata is invalid")
            _validate_provider_schema(collection_name, provider)
            typ = provider.get("type", "http")
            path = provider.get("path")
            if typ not in {"http", "file"} or not isinstance(path, str):
                raise ImportInvalid(collection_name + " type or path is invalid")
            match = re.fullmatch(
                r"/etc/mihomo/providers/([a-f0-9]{64}\.(?:ya?ml|json|txt|mrs))",
                path, re.I)
            if not match:
                raise ImportInvalid(collection_name + " path is outside the managed directory")
            leaf = match.group(1)
            if typ == "file":
                if leaf not in metadata["managed-files"]:
                    raise ImportInvalid(collection_name + " local file is not embedded")
                local_leaves.add(leaf)
                if "url" in provider:
                    raise ImportInvalid(collection_name + " file source has a URL")
            else:
                url = provider.get("url")
                if (not isinstance(url, str) or len(url) > 8192
                        or not re.fullmatch(r"https?://[^\s\x00]+", url, re.I)):
                    raise ImportInvalid(collection_name + " URL is invalid")
                if leaf in metadata["managed-files"]:
                    raise ImportInvalid(collection_name + " remote path collides with an embedded file")
                if leaf.split(".", 1)[0].lower() != hashlib.sha256(
                        (collection_name + ":" + name).encode("utf-8")).hexdigest():
                    raise ImportInvalid(collection_name + " remote path is not canonical")
    if local_leaves != set(metadata["managed-files"]):
        raise ImportInvalid("managed provider files are not an exact reference closure")

    groups = (model.get("_pdg") or {}).get("policy-groups") or []
    group_names: set[str] = set()
    for group in groups:
        if (not isinstance(group, dict) or not _validate_safe_value(group)
                or not isinstance(group.get("name"), str)
                or not _valid_name(group["name"])
                or group["name"] in group_names
                or group.get("type") not in {"select", "url-test", "fallback", "load-balance"}
                or not isinstance(group.get("proxies", []), list)
                or not isinstance(group.get("use", []), list)):
            raise ImportInvalid("proxy group metadata is invalid")
        _validate_group_schema(group)
        group_names.add(group["name"])
    outbound_tags = {item.get("tag") for item in model.get("outbounds", [])
                     if isinstance(item, dict) and isinstance(item.get("tag"), str)}
    proxy_tags = {item.get("tag") for item in model.get("outbounds", [])
                  if isinstance(item, dict) and isinstance(item.get("tag"), str)
                  and item.get("type") not in {"direct", "selector", "urltest"}}
    if group_names & proxy_tags:
        raise ImportInvalid("proxy and group names collide")
    if group_names & (_reserved_targets() | direct_tags):
        raise ImportInvalid("proxy group name collides with a reserved target")
    known = outbound_tags | group_names | {"DIRECT", "REJECT"}
    graph: dict[str, set[str]] = {}
    for group in groups:
        members = group.get("proxies", [])
        uses = group.get("use", [])
        if (any(not isinstance(item, str) or item not in known for item in members)
                or any(not isinstance(item, str) or item not in providers for item in uses)):
            raise ImportInvalid("proxy group references an undefined member or provider")
        graph[group["name"]] = {item for item in members if item in group_names}
    visiting: set[str] = set()
    visited: set[str] = set()

    def visit(name: str) -> None:
        if name in visiting:
            raise ImportInvalid("proxy groups contain a dependency cycle")
        if name in visited:
            return
        visiting.add(name)
        for child in graph.get(name, set()):
            visit(child)
        visiting.remove(name)
        visited.add(name)

    for name in graph:
        visit(name)


def _validate_safe_value(value: Any, depth: int = 0, budget: list[int] | None = None) -> bool:
    budget = [0] if budget is None else budget
    budget[0] += 1
    if depth > 12 or budget[0] > 4096:
        return False
    if value is None or isinstance(value, (bool, int, float)):
        return not isinstance(value, float) or value == value and abs(value) != float("inf")
    if isinstance(value, str):
        return len(value) <= 16384 and "\x00" not in value
    if isinstance(value, list):
        return all(_validate_safe_value(item, depth + 1, budget) for item in value)
    if isinstance(value, dict):
        return all(isinstance(key, str) and 0 < len(key) <= 128 and "\x00" not in key
                   and _validate_safe_value(item, depth + 1, budget)
                   for key, item in value.items())
    return False


def _choose_config(files: dict[str, bytes], kind: str) -> tuple[str, bytes]:
    names = list(files)
    if kind == "pdg":
        preferred = ["model.json", "etc/sing-box/config.json", "config.json"]
        candidates = [name for name in preferred if name in files]
        if not candidates:
            candidates = [name for name in names if name.endswith("/etc/sing-box/config.json")]
    else:
        preferred_bases = (
            ("mihomo.yaml", "mihomo.yml", "config.yaml", "config.yml")
            if kind == "mihomo" else
            ("mosdns.yaml", "mosdns.yml", "config.yaml", "config.yml")
        )
        candidates = [name for name in names if pathlib.PurePosixPath(name).name.lower() in preferred_bases]
        candidates.sort(key=lambda name: (len(pathlib.PurePosixPath(name).parts), name))
    if len(candidates) != 1:
        raise ImportInvalid("archive must contain exactly one recognizable configuration")
    return candidates[0], files[candidates[0]]


def _proxy_to_model(item: Any) -> dict[str, Any]:
    if not isinstance(item, dict):
        raise ImportInvalid("proxy entry must be a mapping")
    name = _normalize_name(item.get("name"), "proxy name")
    typ = item.get("type")
    if not isinstance(typ, str):
        raise ImportInvalid("proxy name or type is invalid")
    mapping = {
        "ss": "shadowsocks", "socks5": "socks", "socks": "socks",
        "vmess": "vmess", "vless": "vless", "trojan": "trojan",
        "hysteria": "hysteria", "hysteria2": "hysteria2", "tuic": "tuic",
        "anytls": "anytls", "http": "http",
    }
    if typ not in mapping:
        raise ImportInvalid("proxy type is not supported")
    out = {"tag": name, "type": mapping[typ]}
    aliases = {
        "server": "server", "port": "server_port", "uuid": "uuid",
        "password": "password", "username": "username", "cipher": "method",
        "alterId": "alter_id", "flow": "flow", "auth": "auth",
        "auth-str": "auth_str", "up": "up", "down": "down",
        "congestion-controller": "congestion_control",
        "udp-relay-mode": "udp_relay_mode",
    }
    for source, target in aliases.items():
        if source in item:
            out[target] = copy.deepcopy(item[source])
    if "server" not in out or "server_port" not in out:
        raise ImportInvalid("proxy server and port are required")
    if type(out["server_port"]) is not int or not 1 <= out["server_port"] <= 65535:
        raise ImportInvalid("proxy port is invalid")
    tls = {}
    if item.get("tls") or typ in {"trojan", "hysteria", "hysteria2", "tuic", "anytls"}:
        tls["enabled"] = True
    sni = item.get("servername", item.get("sni"))
    if isinstance(sni, str) and sni:
        tls["server_name"] = sni
    if item.get("skip-cert-verify") is True:
        tls["insecure"] = True
    if isinstance(item.get("alpn"), list):
        tls["alpn"] = copy.deepcopy(item["alpn"])
    reality = item.get("reality-opts")
    if isinstance(reality, dict):
        tls["reality"] = {
            "enabled": True, "public_key": reality.get("public-key", ""),
            "short_id": reality.get("short-id", "")}
    fingerprint = item.get("client-fingerprint")
    if isinstance(fingerprint, str) and fingerprint:
        tls["utls"] = {"enabled": True, "fingerprint": fingerprint}
    if tls:
        out["tls"] = tls
    network = item.get("network")
    if network == "ws":
        opts = item.get("ws-opts") if isinstance(item.get("ws-opts"), dict) else {}
        out["transport"] = {"type": "ws", "path": opts.get("path", "/")}
        if isinstance(opts.get("headers"), dict):
            out["transport"]["headers"] = copy.deepcopy(opts["headers"])
    elif network == "grpc":
        opts = item.get("grpc-opts") if isinstance(item.get("grpc-opts"), dict) else {}
        out["transport"] = {"type": "grpc", "service_name": opts.get("grpc-service-name", "")}
    if item.get("tfo") is True:
        out["tcp_fast_open"] = True
    mapped = {
        "name", "type", "server", "port", "uuid", "password", "username",
        "cipher", "alterId", "flow", "auth", "auth-str", "up", "down",
        "congestion-controller", "udp-relay-mode", "tls", "servername", "sni",
        "skip-cert-verify", "alpn", "reality-opts", "client-fingerprint",
        "network", "ws-opts", "grpc-opts", "tfo",
    }
    advanced = {key: copy.deepcopy(value) for key, value in item.items() if key not in mapped}
    if advanced:
        out["_pdg_mihomo"] = {"advanced": advanced}
    return out


def _safe_target(
        value: str, direct_tag: str, known: set[str], block_tag: str | None = None) -> str:
    if value == "DIRECT":
        return direct_tag
    if value == "REJECT" and block_tag:
        return block_tag
    value = _normalize_name(value, "policy target")
    if value not in known:
        raise ImportInvalid("rule references an undefined policy target")
    return value


def _rules_to_model(
        rules: Any, direct_tag: str, known: set[str], block_tag: str | None = None
        ) -> dict[str, Any]:
    if not isinstance(rules, list) or not rules:
        raise ImportInvalid("Mihomo rules must be a non-empty list")
    out = []
    final = direct_tag
    match_seen = False
    for index, raw in enumerate(rules):
        if not isinstance(raw, str) or len(raw) > 4096:
            raise ImportInvalid("Mihomo rule is invalid")
        parts = [piece.strip() for piece in raw.split(",")]
        kind = parts[0].upper() if parts else ""
        if kind == "MATCH":
            if len(parts) != 2 or match_seen or index != len(rules) - 1:
                raise ImportInvalid("MATCH rule is invalid")
            match_seen = True
            final = _safe_target(parts[1], direct_tag, known, block_tag)
            continue
        # Suffix parameters such as `no-resolve` have target-specific runtime
        # semantics.  PDG does not currently model them, so accepting and
        # dropping a fourth field would silently change routing behavior.
        if kind not in _SUPPORTED_RULES or len(parts) != 3:
            raise ImportInvalid("Mihomo rule type is not supported")
        value, target = parts[1], _safe_target(parts[2], direct_tag, known, block_tag)
        if not value or len(value) > 2048:
            raise ImportInvalid("Mihomo rule value is invalid")
        key = _SUPPORTED_RULES[kind]
        if key == "rule_set":
            out.append({"rule_set": _normalize_name(value, "rule provider name"),
                        "outbound": target})
        else:
            out.append({key: [value], "outbound": target})
    if not match_seen:
        raise ImportInvalid("Mihomo rules must end with one MATCH rule")
    return {"rules": out, "final": final}


def _managed_provider(
        name: str, provider: Any, archive: dict[str, bytes] | None,
        config_name: str, managed_files: dict[str, str], provider_kind: str,
        referenced_members: set[str]) -> dict[str, Any]:
    name = _normalize_name(name, "provider name")
    if not isinstance(provider, dict):
        raise ImportInvalid("provider definition is invalid")
    result = copy.deepcopy(provider)
    path = result.get("path")
    typ = result.get("type", "http")
    if typ not in {"http", "file"}:
        raise ImportInvalid("provider type is not supported")
    if typ == "file":
        if not isinstance(path, str) or not archive:
            raise ImportInvalid("local provider requires an archive member")
        base = pathlib.PurePosixPath(config_name).parent
        relative = pathlib.PurePosixPath(path.removeprefix("./"))
        joined = (base / relative).as_posix()
        normalized = _normalize_member(joined)
        data = archive.get(normalized)
        if data is None or not data or len(data) > MAX_ARCHIVE_FILE:
            raise ImportInvalid("referenced local provider file is missing")
        suffix = pathlib.PurePosixPath(normalized).suffix.lower()
        if not _PROVIDER_EXT_RE.search(suffix):
            raise ImportInvalid("local provider file type is not supported")
        leaf = _sha(data) + suffix
        referenced_members.add(normalized)
        managed_files[leaf] = base64.b64encode(data).decode("ascii")
        result["path"] = "/etc/mihomo/providers/" + leaf
    else:
        url = result.get("url")
        if not isinstance(url, str) or not re.match(r"^https?://", url, re.I):
            raise ImportInvalid("remote provider URL is invalid")
        suffix = pathlib.PurePosixPath(str(path or "provider.yaml")).suffix.lower()
        suffix = suffix if _PROVIDER_EXT_RE.fullmatch(suffix) else ".yaml"
        result["path"] = "/etc/mihomo/providers/" + hashlib.sha256(
            (provider_kind + ":" + name).encode("utf-8")).hexdigest() + suffix
    return result


def mihomo_to_model(
        doc: dict[str, Any], current: dict[str, Any], *, archive: dict[str, bytes] | None,
        config_name: str) -> tuple[dict[str, Any], list[str]]:
    proxies = doc.get("proxies") or []
    if not isinstance(proxies, list):
        raise ImportInvalid("proxies must be a list")
    converted = [_proxy_to_model(item) for item in proxies]
    names = {item["tag"] for item in converted}
    if len(names) != len(converted):
        raise ImportInvalid("proxy names must be unique")
    direct = next((item for item in current.get("outbounds", [])
                   if isinstance(item, dict) and item.get("type") == "direct"), None)
    direct = copy.deepcopy(direct or {"type": "direct", "tag": "direct"})
    direct_tag = direct.get("tag", "direct")
    if direct_tag in _reserved_targets():
        raise ImportInvalid("current direct tag collides with a reserved Mihomo target")

    managed_files: dict[str, str] = {}
    referenced_members: set[str] = set()
    providers = {}
    raw_proxy_providers = doc.get("proxy-providers", {})
    raw_rule_providers = doc.get("rule-providers", {})
    if not isinstance(raw_proxy_providers, dict) or not isinstance(raw_rule_providers, dict):
        raise ImportInvalid("proxy-providers and rule-providers must be mappings")
    for name, provider in raw_proxy_providers.items():
        canonical = _normalize_name(name, "proxy provider name")
        if canonical in providers:
            raise ImportInvalid("proxy provider names must be unique after normalization")
        providers[canonical] = _managed_provider(
            canonical, provider, archive, config_name, managed_files, "proxy-provider",
            referenced_members)
    rule_providers = {}
    for name, provider in raw_rule_providers.items():
        canonical = _normalize_name(name, "rule provider name")
        if canonical in rule_providers:
            raise ImportInvalid("rule provider names must be unique after normalization")
        rule_providers[canonical] = _managed_provider(
            canonical, provider, archive, config_name, managed_files, "rule-provider",
            referenced_members)
    if archive is not None:
        expected_members = {config_name} | referenced_members
        if "manifest.json" in archive:
            expected_members.add("manifest.json")
        if set(archive) != expected_members:
            raise ImportInvalid("Mihomo archive is not an exact provider reference closure")

    groups = doc.get("proxy-groups") or []
    if not isinstance(groups, list):
        raise ImportInvalid("proxy-groups must be a list")
    group_names = set()
    managed_groups = []
    for group in groups:
        if not isinstance(group, dict):
            raise ImportInvalid("proxy group is invalid")
        canonical_group = copy.deepcopy(group)
        canonical_group["name"] = _normalize_name(group.get("name"), "proxy group name")
        canonical_group["proxies"] = [
            _normalize_name(member, "proxy group member")
            if member not in {"DIRECT", "REJECT"} else member
            for member in (group.get("proxies") or [])
        ]
        canonical_group["use"] = [
            _normalize_name(provider, "proxy provider name")
            for provider in (group.get("use") or [])
        ]
        if canonical_group["name"] in group_names or group.get("type") not in {
                "select", "url-test", "fallback", "load-balance"}:
            raise ImportInvalid("proxy group type or name is invalid")
        group_names.add(canonical_group["name"])
        managed_groups.append(canonical_group)
    if names & group_names:
        raise ImportInvalid("proxy and group names must not collide")
    if (names | group_names) & ({direct_tag} | _reserved_targets()):
        raise ImportInvalid("proxy or group name collides with a reserved target")
    current_blocks = [copy.deepcopy(item) for item in current.get("outbounds", [])
                      if isinstance(item, dict) and item.get("type") == "block"]
    if len(current_blocks) > 1:
        raise ImportInvalid("current model contains ambiguous block outbounds")
    block = current_blocks[0] if current_blocks else None
    block_tag = block.get("tag") if block else None
    reject_referenced = any(
        isinstance(group, dict) and "REJECT" in (group.get("proxies") or [])
        for group in managed_groups)
    reject_referenced = reject_referenced or any(
        isinstance(rule, str) and re.search(r",\s*REJECT(?:\s*,|\s*$)", rule, re.I)
        for rule in (doc.get("rules") or []))
    if reject_referenced and block is None:
        block_tag = "block"
        if block_tag in names | group_names | {direct_tag}:
            raise ImportInvalid("REJECT requires a block outbound but its canonical tag collides")
        block = {"type": "block", "tag": block_tag}
    known = names | group_names | {direct_tag, "REJECT"}
    if block_tag:
        known.add(block_tag)
    for group in managed_groups:
        members = group.get("proxies") or []
        uses = group.get("use") or []
        if not isinstance(members, list) or not isinstance(uses, list):
            raise ImportInvalid("proxy group members are invalid")
        for member in members:
            if member not in known and member not in {"DIRECT", "REJECT"}:
                raise ImportInvalid("proxy group references an undefined member")
        for provider in uses:
            if provider not in providers:
                raise ImportInvalid("proxy group references an undefined provider")
    graph = {group["name"]: {member for member in group.get("proxies") or []
                              if member in group_names}
             for group in managed_groups}
    visiting: set[str] = set()
    visited: set[str] = set()

    def visit(name: str):
        if name in visiting:
            raise ImportInvalid("proxy groups contain a dependency cycle")
        if name in visited:
            return
        visiting.add(name)
        for child in graph.get(name, set()):
            visit(child)
        visiting.remove(name)
        visited.add(name)

    for name in graph:
        visit(name)
    known |= {"DIRECT"}
    route = _rules_to_model(doc.get("rules"), direct_tag, known, block_tag)
    for rule in route["rules"]:
        if "rule_set" in rule and rule["rule_set"] not in rule_providers:
            raise ImportInvalid("rule references an undefined rule provider")

    advanced = {
        key: copy.deepcopy(value) for key, value in doc.items()
        if key not in _PDG_OWNED_MIHOMO | {
            "proxies", "proxy-providers", "proxy-groups", "rules", "rule-providers",
            "mode", "log-level"}
    }
    warnings = []
    ignored = sorted(
        key for key in doc
        if key in (_PDG_OWNED_MIHOMO - _MIHOMO_IMPORTED_SECTIONS))
    if ignored:
        warnings.append("PDG-managed runtime fields will be rebound: " + ", ".join(ignored))
    for group in managed_groups:
        group["proxies"] = [direct_tag if member == "DIRECT" else member
                            for member in group.get("proxies") or []]
    model = {
        "outbounds": [direct] + ([block] if block else []) + converted,
        "route": route,
        "_pdg": {"schema": 3, "policy-groups": managed_groups, "mihomo": {
            "proxy-providers": providers,
            "rule-providers": rule_providers,
            "advanced": advanced,
            "managed-files": managed_files,
        }},
    }
    normalized = normalize_model(model)
    warnings.extend(_inactive_advanced_warnings(normalized))
    return normalized, warnings


def _mosdns_contract(doc: dict[str, Any], current: dict[str, Any] | None) -> dict[str, Any]:
    if current is None:
        raise ImportInvalid("current managed MosDNS configuration is unavailable")

    def checked_graph(document: Any) -> tuple[list[dict[str, Any]], dict[str, dict[str, Any]]]:
        if not isinstance(document, dict) or set(document) - {"log", "plugins"}:
            raise ImportInvalid("MosDNS top-level fields are not managed by PDG")
        log = document.get("log") or {}
        if (not isinstance(log, dict) or set(log) - {"level"}
                or log.get("level", "warn") not in {"debug", "info", "warn", "error"}):
            raise ImportInvalid("MosDNS log configuration is invalid")
        graph_plugins = document.get("plugins")
        if not isinstance(graph_plugins, list) or len(graph_plugins) != len(_REQUIRED_MOSDNS):
            raise ImportInvalid("MosDNS plugin graph is invalid")
        graph = {}
        for plugin in graph_plugins:
            if not isinstance(plugin, dict) or set(plugin) != {"tag", "type", "args"}:
                raise ImportInvalid("MosDNS plugin entry is invalid")
            tag, typ = plugin.get("tag"), plugin.get("type")
            if (not isinstance(tag, str) or tag in graph
                    or _REQUIRED_MOSDNS.get(tag) != typ):
                raise ImportInvalid("MosDNS configuration does not match the PDG contract")
            graph[tag] = plugin
        if set(graph) != set(_REQUIRED_MOSDNS):
            raise ImportInvalid("MosDNS configuration does not match the PDG contract")

        for tag, plugin in graph.items():
            typ, args = plugin["type"], plugin["args"]
            if typ == "forward":
                if (not isinstance(args, dict) or set(args) != {"concurrent", "upstreams"}
                        or type(args.get("concurrent")) is not int
                        or not 1 <= args["concurrent"] <= 16
                        or not isinstance(args.get("upstreams"), list)
                        or not 1 <= len(args["upstreams"]) <= 16):
                    raise ImportInvalid("MosDNS forward args are invalid")
                for upstream in args["upstreams"]:
                    addr = upstream.get("addr") if isinstance(upstream, dict) else None
                    if (not isinstance(upstream, dict) or set(upstream) != {"addr"}
                            or not isinstance(addr, str) or len(addr) > 2048
                            or not re.fullmatch(r"(?:https|udp|tcp|tls)://[^\s\x00]+", addr)):
                        raise ImportInvalid("MosDNS upstream is invalid")
            elif typ == "domain_set":
                if (not isinstance(args, dict) or set(args) != {"files"}
                        or not isinstance(args.get("files"), list) or not args["files"]
                        or any(not isinstance(path, str) or len(path) > 4096 or "\x00" in path
                               for path in args["files"])):
                    raise ImportInvalid("MosDNS domain_set args are invalid")
            elif typ == "ip_set":
                if (not isinstance(args, dict) or set(args) != {"ips"}
                        or not isinstance(args.get("ips"), list) or not args["ips"]):
                    raise ImportInvalid("MosDNS ip_set args are invalid")
                try:
                    for value in args["ips"]:
                        if value != "__INTERNAL_CIDR__":
                            ipaddress.ip_network(value, strict=False)
                except (TypeError, ValueError) as exc:
                    raise ImportInvalid("MosDNS client network is invalid") from exc
            elif typ == "ecs_handler":
                if (not isinstance(args, dict)
                        or set(args) != {"forward", "send", "preset", "mask4", "mask6"}
                        or type(args.get("forward")) is not bool
                        or type(args.get("send")) is not bool
                        or type(args.get("mask4")) is not int or not 0 <= args["mask4"] <= 32
                        or type(args.get("mask6")) is not int or not 0 <= args["mask6"] <= 128):
                    raise ImportInvalid("MosDNS ECS args are invalid")
                try:
                    ipaddress.ip_address(args.get("preset"))
                except (TypeError, ValueError) as exc:
                    raise ImportInvalid("MosDNS ECS preset is invalid") from exc
            elif typ == "rate_limiter":
                if (not isinstance(args, dict)
                        or set(args) != {"qps", "burst", "mask4", "mask6"}
                        or any(type(args.get(key)) is not int for key in args)
                        or not 1 <= args["qps"] <= 100000
                        or not args["qps"] <= args["burst"] <= 200000
                        or not 0 <= args["mask4"] <= 32 or not 0 <= args["mask6"] <= 128):
                    raise ImportInvalid("MosDNS rate limiter args are invalid")
            elif typ == "cache":
                size = args.get("size") if isinstance(args, dict) else None
                if (not isinstance(args, dict) or set(args) != {"size", "lazy_cache_ttl"}
                        or not (size == "__MOSDNS_CACHE__" or type(size) is int
                                and 128 <= size <= 1048576)
                        or type(args.get("lazy_cache_ttl")) is not int
                        or not 60 <= args["lazy_cache_ttl"] <= 604800):
                    raise ImportInvalid("MosDNS cache args are invalid")
            elif typ in {"udp_server", "tcp_server"}:
                expected_keys = ({"entry", "listen", "cert", "key"}
                                 if tag == "dot_server" else {"entry", "listen"})
                if (not isinstance(args, dict) or set(args) != expected_keys
                        or args.get("entry") != "main_sequence"
                        or not isinstance(args.get("listen"), str)
                        or tag == "dot_server" and (
                            not isinstance(args.get("cert"), str)
                            or not isinstance(args.get("key"), str))):
                    raise ImportInvalid("MosDNS listener args are invalid")
            elif typ == "sequence" and not isinstance(args, list):
                raise ImportInvalid("MosDNS sequence args are invalid")
        return graph_plugins, graph

    plugins, by_tag = checked_graph(doc)
    _current_plugins, current_by_tag = checked_graph(current)
    expected_rule_files = {
        "geosite_unlock": ["unlock.txt"],
        "geosite_cn": [
            "geosite_cn.txt", "geosite_apple.txt", "custom_direct.txt",
            "ruleset_direct.txt",
        ],
        "explicit_hijack": ["custom_hijack.txt", "ruleset_hijack.txt"],
        "force_hijack": ["mitm_hijack.txt"],
    }
    for tag, plugin in current_by_tag.items():
        if plugin["type"] != "domain_set":
            continue
        paths = plugin["args"]["files"]
        pure_paths = [pathlib.PurePosixPath(path) for path in paths]
        expected_rule_root = pathlib.Path(MOSDNS_RULE_DIR).as_posix()
        if any(path.parent.as_posix() != expected_rule_root for path in pure_paths):
            raise ImportInvalid("current managed MosDNS rule path is invalid")
        leaves = [path.name for path in pure_paths]
        if tag == "hijack_set":
            if (len(leaves) != 2 or leaves[1] != "custom_hijack.txt"
                    or leaves[0] not in {
                        "geosite_geolocation-!cn.txt", "geosite_gfw.txt",
                        "ruleset_hijack.txt",
                    }):
                raise ImportInvalid("current managed MosDNS rule path is invalid")
        elif leaves != expected_rule_files.get(tag):
            raise ImportInvalid("current managed MosDNS rule path is invalid")
    expected_listeners = {
        "udp_server": "0.0.0.0:53",
        "tcp_server": "0.0.0.0:53",
        "dot_server": "0.0.0.0:853",
    }
    for tag, expected_listen in expected_listeners.items():
        if current_by_tag[tag]["args"]["listen"] != expected_listen:
            raise ImportInvalid("current managed MosDNS listener is invalid")
    current_dot_args = current_by_tag["dot_server"]["args"]
    cert, key = current_dot_args["cert"], current_dot_args["key"]
    expected_cert_root = pathlib.PurePosixPath(pathlib.Path(MOSDNS_CERT_DIR).as_posix())
    if (pathlib.PurePosixPath(cert) != expected_cert_root / "fullchain.pem"
            or pathlib.PurePosixPath(key) != expected_cert_root / "privkey.pem"):
        raise ImportInvalid("current managed MosDNS certificate paths are invalid")
    gfw_internal_sequence = [
        ("!$client_limiter", "reject 5"), (None, "$lazy_cache"),
        (None, "jump has_resp"), ("qname $force_hijack", "goto force_hijack_seq"),
        ("qname $explicit_hijack", "goto force_hijack_seq"),
        ("qname $geosite_cn", "$ecs_china"),
        ("qname $geosite_cn", "$local_upstream"),
        (None, "jump has_resp"), ("!qname $hijack_set", "$ecs_neutral"),
        ("!qname $hijack_set", "$remote_upstream"),
        (None, "jump has_resp"), ("qtype 28", "reject 0"),
        ("qtype 65", "reject 0"), (None, "jump has_resp"),
        ("qtype 1", "black_hole "), (None, "jump has_resp"),
        (None, "$ecs_neutral"), (None, "$remote_upstream"),
    ]
    # ``lib/mosdns.sh::_mosdns_hijack_shape`` is the runtime source of truth:
    # all mode removes exactly these two negative-hijack gates, while gfw mode
    # installs them at this precise priority.  Both are managed production
    # shapes; no other deletion, insertion or reordering is accepted.
    all_internal_sequence = (
        gfw_internal_sequence[:8] + gfw_internal_sequence[10:])
    expected_sequences = {
        "force_hijack_seq": [
            [("qtype 28", "reject 0"), ("qtype 65", "reject 0"),
             (None, "jump has_resp"), ("qtype 1", "black_hole ")],
        ],
        "internal_sequence": [gfw_internal_sequence, all_internal_sequence],
        "main_sequence": [
            [("client_ip $npn_clients", "goto internal_sequence"),
             ("qname $geosite_unlock", "$unlock_upstream"),
             (None, "jump has_resp"), (None, "$remote_upstream")],
        ],
    }

    def sequence_error(args: Any, expected: list[tuple[str | None, str]]) -> str | None:
        if not isinstance(args, list) or len(args) != len(expected):
            return "MosDNS managed sequence shape is invalid"
        for item, (matches, execution) in zip(args, expected):
            if not isinstance(item, dict) or set(item) - {"matches", "exec"}:
                return "MosDNS managed sequence entry is invalid"
            if matches is None:
                if "matches" in item:
                    return "MosDNS managed sequence order is invalid"
            elif item.get("matches") != matches:
                return "MosDNS managed sequence order is invalid"
            actual = item.get("exec")
            if not isinstance(actual, str) or not (
                    actual.startswith(execution) if execution == "black_hole "
                    else actual == execution):
                return "MosDNS managed sequence order is invalid"
        return None

    def validate_managed_sequences(graph: dict[str, dict[str, Any]]) -> None:
        for tag, variants in expected_sequences.items():
            args = graph[tag].get("args")
            errors = [sequence_error(args, expected) for expected in variants]
            if all(error is not None for error in errors):
                # Prefer the more specific diagnostic from a same-length
                # managed variant; otherwise every sanctioned variant
                # rejected the shape.
                specific = next((
                    error for error, expected in zip(errors, variants)
                    if isinstance(args, list) and len(args) == len(expected)
                ), None)
                raise ImportInvalid(
                    specific or "MosDNS managed sequence shape is invalid")
        if graph["has_resp"].get("args") != [
                {"matches": "has_resp", "exec": "accept"}]:
            raise ImportInvalid("MosDNS has_resp sequence is invalid")

    validate_managed_sequences(by_tag)
    if current:
        # The current sequence is copied below to preserve the PDG profile's
        # hijack mode.  Prove it is a sanctioned managed shape first rather
        # than trusting live YAML merely because its tag inventory is valid.
        validate_managed_sequences(current_by_tag)
    # Every explicit plugin reference must resolve inside this graph.  This
    # catches typos before the expensive isolated mosdns probe.
    references = re.compile(r"(?:^|\s)\$([A-Za-z0-9_.-]+)|(?:jump|goto)\s+([A-Za-z0-9_.-]+)")
    for plugin in plugins:
        args = plugin.get("args")
        items = args if isinstance(args, list) else []
        for item in items:
            if not isinstance(item, dict):
                continue
            for field in ("matches", "exec"):
                value = item.get(field)
                if not isinstance(value, str):
                    continue
                for match in references.finditer(value):
                    target = match.group(1) or match.group(2)
                    if target not in by_tag:
                        raise ImportInvalid("MosDNS sequence has an unresolved plugin reference")
    if current:
        # Hijack mode lives in PDG's profile and is changed through its own
        # transaction.  Importing MosDNS must not silently switch that mode or
        # leave profile/config inconsistent.  Both sides were independently
        # proven to be one of the two exact managed shapes above.
        by_tag["internal_sequence"]["args"] = copy.deepcopy(
            current_by_tag["internal_sequence"]["args"])
        npn = (current_by_tag.get("npn_clients") or {}).get("args")
        if isinstance(npn, dict) and isinstance(npn.get("ips"), list):
            by_tag["npn_clients"].setdefault("args", {})["ips"] = copy.deepcopy(npn["ips"])
        current_dot = (current_by_tag.get("dot_server") or {}).get("args")
        if isinstance(current_dot, dict):
            for field in ("cert", "key"):
                if isinstance(current_dot.get(field), str):
                    by_tag["dot_server"]["args"][field] = current_dot[field]
        for tag in ("udp_server", "tcp_server", "dot_server"):
            by_tag[tag]["args"]["listen"] = current_by_tag[tag]["args"]["listen"]
        # Rule files are PDG transaction outputs, not portable user identity.
        # Bind every managed domain_set to the exact current paths.
        for tag, live in current_by_tag.items():
            live_args = live.get("args") if isinstance(live, dict) else None
            incoming_args = by_tag[tag].get("args")
            if (live.get("type") == "domain_set" and isinstance(live_args, dict)
                    and isinstance(live_args.get("files"), list)
                    and isinstance(incoming_args, dict)):
                incoming_args["files"] = copy.deepcopy(live_args["files"])
        live_cache = (current_by_tag.get("lazy_cache") or {}).get("args")
        incoming_cache = (by_tag.get("lazy_cache") or {}).get("args")
        if (isinstance(live_cache, dict) and isinstance(live_cache.get("size"), int)
                and isinstance(incoming_cache, dict)):
            incoming_cache["size"] = live_cache["size"]
        old_ips = set()
        for plugin in current.get("plugins", []):
            if isinstance(plugin, dict) and plugin.get("type") == "sequence":
                for item in plugin.get("args") or []:
                    if isinstance(item, dict) and isinstance(item.get("exec"), str):
                        match = re.fullmatch(r"black_hole ([0-9a-fA-F:.]+)", item["exec"])
                        if match:
                            old_ips.add(match.group(1))
        if len(old_ips) != 1:
            raise ImportInvalid("current managed MosDNS server identity is invalid")
        server_ip = next(iter(old_ips))
        try:
            ipaddress.ip_address(server_ip)
        except ValueError as exc:
            raise ImportInvalid("current managed MosDNS server identity is invalid") from exc
        for plugin in plugins:
            if plugin.get("type") == "sequence":
                for item in plugin.get("args") or []:
                    if isinstance(item, dict) and isinstance(item.get("exec"), str) and (
                            item["exec"].startswith("black_hole ")):
                        item["exec"] = "black_hole " + server_ip
    placeholder = re.compile(r"__[A-Z0-9_]+__")

    def reject_placeholders(value):
        if isinstance(value, str) and placeholder.search(value):
            raise ImportInvalid("MosDNS configuration contains an unresolved placeholder")
        if isinstance(value, dict):
            for child in value.values():
                reject_placeholders(child)
        elif isinstance(value, list):
            for child in value:
                reject_placeholders(child)

    reject_placeholders(doc)
    return doc


def _read_optional_yaml(path: str) -> dict[str, Any] | None:
    try:
        data = pathlib.Path(path).read_bytes()
    except OSError:
        return None
    try:
        return _safe_yaml_load(data)
    except ConfigIOError:
        return None


def _ruleset_names(data: bytes, *, source: str) -> set[str]:
    if not isinstance(data, bytes) or not data or len(data) > MAX_ARCHIVE_FILE:
        raise ImportInvalid(source + " PDG ruleset metadata is too large or empty")
    doc = _strict_json(data)
    if not isinstance(doc, dict) or any(
            not _valid_name(name) for name in doc):
        raise ImportInvalid(source + " PDG ruleset metadata is invalid")
    names = set(doc)
    reserved = sorted(names & _reserved_targets())
    if reserved:
        raise ImportInvalid(
            source + " PDG ruleset metadata uses a reserved Mihomo target: "
            + ", ".join(reserved))
    return names


def _current_ruleset_names() -> set[str]:
    try:
        with open(RULESET_META_PATH, "rb") as stream:
            data = stream.read(MAX_ARCHIVE_FILE + 1)
    except FileNotFoundError:
        return set()
    except OSError as exc:
        raise ImportInvalid("current PDG ruleset metadata is unavailable") from exc
    return _ruleset_names(data, source="current")


def _model_bytes(model: dict[str, Any]) -> bytes:
    return json.dumps(model, ensure_ascii=False, indent=2).encode("utf-8") + b"\n"


def _restore_bundle(
        payload: bytes, model: dict[str, Any], mode: str,
        resolutions: dict[str, str], mosdns_override: bytes | None = None) -> bytes:
    files = _archive_files(payload, total_limit=MAX_LEGACY_PDG_TOTAL)
    if files is None:
        files = {}
    files = dict(files)
    source_v2 = "manifest.json" in files
    incoming_direct_tag = None
    for name, data in files.items():
        if name in {"model.json", "config.json", "etc/sing-box/config.json"} \
                or name.endswith("/etc/sing-box/config.json"):
            try:
                incoming_direct_tag = _single_direct(
                    normalize_model(_strict_json(data)), "incoming")[1]
            except Exception:
                # The preview path already validated the selected model.  If a
                # legacy archive has several candidate names, only the chosen
                # valid one contributes a direct identity.
                continue
            break
    files.pop("manifest.json", None)
    files.pop("model.json", None)
    files.pop("config.json", None)
    for name in list(files):
        if (name.endswith("/etc/sing-box/config.json")
                or name.startswith("etc/mihomo/providers/")):
            files.pop(name)
    if mode == "merge":
        if resolutions.get("component:mosdns", "existing") == "existing":
            for name in list(files):
                if name == "etc/mosdns/config.yaml" or name.startswith("etc/mosdns/rules/"):
                    files.pop(name)
        if resolutions.get("component:rulesets", "existing") == "existing":
            for name in list(files):
                if name == "opt/pdg-bot/rulesets.json" or name.startswith("etc/sing-box/rs/"):
                    files.pop(name)
    if mosdns_override is not None and (mode == "replace" or resolutions.get(
            "component:mosdns", "existing") == "incoming"):
        files["etc/mosdns/config.yaml"] = mosdns_override
    final_direct_tag = _single_direct(model, "result")[1]
    ruleset_meta_name = "opt/pdg-bot/rulesets.json"
    if (ruleset_meta_name in files and incoming_direct_tag
            and incoming_direct_tag != final_direct_tag):
        try:
            ruleset_meta = _strict_json(files[ruleset_meta_name])
            if not isinstance(ruleset_meta, dict):
                raise ValueError("not an object")
            for item in ruleset_meta.values():
                if isinstance(item, dict) and item.get("outbound") == incoming_direct_tag:
                    item["outbound"] = final_direct_tag
            files[ruleset_meta_name] = json.dumps(
                ruleset_meta, ensure_ascii=False, indent=2).encode("utf-8")
        except Exception as exc:
            raise ImportInvalid(
                "ruleset metadata cannot be rebound to the current direct tag") from exc
    for leaf, encoded in model["_pdg"]["mihomo"]["managed-files"].items():
        files["etc/mihomo/providers/" + leaf] = base64.b64decode(
            encoded, validate=True)
    files["etc/sing-box/config.json"] = _model_bytes(model)
    expanded = sum(len(data) for data in files.values())
    # A historical 32--64 MiB archive stays legacy on the internal restore
    # path; labelling it v2 would falsely promise that it fits the fixed v2 Web
    # envelope.  Smaller legacy packages are upgraded to the strict manifest.
    if source_v2 or expanded <= MAX_ARCHIVE_TOTAL:
        manifest = {
            "version": 2,
            "createdAt": dt.datetime.now(dt.timezone.utc).replace(
                microsecond=0).isoformat().replace("+00:00", "Z"),
            "files": [{"path": name, "size": len(data), "sha256": _sha(data)}
                      for name, data in sorted(files.items())],
        }
        files["manifest.json"] = json.dumps(
            manifest, ensure_ascii=True, sort_keys=True, indent=2).encode("utf-8") + b"\n"
    total_limit = MAX_ARCHIVE_TOTAL if "manifest.json" in files else MAX_LEGACY_PDG_TOTAL
    if (len(files) > MAX_ARCHIVE_FILES
            or any(len(data) > _archive_member_limit(name)
                   for name, data in files.items())
            or sum(len(data) for data in files.values()) > total_limit):
        raise ImportInvalid("resulting PDG bundle exceeds the restorable limits")
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w:gz") as archive:
        for name, data in sorted(files.items()):
            info = tarfile.TarInfo(name)
            info.size = len(data)
            info.mode = 0o600
            archive.addfile(info, io.BytesIO(data))
    result = stream.getvalue()
    if len(result) > (MAX_UPLOAD if "manifest.json" in files else MAX_LEGACY_PDG_UPLOAD):
        raise ImportInvalid("resulting PDG bundle exceeds the upload limit")
    return result


def _single_direct(model: dict[str, Any], label: str) -> tuple[dict[str, Any], str]:
    direct = [item for item in model.get("outbounds", [])
              if isinstance(item, dict) and item.get("type") == "direct"]
    if (len(direct) != 1 or not isinstance(direct[0].get("tag"), str)
            or not _MACHINE_TAG_RE.fullmatch(direct[0]["tag"])):
        raise ImportInvalid(
            label + " PDG model must contain exactly one valid direct outbound")
    return direct[0], direct[0]["tag"]


def _rebind_incoming_direct(
        current: dict[str, Any], incoming: dict[str, Any]) -> dict[str, Any]:
    """Bind a portable/legacy package's direct references to this machine."""
    _current_direct, current_tag = _single_direct(current, "current")
    incoming_direct, incoming_tag = _single_direct(incoming, "incoming")
    if incoming_tag == current_tag:
        return incoming
    if any(isinstance(item, dict) and item is not incoming_direct
           and item.get("tag") == current_tag for item in incoming["outbounds"]):
        raise ImportInvalid("incoming model collides with the current direct tag")

    try:
        result = _pdgmodel().rebind_direct(incoming, current_tag)
    except (TypeError, ValueError) as exc:
        raise ImportInvalid("incoming direct tag cannot be rebound: " + str(exc)) from exc
    return normalize_model(result)


def _model_name_occupancy(model: dict[str, Any]) -> set[str]:
    names = {
        item.get("tag") for item in model.get("outbounds", [])
        if isinstance(item, dict) and item.get("type") != "direct"
        and isinstance(item.get("tag"), str)
    }
    metadata = model.get("_pdg") or {}
    names.update(
        group.get("name") for group in metadata.get("policy-groups") or []
        if isinstance(group, dict) and isinstance(group.get("name"), str))
    return names


def _ordered_model_names(model: dict[str, Any]) -> list[str]:
    ordered: list[str] = []
    seen: set[str] = set()
    for item in model.get("outbounds", []):
        name = item.get("tag") if isinstance(item, dict) else None
        if (item.get("type") != "direct" if isinstance(item, dict) else False) \
                and isinstance(name, str) and name not in seen:
            seen.add(name)
            ordered.append(name)
    metadata = model.get("_pdg") or {}
    for group in metadata.get("policy-groups") or []:
        name = group.get("name") if isinstance(group, dict) else None
        if isinstance(name, str) and name not in seen:
            seen.add(name)
            ordered.append(name)
    return ordered


def _merge_model(
        current: dict[str, Any], incoming: dict[str, Any], mode: str,
        resolutions: dict[str, str]) -> dict[str, Any]:
    current = normalize_model(current)
    incoming = normalize_model(incoming)
    incoming = _rebind_incoming_direct(current, incoming)
    if mode == "replace":
        result = copy.deepcopy(current)
        machine_direct, _direct_tag = _single_direct(current, "current")
        result["outbounds"] = [copy.deepcopy(machine_direct)] + [
            copy.deepcopy(item) for item in incoming["outbounds"]
            if isinstance(item, dict) and item.get("type") != "direct"]
        result["route"] = copy.deepcopy(incoming["route"])
        result["_pdg"]["policy-groups"] = copy.deepcopy(
            incoming["_pdg"]["policy-groups"])
        result["_pdg"]["mihomo"] = copy.deepcopy(incoming["_pdg"]["mihomo"])
        return _prune_managed_files(result)
    result = copy.deepcopy(current)
    current_names = _model_name_occupancy(current)
    incoming_names = _model_name_occupancy(incoming)
    incoming_outbounds = {
        item.get("tag"): item for item in incoming["outbounds"]
        if isinstance(item, dict) and item.get("type") != "direct"
        and isinstance(item.get("tag"), str)
    }
    incoming_groups = {
        group.get("name"): group
        for group in incoming["_pdg"]["policy-groups"]
        if isinstance(group, dict) and isinstance(group.get("name"), str)
    }
    cur_ext = result["_pdg"]["mihomo"]
    for name in _ordered_model_names(incoming):
        choice = resolutions.get("name:" + name, "incoming")
        if name in current_names and name in incoming_names and choice == "existing":
            continue
        # One name is one logical slot.  Replacing it removes both possible
        # representations before installing the incoming pair, so an ordinary
        # proxy and an editable or metadata-only group cannot drift apart.
        result["outbounds"] = [
            item for item in result["outbounds"]
            if not (isinstance(item, dict) and item.get("type") != "direct"
                    and item.get("tag") == name)]
        result["_pdg"]["policy-groups"] = [
            group for group in result["_pdg"]["policy-groups"]
            if not (isinstance(group, dict) and group.get("name") == name)]
        if name in incoming_outbounds:
            result["outbounds"].append(copy.deepcopy(incoming_outbounds[name]))
        if name in incoming_groups:
            result["_pdg"]["policy-groups"].append(
                copy.deepcopy(incoming_groups[name]))
    result["route"]["rules"] = copy.deepcopy(incoming["route"].get("rules") or []) + copy.deepcopy(
        result["route"].get("rules") or [])
    if incoming["route"].get("final"):
        result["route"]["final"] = incoming["route"]["final"]
    inc_ext = incoming["_pdg"]["mihomo"]
    for name, provider in inc_ext["proxy-providers"].items():
        if (name not in cur_ext["proxy-providers"] or resolutions.get(
                "proxy-provider:" + name, "incoming") == "incoming"):
            cur_ext["proxy-providers"][name] = copy.deepcopy(provider)
    for name, provider in inc_ext["rule-providers"].items():
        if (name not in cur_ext["rule-providers"] or resolutions.get(
                "rule-provider:" + name, "incoming") == "incoming"):
            cur_ext["rule-providers"][name] = copy.deepcopy(provider)
    cur_ext["managed-files"].update(copy.deepcopy(inc_ext["managed-files"]))
    cur_ext["advanced"].update(copy.deepcopy(inc_ext["advanced"]))
    return _prune_managed_files(result)


def _prune_managed_files(model: dict[str, Any]) -> dict[str, Any]:
    metadata = model["_pdg"]["mihomo"]
    needed = set()
    for field in ("proxy-providers", "rule-providers"):
        for provider in metadata[field].values():
            if isinstance(provider, dict) and provider.get("type", "http") == "file":
                path = provider.get("path", "")
                match = re.fullmatch(
                    r"/etc/mihomo/providers/([a-f0-9]{64}\.(?:ya?ml|json|txt|mrs))",
                    path, re.I)
                if not match or match.group(1) not in metadata["managed-files"]:
                    raise ImportInvalid("merged model references a missing managed provider file")
                needed.add(match.group(1))
    metadata["managed-files"] = {
        leaf: encoded for leaf, encoded in metadata["managed-files"].items() if leaf in needed
    }
    return normalize_model(model)


class ConfigIO:
    def __init__(self, *, bot=None, staging_dir: str = STAGING_DIR,
                 enforce_root_owner: bool = True,
                 janitor_interval: float | None = None, clock=None):
        self.bot = bot
        self.staging_dir = os.path.abspath(staging_dir)
        self.enforce_root_owner = bool(enforce_root_owner)
        self._clock = clock if callable(clock) else time.time
        self._gc_lock = threading.Lock()
        self._janitor_stop = threading.Event()
        self._janitor_thread: threading.Thread | None = None
        # Parsing retains the bounded upload, extracted members and preview
        # record briefly at once.  A single slot keeps that worst case within
        # the 512 MiB production profile instead of multiplying it per worker.
        self._preview_slots = threading.BoundedSemaphore(1)
        self._ensure_stage_dir()
        interval = (60.0 if janitor_interval is None and self.enforce_root_owner
                    else janitor_interval)
        if interval is not None:
            if not isinstance(interval, (int, float)) or not 0.01 <= interval <= 3600:
                raise ConfigIOError("invalid import janitor interval")
            self._janitor_thread = threading.Thread(
                target=self._janitor_loop, args=(float(interval),),
                name="pdg-config-import-janitor", daemon=True)
            self._janitor_thread.start()

    def _janitor_loop(self, interval: float) -> None:
        while not self._janitor_stop.wait(interval):
            try:
                self._gc()
            except Exception:
                # The next preview also performs synchronous GC.  A damaged
                # root-only staging directory must not terminate the daemon.
                pass

    def close(self) -> None:
        self._janitor_stop.set()
        thread = self._janitor_thread
        if thread is not None and thread is not threading.current_thread():
            thread.join(timeout=2)
        self._janitor_thread = None

    def _ensure_stage_dir(self) -> None:
        try:
            before = os.lstat(self.staging_dir)
        except FileNotFoundError:
            before = None
        if before is not None and (not stat.S_ISDIR(before.st_mode) or stat.S_ISLNK(before.st_mode)):
            raise ConfigIOError("invalid import staging directory")
        os.makedirs(self.staging_dir, mode=0o700, exist_ok=True)
        info = os.lstat(self.staging_dir)
        if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode):
            raise ConfigIOError("invalid import staging directory")
        if os.name != "nt" and self.enforce_root_owner and info.st_uid != 0:
            raise ConfigIOError("import staging directory is not root-owned")
        os.chmod(self.staging_dir, 0o700)
        self._gc()

    def _path(self, import_id: str, suffix: str) -> str:
        if not isinstance(import_id, str) or not _IMPORT_ID_RE.fullmatch(import_id):
            raise ImportNotFound("preview not found")
        return os.path.join(self.staging_dir, import_id + suffix)

    def _safe_unlink(self, path: str) -> None:
        try:
            info = os.lstat(path)
            if stat.S_ISREG(info.st_mode) and not stat.S_ISLNK(info.st_mode) and info.st_nlink == 1:
                os.unlink(path)
        except FileNotFoundError:
            pass

    def _read_regular(self, path: str, maximum: int) -> bytes:
        flags = (os.O_RDONLY | getattr(os, "O_BINARY", 0)
                 | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0))
        fd = os.open(path, flags)
        try:
            info = os.fstat(fd)
            if (not stat.S_ISREG(info.st_mode)
                    or (os.name != "nt" and info.st_nlink != 1)
                    or not 0 < info.st_size <= maximum
                    or (os.name != "nt" and self.enforce_root_owner and info.st_uid != 0)
                    or (os.name != "nt" and info.st_mode & (
                        stat.S_IWGRP | stat.S_IWOTH))):
                raise ImportNotFound("staged file is not trusted")
            chunks = []
            remaining = info.st_size
            while remaining:
                chunk = os.read(fd, min(64 * 1024, remaining))
                if not chunk:
                    raise ImportNotFound("staged file is incomplete")
                chunks.append(chunk)
                remaining -= len(chunk)
            return b"".join(chunks)
        finally:
            os.close(fd)

    def _gc(self) -> None:
        with self._gc_lock:
            now = self._clock()
            cutoff = now - PREVIEW_TTL
            try:
                names = os.listdir(self.staging_dir)
            except OSError:
                return
            ids = {name.rsplit(".", 1)[0] for name in names
                   if name.endswith((".json", ".upload", ".claim"))}
            for import_id in ids:
                if not _IMPORT_ID_RE.fullmatch(import_id):
                    continue
                json_path = self._path(import_id, ".json")
                upload_path = self._path(import_id, ".upload")
                claim_path = self._path(import_id, ".claim")
                data_paths = [json_path, upload_path]
                try:
                    newest = max(os.lstat(path).st_mtime for path in data_paths
                                 if os.path.lexists(path))
                except (OSError, ValueError):
                    newest = 0
                if newest >= cutoff:
                    continue
                # Claim the import id before inspecting/deleting.  prepare,
                # apply and cancel use the same O_EXCL state transition, so GC
                # cannot remove a record while another thread is claiming it.
                stale_claim = None
                try:
                    self._create_exclusive(claim_path, b"gc")
                except FileExistsError:
                    # A queued/running import owns its claim during the bounded
                    # job window.  After the protection window an orphaned
                    # claim must not pin credentials forever.  Rename first,
                    # then O_EXCL-create our own claim: a concurrent claimant
                    # wins the gap and makes this GC pass back off safely.
                    try:
                        claim_info = os.lstat(claim_path)
                        if (not stat.S_ISREG(claim_info.st_mode)
                                or stat.S_ISLNK(claim_info.st_mode)
                                or (os.name != "nt" and claim_info.st_nlink != 1)
                                or now - claim_info.st_mtime < CLAIM_PROTECTION_TTL):
                            continue
                        stale_claim = claim_path + ".stale-" + secrets.token_hex(8)
                        os.replace(claim_path, stale_claim)
                        self._create_exclusive(claim_path, b"gc")
                    except (FileExistsError, FileNotFoundError, OSError):
                        if stale_claim:
                            self._safe_unlink(stale_claim)
                        continue
                    self._safe_unlink(stale_claim)
                protected = False
                try:
                    try:
                        record = _strict_json(self._read_regular(
                            json_path, MAX_RECORD_BYTES))
                        apply = record.get("apply") if isinstance(record, dict) else None
                        protected = (isinstance(apply, dict)
                                     and apply.get("claimed") is True
                                     and isinstance(apply.get("claimedAt"), (int, float))
                                     and now - apply["claimedAt"] < CLAIM_PROTECTION_TTL)
                    except Exception:
                        pass
                    if not protected:
                        self._safe_unlink(json_path)
                        self._safe_unlink(upload_path)
                finally:
                    self._safe_unlink(claim_path)

    @staticmethod
    def _write_file(path: str, data: bytes) -> None:
        directory = os.path.dirname(path)
        fd, temporary = tempfile.mkstemp(prefix=".pdg-import.", dir=directory)
        try:
            if hasattr(os, "fchmod"):
                os.fchmod(fd, 0o600)
            else:  # pragma: no cover - Windows contract tests
                os.chmod(temporary, 0o600)
            with os.fdopen(fd, "wb") as stream:
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, path)
        finally:
            try:
                os.unlink(temporary)
            except FileNotFoundError:
                pass

    def _create_exclusive(self, path: str, data: bytes = b"") -> None:
        flags = (os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
                 | getattr(os, "O_CLOEXEC", 0))
        flags |= getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(path, flags, 0o600)
        try:
            if hasattr(os, "fchmod"):
                os.fchmod(fd, 0o600)
            else:  # pragma: no cover - Windows contract tests
                os.chmod(path, 0o600)
            if os.name != "nt" and self.enforce_root_owner:
                os.fchown(fd, 0, 0)
            if data:
                view = memoryview(data)
                while view:
                    written = os.write(fd, view)
                    if written <= 0:
                        raise ConfigIOError("cannot create staged file")
                    view = view[written:]
            os.fsync(fd)
        finally:
            os.close(fd)

    def _load_bot(self):
        if self.bot is not None:
            return self.bot
        path = BOT_PATH
        if not os.path.isfile(path):
            fallback = os.path.abspath(os.path.join(
                os.path.dirname(__file__), "..", "bot", "pdg-bot.py"))
            path = fallback
        spec = importlib.util.spec_from_file_location("_pdg_config_io_bot", path)
        if spec is None or spec.loader is None:
            raise ConfigIOError("PDG transaction backend is unavailable")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        self.bot = module
        return module

    def _current_model(self) -> dict[str, Any]:
        if self.bot is not None:
            try:
                return normalize_model(self.bot.load())
            except Exception as exc:
                raise ConfigIOError("current model is unavailable") from exc
        try:
            return normalize_model(_strict_json(pathlib.Path(MODEL_PATH).read_bytes()))
        except Exception:
            bot = self._load_bot()
            try:
                return normalize_model(bot.load())
            except Exception as exc:
                raise ConfigIOError("current model is unavailable") from exc

    @staticmethod
    def _raw_file_sha(path: str) -> str | None:
        flags = (os.O_RDONLY | getattr(os, "O_BINARY", 0)
                 | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0))
        try:
            fd = os.open(path, flags)
        except FileNotFoundError:
            return None
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                raise ImportConflict("managed configuration path is not a regular file")
            digest = hashlib.sha256()
            while True:
                chunk = os.read(fd, 64 * 1024)
                if not chunk:
                    break
                digest.update(chunk)
            return digest.hexdigest()
        finally:
            os.close(fd)

    @staticmethod
    def _read_managed_regular(path: str, maximum: int) -> bytes:
        flags = (os.O_RDONLY | getattr(os, "O_BINARY", 0)
                 | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0))
        fd = os.open(path, flags)
        try:
            before = os.fstat(fd)
            if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1
                    or not 0 < before.st_size <= maximum):
                raise ConfigIOError("configuration export is unavailable")
            chunks = []
            actual = 0
            while True:
                chunk = os.read(fd, min(64 * 1024, maximum + 1 - actual))
                if not chunk:
                    break
                actual += len(chunk)
                if actual > maximum:
                    raise ConfigIOError("configuration export is unavailable")
                chunks.append(chunk)
            after = os.fstat(fd)
            if (actual != before.st_size or before.st_ino != after.st_ino
                    or before.st_size != after.st_size
                    or before.st_mtime_ns != after.st_mtime_ns):
                raise ImportConflict("configuration changed during export")
            return b"".join(chunks)
        finally:
            os.close(fd)

    def _provider_baselines(self, leaves: set[str]) -> dict[str, str | None]:
        out = {}
        for leaf in sorted(leaves):
            if not re.fullmatch(r"[a-f0-9]{64}\.(?:ya?ml|json|txt|mrs)", leaf, re.I):
                raise ImportInvalid("managed provider file name is invalid")
            value = self._raw_file_sha(os.path.join(MIHOMO_PROVIDER_DIR, leaf))
            if value is not None and value != leaf.split(".", 1)[0]:
                raise ImportConflict("managed provider file integrity check failed")
            out[leaf] = value
        return out

    def _component_baselines(
            self, archive_files: dict[str, bytes]) -> dict[str, str | None]:
        targets = {
            "rs_meta": RULESET_META_PATH,
            "mosdns_rule:custom_direct.txt": os.path.join(
                MOSDNS_RULE_DIR, "custom_direct.txt"),
            "mosdns_rule:custom_hijack.txt": os.path.join(
                MOSDNS_RULE_DIR, "custom_hijack.txt"),
            "mosdns_rule:ruleset_direct.txt": os.path.join(
                MOSDNS_RULE_DIR, "ruleset_direct.txt"),
            "mosdns_rule:ruleset_hijack.txt": os.path.join(
                MOSDNS_RULE_DIR, "ruleset_hijack.txt"),
        }
        leaves = {
            name[len("etc/sing-box/rs/"):]
            for name in archive_files if name.startswith("etc/sing-box/rs/")
        }
        try:
            leaves.update(
                name for name in os.listdir(RULESET_DIR)
                if re.fullmatch(r"[A-Za-z0-9_.-]+\.(?:json|mrs)", name))
        except FileNotFoundError:
            pass
        except OSError as exc:
            raise ImportConflict("managed ruleset directory is unavailable") from exc
        try:
            current_meta = _strict_json(pathlib.Path(RULESET_META_PATH).read_bytes())
            if isinstance(current_meta, dict):
                for value in current_meta.values():
                    if isinstance(value, dict):
                        leaf = pathlib.PurePosixPath(str(value.get("path") or "")).name
                        if re.fullmatch(r"[A-Za-z0-9_.-]+\.(?:json|mrs)", leaf):
                            leaves.add(leaf)
        except FileNotFoundError:
            pass
        except Exception as exc:
            raise ImportConflict("managed ruleset metadata is unavailable") from exc
        for leaf in leaves:
            targets["ruleset:" + leaf] = os.path.join(RULESET_DIR, leaf)
        return {target: self._raw_file_sha(path) for target, path in sorted(targets.items())}

    def preview_stream(
            self, kind: str, stream, size: int,
            content_type: str = "") -> dict[str, Any]:
        if kind not in {"pdg", "mihomo", "mosdns"} or type(size) is not int or not (
                0 < size <= _upload_limit(kind)):
            raise ImportInvalid("upload is invalid")
        # Claim a parser/upload slot before creating a staging file or reading
        # the request body.  ThreadingHTTPServer must not permit an unbounded
        # number of concurrent bounded disk writes ahead of the parser gate.
        if not self._preview_slots.acquire(blocking=False):
            raise ConfigIOError("too many import previews")
        try:
            self._gc()
            import_id = "imp-" + secrets.token_hex(16)
            upload_path = self._path(import_id, ".upload")
            flags = (os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
                     | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0))
            fd = os.open(upload_path, flags, 0o600)
            digest = hashlib.sha256()
            received = 0
            try:
                if hasattr(os, "fchmod"):
                    os.fchmod(fd, 0o600)
                else:  # pragma: no cover - Windows contract tests
                    os.chmod(upload_path, 0o600)
                if os.name != "nt" and self.enforce_root_owner:
                    os.fchown(fd, 0, 0)
                while received < size:
                    chunk = stream.read(min(64 * 1024, size - received))
                    if not chunk:
                        raise ImportInvalid("upload is incomplete")
                    if not isinstance(chunk, bytes):
                        raise ImportInvalid("upload stream is invalid")
                    view = memoryview(chunk)
                    while view:
                        written = os.write(fd, view)
                        if written <= 0:
                            raise ConfigIOError("cannot stage upload")
                        view = view[written:]
                    digest.update(chunk)
                    received += len(chunk)
                os.fsync(fd)
            except Exception:
                os.close(fd)
                self._safe_unlink(upload_path)
                raise
            else:
                os.close(fd)
            payload = self._read_regular(upload_path, _upload_limit(kind))
            if len(payload) != size or _sha(payload) != digest.hexdigest():
                raise ImportConflict("staged upload integrity check failed")
            return self._preview_payload(
                kind, payload, content_type, import_id=import_id,
                upload_sha=digest.hexdigest(), upload_already=True)
        except Exception:
            if "upload_path" in locals():
                self._safe_unlink(upload_path)
            raise
        finally:
            self._preview_slots.release()

    def preview(self, kind: str, payload: bytes, content_type: str = "") -> dict[str, Any]:
        if not isinstance(payload, bytes):
            raise ImportInvalid("upload is invalid")
        self._gc()
        return self._preview_payload(kind, payload, content_type)

    def _preview_payload(
            self, kind: str, payload: bytes, content_type: str = "", *,
            import_id: str | None = None, upload_sha: str | None = None,
            upload_already: bool = False) -> dict[str, Any]:
        if kind not in {"pdg", "mihomo", "mosdns"} or not isinstance(payload, bytes) or not (
                0 < len(payload) <= _upload_limit(kind)):
            raise ImportInvalid("upload is invalid")
        archive = _archive_files(
            payload, total_limit=(MAX_LEGACY_PDG_TOTAL
                                  if kind == "pdg" else MAX_ARCHIVE_TOTAL))
        if archive is None and len(payload) > (
                MAX_MODEL_FILE if kind == "pdg" else MAX_ARCHIVE_FILE):
            raise ImportInvalid("configuration file is too large")
        files = archive or {("model.json" if kind == "pdg" else "config.yaml"): payload}
        if kind == "mosdns" and archive is not None:
            raise ImportInvalid("MosDNS imports must be a single managed YAML file")
        if archive:
            _verify_manifest(files)
            if kind == "pdg":
                _verify_pdg_members(files)
                if ("manifest.json" in files and (
                        len(payload) > MAX_UPLOAD
                        or sum(len(data) for data in files.values()) > MAX_ARCHIVE_TOTAL)):
                    raise ImportInvalid("v2 PDG archive exceeds the standard Web envelope")
        name, config_data = _choose_config(files, kind)
        current = self._current_model()
        warnings: list[str] = []
        conflicts: list[dict[str, str]] = []
        candidate: dict[str, Any]
        if kind == "pdg":
            try:
                incoming = normalize_model(_strict_json(config_data))
            except ConfigIOError:
                raise
            except Exception as exc:
                raise ImportInvalid("PDG model JSON is invalid") from exc
            incoming = _rebind_incoming_direct(current, incoming)
            warnings.extend(_inactive_advanced_warnings(incoming))
            managed = incoming["_pdg"]["mihomo"]["managed-files"]
            archived_provider_leaves = {
                name[len("etc/mihomo/providers/"):]
                for name in files if name.startswith("etc/mihomo/providers/")
            } if archive else set()
            if managed and archive is None:
                raise ImportInvalid(
                    "PDG models with local providers require a complete archive")
            if archive and archived_provider_leaves != set(managed):
                raise ImportInvalid(
                    "PDG provider archive is not an exact model reference closure")
            for leaf in archived_provider_leaves:
                archived = files["etc/mihomo/providers/" + leaf]
                try:
                    expected = base64.b64decode(managed[leaf], validate=True)
                except Exception as exc:
                    raise ImportInvalid("PDG managed provider content is invalid") from exc
                if archived != expected:
                    raise ImportInvalid("PDG managed provider content does not match the model")
            incoming_ruleset_meta = files.get("opt/pdg-bot/rulesets.json")
            incoming_ruleset_names: set[str] = set()
            if incoming_ruleset_meta is not None:
                incoming_ruleset_names = _ruleset_names(
                    incoming_ruleset_meta, source="imported")
                try:
                    _pdgmodel().validate_ruleset_namespace(
                        incoming, incoming_ruleset_names)
                except (TypeError, ValueError) as exc:
                    raise ImportInvalid(
                        "imported PDG ruleset namespace is invalid: "
                        + str(exc)) from exc
            conflicts = [
                {"name": item, "kind": "name", "default": "incoming"}
                for item in sorted(
                    _model_name_occupancy(current) & _model_name_occupancy(incoming))]
            cur_ext = current["_pdg"]["mihomo"]
            inc_ext = incoming["_pdg"]["mihomo"]
            for provider_kind, field in (("proxy-provider", "proxy-providers"),
                                         ("rule-provider", "rule-providers")):
                conflicts.extend(
                    {"name": item, "kind": provider_kind, "default": "incoming"}
                    for item in sorted(set(cur_ext[field]) & set(inc_ext[field])))
            if archive and any(name == "etc/mosdns/config.yaml" or name.startswith(
                    "etc/mosdns/rules/") for name in files):
                conflicts.append({"name": "mosdns", "kind": "component", "default": "existing"})
            if archive and any(name == "opt/pdg-bot/rulesets.json" or name.startswith(
                    "etc/sing-box/rs/") for name in files):
                conflicts.append({"name": "rulesets", "kind": "component", "default": "existing"})
            candidate = {"model": incoming}
            rule_provider_names = set(
                incoming["_pdg"]["mihomo"]["rule-providers"])
            # Preview precedes the merge/replace and component choices.  Keep
            # both namespace checks in the root-only staged record, then make
            # prepare_apply reject the selected unsafe state before a durable
            # job can start.  This permits a safe merge that keeps live
            # rulesets even when an unused incoming metadata file collides.
            existing_ruleset_names = _current_ruleset_names()
            candidate["rulesetCollisions"] = {
                "incomingPresent": incoming_ruleset_meta is not None,
                "incoming": sorted(rule_provider_names & incoming_ruleset_names),
                "existing": sorted(rule_provider_names & existing_ruleset_names),
                "incomingNames": sorted(incoming_ruleset_names),
                "existingNames": sorted(existing_ruleset_names),
            }
            incoming_mosdns = files.get("etc/mosdns/config.yaml")
            if incoming_mosdns is not None:
                current_mosdns = _read_optional_yaml(MOSDNS_PATH)
                if current_mosdns is None:
                    raise ImportInvalid("current managed MosDNS configuration is unavailable")
                managed_mosdns = _mosdns_contract(
                    _safe_yaml_load(incoming_mosdns), current_mosdns)
                candidate["mosdns"] = base64.b64encode(
                    _safe_yaml_dump(managed_mosdns)).decode("ascii")
            summary = {"outbounds": len(incoming["outbounds"]),
                       "rules": len(incoming["route"].get("rules") or []),
                       "managedFiles": len(incoming["_pdg"]["mihomo"]["managed-files"]),
                       "bundleMosdns": any(name == "etc/mosdns/config.yaml" for name in files),
                       "bundleRulesets": any(name == "opt/pdg-bot/rulesets.json" for name in files)}
        elif kind == "mihomo":
            doc = _safe_yaml_load(config_data)
            incoming, warnings = mihomo_to_model(
                doc, current, archive=archive, config_name=name)
            incoming = _rebind_incoming_direct(current, incoming)
            conflicts = [
                {"name": item, "kind": "name", "default": "incoming"}
                for item in sorted(
                    _model_name_occupancy(current) & _model_name_occupancy(incoming))]
            current_ext = current["_pdg"]["mihomo"]
            incoming_ext = incoming["_pdg"]["mihomo"]
            for provider_kind, field in (("proxy-provider", "proxy-providers"),
                                         ("rule-provider", "rule-providers")):
                conflicts.extend(
                    {"name": item, "kind": provider_kind, "default": "incoming"}
                    for item in sorted(set(current_ext[field]) & set(incoming_ext[field])))
            candidate = {"model": incoming}
            summary = {
                "proxies": sum(
                    1 for item in incoming["outbounds"]
                    if isinstance(item, dict) and item.get("type") not in {
                        "direct", "selector", "urltest"}),
                "proxyProviders": len(incoming["_pdg"]["mihomo"]["proxy-providers"]),
                "proxyGroups": len(incoming["_pdg"]["policy-groups"]),
                "ruleProviders": len(incoming["_pdg"]["mihomo"]["rule-providers"]),
                "rules": len(incoming["route"].get("rules") or []),
            }
        else:
            doc = _safe_yaml_load(config_data)
            current_mosdns = _read_optional_yaml(MOSDNS_PATH)
            if current_mosdns is None:
                raise ImportInvalid("current managed MosDNS configuration is unavailable")
            managed = _mosdns_contract(doc, current_mosdns)
            candidate = {"mosdns": base64.b64encode(_safe_yaml_dump(managed)).decode("ascii")}
            summary = {"plugins": len(managed["plugins"]), "mode": "replace"}
            warnings.append("MosDNS plugin graphs are replace-only; local identity will be rebound.")

        if kind == "mihomo":
            try:
                _pdgmodel().validate_ruleset_namespace(
                    candidate["model"], _current_ruleset_names())
            except (TypeError, ValueError) as exc:
                raise ImportInvalid(
                    "imported model collides with a PDG ruleset: "
                    + str(exc)) from exc

        # The Web UI renders and submits the complete conflict set.  Reject
        # oversized previews before persisting either record or upload so the
        # exact-choice contract can never create an unappliable preview.
        if len(conflicts) > MAX_CONFLICTS:
            raise ImportInvalid("configuration has too many conflicts")
        for conflict in conflicts:
            canonical = conflict["kind"] + "\0" + conflict["name"]
            conflict["conflictId"] = hashlib.sha256(
                canonical.encode("utf-8")).hexdigest()[:24]

        import_id = import_id or ("imp-" + secrets.token_hex(16))
        upload_sha = upload_sha or _sha(payload)
        record = {
            "version": 1, "id": import_id, "kind": kind,
            "created": int(time.time()), "uploadSha256": upload_sha,
            "uploadSize": len(payload), "baseModelSha256": _sha(_model_bytes(current)),
            "baseModelFileSha256": self._raw_file_sha(MODEL_PATH),
            "candidate": candidate, "summary": summary,
            "warnings": warnings, "conflicts": conflicts,
        }
        if kind in {"mosdns", "pdg"}:
            record["baseMosdnsSha256"] = self._raw_file_sha(MOSDNS_PATH)
        if kind == "pdg":
            record["componentBaselines"] = self._component_baselines(files)
        if kind != "mosdns":
            candidate_model = normalize_model(candidate["model"])
            leaves = set(current["_pdg"]["mihomo"]["managed-files"]) | set(
                candidate_model["_pdg"]["mihomo"]["managed-files"])
            record["providerBaselines"] = self._provider_baselines(leaves)
        encoded = json.dumps(record, ensure_ascii=True, sort_keys=True,
                             separators=(",", ":")).encode("utf-8")
        if len(encoded) > MAX_RECORD_BYTES:
            raise ImportInvalid("import preview metadata is too large")
        if not upload_already:
            self._create_exclusive(self._path(import_id, ".upload"), payload)
        try:
            self._write_file(self._path(import_id, ".json"), encoded)
        except Exception:
            self._safe_unlink(self._path(import_id, ".upload"))
            raise
        return {
            "importId": import_id, "kind": kind, "expiresIn": PREVIEW_TTL,
            "summary": summary, "warnings": warnings, "conflicts": conflicts,
            "modes": ["replace"] if kind == "mosdns" else ["merge", "replace"],
        }

    def _record(self, import_id: str, *, require_fresh: bool = True) -> dict[str, Any]:
        path = self._path(import_id, ".json")
        try:
            record = _strict_json(self._read_regular(path, MAX_RECORD_BYTES))
        except FileNotFoundError as exc:
            raise ImportNotFound("preview not found") from exc
        except ImportNotFound:
            raise
        except Exception as exc:
            raise ImportNotFound("preview not found") from exc
        if not isinstance(record, dict) or record.get("id") != import_id:
            raise ImportNotFound("preview not found")
        if require_fresh and time.time() - record.get("created", 0) > PREVIEW_TTL:
            apply = record.get("apply")
            active_claim = isinstance(apply, dict) and apply.get("claimed") is True and (
                time.time() - apply.get("claimedAt", 0) < 2 * 60 * 60)
            if not active_claim:
                self.discard(import_id)
                raise ImportExpired("preview expired")
        try:
            raw = self._read_regular(
                self._path(import_id, ".upload"), _upload_limit(record.get("kind", "")))
        except OSError as exc:
            raise ImportNotFound("preview not found") from exc
        if len(raw) != record.get("uploadSize") or _sha(raw) != record.get("uploadSha256"):
            raise ImportConflict("staged upload integrity check failed")
        return record

    def prepare_apply(self, import_id: str, body: dict[str, Any]) -> dict[str, Any]:
        claim_path = self._path(import_id, ".claim")
        try:
            self._create_exclusive(claim_path, secrets.token_bytes(32))
        except FileExistsError as exc:
            raise ImportConflict("preview has already been claimed") from exc
        try:
            # The claim is the per-import state lock.  Reading the record before
            # acquiring it lets a concurrent cancel remove the upload and then
            # allows this path to recreate stale metadata for a missing upload.
            record = self._record(import_id)
            if "apply" in record:
                raise ImportConflict("preview has already been claimed")
            if not isinstance(body, dict) or set(body) - {
                    "confirm", "mode", "conflicts"} or body.get("confirm") is not True:
                raise ImportInvalid("apply confirmation is invalid")
            mode = body.get("mode", "merge")
            allowed_modes = ({"replace"} if record["kind"] == "mosdns"
                             else {"merge", "replace"})
            if mode not in allowed_modes:
                raise ImportInvalid("apply mode is invalid")
            resolutions = body.get("conflicts") or {}
            if not isinstance(resolutions, dict):
                raise ImportInvalid("conflict choices are invalid")
            expected = {item["conflictId"] for item in record.get("conflicts") or []}
            if set(resolutions) != expected or any(
                    value not in {"incoming", "existing"}
                    for value in resolutions.values()):
                raise ImportInvalid("conflict choices are invalid")
            if mode == "replace" and any(
                    value != "incoming" for value in resolutions.values()):
                raise ImportInvalid(
                    "replace mode requires all conflicts to use imported content")
            if record["kind"] == "pdg":
                collision_state = (record.get("candidate") or {}).get(
                    "rulesetCollisions")
                if (not isinstance(collision_state, dict)
                        or set(collision_state) != {
                            "incomingPresent", "incoming", "existing",
                            "incomingNames", "existingNames"}
                        or type(collision_state["incomingPresent"]) is not bool
                        or any(not isinstance(values, list)
                               or any(not _valid_name(name)
                                      for name in values)
                               for values in (
                                   collision_state["incoming"],
                                   collision_state["existing"],
                                   collision_state["incomingNames"],
                                   collision_state["existingNames"]))):
                    raise ImportInvalid("ruleset collision state is invalid")
                ruleset_choice = "existing"
                ruleset_conflict = next((
                    item for item in record.get("conflicts") or []
                    if item.get("kind") == "component"
                    and item.get("name") == "rulesets"), None)
                if collision_state["incomingPresent"] and (
                        mode == "replace" or (
                            ruleset_conflict is not None
                            and resolutions.get(ruleset_conflict["conflictId"])
                            == "incoming")):
                    ruleset_choice = "incoming"
                selected_collisions = collision_state[ruleset_choice]
                if selected_collisions:
                    raise ImportInvalid(
                        "imported rule-provider collides with the selected PDG ruleset state: "
                        + ", ".join(sorted(selected_collisions)))
                choices = resolutions
                semantic_resolutions = {
                    item["kind"] + ":" + item["name"]:
                    choices[item["conflictId"]]
                    for item in record.get("conflicts") or []
                }
                current = self._current_model()
                incoming = normalize_model(record["candidate"]["model"])
                final = _merge_model(
                    current, incoming, mode, semantic_resolutions)
                try:
                    _pdgmodel().validate_ruleset_namespace(
                        final, collision_state[ruleset_choice + "Names"])
                except (TypeError, ValueError) as exc:
                    raise ImportInvalid(
                        "selected PDG ruleset namespace is invalid: "
                        + str(exc)) from exc
            record["apply"] = {
                "mode": mode, "conflicts": resolutions, "confirmed": True,
                "claimed": True, "claimedAt": int(time.time())}
            self._write_file(
                self._path(import_id, ".json"),
                json.dumps(record, ensure_ascii=True, sort_keys=True,
                           separators=(",", ":")).encode("utf-8"))
        except Exception:
            self._safe_unlink(claim_path)
            raise
        return {"importId": import_id, "kind": record["kind"], "mode": mode}

    def release_claim(self, import_id: str) -> None:
        """Undo a pre-run claim when JobStore could not publish/launch a job."""
        record = self._record(import_id, require_fresh=False)
        record.pop("apply", None)
        self._write_file(
            self._path(import_id, ".json"),
            json.dumps(record, ensure_ascii=True, sort_keys=True,
                       separators=(",", ":")).encode("utf-8"))
        self._safe_unlink(self._path(import_id, ".claim"))

    def discard(self, import_id: str) -> None:
        for suffix in (".json", ".upload", ".claim"):
            self._safe_unlink(self._path(import_id, suffix))

    def cancel(self, import_id: str) -> None:
        claim_path = self._path(import_id, ".claim")
        try:
            self._create_exclusive(claim_path, b"cancel")
        except FileExistsError as exc:
            raise ImportConflict("claimed preview cannot be cancelled") from exc
        try:
            record = self._record(import_id)
            if "apply" in record:
                raise ImportConflict("claimed preview cannot be cancelled")
            self.discard(import_id)
        finally:
            self._safe_unlink(claim_path)

    def apply(self, import_id: str) -> None:
        record = self._record(import_id)
        plan = record.get("apply")
        if not isinstance(plan, dict) or plan.get("confirmed") is not True:
            raise ImportInvalid("preview is not authorized for apply")
        bot = self._load_bot()
        current = normalize_model(bot.load())
        if _sha(_model_bytes(current)) != record.get("baseModelSha256"):
            raise ImportConflict("configuration changed after preview")
        kind = record["kind"]
        if kind == "mosdns":
            if self._raw_file_sha(MOSDNS_PATH) != record.get("baseMosdnsSha256"):
                raise ImportConflict("MosDNS configuration changed after preview")
            data = base64.b64decode(record["candidate"]["mosdns"], validate=True)
            result = bot.tx_apply(
                "web_import_mosdns", files={"mosdns_conf": data}, services=("mosdns",),
                file_expects={"mosdns_conf": record.get("baseMosdnsSha256")})
        else:
            incoming = normalize_model(record["candidate"]["model"])
            choices = plan.get("conflicts") or {}
            resolutions = {
                item["kind"] + ":" + item["name"]: choices[item["conflictId"]]
                for item in record.get("conflicts") or []
            }
            final = _merge_model(current, incoming, plan["mode"], resolutions)
            if kind == "pdg" and self._raw_file_sha(
                    MOSDNS_PATH) != record.get("baseMosdnsSha256"):
                raise ImportConflict("MosDNS configuration changed after preview")
            current_files = current["_pdg"]["mihomo"]["managed-files"]
            final_files = final["_pdg"]["mihomo"]["managed-files"]
            files: dict[str, bytes | None] = {}
            for leaf, encoded in final_files.items():
                files["mihomo_provider:" + leaf] = base64.b64decode(encoded, validate=True)
            for leaf in set(current_files) - set(final_files):
                files["mihomo_provider:" + leaf] = None
            baselines = record.get("providerBaselines")
            if not isinstance(baselines, dict) or self._provider_baselines(
                    set(baselines)) != baselines:
                raise ImportConflict("managed provider files changed after preview")
            file_expects = {
                "mihomo_provider:" + leaf: baseline
                for leaf, baseline in baselines.items()
                if "mihomo_provider:" + leaf in files
            }

            def modify(model):
                model.clear()
                model.update(copy.deepcopy(final))

            if kind == "pdg":
                raw = self._read_regular(
                    self._path(import_id, ".upload"), MAX_LEGACY_PDG_UPLOAD)
                restore = getattr(bot, "restore_from", None)
                if not callable(restore):
                    raise ConfigIOError("PDG restore backend is unavailable")
                result = restore(
                    _restore_bundle(
                        raw, final, plan["mode"], resolutions,
                        base64.b64decode(record["candidate"]["mosdns"], validate=True)
                        if "mosdns" in record["candidate"] else None),
                    expected={
                        "model": record.get("baseModelFileSha256"),
                        "mosdns": record.get("baseMosdnsSha256"),
                        "providers": baselines,
                        "files": record.get("componentBaselines"),
                    })
            else:
                result = bot.tx_apply(
                    "web_import_" + kind, model_mod=modify, files=files,
                    file_expects=file_expects,
                    model_expect=record.get("baseModelFileSha256"))
        try:
            ok, _message = result
        except Exception as exc:
            raise ConfigIOError("configuration transaction failed") from exc
        if ok is not True:
            raise ConfigIOError("configuration transaction failed")
        self.discard(import_id)

    def export(self, kind: str) -> tuple[bytes, str, str]:
        if kind == "pdg":
            bot = self._load_bot()
            fn = getattr(bot, "backup_blob", None)
            if not callable(fn):
                raise ConfigIOError("PDG backup backend is unavailable")
            data = fn()
            if not isinstance(data, bytes) or not 0 < len(data) <= MAX_UPLOAD:
                raise ConfigIOError("PDG backup is unavailable")
            return data, "pdg-config-v3.tar.gz", "application/gzip"
        path = MIHOMO_PATH if kind == "mihomo" else MOSDNS_PATH if kind == "mosdns" else ""
        if not path:
            raise ImportInvalid("export kind is invalid")
        data = None
        for _attempt in range(3):
            try:
                first = self._read_managed_regular(path, MAX_UPLOAD)
                second = self._read_managed_regular(path, MAX_UPLOAD)
            except OSError as exc:
                raise ConfigIOError("configuration export is unavailable") from exc
            if first == second:
                data = first
                break
        if data is None:
            raise ImportConflict("configuration changed during export")
        if not data or len(data) > MAX_UPLOAD:
            raise ConfigIOError("configuration export is unavailable")
        name = "mihomo-config.yaml" if kind == "mihomo" else "mosdns-config.yaml"
        return data, name, "application/yaml; charset=utf-8"


def _arguments(argv=None):
    parser = argparse.ArgumentParser(description="PDG managed configuration import runner")
    sub = parser.add_subparsers(dest="command", required=True)
    apply = sub.add_parser("apply")
    apply.add_argument("--import-id", required=True)
    discard = sub.add_parser("discard")
    discard.add_argument("--import-id", required=True)
    return parser.parse_args(argv)


def main(argv=None) -> int:
    args = _arguments(argv)
    manager = None
    try:
        manager = ConfigIO()
        if args.command == "apply":
            try:
                manager.apply(args.import_id)
            finally:
                # Terminal success and failure both remove staged secrets.
                manager.discard(args.import_id)
            return 0
        if args.command == "discard":
            manager.discard(args.import_id)
            return 0
    except Exception:
        return 1
    return 1


if __name__ == "__main__":
    raise SystemExit(main())

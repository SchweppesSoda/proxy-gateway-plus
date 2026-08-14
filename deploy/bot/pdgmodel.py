#!/usr/bin/env python3
"""PDG canonical model schema v3 and policy-group validation.

Schema v3 has exactly one policy-group representation: ``_pdg.policy-groups``.
Mihomo metadata remains limited to providers, safe runtime extensions and
embedded provider files.  This module is deliberately dependency-free so the
Bot, renderer and Web import/control surfaces all use the same migration and
validation rules.
"""
from __future__ import annotations

import copy
import re
import unicodedata
from typing import Any


SCHEMA_VERSION = 3
# Machine-only tags (the direct/block/DNS plumbing) deliberately stay ASCII.
# User-facing proxy, policy-group and provider names use ``normalize_name``.
TAG_RE = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")
NAME_MAX_CODEPOINTS = 64
NAME_MAX_UTF8_BYTES = 256
# Invisible format controls that can spoof/reorder labels or make two names
# visually indistinguishable.  U+200D (ZWJ) is intentionally allowed so
# ordinary emoji sequences remain intact.
_DANGEROUS_NAME_CODEPOINTS = frozenset({
    0x00AD, 0x034F, 0x061C, 0x115F, 0x1160, 0x17B4, 0x17B5,
    0x180E, 0x200B, 0x200E, 0x200F, 0x202A, 0x202B, 0x202C,
    0x202D, 0x202E, 0x2060, 0x2061, 0x2062, 0x2063, 0x2064,
    0x2066, 0x2067, 0x2068, 0x2069, 0x206A, 0x206B, 0x206C,
    0x206D, 0x206E, 0x206F, 0x3164, 0xFEFF, 0xFFA0,
})
GROUP_TYPES = frozenset({"select", "url-test", "fallback", "load-balance"})
# Keep this set in lock-step with ``sb2mihomo.PROXY_TYPES`` and the Bot's
# editable exit inventory.  Other sing-box outbounds (notably ``dns``) are
# machine plumbing: their tag still occupies the shared namespace, but they
# must never become a policy-group member or route target merely because they
# have a tag.
PROXY_OUTBOUND_TYPES = frozenset({
    "shadowsocks", "vmess", "trojan", "vless", "hysteria", "hysteria2",
    "tuic", "anytls", "shadowtls", "socks", "http",
})
ROUTABLE_OUTBOUND_TYPES = PROXY_OUTBOUND_TYPES | {"direct", "block"}
# Mihomo exposes these names without a user-defined proxy.  Treat both the
# built-in outbound policies and the built-in GLOBAL group as occupied so a
# perfectly valid PDG tag cannot acquire different meaning after rendering.
RESERVED_TARGETS = frozenset({
    "DIRECT", "REJECT", "REJECT-DROP", "PASS", "PASS-RULE", "COMPATIBLE",
    "GLOBAL",
})
V3_META_FIELDS = frozenset({"schema", "policy-groups", "mihomo"})
V3_MIHOMO_FIELDS = frozenset({
    "proxy-providers", "rule-providers", "advanced", "managed-files"})
DIRECT_SETTING_RESERVED = RESERVED_TARGETS | {"block", "dns-out"}
GROUP_COMMON_FIELDS = frozenset({"name", "type", "proxies", "use"})
GROUP_FIELDS = {
    "select": GROUP_COMMON_FIELDS | {"lazy", "disable-udp", "hidden"},
    "url-test": GROUP_COMMON_FIELDS | {
        "url", "interval", "tolerance", "lazy", "disable-udp", "hidden"},
    "fallback": GROUP_COMMON_FIELDS | {
        "url", "interval", "lazy", "disable-udp", "hidden"},
    "load-balance": GROUP_COMMON_FIELDS | {
        "url", "interval", "lazy", "disable-udp", "hidden", "strategy"},
}
DEFAULT_TEST_URL = "https://www.gstatic.com/generate_204"


class ModelError(ValueError):
    pass


class NameValidationError(ModelError):
    """Stable name-validation failure that never embeds the rejected value."""

    def __init__(self, reason: str, label: str = "name"):
        self.reason = reason
        messages = {
            "type": "is not a text name",
            "encoding": "is not valid UTF-8",
            "length": "must be 1-64 characters and at most 256 UTF-8 bytes",
            "unsafe": "contains a control or unsafe invisible character",
            "canonical": "is not NFC-normalized or has outer whitespace",
        }
        super().__init__(label + " " + messages.get(reason, "is invalid"))


def normalize_name(value: Any, label: str = "name") -> str:
    """Return the canonical user-facing identifier without lossy rewriting.

    Names are UTF-8/NFC display strings.  Only surrounding whitespace is
    discarded; internal whitespace, CJK, emoji and punctuation are preserved.
    """
    if not isinstance(value, str):
        raise NameValidationError("type", label)
    canonical = unicodedata.normalize("NFC", value)
    for ch in canonical:
        codepoint = ord(ch)
        category = unicodedata.category(ch)
        if (codepoint < 0x20 or 0x7F <= codepoint <= 0x9F
                or category in {"Cs", "Zl", "Zp"}
                or (category == "Cf" and codepoint != 0x200D)
                or codepoint in _DANGEROUS_NAME_CODEPOINTS):
            raise NameValidationError("unsafe", label)
    name = canonical.strip()
    try:
        encoded = name.encode("utf-8", "strict")
    except UnicodeEncodeError as exc:
        raise NameValidationError("encoding", label) from exc
    if (not name or len(name) > NAME_MAX_CODEPOINTS
            or len(encoded) > NAME_MAX_UTF8_BYTES):
        raise NameValidationError("length", label)
    return name


def validate_name(value: Any, label: str = "name") -> str:
    """Validate a stored canonical name and return it unchanged."""
    name = normalize_name(value, label)
    if name != value:
        raise NameValidationError("canonical", label)
    return name


def is_valid_name(value: Any, *, canonical: bool = True) -> bool:
    try:
        (validate_name if canonical else normalize_name)(value)
        return True
    except (TypeError, ValueError):
        return False


def validate_declared_schema_shape(model: Any) -> None:
    """Reject a declared v3 envelope before defaults or normalization run."""
    if not isinstance(model, dict):
        return
    meta = model.get("_pdg")
    if not isinstance(meta, dict) or meta.get("schema") != SCHEMA_VERSION:
        return
    if set(meta) != V3_META_FIELDS or type(meta.get("policy-groups")) is not list:
        raise ModelError("declared schema v3 metadata has an invalid shape")
    mihomo = meta.get("mihomo")
    if (type(mihomo) is not dict or set(mihomo) != V3_MIHOMO_FIELDS
            or any(type(mihomo.get(key)) is not dict for key in V3_MIHOMO_FIELDS)):
        raise ModelError("declared schema v3 Mihomo metadata has an invalid shape")


def validate_direct_tag_setting(value: Any) -> str:
    """Validate an operator-requested machine direct tag (not legacy rebinding)."""
    tag = _tag(value, "direct tag")
    if tag.casefold() in {"direct", "jp"} or tag in DIRECT_SETTING_RESERVED:
        raise ModelError("direct tag is reserved for compatibility or Mihomo")
    return tag


def _tag(value: Any, label: str) -> str:
    if not isinstance(value, str) or not TAG_RE.fullmatch(value):
        raise ModelError(label + " is not a valid tag")
    return value


def _name(value: Any, label: str) -> str:
    return validate_name(value, label)


def direct_tag(model: dict[str, Any]) -> str:
    direct = [item for item in model.get("outbounds", [])
              if isinstance(item, dict) and item.get("type") == "direct"]
    if len(direct) != 1:
        raise ModelError("model must contain exactly one direct outbound")
    return _tag(direct[0].get("tag"), "direct tag")


def policy_groups(model: dict[str, Any]) -> list[dict[str, Any]]:
    meta = model.get("_pdg") if isinstance(model, dict) else None
    groups = meta.get("policy-groups") if isinstance(meta, dict) else None
    return groups if isinstance(groups, list) else []


def _duration_seconds(value: Any) -> int:
    if type(value) is int:
        return value
    if not isinstance(value, str):
        return -1
    match = re.fullmatch(r"(\d+)([smh]?)", value)
    if not match:
        return -1
    return int(match.group(1)) * {"": 1, "s": 1, "m": 60, "h": 3600}[match.group(2)]


def _canonical_group(outbound: dict[str, Any], direct: str) -> dict[str, Any]:
    typ = outbound.get("type")
    if typ not in {"selector", "urltest"}:
        raise ModelError("not a legacy canonical group")
    group: dict[str, Any] = {
        "name": _name(outbound.get("tag"), "group name"),
        "type": "select" if typ == "selector" else "url-test",
        "proxies": copy.deepcopy(outbound.get("outbounds", [])),
        "use": [],
    }
    if typ == "urltest":
        group.update({
            "url": outbound.get("url", DEFAULT_TEST_URL),
            "interval": _duration_seconds(outbound.get("interval", "180s")),
            "tolerance": outbound.get("tolerance", 50),
        })
    # Canonical v2 used the machine tag; imported Mihomo metadata used DIRECT.
    group["proxies"] = [direct if item == "DIRECT" else item
                        for item in group["proxies"]]
    return group


def _legacy_groups(
        model: dict[str, Any], mihomo: dict[str, Any], schema: int
) -> list[dict[str, Any]]:
    """Merge v2 mirrors and reject every disagreement before discarding either."""
    direct = direct_tag(model)
    canonical: dict[str, dict[str, Any]] = {}
    for item in model.get("outbounds", []):
        if not isinstance(item, dict) or item.get("type") not in {
                "selector", "urltest"}:
            continue
        group = _canonical_group(item, direct)
        name = group["name"]
        if name in canonical:
            raise ModelError("duplicate legacy canonical group: " + name)
        canonical[name] = group
    raw_groups = mihomo.get("proxy-groups", [])
    if not isinstance(raw_groups, list):
        raise ModelError("invalid legacy proxy-groups metadata")
    metadata: dict[str, dict[str, Any]] = {}
    order: list[str] = []
    for raw in raw_groups:
        if not isinstance(raw, dict):
            raise ModelError("invalid legacy proxy group")
        name = _name(raw.get("name"), "group name")
        if name in metadata:
            raise ModelError("duplicate legacy proxy group: " + name)
        group = copy.deepcopy(raw)
        if isinstance(group.get("proxies"), list):
            group["proxies"] = [direct if item == "DIRECT" else item
                                for item in group["proxies"]]
        metadata[name] = group
        order.append(name)

    for name, mirror in canonical.items():
        raw = metadata.get(name)
        if raw is None:
            # Schema v2 introduced the Mihomo mirror.  A missing half is not a
            # harmless old-format omission: accepting it would silently choose
            # one of two alleged authorities.  Schema v1 predates that mirror,
            # so canonical-only models remain a supported legacy input.
            if schema == 2:
                raise ModelError(
                    "legacy canonical policy group is missing its mirror: " + name)
            metadata[name] = mirror
            order.append(name)
            continue
        expected_type = mirror["type"]
        representable = not raw.get("use") and "REJECT" not in raw.get("proxies", [])
        if raw.get("type") != expected_type or not representable:
            raise ModelError("legacy policy-group representations disagree: " + name)
        if raw.get("proxies", []) != mirror["proxies"]:
            raise ModelError("legacy policy-group memberships disagree: " + name)
        if expected_type == "url-test" and (
                raw.get("url", DEFAULT_TEST_URL) != mirror.get("url", DEFAULT_TEST_URL)
                or raw.get("interval", 180) != mirror.get("interval", 180)
                or raw.get("tolerance", 50) != mirror.get("tolerance", 50)):
            raise ModelError("legacy policy-group probe settings disagree: " + name)
    for name, raw in metadata.items():
        # A fully representable select/url-test metadata group was supposed to
        # have a canonical mirror in v2.  Its absence is ambiguous and closes.
        if (name not in canonical and raw.get("type") in {"select", "url-test"}
                and not raw.get("use") and "REJECT" not in raw.get("proxies", [])):
            raise ModelError("legacy editable policy group is missing its mirror: " + name)
    return [metadata[name] for name in order]


def _canonicalize_user_names(model: dict[str, Any]) -> None:
    """Normalize every user-facing namespace key and its modeled references."""
    meta = model.get("_pdg") or {}
    mihomo = meta.get("mihomo") or {}
    groups = meta.get("policy-groups") or []
    aliases: dict[str, str] = {}

    def remember(value: Any, label: str) -> str:
        canonical = normalize_name(value, label)
        aliases[value] = canonical
        return canonical

    for outbound in model.get("outbounds", []):
        if (isinstance(outbound, dict)
                and outbound.get("type") in PROXY_OUTBOUND_TYPES):
            outbound["tag"] = remember(outbound.get("tag"), "outbound tag")
    for group in groups:
        if isinstance(group, dict):
            group["name"] = remember(group.get("name"), "group name")

    for field, label in (("proxy-providers", "proxy provider name"),
                         ("rule-providers", "rule provider name")):
        collection = mihomo.get(field)
        if not isinstance(collection, dict):
            continue
        rebuilt = {}
        for raw, value in collection.items():
            canonical = remember(raw, label)
            if canonical in rebuilt:
                raise ModelError(label + " collides after Unicode normalization")
            rebuilt[canonical] = value
        mihomo[field] = rebuilt

    def reference(value: Any, label: str) -> str:
        if not isinstance(value, str):
            raise ModelError(label + " is not a valid name")
        return aliases.get(value, normalize_name(value, label))

    for outbound in model.get("outbounds", []):
        if not isinstance(outbound, dict):
            continue
        if isinstance(outbound.get("detour"), str):
            outbound["detour"] = reference(outbound["detour"], "outbound detour")
        if isinstance(outbound.get("outbounds"), list):
            outbound["outbounds"] = [
                reference(item, "outbound member") for item in outbound["outbounds"]]
    for group in groups:
        if not isinstance(group, dict):
            continue
        group["proxies"] = [
            item if item == "REJECT" else reference(item, "group member")
            for item in (group.get("proxies") or [])
        ]
        group["use"] = [
            reference(item, "proxy provider name")
            for item in (group.get("use") or [])
        ]
    route = model.get("route") or {}
    if isinstance(route.get("final"), str):
        route["final"] = reference(route["final"], "route target")
    for rule in route.get("rules", []) or []:
        if not isinstance(rule, dict):
            continue
        if isinstance(rule.get("outbound"), str):
            rule["outbound"] = reference(rule["outbound"], "route target")
        if isinstance(rule.get("rule_set"), str):
            rule["rule_set"] = reference(rule["rule_set"], "rule provider name")
    for rule_set in route.get("rule_set", []) or []:
        if isinstance(rule_set, dict) and isinstance(rule_set.get("tag"), str):
            rule_set["tag"] = reference(rule_set["tag"], "rule provider name")


def migrate(model: Any) -> dict[str, Any]:
    """Return a validated schema-v3 copy; reads never write the source file."""
    if not isinstance(model, dict):
        raise ModelError("model root must be an object")
    # A document that claims v3 must already have the exact v3 envelope.
    # Running default-filling first would silently repair attacker/user damage
    # and choose semantics for an allegedly canonical authority.
    validate_declared_schema_shape(model)
    result = copy.deepcopy(model)
    if not isinstance(result.get("outbounds"), list) or not isinstance(
            result.get("route"), dict):
        raise ModelError("model is missing outbounds or route")
    direct_tag(result)
    meta = result.get("_pdg") or {}
    if not isinstance(meta, dict):
        raise ModelError("invalid PDG metadata")
    schema = meta.get("schema", 1)
    if schema not in {1, 2, 3}:
        raise ModelError("unsupported model schema")
    mihomo = meta.get("mihomo") or {}
    if not isinstance(mihomo, dict):
        raise ModelError("invalid Mihomo metadata")
    allowed_mihomo = {
        "proxy-providers", "rule-providers", "advanced", "managed-files",
        "proxy-groups",
    }
    if set(mihomo) - allowed_mihomo:
        raise ModelError("invalid Mihomo metadata field")

    if schema == 3:
        groups = copy.deepcopy(meta["policy-groups"])
        if any(isinstance(item, dict) and item.get("type") in {"selector", "urltest"}
               for item in result["outbounds"]):
            raise ModelError("schema v3 forbids canonical group outbounds")
    else:
        if set(meta) - {"schema", "mihomo"}:
            raise ModelError("invalid legacy PDG metadata")
        groups = _legacy_groups(result, mihomo, schema)
        result["outbounds"] = [
            item for item in result["outbounds"]
            if not (isinstance(item, dict) and item.get("type") in {"selector", "urltest"})
        ]

    normalized_mihomo = {}
    for key, default in (("proxy-providers", {}), ("rule-providers", {}),
                         ("advanced", {}), ("managed-files", {})):
        value = mihomo.get(key, default)
        if not isinstance(value, type(default)):
            raise ModelError("invalid Mihomo metadata field: " + key)
        normalized_mihomo[key] = copy.deepcopy(value)
    result["_pdg"] = {
        "schema": SCHEMA_VERSION,
        "policy-groups": groups,
        "mihomo": normalized_mihomo,
    }
    _canonicalize_user_names(result)
    validate(result)
    return result


def _validate_group(group: Any) -> tuple[str, list[str], list[str]]:
    if not isinstance(group, dict):
        raise ModelError("policy group must be an object")
    name = _name(group.get("name"), "group name")
    typ = group.get("type")
    if typ not in GROUP_TYPES or set(group) - GROUP_FIELDS[typ]:
        raise ModelError("policy group contains unsupported runtime fields for its type: " + name)
    proxies = group.get("proxies", [])
    uses = group.get("use", [])
    if (not isinstance(proxies, list) or not isinstance(uses, list)
            or any(not isinstance(item, str) for item in proxies + uses)
            or len(proxies) != len(set(proxies)) or len(uses) != len(set(uses))
            or not proxies and not uses):
        raise ModelError("policy group members/providers are invalid: " + name)
    for key in ("lazy", "disable-udp", "hidden"):
        if key in group and type(group[key]) is not bool:
            raise ModelError("policy group boolean option is invalid: " + name)
    if typ in {"url-test", "fallback", "load-balance"}:
        url = group.get("url", DEFAULT_TEST_URL)
        if not isinstance(url, str) or not re.fullmatch(r"https?://[^\s\x00]+", url, re.I):
            raise ModelError("policy group URL is invalid: " + name)
        interval = group.get("interval", 180)
        if type(interval) is not int or not 1 <= interval <= 604800:
            raise ModelError("policy group interval is invalid: " + name)
    if "tolerance" in group and (
            type(group["tolerance"]) is not int or not 0 <= group["tolerance"] <= 65535):
        raise ModelError("policy group tolerance is invalid: " + name)
    if "strategy" in group and group["strategy"] not in {
            "consistent-hashing", "round-robin", "sticky-sessions"}:
        raise ModelError("policy group strategy is invalid: " + name)
    return name, proxies, uses


def validate(model: dict[str, Any]) -> None:
    if not isinstance(model, dict) or not isinstance(model.get("outbounds"), list):
        raise ModelError("invalid model")
    direct = direct_tag(model)
    if direct in RESERVED_TARGETS:
        raise ModelError("direct tag collides with a reserved target")
    meta = model.get("_pdg")
    if (not isinstance(meta, dict) or meta.get("schema") != SCHEMA_VERSION
            or set(meta) != V3_META_FIELDS):
        raise ModelError("model is not canonical schema v3")
    mihomo = meta.get("mihomo")
    if not isinstance(mihomo, dict) or set(mihomo) != V3_MIHOMO_FIELDS:
        raise ModelError("invalid schema-v3 Mihomo metadata")
    providers = mihomo["proxy-providers"]
    rule_providers = mihomo["rule-providers"]
    if not isinstance(providers, dict) or not isinstance(rule_providers, dict):
        raise ModelError("providers must be mappings")

    outbound_names: set[str] = set()
    routable: set[str] = set()
    for outbound in model["outbounds"]:
        if not isinstance(outbound, dict):
            raise ModelError("outbound must be an object")
        validator = _name if outbound.get("type") in PROXY_OUTBOUND_TYPES else _tag
        name = validator(outbound.get("tag"), "outbound tag")
        if name in outbound_names:
            raise ModelError("duplicate outbound tag: " + name)
        if outbound.get("type") in {"selector", "urltest"}:
            raise ModelError("schema v3 policy groups cannot be outbounds")
        outbound_names.add(name)
        if outbound.get("type") in ROUTABLE_OUTBOUND_TYPES:
            routable.add(name)

    groups: dict[str, dict[str, Any]] = {}
    group_parts: dict[str, tuple[list[str], list[str]]] = {}
    for group in meta["policy-groups"]:
        name, proxies, uses = _validate_group(group)
        if name in groups:
            raise ModelError("duplicate policy group: " + name)
        groups[name] = group
        group_parts[name] = (proxies, uses)

    provider_names = set(providers) | set(rule_providers)
    for name in provider_names:
        _name(name, "provider name")
    occupied = outbound_names | set(groups) | set(providers) | set(rule_providers)
    if len(occupied) != (len(outbound_names) + len(groups) + len(providers)
                         + len(rule_providers)):
        raise ModelError("proxy/group/provider names share one namespace")
    if occupied & RESERVED_TARGETS:
        raise ModelError("name collides with a reserved Mihomo target")

    known_members = routable | set(groups) | {"REJECT"}
    block_tags = {item["tag"] for item in model["outbounds"]
                  if item.get("type") == "block"}
    graph: dict[str, set[str]] = {}
    for name, (members, uses) in group_parts.items():
        if any(item not in known_members for item in members):
            raise ModelError("policy group references an undefined member: " + name)
        # Machine block tags and literal REJECT all render to one Clash
        # candidate.  Multiple aliases in one group cannot be selected or
        # reported without guessing, so reject that model before rendering.
        reject_aliases = [item for item in members
                          if item == "REJECT" or item in block_tags]
        if len(reject_aliases) > 1:
            raise ModelError("policy group has ambiguous REJECT members: " + name)
        if any(item not in providers for item in uses):
            raise ModelError("policy group references an undefined proxy provider: " + name)
        graph[name] = {item for item in members if item in groups}

    visiting: set[str] = set()
    visited: set[str] = set()
    def visit(name: str) -> None:
        if name in visiting:
            raise ModelError("policy groups contain a dependency cycle")
        if name in visited:
            return
        visiting.add(name)
        for child in graph[name]:
            visit(child)
        visiting.remove(name)
        visited.add(name)
    for name in graph:
        visit(name)

    routable |= set(groups)
    route = model.get("route")
    if not isinstance(route, dict) or route.get("final") not in routable:
        raise ModelError("route.final references an undefined target")
    rules = route.get("rules", [])
    if not isinstance(rules, list):
        raise ModelError("route.rules must be a list")
    for rule in rules:
        if not isinstance(rule, dict):
            raise ModelError("route rule must be an object")
        target = rule.get("outbound")
        if target is not None and target not in routable:
            raise ModelError("route rule references an undefined target")


def routable_tags_unchecked(model: dict[str, Any]) -> list[str]:
    """Return ordered route targets while a reference-closing mutation is in flight.

    Callers must validate the finished model.  This deliberately avoids
    ``migrate`` because deleting a referenced group/proxy creates a brief,
    expected dangling state before route and ruleset targets are cascaded.
    """
    tags = [item["tag"] for item in model["outbounds"]
            if isinstance(item, dict)
            and item.get("type") in ROUTABLE_OUTBOUND_TYPES
            and isinstance(item.get("tag"), str)]
    tags.extend(group["name"] for group in policy_groups(model))
    return tags


def routable_tags(model: dict[str, Any]) -> list[str]:
    return routable_tags_unchecked(migrate(model))


def model_namespace(model: dict[str, Any]) -> set[str]:
    canonical = migrate(model)
    meta = canonical["_pdg"]
    names = {item["tag"] for item in canonical["outbounds"]}
    names |= {group["name"] for group in meta["policy-groups"]}
    names |= set(meta["mihomo"]["proxy-providers"])
    names |= set(meta["mihomo"]["rule-providers"])
    return names


def validate_ruleset_namespace(model: dict[str, Any], names: Any) -> None:
    if not isinstance(names, (set, frozenset, list, tuple)):
        raise ModelError("ruleset provider names are invalid")
    canonical = [normalize_name(name, "ruleset provider name") for name in names]
    checked = set(canonical)
    if len(checked) != len(canonical):
        raise ModelError("ruleset provider names collide after Unicode normalization")
    collisions = sorted(checked & (model_namespace(model) | set(RESERVED_TARGETS)))
    if collisions:
        raise ModelError("ruleset provider names 与 Mihomo 命名空间同名: "
                         + ", ".join(collisions))


def rename_references(model: dict[str, Any], old: str, new: str, *, rename_group=False) -> None:
    for group in policy_groups(model):
        if rename_group and group.get("name") == old:
            group["name"] = new
        group["proxies"] = [new if item == old else item
                            for item in group.get("proxies", [])]
    route = model.get("route", {})
    if route.get("final") == old:
        route["final"] = new
    for rule in route.get("rules", []):
        if isinstance(rule, dict) and rule.get("outbound") == old:
            rule["outbound"] = new


def rebind_direct(model: dict[str, Any], new: str) -> dict[str, Any]:
    result = migrate(model)
    old = direct_tag(result)
    new = _tag(new, "direct tag")
    if new == old:
        return result
    if new in RESERVED_TARGETS:
        raise ModelError("direct tag collides with a reserved target")
    occupied = {item.get("tag") for item in result["outbounds"]
                if item.get("tag") != old}
    occupied |= {group.get("name") for group in policy_groups(result)}
    occupied |= set(result["_pdg"]["mihomo"]["proxy-providers"])
    occupied |= set(result["_pdg"]["mihomo"]["rule-providers"])
    if new in occupied:
        raise ModelError("direct tag collides with an existing model name")
    for outbound in result["outbounds"]:
        if outbound.get("type") == "direct":
            outbound["tag"] = new
    rename_references(result, old, new)
    validate(result)
    return result


def rebind_direct_preserve_schema(model: dict[str, Any], new: str) -> dict[str, Any]:
    """Rebind a restored legacy/current model without changing its disk schema.

    Snapshot rollback can restore the executable bundle that originally wrote
    the model.  Converting an old schema to v3 while also restoring an old Bot
    would make that snapshot internally incompatible.  We therefore use the
    v3 view for strict preflight/collision validation, rewrite both recognized
    legacy representations in the original document, and validate the result
    through migration again without persisting that migrated view.
    """
    if not isinstance(model, dict):
        raise ModelError("model root must be an object")
    result = copy.deepcopy(model)
    old = direct_tag(result)
    new = _tag(new, "direct tag")
    # This proves the destination namespace against the shared v3 validator.
    rebind_direct(result, new)
    if old == new:
        return result
    for outbound in result.get("outbounds", []):
        if not isinstance(outbound, dict):
            continue
        if outbound.get("type") == "direct":
            outbound["tag"] = new
        if outbound.get("type") in {"selector", "urltest"}:
            outbound["outbounds"] = [
                new if item == old else item
                for item in outbound.get("outbounds", [])
            ]
    meta = result.get("_pdg")
    if isinstance(meta, dict):
        for group in meta.get("policy-groups", []) or []:
            if isinstance(group, dict):
                group["proxies"] = [
                    new if item == old else item
                    for item in group.get("proxies", [])
                ]
        mihomo = meta.get("mihomo")
        if isinstance(mihomo, dict):
            for group in mihomo.get("proxy-groups", []) or []:
                if isinstance(group, dict):
                    group["proxies"] = [
                        new if item == old else item
                        for item in group.get("proxies", [])
                    ]
    route = result.get("route") or {}
    if route.get("final") == old:
        route["final"] = new
    for rule in route.get("rules", []) or []:
        if isinstance(rule, dict) and rule.get("outbound") == old:
            rule["outbound"] = new
    migrate(result)
    return result

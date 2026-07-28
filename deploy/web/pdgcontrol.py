#!/usr/bin/env python3
"""Sanitized, transactional control adapter for the native PDG web UI.

This module deliberately contains no HTTP or authentication code.  It imports the
existing Telegram bot implementation and reuses its validated operations and
``tx_apply`` transaction entry point.  Canonical PDG configuration files are
never opened for writing here.
"""
from __future__ import annotations

import copy
import hashlib
import importlib
import importlib.util
import ipaddress
import json
import os
import re
import sys
import urllib.parse
from collections import Counter
from dataclasses import dataclass
from typing import Any


_TAG_RE = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")
_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?$"
)
_SAFE_TYPE_RE = re.compile(r"^[a-zA-Z0-9_.-]{1,32}$")
_SAFE_VERSION_RE = re.compile(r"^[A-Za-z0-9_.+:/ -]{1,96}$")
_ROLLBACK_UNIT = "pdg-web-rollback.service"
_PROXY_LINK_RE = re.compile(
    r"(?i)\b(?:ss|ssr|vmess|vless|trojan|hysteria2?|hy2|tuic|anytls|"
    r"shadowtls|socks5?|https?)://[^\s\"'<>]+"
)
_TG_TOKEN_RE = re.compile(r"\b\d{8,10}:[A-Za-z0-9_-]{30,}\b")
_UUID_RE = re.compile(
    r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b"
)
_KEY_VALUE_RE = re.compile(
    r"(?i)(?<![A-Za-z0-9])("
    r"(?:[A-Za-z0-9]+[-_])*"
    r"(?:password|passwd|secret|token|uuid|psk|private[-_]?key|"
    r"authorization|credentials?|api[-_]?key|access[-_]?key|"
    r"cookie|session)"
    r")\s*[:=]\s*(?:\"[^\"\r\n]*\"|'[^'\r\n]*'|[^\s\"',}]+)"
)
_SENSITIVE_HEADER_RE = re.compile(
    r"(?i)(?<![A-Za-z0-9])("
    r"(?:proxy[-_])?authorization|(?:set[-_])?cookie"
    r")\s*[:=]\s*[^\r\n]*"
)


class ControlError(Exception):
    """Safe error carrying only a fixed public code/message."""

    status = 500
    code = "operation_failed"
    public_message = "Operation could not be completed."

    def __init__(self, public_message: str | None = None):
        super().__init__(public_message or self.public_message)
        if public_message is not None:
            self.public_message = public_message


class ValidationError(ControlError):
    status = 400
    code = "invalid_request"
    public_message = "Request data is invalid."


class NotFoundError(ControlError):
    status = 404
    code = "not_found"
    public_message = "The requested item was not found."


class ConflictError(ControlError):
    status = 409
    code = "conflict"
    public_message = "The requested change conflicts with current configuration."


class BusyError(ControlError):
    status = 409
    code = "configuration_busy"
    public_message = "Another configuration operation is in progress."


class UnavailableError(ControlError):
    status = 503
    code = "unavailable"
    public_message = "The requested operation is temporarily unavailable."


@dataclass(frozen=True)
class ActionResult:
    action: str
    accepted: bool = True
    details: dict[str, Any] | None = None

    def view(self) -> dict[str, Any]:
        out: dict[str, Any] = {"action": self.action, "accepted": self.accepted}
        if self.details:
            out.update(self.details)
        return out


def _load_module_from_path(path: str):
    path = os.path.abspath(path)
    if not os.path.isfile(path):
        raise RuntimeError("PDG bot module is unavailable")
    name = "_pdg_web_bot_" + hashlib.sha256(path.encode()).hexdigest()[:12]
    old = sys.modules.get(name)
    if old is not None:
        return old
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError("PDG bot module cannot be loaded")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    module_dir = os.path.dirname(path)
    if module_dir not in sys.path:
        sys.path.insert(0, module_dir)
    try:
        spec.loader.exec_module(module)
    except BaseException:
        sys.modules.pop(name, None)
        raise
    return module


def load_bot_module():
    """Load the deployed bot, an explicit test override, or the repo copy."""

    override = os.environ.get("PDG_BOT_MODULE", "").strip()
    if override:
        if os.path.isfile(override) or os.path.sep in override or (
                os.path.altsep and os.path.altsep in override):
            return _load_module_from_path(override)
        return importlib.import_module(override)

    deployed = "/opt/pdg-bot/bot.py"
    if os.path.isfile(deployed):
        return _load_module_from_path(deployed)
    fallback = os.path.abspath(
        os.path.join(os.path.dirname(__file__), "..", "bot", "pdg-bot.py")
    )
    return _load_module_from_path(fallback)


def _safe_text(value: Any, limit: int = 128) -> str:
    text = str(value or "")
    text = "".join(ch for ch in text if ch >= " " and ch not in "\x7f")
    return text[:limit]


def _tag(value: Any, *, field: str = "tag") -> str:
    if not isinstance(value, str) or not _TAG_RE.fullmatch(value):
        raise ValidationError(f"{field} is invalid.")
    return value


def _domain(value: Any) -> str:
    if not isinstance(value, str):
        raise ValidationError("domain is invalid.")
    value = value.strip().lstrip(".").lower()
    if not _DOMAIN_RE.fullmatch(value):
        raise ValidationError("domain is invalid.")
    return value


def _string(value: Any, *, field: str, maximum: int, allow_empty: bool = False) -> str:
    if not isinstance(value, str):
        raise ValidationError(f"{field} is invalid.")
    value = value.strip()
    if (not value and not allow_empty) or len(value) > maximum:
        raise ValidationError(f"{field} is invalid.")
    if any(ord(ch) < 32 or ord(ch) == 127 for ch in value):
        raise ValidationError(f"{field} is invalid.")
    return value


def _bool(value: Any, *, field: str) -> bool:
    if type(value) is not bool:
        raise ValidationError(f"{field} is invalid.")
    return value


def _dict_keys(body: Any, *, allowed: set[str], required: set[str] = frozenset()):
    if not isinstance(body, dict):
        raise ValidationError()
    keys = set(body)
    if not required.issubset(keys) or not keys.issubset(allowed):
        raise ValidationError()


def _safe_host(value: Any) -> str | None:
    if not isinstance(value, str) or not value or len(value) > 253:
        return None
    value = value.strip()
    try:
        ipaddress.ip_address(value.strip("[]"))
        return value
    except ValueError:
        pass
    if re.fullmatch(r"[A-Za-z0-9.-]+", value):
        return value[:253]
    return None


def _safe_endpoint(addr: Any) -> str:
    """Return a display-only endpoint without credentials or opaque URL paths."""

    if not isinstance(addr, str):
        return "configured"
    value = addr.strip()
    if not value:
        return "configured"
    if "://" not in value:
        host = value.rsplit("@", 1)[-1]
        return _safe_text(host, 128) if re.fullmatch(r"[A-Za-z0-9.:[\]-]+", host) else "configured"
    try:
        parsed = urllib.parse.urlsplit(value)
        host = parsed.hostname
        if not host or parsed.scheme.lower() not in (
                "udp", "tcp", "tls", "https", "http", "quic", "h3"):
            return "configured"
        shown_host = f"[{host}]" if ":" in host else host
        port = f":{parsed.port}" if parsed.port is not None else ""
        path = parsed.path or ""
        if path:
            safe_path = urllib.parse.unquote(path)
            path = safe_path if safe_path in {"/dns-query", "/resolve"} else ""
        return f"{parsed.scheme.lower()}://{shown_host}{port}{path}"
    except (ValueError, UnicodeError):
        return "configured"


def sanitize_log_line(value: Any) -> str:
    """Aggressively redact credentials and proxy links from journal output."""

    text = _safe_text(value, 1000)
    text = _TG_TOKEN_RE.sub("<redacted>", text)
    text = _UUID_RE.sub("<redacted>", text)
    text = _PROXY_LINK_RE.sub("<redacted-link>", text)
    text = _SENSITIVE_HEADER_RE.sub(
        lambda match: match.group(1) + "=<redacted>", text)
    text = _KEY_VALUE_RE.sub(lambda m: m.group(1) + "=<redacted>", text)
    text = re.sub(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]{8,}", "Bearer <redacted>", text)
    return text[:600]


class PDGControl:
    """Business operations for the frozen ``/api/v1`` surface."""

    def __init__(self, bot_module=None):
        self.bot = bot_module or load_bot_module()

    # ---- common ---------------------------------------------------------
    def _load(self) -> dict[str, Any]:
        try:
            model = self.bot.load()
        except Exception as exc:
            raise UnavailableError() from exc
        if not isinstance(model, dict):
            raise UnavailableError()
        return model

    def _meta(self) -> dict[str, dict[str, Any]]:
        try:
            meta = self.bot._rs_meta()
        except Exception:
            return {}
        return meta if isinstance(meta, dict) else {}

    def _busy(self, message: Any) -> bool:
        return message in {
            getattr(self.bot, "BUSY_MSG", object()),
            getattr(self.bot, "NOLOCK_MSG", object()),
        }

    def _result(self, result: Any) -> None:
        try:
            ok, message = result
        except Exception as exc:
            raise ControlError() from exc
        if ok:
            return
        if self._busy(message):
            raise BusyError()
        raise ControlError()

    def _tx(self, op: str, **kwargs: Any) -> None:
        fn = getattr(self.bot, "tx_apply", None)
        if not callable(fn):
            raise UnavailableError()
        self._result(fn(op, **kwargs))

    def _service_states(self) -> dict[str, str]:
        states: dict[str, str] = {}
        for unit in ("mosdns", "mihomo", "pdg-bot", "pdg-web"):
            try:
                result = self.bot.sh(["systemctl", "is-active", unit])
                value = str(getattr(result, "stdout", "")).strip().splitlines()[0]
            except Exception:
                value = "unknown"
            states[unit] = value if value in (
                "active", "inactive", "failed", "activating", "deactivating") else "unknown"
        return states

    # ---- sanitized reads ------------------------------------------------
    def _exit_items(self, model: dict[str, Any] | None = None) -> list[dict[str, Any]]:
        model = self._load() if model is None else model
        final = (model.get("route") or {}).get("final")
        out: list[dict[str, Any]] = []
        proxy_types = set(getattr(self.bot, "PROXY_TYPES", ()))
        for position, item in enumerate(model.get("outbounds") or []):
            if not isinstance(item, dict):
                continue
            tag = item.get("tag")
            typ = item.get("type")
            if not isinstance(tag, str) or not _TAG_RE.fullmatch(tag):
                continue
            if not isinstance(typ, str) or not _SAFE_TYPE_RE.fullmatch(typ):
                typ = "unknown"
            kind = "group" if typ == "urltest" else ("direct" if typ == "direct" else "proxy")
            if typ not in proxy_types | {"urltest", "direct"}:
                kind = "other"
            view: dict[str, Any] = {
                "tag": tag,
                "type": typ,
                "kind": kind,
                "position": position,
                "isDefault": tag == final,
                "editable": kind in {"proxy", "group"},
                "deletable": kind in {"proxy", "group"},
            }
            host = _safe_host(item.get("server"))
            port = item.get("server_port")
            if host is not None:
                view["server"] = host
            if type(port) is int and 0 < port <= 65535:
                view["server_port"] = port
            if kind == "group":
                view["members"] = [
                    member for member in item.get("outbounds", [])
                    if isinstance(member, str) and _TAG_RE.fullmatch(member)
                ][:64]
            out.append(view)
        return out

    @staticmethod
    def _public_exit_item(item: dict[str, Any]) -> dict[str, Any]:
        """Project internal bookkeeping fields out of the public API."""

        view: dict[str, Any] = {
            "tag": item["tag"],
            "type": item["type"],
        }
        for key in ("server", "server_port", "members"):
            if key in item:
                view[key] = item[key]
        return view

    def exits(self) -> dict[str, Any]:
        model = self._load()
        internal_items = self._exit_items(model)
        items = [self._public_exit_item(item) for item in internal_items]
        route = model.get("route") or {}
        try:
            targets = [
                value for value in self.bot.exit_tags(model)
                if isinstance(value, str) and _TAG_RE.fullmatch(value)
            ]
        except Exception:
            targets = [
                item["tag"] for item in internal_items if item["kind"] != "other"
            ]
        return {
            "items": items,
            "order": [item["tag"] for item in items],
            "default": _safe_text(route.get("final"), 64),
            "targets": targets,
        }

    def _group_items(
            self, model: dict[str, Any] | None = None) -> list[dict[str, Any]]:
        return [
            {"tag": item["tag"], "members": item.get("members", [])}
            for item in self._exit_items(model) if item["kind"] == "group"
        ]

    def groups(self) -> dict[str, Any]:
        return {"items": self._group_items()}

    def _rule_items(self) -> list[dict[str, Any]]:
        model = self._load()
        rows: list[dict[str, Any]] = []
        seen: set[str] = set()
        for rule in (model.get("route") or {}).get("rules") or []:
            if not isinstance(rule, dict) or "outbound" not in rule or rule.get("rule_set"):
                continue
            outbound = rule.get("outbound")
            if not isinstance(outbound, str) or not _TAG_RE.fullmatch(outbound):
                continue
            for kind, key in (("suffix", "domain_suffix"), ("exact", "domain")):
                for value in rule.get(key) or []:
                    if isinstance(value, str) and _DOMAIN_RE.fullmatch(value) and value not in seen:
                        rows.append({"domain": value, "target": outbound, "kind": kind})
                        seen.add(value)
        try:
            direct = self.bot._read_direct()
        except Exception:
            direct = []
        for value in direct:
            if isinstance(value, str) and _DOMAIN_RE.fullmatch(value) and value not in seen:
                rows.append({"domain": value, "target": "direct", "kind": "direct"})
                seen.add(value)
        return rows

    def _targets(self, *, include_direct: bool = True) -> list[str]:
        model = self._load()
        try:
            values = [
                value for value in self.bot.exit_tags(model)
                if isinstance(value, str) and _TAG_RE.fullmatch(value)
            ]
        except Exception:
            values = []
        if include_direct and "direct" not in values:
            values.insert(0, "direct")
        return values

    def rules(self) -> dict[str, Any]:
        return {"items": self._rule_items(), "targets": self._targets()}

    def _ruleset_items(self) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        for name, item in self._meta().items():
            if not isinstance(name, str) or not _TAG_RE.fullmatch(name) or not isinstance(item, dict):
                continue
            view: dict[str, Any] = {
                "name": name,
                "label": _safe_text(item.get("label") or name, 40),
                "target": (
                    item.get("outbound")
                    if isinstance(item.get("outbound"), str)
                    and _TAG_RE.fullmatch(item["outbound"])
                    else "unknown"
                ),
                "url": _safe_endpoint(item.get("url")),
            }
            behavior = item.get("behavior")
            if behavior in {"domain", "ipcidr", "classical"}:
                view["behavior"] = behavior
            out.append(view)
        return out

    def rulesets(self) -> dict[str, Any]:
        return {"items": self._ruleset_items()}

    def dns(self) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for which in ("remote", "local"):
            try:
                values = self.bot._upstreams(which)
            except Exception:
                values = []
            result[which] = [_safe_endpoint(value) for value in values[:8]]
        return result

    def settings(self) -> dict[str, Any]:
        model = self._load()
        try:
            tfo = bool(self.bot._tfo_on(model))
        except Exception:
            tfo = False
        try:
            platform = self.bot._platform()
        except Exception:
            platform = "unknown"
        if platform not in {"ios", "android"}:
            platform = "unknown"
        def profile_choice(key: str, allowed: set[str]) -> str:
            try:
                value = self.bot._profile_get(key, "")
            except Exception:
                value = ""
            return value if value in allowed else "unknown"
        return {
            "tfo": tfo,
            "hijack_mode": profile_choice("PDG_HIJACK_MODE", {"all", "gfw"}),
            "quic_mode": profile_choice("PDG_QUIC_MODE", {"tproxy", "reject"}),
            "firewall_mode": profile_choice(
                "PDG_FIREWALL_MODE", {"managed", "external"}),
        }

    def overview(self) -> dict[str, Any]:
        self._load()
        try:
            dot_host = _safe_text(self.bot._dot_host(), 253)
        except Exception:
            dot_host = "unknown"
        try:
            server_ip = _safe_text(self.bot._server_ip(), 64)
            ipaddress.ip_address(server_ip)
        except (Exception, ValueError):
            server_ip = "unknown"
        try:
            platform = self.bot._platform()
        except Exception:
            platform = "unknown"
        if platform not in {"ios", "android"}:
            platform = "unknown"
        version = "unknown"
        try:
            result = self.bot._git("describe", "--tags", "--always")
            candidate = str(getattr(result, "stdout", "")).strip()
            if _SAFE_VERSION_RE.fullmatch(candidate):
                version = candidate
        except Exception:
            pass
        doctor: Any
        try:
            checks = importlib.import_module("checks")
            raw_results = checks.run()
            doctor = [
                {
                    "level": level if level in {"ok", "warn", "fail"} else "warn",
                    "check": _safe_text(label, 80),
                    "detail": sanitize_log_line(detail),
                }
                for level, label, detail in list(raw_results)[:50]
            ]
        except Exception:
            try:
                doctor = sanitize_log_line(self.bot.doctor_text())
            except Exception:
                doctor = "unavailable"
        return {
            "status": self._service_states(),
            "doctor": doctor,
            "version": version,
            "platform": platform,
            "dot_domain": dot_host,
        }

    def logs(self, line_limit: int = 100) -> dict[str, Any]:
        if type(line_limit) is not int or not 10 <= line_limit <= 200:
            raise ValidationError("lines is invalid.")
        lines: list[str] = []
        for unit in ("mosdns", "mihomo", "pdg-bot", "pdg-web"):
            try:
                result = self.bot.sh([
                    "journalctl", "-u", unit, "-n", "50", "--no-pager",
                    "--output=short-iso",
                ])
                raw = str(getattr(result, "stdout", ""))
            except Exception:
                raw = ""
            for line in raw.splitlines()[-50:]:
                clean = sanitize_log_line(line)
                if clean:
                    lines.append(clean)
        return {"lines": lines[-line_limit:]}

    def _connection_summary(self) -> dict[str, Any]:
        try:
            data = self.bot.clash_get("/connections")
        except Exception:
            return {"available": False, "connections": 0, "uploadTotal": 0, "downloadTotal": 0,
                    "byExit": []}
        if not isinstance(data, dict):
            data = {}
        counts: Counter[str] = Counter()
        uploads: Counter[str] = Counter()
        downloads: Counter[str] = Counter()
        connections = data.get("connections")
        if not isinstance(connections, list):
            connections = []
        for conn in connections[:10000]:
            if not isinstance(conn, dict):
                continue
            chains = conn.get("chains")
            tag = chains[0] if isinstance(chains, list) and chains else "unknown"
            if not isinstance(tag, str) or not _TAG_RE.fullmatch(tag):
                tag = "unknown"
            counts[tag] += 1
            up = conn.get("upload")
            down = conn.get("download")
            if type(up) is int and 0 <= up <= (1 << 63):
                uploads[tag] += up
            if type(down) is int and 0 <= down <= (1 << 63):
                downloads[tag] += down
        by_exit = [
            {"tag": tag, "connections": count, "upload": uploads[tag], "download": downloads[tag]}
            for tag, count in counts.most_common(128)
        ]
        upload_total = data.get("uploadTotal")
        download_total = data.get("downloadTotal")
        return {
            "available": True,
            "connections": len(connections),
            "uploadTotal": upload_total if type(upload_total) is int and upload_total >= 0 else 0,
            "downloadTotal": download_total if type(download_total) is int and download_total >= 0 else 0,
            "byExit": by_exit,
        }

    def traffic(self) -> dict[str, Any]:
        return self._connection_summary()

    def runtime(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "backend": "mihomo",
            "services": self._service_states(),
            "traffic": self._connection_summary(),
        }
        try:
            version = self.bot.clash_get("/version")
            value = version.get("version") if isinstance(version, dict) else None
            if isinstance(value, str) and _SAFE_VERSION_RE.fullmatch(value):
                out["version"] = value
        except Exception:
            pass
        try:
            memory = self.bot.clash_get("/memory")
            if isinstance(memory, dict):
                value = memory.get("inuse")
                if type(value) is int and 0 <= value <= (1 << 63):
                    out["memory"] = value
        except Exception:
            pass
        return out

    # ---- exits and groups ----------------------------------------------
    def add_exit(self, body: dict[str, Any]) -> dict[str, Any]:
        _dict_keys(body, allowed={"link"}, required={"link"})
        link = _string(body["link"], field="link", maximum=8192)
        try:
            outbound = self.bot.parse_link(link)
        except Exception as exc:
            link = ""
            raise ValidationError("Proxy link is invalid.") from exc
        link = ""
        if not isinstance(outbound, dict):
            raise ValidationError("Proxy link is invalid.")
        tag = outbound.get("tag")
        typ = outbound.get("type")
        if not isinstance(tag, str) or not _TAG_RE.fullmatch(tag):
            raise ValidationError("Proxy link is invalid.")
        if typ not in set(getattr(self.bot, "PROXY_TYPES", ())):
            raise ValidationError("Proxy link is invalid.")
        if any(item["tag"] == tag for item in self._exit_items()):
            raise ConflictError()

        def modify(model):
            if any(item.get("tag") == tag for item in model.get("outbounds", [])):
                raise ValueError("tag conflict")
            model.setdefault("outbounds", []).append(outbound)

        self._tx("web_exit_add", model_mod=modify)
        outbound = {}
        item = next(
            (item for item in self._exit_items() if item["tag"] == tag),
            {"tag": tag, "type": typ},
        )
        return self._public_exit_item(item)

    def rename_exit(self, old: str, body: dict[str, Any]) -> dict[str, Any]:
        old = _tag(old)
        _dict_keys(body, allowed={"name"}, required={"name"})
        new = _tag(body["name"])
        if new == old:
            raise ConflictError()
        fn = getattr(self.bot, "rename_exit", None)
        if not callable(fn):
            raise UnavailableError()
        self._result(fn(old, new))
        item = next(
            (item for item in self._exit_items() if item["tag"] == new),
            {"tag": new, "type": "unknown"},
        )
        return self._public_exit_item(item)

    def _delete_outbound(self, tag: str, *, group_only: bool = False) -> None:
        tag = _tag(tag)
        before = next((item for item in self._exit_items() if item["tag"] == tag), None)
        if before is None or not before["deletable"]:
            raise NotFoundError()
        if group_only and before["kind"] != "group":
            raise NotFoundError()
        files: dict[str, bytes] = {}

        def modify(model):
            outbounds = model.get("outbounds") or []
            target = next((item for item in outbounds if item.get("tag") == tag), None)
            if target is None or target.get("type") == "direct":
                raise ValueError("not deletable")
            if group_only and target.get("type") != "urltest":
                raise ValueError("not group")
            model["outbounds"] = [item for item in outbounds if item.get("tag") != tag]
            for item in model["outbounds"]:
                if item.get("type") == "urltest":
                    item["outbounds"] = [
                        member for member in item.get("outbounds", []) if member != tag
                    ]
            model["outbounds"] = [
                item for item in model["outbounds"]
                if not (item.get("type") == "urltest" and len(item.get("outbounds", [])) < 2)
            ]
            live = {
                item.get("tag") for item in model["outbounds"]
                if isinstance(item, dict) and isinstance(item.get("tag"), str)
            }
            final = (model.get("route") or {}).get("final")
            if final not in live:
                final = next((
                    item.get("tag") for item in model["outbounds"]
                    if item.get("type") in set(getattr(self.bot, "PROXY_TYPES", ())) | {
                        "urltest", "direct"}
                ), None)
                if final is None:
                    raise ValueError("no fallback")
                model.setdefault("route", {})["final"] = final
            for rule in (model.get("route") or {}).get("rules") or []:
                if rule.get("outbound") not in live:
                    rule["outbound"] = final
            meta = copy.deepcopy(self._meta())
            dirty = False
            for value in meta.values():
                if isinstance(value, dict) and value.get("outbound") not in live:
                    value["outbound"] = final
                    dirty = True
            if dirty:
                files["rs_meta"] = json.dumps(
                    meta, ensure_ascii=False, indent=2).encode("utf-8")

        self._tx("web_outbound_delete", model_mod=modify, files=files)

    def delete_exit(self, tag: str) -> dict[str, Any]:
        self._delete_outbound(tag)
        return {"deleted": True}

    def reorder_exits(self, body: dict[str, Any]) -> dict[str, Any]:
        _dict_keys(body, allowed={"order"}, required={"order"})
        order = body["order"]
        if not isinstance(order, list) or not 1 <= len(order) <= 128:
            raise ValidationError()
        tags = [_tag(value) for value in order]
        if len(set(tags)) != len(tags):
            raise ValidationError()
        fn = getattr(self.bot, "reorder_exits", None)
        if not callable(fn):
            raise UnavailableError()
        self._result(fn(tags))
        return self.exits()

    def set_default_exit(self, body: dict[str, Any]) -> dict[str, Any]:
        _dict_keys(body, allowed={"tag"}, required={"tag"})
        tag = _tag(body["tag"])

        def modify(model):
            allowed = set(self.bot.exit_tags(model))
            if tag not in allowed:
                raise ValueError("unknown exit")
            model.setdefault("route", {})["final"] = tag

        self._tx("web_default_exit", model_mod=modify)
        return {"tag": tag}

    def add_group(self, body: dict[str, Any]) -> dict[str, Any]:
        _dict_keys(body, allowed={"name", "members"}, required={"name", "members"})
        tag = _tag(body["name"])
        members = self._members(body["members"])
        fn = getattr(self.bot, "add_group", None)
        if not callable(fn):
            raise UnavailableError()
        self._result(fn(tag, members))
        return next((item for item in self._group_items() if item["tag"] == tag),
                    {"tag": tag, "members": members})

    def _members(self, value: Any) -> list[str]:
        if not isinstance(value, list) or not 2 <= len(value) <= 64:
            raise ValidationError("members is invalid.")
        members = [_tag(item, field="member") for item in value]
        if len(set(members)) != len(members):
            raise ValidationError("members is invalid.")
        return members

    def patch_group(self, old: str, body: dict[str, Any]) -> dict[str, Any]:
        old = _tag(old)
        _dict_keys(body, allowed={"members"}, required={"members"})
        members = self._members(body["members"])
        current = next((item for item in self._group_items() if item["tag"] == old), None)
        if current is None:
            raise NotFoundError()
        fn = getattr(self.bot, "add_group", None)
        if not callable(fn):
            raise UnavailableError()
        self._result(fn(old, members))
        return next((item for item in self._group_items() if item["tag"] == old),
                    {"tag": old, "members": members})

    def delete_group(self, tag: str) -> dict[str, Any]:
        self._delete_outbound(tag, group_only=True)
        return {"deleted": True}

    # ---- rules ----------------------------------------------------------
    def add_rule(self, body: dict[str, Any]) -> dict[str, Any]:
        _dict_keys(body, allowed={"domain", "target"}, required={"domain", "target"})
        domain = _domain(body["domain"])
        target = _string(body["target"], field="target", maximum=64)
        if target != "direct":
            target = _tag(target, field="target")
        if any(item["domain"] == domain for item in self._rule_items()):
            raise ConflictError()
        fn = getattr(self.bot, "add_rule", None)
        if not callable(fn):
            raise UnavailableError()
        self._result(fn(domain, target))
        return {"domain": domain, "target": target}

    def patch_rule(self, old: str, body: dict[str, Any]) -> dict[str, Any]:
        old = _domain(old)
        _dict_keys(body, allowed={"target"}, required={"target"})
        current = next((item for item in self._rule_items() if item["domain"] == old), None)
        if current is None:
            raise NotFoundError()
        target = _string(body["target"], field="target", maximum=64)
        if target != "direct":
            target = _tag(target, field="target")
        files: dict[str, bytes] = {}
        file_expects: dict[str, str | None] = {}
        snapshot = getattr(self.bot, "_domain_file_snapshot", None)
        direct_path = getattr(self.bot, "MOSDNS_DIRECT", None)
        hijack_path = getattr(self.bot, "MOSDNS_HIJACK", None)
        if (
                not callable(snapshot) or not isinstance(direct_path, str)
                or not isinstance(hijack_path, str)):
            raise UnavailableError()

        def modify(model):
            allowed = set(self.bot.exit_tags(model))
            if target != "direct" and target not in allowed:
                raise ValueError("unknown exit")
            rules = (model.get("route") or {}).get("rules") or []
            found = False
            domain_key = "domain_suffix"
            for rule in rules:
                for key in ("domain_suffix", "domain"):
                    if old in (rule.get(key) or []):
                        rule[key] = [item for item in rule[key] if item != old]
                        if key == "domain":
                            domain_key = "domain"
                        found = True
            model["route"]["rules"] = [
                rule for rule in rules
                if rule.get("action") or "outbound" not in rule or rule.get("rule_set")
                or rule.get("domain_suffix") or rule.get("domain")
                or rule.get("domain_keyword") or rule.get("ip_cidr")
            ]
            direct, direct_sha = snapshot(direct_path)
            hijack, hijack_sha = snapshot(hijack_path)
            direct = list(direct)
            hijack = list(hijack)
            if old in direct:
                direct = [item for item in direct if item != old]
                found = True
            if old in hijack:
                hijack = [item for item in hijack if item != old]
            if not found:
                raise ValueError("rule disappeared")
            if target == "direct":
                direct.append(old)
                hijack = [item for item in hijack if item != old]
            else:
                hijack.append(old)
                direct = [item for item in direct if item != old]
                existing = next((
                    rule for rule in model["route"]["rules"]
                    if rule.get("outbound") == target and not rule.get("rule_set")
                    and rule.get(domain_key) is not None
                ), None)
                if existing is None:
                    index = 1 if (model["route"]["rules"]
                                  and model["route"]["rules"][0].get("action") == "reject") else 0
                    model["route"]["rules"].insert(
                        index, {domain_key: [old], "outbound": target})
                else:
                    existing.setdefault(domain_key, [])
                    if old not in existing[domain_key]:
                        existing[domain_key].append(old)
            files["mosdns_rule:custom_direct.txt"] = self.bot._direct_text(direct)
            files["mosdns_rule:custom_hijack.txt"] = self.bot._hijack_text(hijack)
            file_expects["mosdns_rule:custom_direct.txt"] = direct_sha
            file_expects["mosdns_rule:custom_hijack.txt"] = hijack_sha

        self._tx(
            "web_rule_patch",
            model_mod=modify,
            files=files,
            file_expects=file_expects,
        )
        return {"domain": old, "target": target}

    def delete_rule(self, domain: str) -> dict[str, Any]:
        domain = _domain(domain)
        if not any(item["domain"] == domain for item in self._rule_items()):
            raise NotFoundError()
        fn = getattr(self.bot, "del_rule", None)
        if not callable(fn):
            raise UnavailableError()
        self._result(fn(domain))
        return {"deleted": True}

    # ---- rule sets ------------------------------------------------------
    def add_ruleset(self, body: dict[str, Any]) -> dict[str, Any]:
        _dict_keys(
            body, allowed={"url", "target", "label", "behavior"},
            required={"url", "target"})
        url = _string(body["url"], field="url", maximum=2048)
        try:
            parsed = urllib.parse.urlsplit(url)
        except ValueError as exc:
            raise ValidationError("url is invalid.") from exc
        if parsed.scheme not in {"https", "http"} or not parsed.hostname:
            raise ValidationError("url is invalid.")
        target = _tag(body["target"], field="target")
        label = _string(
            body.get("label", ""), field="label", maximum=40, allow_empty=True)
        behavior = body.get("behavior", "")
        if behavior not in {"", "domain", "ipcidr", "classical"}:
            raise ValidationError("behavior is invalid.")
        fn = getattr(self.bot, "add_ruleset", None)
        if not callable(fn):
            raise UnavailableError()
        self._result(fn(url, target, label, behavior))
        name = "rs_" + hashlib.sha1(url.encode()).hexdigest()[:8]
        url = ""
        return next((item for item in self._ruleset_items() if item["name"] == name),
                    {"name": name, "label": label or name, "target": target})

    def patch_ruleset(self, name: str, body: dict[str, Any]) -> dict[str, Any]:
        name = _tag(name, field="name")
        _dict_keys(body, allowed={"label"}, required={"label"})
        current = self._meta().get(name)
        if not isinstance(current, dict):
            raise NotFoundError()
        label = _string(body["label"], field="label", maximum=40, allow_empty=True)
        fn = getattr(self.bot, "set_ruleset_label", None)
        if not callable(fn):
            raise UnavailableError()
        self._result(fn(name, label))
        return next((item for item in self._ruleset_items() if item["name"] == name),
                    {"name": name})

    def delete_ruleset(self, name: str) -> dict[str, Any]:
        name = _tag(name, field="name")
        if name not in self._meta():
            raise NotFoundError()
        fn = getattr(self.bot, "del_ruleset", None)
        if not callable(fn):
            raise UnavailableError()
        self._result(fn(name))
        return {"deleted": True}

    # ---- DNS/settings/actions -----------------------------------------
    def set_dns(self, which: str, body: dict[str, Any]) -> dict[str, Any]:
        if which not in {"remote", "local"}:
            raise NotFoundError()
        _dict_keys(body, allowed={"addresses"}, required={"addresses"})
        values = body["addresses"]
        if not isinstance(values, list) or not 1 <= len(values) <= 8:
            raise ValidationError("upstreams is invalid.")
        upstreams = [
            _string(value, field="upstream", maximum=512) for value in values
        ]
        fn = getattr(self.bot, "set_mosdns_upstream", None)
        if not callable(fn):
            raise UnavailableError()
        self._result(fn(which, upstreams))
        upstreams = []
        return self.dns()

    def set_tfo(self, body: dict[str, Any]) -> dict[str, Any]:
        _dict_keys(body, allowed={"enabled"}, required={"enabled"})
        enabled = _bool(body["enabled"], field="enabled")
        fn = getattr(self.bot, "set_tfo", None)
        if not callable(fn):
            raise UnavailableError()
        self._result(fn(enabled))
        return {"enabled": enabled}

    def action(self, action: str, body: dict[str, Any]) -> dict[str, Any]:
        if action in {"restart", "rules-update", "snapshot"}:
            _dict_keys(body, allowed=set())
        elif action == "rollback":
            _dict_keys(body, allowed={"index"}, required={"index"})
            index = body["index"]
            if type(index) is not int or not 0 <= index <= 10000:
                raise ValidationError("index is invalid.")
        elif action == "software-update":
            _dict_keys(body, allowed={"confirm"}, required={"confirm"})
            if body["confirm"] is not True:
                raise ValidationError("confirm must be true.")
        else:
            raise NotFoundError()
        if action == "restart":
            self._tx("web_restart", services=("mihomo", "mosdns"))
            return ActionResult(action).view()
        if action == "rules-update":
            script = getattr(self.bot, "UPDATE_SCRIPT", "/opt/pdg-bot/update-rules.sh")
            try:
                result = self.bot.sh(["/bin/bash", script])
            except Exception as exc:
                raise ControlError() from exc
            if getattr(result, "returncode", 1) != 0:
                raise ControlError()
            fn = getattr(self.bot, "refresh_rulesets", None)
            if not callable(fn):
                raise UnavailableError()
            try:
                refreshed, failed = fn()
            except Exception as exc:
                raise ControlError() from exc
            if not isinstance(refreshed, int) or isinstance(refreshed, bool) or refreshed < 0:
                raise ControlError()
            if isinstance(failed, (list, tuple)):
                failed_count = len(failed)
            elif failed in (None, False):
                failed_count = 0
            else:
                failed_count = 1
            if failed_count:
                raise ControlError(
                    "Rule update finished with one or more failed sources; "
                    "valid previous copies remain in use."
                )
            return ActionResult(action, details={
                "refreshed": refreshed,
                "failed": 0,
            }).view()
        if action == "snapshot":
            cli = os.environ.get("PDG_CLI", "/usr/local/bin/pdg")
            try:
                result = self.bot.sh([cli, "snapshot"])
            except Exception as exc:
                raise ControlError() from exc
            if getattr(result, "returncode", 1) != 0:
                raise ControlError()
            return ActionResult(action).view()
        if action == "rollback":
            argv = [
                "systemd-run",
                "--collect",
                "--unit=" + _ROLLBACK_UNIT,
                "--",
                "/usr/local/bin/pdg",
                "rollback",
                str(index),
            ]
            try:
                result = self.bot.sh(argv)
            except Exception as exc:
                raise ControlError() from exc
            if getattr(result, "returncode", 1) != 0:
                raise ControlError()
            return ActionResult(action).view()
        if action == "software-update":
            check = getattr(self.bot, "update_check", None)
            start = getattr(self.bot, "start_update", None)
            if not callable(check) or not callable(start):
                raise UnavailableError()
            try:
                checked = check()
            except Exception as exc:
                raise ControlError() from exc
            if (
                not isinstance(checked, (tuple, list))
                or len(checked) != 2
                or checked[0] is not True
            ):
                raise ControlError()
            checked = None
            try:
                accepted = start()
            except Exception as exc:
                raise ControlError() from exc
            if accepted is not True:
                raise ControlError()
            return ActionResult(action).view()
        raise NotFoundError()

#!/usr/bin/env python3
"""Sanitized, transactional control adapter for the native PDG web UI.

This module deliberately contains no HTTP or authentication code.  It imports the
existing Telegram bot implementation and reuses its validated operations and
``tx_apply`` transaction entry point.  Canonical PDG configuration files are
never opened for writing here.
"""
from __future__ import annotations

import copy
import contextlib
import hashlib
import importlib
import importlib.util
import ipaddress
import json
import os
import re
import sys
import threading
import unicodedata
import urllib.parse
from collections import Counter
from dataclasses import dataclass
from typing import Any


_MACHINE_TAG_RE = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")
_DANGEROUS_NAME_CODEPOINTS = frozenset({
    0x00AD, 0x034F, 0x061C, 0x115F, 0x1160, 0x17B4, 0x17B5,
    0x180E, 0x200B, 0x200E, 0x200F, 0x202A, 0x202B, 0x202C,
    0x202D, 0x202E, 0x2060, 0x2061, 0x2062, 0x2063, 0x2064,
    0x2066, 0x2067, 0x2068, 0x2069, 0x206A, 0x206B, 0x206C,
    0x206D, 0x206E, 0x206F, 0x3164, 0xFEFF, 0xFFA0,
})
_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?$"
)
_SAFE_TYPE_RE = re.compile(r"^[a-zA-Z0-9_.-]{1,32}$")
_SAFE_VERSION_RE = re.compile(r"^[A-Za-z0-9_.+:/ -]{1,96}$")
_MIHOMO_RESERVED = frozenset({
    "DIRECT", "REJECT", "REJECT-DROP", "PASS", "PASS-RULE", "COMPATIBLE",
    "GLOBAL",
})
_JOB_ID_RE = re.compile(r"^[0-9]{8}t[0-9]{6}z-[a-f0-9]{12}$")
_SNAPSHOT_ID_RE = re.compile(
    r"^[0-9]{8}-[0-9]{6}(?:-[a-f0-9]{8})?$")
_UTC_TIME_RE = re.compile(
    r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$")
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


def load_job_module():
    """Load the colocated maintenance runner without relying on its hyphenated name."""

    path = os.path.abspath(os.path.join(
        os.path.dirname(__file__), "pdg-web-job.py"))
    return _load_module_from_path(path)


def load_config_io_module():
    path = os.path.abspath(os.path.join(
        os.path.dirname(__file__), "pdgconfigio.py"))
    return _load_module_from_path(path)


def _safe_text(value: Any, limit: int = 128) -> str:
    text = str(value or "")
    text = "".join(ch for ch in text if ch >= " " and ch not in "\x7f")
    return text[:limit]


def _name_public_message(reason: str | None = None) -> str:
    return {
        "length": "名称必须为 1–64 个 Unicode 字符，且不超过 256 个 UTF-8 字节。",
        "unsafe": "名称不能包含换行、控制字符、双向控制符或危险隐形字符。",
        "canonical": "名称必须使用 NFC 规范形式且首尾不能有空白。",
        "encoding": "名称必须是有效的 UTF-8 文本。",
        "type": "名称必须是文本。",
    }.get(reason, "名称无效。")


def _normalize_name_fallback(value: Any, *, field: str = "tag") -> str:
    """Test-double fallback; production delegates to the shared pdgmodel helper."""
    if not isinstance(value, str):
        raise ValidationError(_name_public_message("type"))
    canonical = unicodedata.normalize("NFC", value)
    for ch in canonical:
        codepoint = ord(ch)
        category = unicodedata.category(ch)
        if (codepoint < 0x20 or 0x7F <= codepoint <= 0x9F
                or category in {"Cs", "Zl", "Zp"}
                or (category == "Cf" and codepoint != 0x200D)
                or codepoint in _DANGEROUS_NAME_CODEPOINTS):
            raise ValidationError(_name_public_message("unsafe"))
    name = canonical.strip()
    try:
        encoded = name.encode("utf-8", "strict")
    except UnicodeEncodeError as exc:
        raise ValidationError(_name_public_message("encoding")) from exc
    if not name or len(name) > 64 or len(encoded) > 256:
        raise ValidationError(_name_public_message("length"))
    return name


def _valid_name(value: Any) -> bool:
    try:
        return _normalize_name_fallback(value) == value
    except ValidationError:
        return False


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

    def __init__(self, bot_module=None, job_store=None, config_io=None):
        self.bot = bot_module or load_bot_module()
        self._job_store_instance = job_store
        self._config_io_instance = config_io
        # These services are normally initialized by the first HTTP request.
        # ThreadingHTTPServer can run several such requests at once after a
        # restart, so publication must be atomic.  In particular, every
        # ConfigIO owns a preview semaphore and a janitor thread; publishing
        # more than one would split both process-wide coordination domains.
        self._job_store_init_lock = threading.Lock()
        self._config_io_init_lock = threading.Lock()
        self._diagnostic_slots = threading.BoundedSemaphore(1)

    def _name(self, value: Any, *, field: str = "name") -> str:
        helper = getattr(getattr(self.bot, "pdgmodel", None), "normalize_name", None)
        try:
            return (helper(value, field) if callable(helper)
                    else _normalize_name_fallback(value, field=field))
        except (TypeError, ValueError) as exc:
            raise ValidationError(
                _name_public_message(getattr(exc, "reason", None))) from exc

    def _tag(self, value: Any, *, field: str = "tag") -> str:
        name = self._name(value, field=field)
        if name in _MIHOMO_RESERVED:
            raise ValidationError("名称与系统保留名称冲突。")
        return name

    def _valid_name(self, value: Any) -> bool:
        helper = getattr(getattr(self.bot, "pdgmodel", None), "is_valid_name", None)
        if callable(helper):
            try:
                return bool(helper(value))
            except (TypeError, ValueError):
                return False
        return _valid_name(value)

    # ---- common ---------------------------------------------------------
    def _load(self) -> dict[str, Any]:
        try:
            model = self.bot.load()
        except Exception as exc:
            raise UnavailableError() from exc
        if not isinstance(model, dict):
            raise UnavailableError()
        return model

    def _routable_tags_unchecked(self, model: dict[str, Any]) -> list[str]:
        """Ordered targets during a delete, before dangling refs are cascaded."""
        helper = getattr(getattr(self.bot, "pdgmodel", None),
                         "routable_tags_unchecked", None)
        if callable(helper):
            return helper(model)
        # Test doubles and an older colocated Bot may not expose the helper.
        # Derive from the same public type inventory without validating the
        # temporary mid-mutation route closure.
        allowed = set(getattr(self.bot, "PROXY_TYPES", ())) | {"direct", "block"}
        values = [item.get("tag") for item in model.get("outbounds", [])
                  if isinstance(item, dict) and item.get("type") in allowed]
        values += [item.get("name") for item in (
            (model.get("_pdg") or {}).get("policy-groups") or [])
                   if isinstance(item, dict)]
        return [value for value in values if isinstance(value, str)]

    def _model_snapshot(self) -> tuple[dict[str, Any], str]:
        """Return one exact model image and the CAS revision of its raw bytes."""
        snapshot = getattr(self.bot, "_model_snapshot", None)
        if not callable(snapshot):
            raise UnavailableError()
        try:
            model, revision = snapshot()
        except Exception as exc:
            raise UnavailableError() from exc
        if (not isinstance(model, dict) or not isinstance(revision, str)
                or re.fullmatch(r"[a-f0-9]{64}", revision) is None):
            raise UnavailableError()
        return model, revision

    def _policy_cas_body(
            self, body: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any], str]:
        if not isinstance(body, dict):
            raise ValidationError()
        candidate = copy.deepcopy(body)
        revision = candidate.pop("revision", None)
        if not isinstance(revision, str) or re.fullmatch(r"[a-f0-9]{64}", revision) is None:
            raise ValidationError("revision is invalid.")
        model, current = self._model_snapshot()
        if revision != current:
            raise ConflictError()
        return candidate, model, revision

    def _legacy_group_cas_body(
            self, body: dict[str, Any] | None
    ) -> tuple[dict[str, Any], dict[str, Any], str, bool]:
        """Pin a legacy group write to the exact snapshot it validated."""
        if body is None:
            candidate: dict[str, Any] = {}
        elif isinstance(body, dict):
            candidate = copy.deepcopy(body)
        else:
            raise ValidationError()
        supplied = "revision" in candidate
        requested = candidate.pop("revision", None)
        if supplied and (not isinstance(requested, str)
                         or re.fullmatch(r"[a-f0-9]{64}", requested) is None):
            raise ValidationError("revision is invalid.")
        model, current = self._model_snapshot()
        if supplied and requested != current:
            raise ConflictError()
        return candidate, model, current, not supplied

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
        if isinstance(message, str) and "PRECONDITION_FAILED" in message:
            raise ConflictError()
        raise ControlError()

    def _tx(self, op: str, **kwargs: Any) -> None:
        fn = getattr(self.bot, "tx_apply", None)
        if not callable(fn):
            raise UnavailableError()
        self._result(fn(op, **kwargs))

    def _job_store(self):
        if self._job_store_instance is not None:
            return self._job_store_instance
        with self._job_store_init_lock:
            if self._job_store_instance is not None:
                return self._job_store_instance
            try:
                store = load_job_module().JobStore()
            except Exception as exc:
                raise UnavailableError() from exc
            self._job_store_instance = store
            return store

    def _config_io(self):
        if self._config_io_instance is not None:
            return self._config_io_instance
        with self._config_io_init_lock:
            if self._config_io_instance is not None:
                return self._config_io_instance
            try:
                io_module = load_config_io_module()
                manager = io_module.ConfigIO(bot=self.bot)
            except Exception as exc:
                raise UnavailableError() from exc
            # Construction happens under the lock, so there is no losing
            # ConfigIO whose bound janitor target could keep it alive.
            self._config_io_instance = manager
            return manager

    @staticmethod
    def _raise_config_io_error(exc: Exception):
        name = type(exc).__name__
        if name == "ImportInvalid":
            raise ValidationError() from exc
        if name in {"ImportNotFound", "ImportExpired"}:
            raise NotFoundError() from exc
        if name == "ImportConflict":
            raise ConflictError() from exc
        raise ControlError() from exc

    @staticmethod
    def _raise_job_error(exc: Exception, *, request_value: bool = False):
        name = type(exc).__name__
        if name == "JobBusy":
            raise BusyError() from exc
        if name == "JobNotFound":
            raise NotFoundError() from exc
        if name == "JobInvalid" and request_value:
            raise ValidationError() from exc
        raise ControlError() from exc

    @contextlib.contextmanager
    def _maintenance_guard(self):
        # The persistent runner is part of the installed Web bundle.  If its
        # root-only state cannot be initialized, proceeding would bypass the
        # active-job gate (rules-update even performs work before pdgtx), so all
        # synchronous maintenance actions fail closed.
        store = self._job_store()
        guard = getattr(store, "maintenance_guard", None)
        if not callable(guard):
            raise UnavailableError()
        try:
            with guard():
                yield
        except ControlError:
            raise
        except Exception as exc:
            self._raise_job_error(exc)

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
            if not self._valid_name(tag):
                continue
            if not isinstance(typ, str) or not _SAFE_TYPE_RE.fullmatch(typ):
                typ = "unknown"
            kind = ("group" if typ in {"urltest", "selector"}
                    else ("direct" if typ == "direct" else "proxy"))
            if typ not in proxy_types | {"urltest", "selector", "direct"}:
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
                    if self._valid_name(member)
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
                if self._valid_name(value)
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
        model = self._load() if model is None else model
        meta = model.get("_pdg") if isinstance(model, dict) else None
        groups = meta.get("policy-groups") if isinstance(meta, dict) else None
        if not isinstance(groups, list):
            groups = []
        if not groups:
            # Read compatibility for a not-yet-migrated in-memory test/backup;
            # all writes still canonicalize through tx_apply before staging.
            return [
                {"name": item["tag"], "tag": item["tag"], "type": (
                    "select" if item.get("type") == "selector" else "url-test"),
                 "proxies": copy.deepcopy(item.get("members", [])),
                 "members": copy.deepcopy(item.get("members", [])), "use": []}
                for item in self._exit_items(model) if item["kind"] == "group"
            ]
        direct = next((item.get("tag") for item in model.get("outbounds", [])
                       if isinstance(item, dict) and item.get("type") == "direct"), None)
        blocks = {item.get("tag") for item in model.get("outbounds", [])
                  if isinstance(item, dict) and item.get("type") == "block"
                  and isinstance(item.get("tag"), str)}
        out = []
        for group in groups:
            if not isinstance(group, dict) or not isinstance(group.get("name"), str):
                continue
            view = {
                "name": group["name"], "tag": group["name"],
                "type": group.get("type", "unknown"),
                "proxies": copy.deepcopy(group.get("proxies") or []),
                "members": copy.deepcopy(group.get("proxies") or []),
                "use": copy.deepcopy(group.get("use") or []),
            }
            for key in ("url", "interval", "tolerance", "strategy", "lazy",
                        "disable-udp", "hidden"):
                if key in group:
                    view[key] = copy.deepcopy(group[key])
            if group.get("type") == "select":
                view["runtimeCandidates"] = []
                try:
                    runtime = self.bot.clash_get(
                        "/proxies/" + urllib.parse.quote(group["name"], safe=""))
                    selected = runtime.get("now") if isinstance(runtime, dict) else None
                    actual_to_public = self._runtime_member_map(
                        runtime, group, direct=direct, blocks=blocks)
                    candidates = list(dict.fromkeys(actual_to_public.values()))
                    # Provider content is outside the canonical model and can
                    # collide with a mapped machine tag.  Refuse an ambiguous
                    # runtime picker instead of selecting the wrong proxy.
                    if len(candidates) != len(actual_to_public):
                        raise ValueError("ambiguous runtime candidates")
                    view["runtimeCandidates"] = candidates
                    public_selected = actual_to_public.get(selected)
                    if public_selected in candidates:
                        view["runtimeSelected"] = public_selected
                except Exception:
                    view["runtimeSelected"] = None
            out.append(view)
        return out

    @staticmethod
    def _runtime_member_map(runtime: Any, group: dict[str, Any], *, direct, blocks):
        """Map Clash's actual candidates to unambiguous PDG-facing names."""
        actual = runtime.get("all") if isinstance(runtime, dict) else None
        if (not isinstance(actual, list) or len(actual) > 512
                or any(not isinstance(item, str) or not 1 <= len(item) <= 256
                       or "\x00" in item or "\r" in item or "\n" in item
                       for item in actual)):
            raise ValueError("invalid Clash candidate list")
        configured = group.get("proxies") or []
        if not isinstance(configured, list):
            raise ValueError("invalid configured candidates")
        mapping = {}
        for item in actual:
            public = item
            if item == "DIRECT" and direct in configured:
                public = direct
            elif item == "REJECT":
                # Literal REJECT is a first-class explicit member.  A machine
                # block tag is only a display alias when that exact tag is in
                # this group; never infer it from the mere existence of block.
                if "REJECT" in configured:
                    public = "REJECT"
                else:
                    aliases = [value for value in configured if value in blocks]
                    if len(aliases) == 1:
                        public = aliases[0]
            mapping[item] = public
        return mapping

    def groups(self) -> dict[str, Any]:
        return {"items": [
            {"tag": item["name"], "members": copy.deepcopy(item["proxies"])}
            for item in self._group_items()
        ]}

    def policy_groups(self) -> dict[str, Any]:
        model, revision = self._model_snapshot()
        metadata = ((model.get("_pdg") or {}).get("mihomo") or {})
        providers = sorted(
            name for name in (metadata.get("proxy-providers") or {})
            if self._valid_name(name))
        return {
            "items": self._group_items(model),
            "targets": [value for value in self.bot.exit_tags(model)
                        if self._valid_name(value)],
            "providers": providers,
            "revision": revision,
        }

    def _rule_items(self) -> list[dict[str, Any]]:
        model = self._load()
        rows: list[dict[str, Any]] = []
        seen: set[str] = set()
        for rule in (model.get("route") or {}).get("rules") or []:
            if not isinstance(rule, dict) or "outbound" not in rule or rule.get("rule_set"):
                continue
            outbound = rule.get("outbound")
            if not self._valid_name(outbound):
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
                if self._valid_name(value)
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
            if not self._valid_name(name) or not isinstance(item, dict):
                continue
            view: dict[str, Any] = {
                "name": name,
                "label": _safe_text(item.get("label") or name, 64),
                "target": (
                    item.get("outbound")
                    if isinstance(item.get("outbound"), str)
                    and self._valid_name(item["outbound"])
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
                    "level": level if level in {"ok", "info", "warn", "fail"} else "warn",
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
            if not self._valid_name(tag):
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

    # ---- persistent maintenance state --------------------------------
    def export_config(self, kind: str) -> tuple[bytes, str, str]:
        if kind not in {"pdg", "mihomo", "mosdns"}:
            raise NotFoundError()
        try:
            with self._maintenance_guard():
                result = self._config_io().export(kind)
        except Exception as exc:
            if isinstance(exc, ControlError):
                raise
            self._raise_config_io_error(exc)
        if (not isinstance(result, tuple) or len(result) != 3
                or not isinstance(result[0], bytes)
                or not isinstance(result[1], str)
                or not isinstance(result[2], str)):
            raise ControlError()
        return result

    def preview_import(
            self, kind: str, payload: bytes, content_type: str) -> dict[str, Any]:
        if kind not in {"pdg", "mihomo", "mosdns"}:
            raise NotFoundError()
        try:
            with self._maintenance_guard():
                result = self._config_io().preview(kind, payload, content_type)
        except Exception as exc:
            if isinstance(exc, ControlError):
                raise
            self._raise_config_io_error(exc)
        if not isinstance(result, dict):
            raise ControlError()
        return result

    def preview_import_stream(
            self, kind: str, stream, size: int,
            content_type: str) -> dict[str, Any]:
        if kind not in {"pdg", "mihomo", "mosdns"}:
            raise NotFoundError()
        try:
            # Acquire the maintenance gate before the first body read.  The
            # guard remains held through parsing and staging so a new durable
            # maintenance job cannot create a torn multi-component preview.
            with self._maintenance_guard():
                result = self._config_io().preview_stream(
                    kind, stream, size, content_type)
        except Exception as exc:
            if isinstance(exc, ControlError):
                raise
            self._raise_config_io_error(exc)
        if not isinstance(result, dict):
            raise ControlError()
        return result

    def apply_import(self, import_id: str, body: dict[str, Any]) -> dict[str, Any]:
        if not isinstance(import_id, str) or not re.fullmatch(
                r"imp-[a-f0-9]{32}", import_id):
            raise ValidationError("importId is invalid.")
        try:
            prepared = self._config_io().prepare_apply(import_id, body)
        except Exception as exc:
            self._raise_config_io_error(exc)
        if not isinstance(prepared, dict) or prepared.get("importId") != import_id:
            raise ControlError()
        store = self._job_store()
        try:
            raw_job = store.start("config-import", import_id=import_id)
        except Exception as exc:
            can_release = getattr(store, "can_release_import", None)
            if callable(can_release) and can_release(import_id):
                try:
                    self._config_io().release_claim(import_id)
                except Exception:
                    pass
            self._raise_job_error(exc, request_value=True)
        job = self._public_job(raw_job)
        if job is None:
            raise ControlError()
        return ActionResult("config-import", details={"job": job}).view()

    def cancel_import(self, import_id: str) -> dict[str, Any]:
        if not isinstance(import_id, str) or not re.fullmatch(
                r"imp-[a-f0-9]{32}", import_id):
            raise ValidationError("importId is invalid.")
        try:
            self._config_io().cancel(import_id)
        except Exception as exc:
            self._raise_config_io_error(exc)
        return ActionResult("config-import-preview-cancelled").view()

    @staticmethod
    def _public_snapshot(item: Any) -> dict[str, Any] | None:
        if not isinstance(item, dict):
            return None
        snapshot_id = item.get("id")
        created = item.get("createdAt")
        size = item.get("size")
        if (
                not isinstance(snapshot_id, str)
                or not _SNAPSHOT_ID_RE.fullmatch(snapshot_id)
                or not isinstance(created, str)
                or not _UTC_TIME_RE.fullmatch(created)
                or type(size) is not int or not 0 < size <= (1 << 63)):
            return None
        return {
            "id": snapshot_id,
            "createdAt": created,
            "size": size,
            "legacy": snapshot_id.count("-") == 1,
        }

    @staticmethod
    def _public_job(item: Any) -> dict[str, Any] | None:
        if not isinstance(item, dict):
            return None
        job_id = item.get("id")
        kind = item.get("kind")
        status = item.get("status")
        created = item.get("createdAt")
        if (
                not isinstance(job_id, str) or not _JOB_ID_RE.fullmatch(job_id)
                or kind not in {"rollback", "software-update", "config-import"}
                or status not in {
                    "queued", "running", "succeeded", "failed", "interrupted"}
                or not isinstance(created, str)
                or not _UTC_TIME_RE.fullmatch(created)):
            return None
        out = {
            "id": job_id,
            "operation": kind,
            "status": status,
            "createdAt": created,
        }
        for source, target in (
                ("startedAt", "startedAt"), ("finishedAt", "finishedAt")):
            value = item.get(source)
            if isinstance(value, str) and _UTC_TIME_RE.fullmatch(value):
                out[target] = value
        snapshot_id = item.get("snapshotId")
        if (
                isinstance(snapshot_id, str)
                and _SNAPSHOT_ID_RE.fullmatch(snapshot_id)):
            out["snapshotId"] = snapshot_id
        return out

    def snapshots(self) -> dict[str, Any]:
        store = self._job_store()
        try:
            raw = store.list_snapshots()
        except Exception as exc:
            self._raise_job_error(exc)
        if not isinstance(raw, list):
            raise ControlError()
        items = [
            public for public in (self._public_snapshot(item) for item in raw[:10])
            if public is not None
        ]
        return {"items": items}

    def jobs(self) -> dict[str, Any]:
        store = self._job_store()
        try:
            raw = store.list()
        except Exception as exc:
            self._raise_job_error(exc)
        if not isinstance(raw, list):
            raise ControlError()
        items = [
            public for public in (self._public_job(item) for item in raw[:50])
            if public is not None
        ]
        return {"items": items}

    def job(self, job_id: str) -> dict[str, Any]:
        if not isinstance(job_id, str) or not _JOB_ID_RE.fullmatch(job_id):
            raise ValidationError("job id is invalid.")
        store = self._job_store()
        try:
            raw = store.get(job_id)
        except Exception as exc:
            self._raise_job_error(exc, request_value=True)
        public = self._public_job(raw)
        if public is None:
            raise ControlError()
        return public

    # ---- bounded, sanitized diagnostics -------------------------------
    def diagnose_exits(self, body: dict[str, Any]) -> dict[str, Any]:
        _dict_keys(body, allowed=set())
        fn = getattr(self.bot, "probe_exit_delays", None)
        if not callable(fn):
            raise UnavailableError()
        if not self._diagnostic_slots.acquire(blocking=False):
            raise BusyError()
        try:
            try:
                raw = fn(
                    allow_tcp_fallback=False, timeout_ms=5000, max_workers=4)
            except Exception as exc:
                raise ControlError() from exc
        finally:
            self._diagnostic_slots.release()
        if not isinstance(raw, dict) or not isinstance(raw.get("items"), list):
            raise ControlError()
        model = self._load()
        try:
            allowed = set(self.bot.concrete_tags(model))
        except Exception as exc:
            raise ControlError() from exc
        items: list[dict[str, Any]] = []
        seen: set[str] = set()
        for item in raw["items"][:128]:
            if not isinstance(item, dict):
                continue
            tag = item.get("tag")
            status = item.get("status")
            if (
                    not self._valid_name(tag)
                    or tag not in allowed or tag in seen
                    or status not in {
                        "ok", "timeout", "unreachable", "unavailable"}):
                continue
            public: dict[str, Any] = {"tag": tag, "status": status}
            delay = item.get("delay_ms")
            if (
                    status == "ok" and type(delay) is int
                    and 0 <= delay <= 600_000):
                public["delayMs"] = delay
            elif status == "ok":
                continue
            items.append(public)
            seen.add(tag)
        method = raw.get("method")
        available = method == "clash" and bool(items)
        return {"available": available, "items": items}

    def diagnose_domain(self, body: dict[str, Any]) -> dict[str, Any]:
        _dict_keys(body, allowed={"domain"}, required={"domain"})
        domain = _domain(body["domain"])
        fn = getattr(self.bot, "probe_domain_route", None)
        if not callable(fn):
            raise UnavailableError()
        try:
            raw = fn(domain)
        except Exception as exc:
            raise ControlError() from exc
        if not isinstance(raw, dict):
            raise ControlError()
        path = raw.get("path")
        reason = raw.get("reason")
        verified = raw.get("verified")
        confidence = raw.get("confidence")
        dns_verified = raw.get("dns_verified")
        route_confidence = raw.get("route_confidence")
        if (
                path not in {"direct", "gateway", "unknown"}
                or reason not in {
                    "dns_real", "explicit_domain", "keyword", "ruleset",
                    "default", "dns_no_answer", "probe_busy",
                    "probe_unavailable", "config_changed"}
                or type(verified) is not bool
                or confidence not in {"verified", "simulated", "unknown"}
                or type(dns_verified) is not bool
                or route_confidence not in {
                    "verified", "simulated", "unknown"}
                or confidence != route_confidence
                or verified != (route_confidence == "verified")):
            raise ControlError()
        if reason in {"probe_busy", "config_changed"} and (
                path != "unknown" or dns_verified or verified
                or route_confidence != "unknown"):
            raise ControlError()
        if reason == "dns_real" and (
                path != "direct" or not dns_verified
                or route_confidence != "verified"):
            raise ControlError()
        if reason in {
                "explicit_domain", "keyword", "ruleset", "default"} and (
                path != "gateway" or not dns_verified
                or route_confidence != "simulated"):
            raise ControlError()
        if reason == "dns_no_answer" and (
                path != "unknown" or dns_verified
                or route_confidence != "unknown"):
            raise ControlError()
        if reason == "probe_unavailable" and not (
                (path == "unknown" and not dns_verified
                 and route_confidence == "unknown")
                or (path == "gateway" and dns_verified
                    and route_confidence == "unknown")):
            raise ControlError()
        out: dict[str, Any] = {
            "domain": domain,
            "path": path,
            "reason": reason,
            "dnsVerified": dns_verified,
            "routeConfidence": route_confidence,
            # Frozen v1 compatibility for the already-deployed front-end.
            "verified": verified,
            "confidence": confidence,
        }
        target = raw.get("target")
        if self._valid_name(target):
            try:
                allowed = set(self._targets())
            except Exception:
                allowed = set()
            if target in allowed:
                out["target"] = target
        label = raw.get("rule_label")
        if isinstance(label, str):
            out["ruleLabel"] = _safe_text(label, 40)
        return out

    # ---- exits and groups ----------------------------------------------
    def add_exit(self, body: dict[str, Any]) -> dict[str, Any]:
        _dict_keys(body, allowed={"link"}, required={"link"})
        link = _string(body["link"], field="link", maximum=8192)
        try:
            outbound = self.bot.parse_link(link)
        except Exception as exc:
            link = ""
            if getattr(exc, "reason", None):
                raise ValidationError(
                    _name_public_message(getattr(exc, "reason", None))) from exc
            raise ValidationError("Proxy link is invalid.") from exc
        link = ""
        if not isinstance(outbound, dict):
            raise ValidationError("Proxy link is invalid.")
        tag = outbound.get("tag")
        typ = outbound.get("type")
        if not self._valid_name(tag):
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
        old = self._tag(old)
        _dict_keys(body, allowed={"name"}, required={"name"})
        new = self._tag(body["name"])
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

    def replace_exit(self, tag: str, body: dict[str, Any]) -> dict[str, Any]:
        """Replace connection details while preserving tag, position and references."""

        tag = self._tag(tag)
        _dict_keys(body, allowed={"link"}, required={"link"})
        current = next(
            (item for item in self._exit_items() if item["tag"] == tag), None)
        if current is None or current.get("kind") != "proxy":
            raise NotFoundError()
        link = _string(body["link"], field="link", maximum=8192)
        outbound: dict[str, Any] = {}
        parsed: dict[str, Any] = {}
        try:
            try:
                candidate = self.bot.parse_link(link)
            except Exception as exc:
                raise ValidationError("Proxy link is invalid.") from exc
            finally:
                link = ""
            if not isinstance(candidate, dict):
                raise ValidationError("Proxy link is invalid.")
            parsed = candidate
            if parsed.get("type") not in set(getattr(self.bot, "PROXY_TYPES", ())):
                raise ValidationError("Proxy link is invalid.")
            outbound = copy.deepcopy(parsed)
            outbound["tag"] = tag

            def modify(model):
                outbounds = model.get("outbounds")
                if not isinstance(outbounds, list):
                    raise ValueError("outbounds missing")
                indexes = [
                    index for index, item in enumerate(outbounds)
                    if isinstance(item, dict) and item.get("tag") == tag
                ]
                if len(indexes) != 1:
                    raise ValueError("outbound changed")
                index = indexes[0]
                if outbounds[index].get("type") not in set(
                        getattr(self.bot, "PROXY_TYPES", ())):
                    raise ValueError("outbound is no longer replaceable")
                outbounds[index] = copy.deepcopy(outbound)

            self._tx("web_exit_replace", model_mod=modify)
        finally:
            link = ""
            outbound.clear()
            parsed.clear()
        item = next(
            (item for item in self._exit_items() if item["tag"] == tag),
            {"tag": tag, "type": "unknown"},
        )
        return self._public_exit_item(item)

    def _delete_outbound(
            self, tag: str, *, group_only: bool = False,
            model: dict[str, Any] | None = None,
            model_expect: str | None = None) -> None:
        tag = self._tag(tag)
        before = next((item for item in self._exit_items(model)
                       if item["tag"] == tag), None)
        if before is None or not before["deletable"]:
            raise NotFoundError()
        if group_only and before["kind"] != "group":
            raise NotFoundError()
        files: dict[str, bytes] = {}
        file_expects: dict[str, str | None] = {}
        snapshot = getattr(self.bot, "_rs_meta_snapshot", None)
        if not callable(snapshot):
            raise UnavailableError()
        try:
            meta_snapshot, meta_sha = snapshot()
        except Exception as exc:
            raise UnavailableError() from exc
        if (
                not isinstance(meta_snapshot, dict)
                or (meta_sha is not None and (
                    not isinstance(meta_sha, str)
                    or not re.fullmatch(r"[0-9a-f]{64}", meta_sha)))):
            raise UnavailableError()
        meta_snapshot = copy.deepcopy(meta_snapshot)

        def modify(model):
            outbounds = model.get("outbounds") or []
            before_tags = {item.get("tag") for item in outbounds if isinstance(item, dict)}
            target = next((item for item in outbounds if item.get("tag") == tag), None)
            if target is None or target.get("type") == "direct":
                raise ValueError("not deletable")
            if group_only and target.get("type") not in {"urltest", "selector"}:
                raise ValueError("not group")
            model["outbounds"] = [item for item in outbounds if item.get("tag") != tag]
            for item in model["outbounds"]:
                if item.get("type") in {"urltest", "selector"}:
                    item["outbounds"] = [
                        member for member in item.get("outbounds", []) if member != tag
                    ]
            model["outbounds"] = [
                item for item in model["outbounds"]
                if not (item.get("type") in {"urltest", "selector"}
                        and len(item.get("outbounds", [])) < 2)
            ]
            sync_delete = getattr(self.bot, "_mihomo_group_delete", None)
            if callable(sync_delete):
                after_tags = {item.get("tag") for item in model["outbounds"]
                              if isinstance(item, dict)}
                sync_delete(model, before_tags - after_tags)
            live = set(self._routable_tags_unchecked(model))
            # ``direct`` is a MosDNS/mobile pseudo-target, not an outbound tag.
            # It remains valid regardless of which concrete proxy is deleted.
            routable = live | {"direct"}
            final = (model.get("route") or {}).get("final")
            if final not in live:
                final = next((
                    item.get("tag") for item in model["outbounds"]
                    if item.get("type") in set(getattr(self.bot, "PROXY_TYPES", ())) | {
                        "direct"}
                ), None)
                if final is None:
                    raise ValueError("no fallback")
                model.setdefault("route", {})["final"] = final
            for rule in (model.get("route") or {}).get("rules") or []:
                if rule.get("outbound") not in routable:
                    rule["outbound"] = final
            dirty = False
            for value in meta_snapshot.values():
                if (
                        isinstance(value, dict)
                        and value.get("outbound") not in routable):
                    value["outbound"] = final
                    dirty = True
            if dirty:
                files["rs_meta"] = json.dumps(
                    meta_snapshot, ensure_ascii=False, indent=2).encode("utf-8")
                file_expects["rs_meta"] = meta_sha

        tx_args = {
            "model_mod": modify, "files": files,
            "file_expects": file_expects,
        }
        if model_expect is not None:
            tx_args["model_expect"] = model_expect
        self._tx("web_outbound_delete", **tx_args)

    def delete_exit(self, tag: str) -> dict[str, Any]:
        self._delete_outbound(tag)
        return {"deleted": True}

    def reorder_exits(self, body: dict[str, Any]) -> dict[str, Any]:
        _dict_keys(body, allowed={"order"}, required={"order"})
        order = body["order"]
        if not isinstance(order, list) or not 1 <= len(order) <= 128:
            raise ValidationError()
        tags = [self._tag(value) for value in order]
        if len(set(tags)) != len(tags):
            raise ValidationError()
        fn = getattr(self.bot, "reorder_exits", None)
        if not callable(fn):
            raise UnavailableError()
        self._result(fn(tags))
        return self.exits()

    def set_default_exit(self, body: dict[str, Any]) -> dict[str, Any]:
        _dict_keys(body, allowed={"tag"}, required={"tag"})
        tag = self._tag(body["tag"])

        def modify(model):
            allowed = set(self.bot.exit_tags(model))
            if tag not in allowed:
                raise ValueError("unknown exit")
            model.setdefault("route", {})["final"] = tag

        self._tx("web_default_exit", model_mod=modify)
        return {"tag": tag}

    def add_policy_group(self, body: dict[str, Any]) -> dict[str, Any]:
        candidate, model, revision = self._policy_cas_body(body)
        return self.add_group(candidate, _model=model, _model_expect=revision)

    def add_group(
            self, body: dict[str, Any], *, _model=None,
            _model_expect: str | None = None) -> dict[str, Any]:
        deprecated = False
        if _model is None:
            body, current_model, _model_expect, deprecated = (
                self._legacy_group_cas_body(body))
        else:
            current_model = _model
        # Backward-compatible legacy Web payload creates a url-test group.
        legacy_payload = isinstance(body, dict) and set(body) == {"name", "members"}
        if legacy_payload and (current_model.get("_pdg") or {}).get("schema") != 3:
            tag = self._tag(body["name"])
            members = self._members(body["members"])
            fn = getattr(self.bot, "add_group", None)
            if not callable(fn):
                raise UnavailableError()
            self._result(fn(tag, members, model_expect=_model_expect))
            result = next((item for item in self._group_items() if item["tag"] == tag),
                          {"tag": tag, "members": members})
            if deprecated:
                result["deprecated"] = True
            return result
        if legacy_payload:
            body = {
                "name": body["name"], "type": "url-test",
                "proxies": body["members"], "use": [],
                "url": "https://www.gstatic.com/generate_204",
                "interval": 180, "tolerance": 50,
            }
        group = self._policy_group_body(body, require_name=True)
        name = group["name"]

        def modify(model):
            meta = model.setdefault("_pdg", {})
            groups = meta.setdefault("policy-groups", [])
            occupied = {item.get("tag") for item in model.get("outbounds", [])}
            occupied |= {item.get("name") for item in groups if isinstance(item, dict)}
            mihomo = meta.get("mihomo") or {}
            occupied |= set(mihomo.get("proxy-providers") or {})
            occupied |= set(mihomo.get("rule-providers") or {})
            if name in occupied or name in _MIHOMO_RESERVED:
                raise ValueError("name conflict")
            groups.append(copy.deepcopy(group))

        tx_args = {"model_mod": modify}
        if _model_expect is not None:
            tx_args["model_expect"] = _model_expect
        self._tx("web_policy_group_add", **tx_args)
        result = next(item for item in self._group_items() if item["name"] == name)
        if deprecated:
            result["deprecated"] = True
        return result

    def _members(self, value: Any) -> list[str]:
        if not isinstance(value, list) or not 2 <= len(value) <= 64:
            raise ValidationError("members is invalid.")
        members = [self._tag(item, field="member") for item in value]
        if len(set(members)) != len(members):
            raise ValidationError("members is invalid.")
        return members

    def _policy_group_body(
            self, body: dict[str, Any], *, require_name: bool) -> dict[str, Any]:
        allowed = {
            "name", "type", "proxies", "use", "url", "interval", "tolerance",
            "strategy", "lazy", "disable-udp", "hidden",
        }
        _dict_keys(body, allowed=allowed,
                   required={"name", "type"} if require_name else {"type"})
        typ = body.get("type")
        if typ not in {"select", "url-test", "fallback", "load-balance"}:
            raise ValidationError("group type is invalid.")
        group: dict[str, Any] = {"type": typ}
        if require_name or "name" in body:
            group["name"] = self._tag(body["name"], field="name")
        for key in ("proxies", "use"):
            value = body.get(key, [])
            if (not isinstance(value, list) or len(value) > 128
                    or any(not isinstance(item, str) for item in value)):
                raise ValidationError(key + " is invalid.")
            items = []
            for item in value:
                if key == "proxies" and item == "REJECT":
                    items.append(item)
                else:
                    items.append(self._tag(item, field=key))
            if len(items) != len(set(items)):
                raise ValidationError(key + " is invalid.")
            group[key] = items
        if not group["proxies"] and not group["use"]:
            raise ValidationError("group needs a member or provider.")
        option_fields = {
            "select": {"lazy", "disable-udp", "hidden"},
            "url-test": {"url", "interval", "tolerance", "lazy", "disable-udp", "hidden"},
            "fallback": {"url", "interval", "lazy", "disable-udp", "hidden"},
            "load-balance": {"url", "interval", "strategy", "lazy", "disable-udp", "hidden"},
        }[typ]
        if set(body) - ({"name", "type", "proxies", "use"} | option_fields):
            raise ValidationError("group options do not match its type.")
        for key in ("lazy", "disable-udp", "hidden"):
            if key in body:
                group[key] = _bool(body[key], field=key)
        if "url" in option_fields:
            url = body.get("url", "https://www.gstatic.com/generate_204")
            if (not isinstance(url, str) or len(url) > 8192
                    or not re.fullmatch(r"https?://[^\s\x00]+", url, re.I)):
                raise ValidationError("url is invalid.")
            group["url"] = url
            interval = body.get("interval", 180)
            if type(interval) is not int or not 1 <= interval <= 604800:
                raise ValidationError("interval is invalid.")
            group["interval"] = interval
        if "tolerance" in option_fields:
            tolerance = body.get("tolerance", 50)
            if type(tolerance) is not int or not 0 <= tolerance <= 65535:
                raise ValidationError("tolerance is invalid.")
            group["tolerance"] = tolerance
        if "strategy" in option_fields:
            strategy = body.get("strategy", "consistent-hashing")
            if strategy not in {"consistent-hashing", "round-robin", "sticky-sessions"}:
                raise ValidationError("strategy is invalid.")
            group["strategy"] = strategy
        return group

    def patch_policy_group(self, old: str, body: dict[str, Any]) -> dict[str, Any]:
        candidate, model, revision = self._policy_cas_body(body)
        return self.patch_group(
            old, candidate, _model=model, _model_expect=revision)

    def patch_group(
            self, old: str, body: dict[str, Any], *, _model=None,
            _model_expect: str | None = None) -> dict[str, Any]:
        old = self._tag(old)
        deprecated = False
        if _model is None:
            body, model_snapshot, _model_expect, deprecated = (
                self._legacy_group_cas_body(body))
        else:
            model_snapshot = _model
        current = next((item for item in self._group_items(model_snapshot)
                        if item["name"] == old), None)
        if current is None:
            raise NotFoundError()
        if (isinstance(body, dict) and set(body) == {"members"}
                and (model_snapshot.get("_pdg") or {}).get("schema") != 3):
            members = self._members(body["members"])
            fn = getattr(self.bot, "add_group", None)
            if not callable(fn):
                raise UnavailableError()
            self._result(fn(old, members, model_expect=_model_expect))
            result = next((item for item in self._group_items() if item["tag"] == old),
                          {"tag": old, "members": members})
            if deprecated:
                result["deprecated"] = True
            return result
        if isinstance(body, dict) and set(body) == {"members"}:
            legacy_members = copy.deepcopy(body["members"])
            body = {key: copy.deepcopy(value) for key, value in current.items()
                    if key in {"name", "type", "use", "url", "interval", "tolerance",
                               "strategy", "lazy", "disable-udp", "hidden"}}
            body["proxies"] = legacy_members
        # Correct the compatibility transformation without retaining public-only fields.
        if "members" in body:
            body["proxies"] = body.pop("members")
        candidate = self._policy_group_body(body, require_name=True)
        new = candidate["name"]
        files: dict[str, bytes] = {}
        file_expects: dict[str, str | None] = {}
        try:
            rsm, meta_sha = self.bot._rs_meta_snapshot()
        except Exception as exc:
            raise UnavailableError() from exc
        if old != new:
            dirty = False
            for item in rsm.values():
                if isinstance(item, dict) and item.get("outbound") == old:
                    item["outbound"] = new
                    dirty = True
            if dirty:
                files["rs_meta"] = json.dumps(
                    rsm, ensure_ascii=False, indent=2).encode("utf-8")
                file_expects["rs_meta"] = meta_sha

        def modify(model):
            groups = (model.get("_pdg") or {}).get("policy-groups") or []
            matches = [index for index, item in enumerate(groups)
                       if isinstance(item, dict) and item.get("name") == old]
            if len(matches) != 1:
                raise ValueError("group changed")
            if old != new:
                occupied = {item.get("tag") for item in model.get("outbounds", [])}
                occupied |= {item.get("name") for item in groups
                             if isinstance(item, dict) and item.get("name") != old}
                mihomo = (model.get("_pdg") or {}).get("mihomo") or {}
                occupied |= set(mihomo.get("proxy-providers") or {})
                occupied |= set(mihomo.get("rule-providers") or {})
                if new in occupied or new in _MIHOMO_RESERVED:
                    raise ValueError("name conflict")
                self.bot.pdgmodel.rename_references(
                    model, old, new, rename_group=True)
                groups = model["_pdg"]["policy-groups"]
                matches = [index for index, item in enumerate(groups)
                           if item.get("name") == new]
            groups[matches[0]] = copy.deepcopy(candidate)

        tx_args = {
            "model_mod": modify, "files": files,
            "file_expects": file_expects,
        }
        if _model_expect is not None:
            tx_args["model_expect"] = _model_expect
        self._tx("web_policy_group_patch", **tx_args)
        result = next(item for item in self._group_items() if item["name"] == new)
        if deprecated:
            result["deprecated"] = True
        return result

    def delete_policy_group(self, tag: str, body: dict[str, Any]) -> dict[str, Any]:
        candidate, model, revision = self._policy_cas_body(body)
        if candidate:
            raise ValidationError()
        return self.delete_group(tag, _model=model, _model_expect=revision)

    def delete_group(
            self, tag: str, body: dict[str, Any] | None = None, *, _model=None,
            _model_expect: str | None = None) -> dict[str, Any]:
        tag = self._tag(tag)
        deprecated = False
        if _model is None:
            candidate, current, _model_expect, deprecated = (
                self._legacy_group_cas_body(body))
            if candidate:
                raise ValidationError()
        else:
            current = _model
        if (current.get("_pdg") or {}).get("schema") != 3:
            self._delete_outbound(
                tag, group_only=True, model=current,
                model_expect=_model_expect)
            result = {"deleted": True}
            if deprecated:
                result["deprecated"] = True
            return result
        if not any(group.get("name") == tag for group in (
                (current.get("_pdg") or {}).get("policy-groups") or [])):
            raise NotFoundError()
        preview = copy.deepcopy(current)
        before_group_names = {item.get("name") for item in (
            (preview.get("_pdg") or {}).get("policy-groups") or [])}
        self.bot._mihomo_group_delete(preview, {tag})
        after_group_names = {item.get("name") for item in (
            (preview.get("_pdg") or {}).get("policy-groups") or [])}
        removed_names = before_group_names - after_group_names
        fallback = next((value for value in self.bot.exit_tags(current)
                         if value not in removed_names), None)
        if fallback is None:
            raise ConflictError()
        try:
            rsm, meta_sha = self.bot._rs_meta_snapshot()
        except Exception as exc:
            raise UnavailableError() from exc
        dirty = False
        for item in rsm.values():
            if isinstance(item, dict) and item.get("outbound") in removed_names:
                item["outbound"] = fallback
                dirty = True
        files = ({"rs_meta": json.dumps(
            rsm, ensure_ascii=False, indent=2).encode("utf-8")} if dirty else {})
        expects = ({"rs_meta": meta_sha} if dirty else {})

        def modify(model):
            groups = model["_pdg"]["policy-groups"]
            if not any(item.get("name") == tag for item in groups):
                raise ValueError("group changed")
            self.bot._mihomo_group_delete(model, {tag})
            live = set(self._routable_tags_unchecked(model))
            if fallback not in live:
                raise ValueError("fallback changed")
            route = model.get("route", {})
            if route.get("final") not in live:
                route["final"] = fallback
            for rule in route.get("rules", []):
                if (isinstance(rule, dict) and rule.get("outbound") is not None
                        and rule.get("outbound") not in live):
                    rule["outbound"] = fallback

        tx_args = {"model_mod": modify, "files": files, "file_expects": expects}
        if _model_expect is not None:
            tx_args["model_expect"] = _model_expect
        self._tx("web_policy_group_delete", **tx_args)
        result = {"deleted": True}
        if deprecated:
            result["deprecated"] = True
        return result

    def select_group_runtime(self, tag: str, body: dict[str, Any]) -> dict[str, Any]:
        tag = self._tag(tag)
        _dict_keys(body, allowed={"member"}, required={"member"})
        member = body["member"]
        if (not isinstance(member, str) or not 1 <= len(member) <= 256
                or "\x00" in member or "\r" in member or "\n" in member):
            raise ValidationError("member is invalid.")
        model = self._load()
        group = next((item for item in (
            (model.get("_pdg") or {}).get("policy-groups") or [])
                      if item.get("name") == tag), None)
        if group is None or group.get("type") != "select":
            raise NotFoundError()
        direct = next((item.get("tag") for item in model.get("outbounds", [])
                       if item.get("type") == "direct"), None)
        blocks = {item.get("tag") for item in model.get("outbounds", [])
                  if item.get("type") == "block"
                  and isinstance(item.get("tag"), str)}
        try:
            runtime = self.bot.clash_get(
                "/proxies/" + urllib.parse.quote(group["name"], safe=""))
            actual_to_public = self._runtime_member_map(
                runtime, group, direct=direct, blocks=blocks)
        except Exception as exc:
            raise UnavailableError() from exc
        public_to_actual = {}
        for actual, public in actual_to_public.items():
            if public in public_to_actual and public_to_actual[public] != actual:
                raise ConflictError()
            public_to_actual[public] = actual
        runtime_member = public_to_actual.get(member)
        if runtime_member is None:
            raise ValidationError("member is not an active candidate in this select group.")
        fn = getattr(self.bot, "clash_select", None)
        if not callable(fn):
            raise UnavailableError()
        try:
            fn(tag, runtime_member)
        except Exception as exc:
            raise UnavailableError() from exc
        return {"name": tag, "runtimeSelected": member, "persistent": False}

    def set_direct_tag(self, body: dict[str, Any]) -> dict[str, Any]:
        _dict_keys(body, allowed={"tag"}, required={"tag"})
        tag = self._tag(body["tag"])
        validator = getattr(getattr(self.bot, "pdgmodel", None),
                            "validate_direct_tag_setting", None)
        if callable(validator):
            try:
                tag = validator(tag)
            except (TypeError, ValueError) as exc:
                raise ValidationError("direct tag is reserved.") from exc
        fn = getattr(self.bot, "set_direct_tag", None)
        if not callable(fn):
            raise UnavailableError()
        self._result(fn(tag))
        return {"tag": tag}

    # ---- rules ----------------------------------------------------------
    def add_rule(self, body: dict[str, Any]) -> dict[str, Any]:
        _dict_keys(body, allowed={"domain", "target"}, required={"domain", "target"})
        domain = _domain(body["domain"])
        target = _string(body["target"], field="target", maximum=64)
        if target != "direct":
            target = self._tag(target, field="target")
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
            target = self._tag(target, field="target")
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
        target = self._tag(body["target"], field="target")
        label = _string(
            body.get("label", ""), field="label", maximum=256, allow_empty=True)
        if label:
            label = self._name(label, field="label")
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
        name = self._tag(name, field="name")
        _dict_keys(body, allowed={"label"}, required={"label"})
        current = self._meta().get(name)
        if not isinstance(current, dict):
            raise NotFoundError()
        label = _string(body["label"], field="label", maximum=256, allow_empty=True)
        if label:
            label = self._name(label, field="label")
        fn = getattr(self.bot, "set_ruleset_label", None)
        if not callable(fn):
            raise UnavailableError()
        self._result(fn(name, label))
        return next((item for item in self._ruleset_items() if item["name"] == name),
                    {"name": name})

    def set_ruleset_target(
            self, name: str, body: dict[str, Any]) -> dict[str, Any]:
        name = self._tag(name, field="name")
        _dict_keys(body, allowed={"target"}, required={"target"})
        if name not in self._meta():
            raise NotFoundError()
        target = self._tag(body["target"], field="target")
        if target not in set(self._targets()):
            raise ValidationError("target is invalid.")
        fn = getattr(self.bot, "set_ruleset_target", None)
        if not callable(fn):
            raise UnavailableError()
        self._result(fn(name, target))
        return next(
            (item for item in self._ruleset_items() if item["name"] == name),
            {"name": name, "target": target},
        )

    def delete_ruleset(self, name: str) -> dict[str, Any]:
        name = self._tag(name, field="name")
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
            if isinstance(body, dict) and set(body) == {"index"}:
                index = body["index"]
                if type(index) is not int or not 0 <= index <= 10000:
                    raise ValidationError("index is invalid.")
                snapshot_id = None
            elif (
                    isinstance(body, dict)
                    and set(body) == {"snapshotId", "confirm"}):
                if body["confirm"] is not True:
                    raise ValidationError("confirm must be true.")
                snapshot_id = _string(
                    body["snapshotId"], field="snapshotId", maximum=40)
                if not _SNAPSHOT_ID_RE.fullmatch(snapshot_id):
                    raise ValidationError("snapshotId is invalid.")
                index = None
            else:
                raise ValidationError()
        elif action == "software-update":
            _dict_keys(body, allowed={"confirm"}, required={"confirm"})
            if body["confirm"] is not True:
                raise ValidationError("confirm must be true.")
        else:
            raise NotFoundError()
        if action == "restart":
            with self._maintenance_guard():
                self._tx("web_restart", services=("mihomo", "mosdns"))
            return ActionResult(action).view()
        if action == "rules-update":
            with self._maintenance_guard():
                script = getattr(
                    self.bot, "UPDATE_SCRIPT", "/opt/pdg-bot/update-rules.sh")
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
                if (
                        not isinstance(refreshed, int)
                        or isinstance(refreshed, bool) or refreshed < 0):
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
            with self._maintenance_guard():
                try:
                    result = self.bot.sh([cli, "snapshot"])
                except Exception as exc:
                    raise ControlError() from exc
                if getattr(result, "returncode", 1) != 0:
                    raise ControlError()
            return ActionResult(action).view()
        if action == "rollback":
            store = self._job_store()
            try:
                if snapshot_id is None:
                    snapshot_id = store.snapshot_id_for_index(index)
                else:
                    snapshot_id = store.resolve_snapshot_id(snapshot_id)
                raw_job = store.start("rollback", snapshot_id=snapshot_id)
            except Exception as exc:
                self._raise_job_error(exc, request_value=True)
            job = self._public_job(raw_job)
            if job is None:
                raise ControlError()
            return ActionResult(action, details={"job": job}).view()
        if action == "software-update":
            check = getattr(self.bot, "update_check", None)
            if not callable(check):
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
            store = self._job_store()
            try:
                raw_job = store.start("software-update")
            except Exception as exc:
                self._raise_job_error(exc)
            job = self._public_job(raw_job)
            if job is None:
                raise ControlError()
            return ActionResult(action, details={"job": job}).view()
        raise NotFoundError()

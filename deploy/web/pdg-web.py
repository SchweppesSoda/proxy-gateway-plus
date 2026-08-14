#!/usr/bin/env python3
"""Native PDG HTTPS management API and static-file server."""
from __future__ import annotations

import argparse
import base64
import dataclasses
import hashlib
import hmac
import http.cookies
import http.client
import http.server
import ipaddress
import json
import os
import pathlib
import re
import secrets
import socket
import socketserver
import ssl
import stat
import sys
import threading
import time
import unicodedata
import urllib.parse
from collections import defaultdict, deque
from typing import Any


sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from pdgcontrol import (  # noqa: E402
    BusyError,
    ConflictError,
    ControlError,
    NotFoundError,
    PDGControl,
    UnavailableError,
    ValidationError,
)
from pdgwebconfig import (  # noqa: E402
    ConfigError,
    WebConfig,
    load_config,
    normalize_host as _normalize_host,
    normalize_origin as _normalize_origin,
    strict_json_loads as _json_loads,
)


DEFAULT_CONFIG = "/etc/privdns-gateway/web.json"
COOKIE_NAME = "__Host-pdg_session"
CSRF_HEADER = "X-CSRF-Token"
MAX_JSON_BYTES = 64 * 1024
MAX_PASSWORD_BYTES = 1024
MAX_IMPORT_BYTES = 36 * 1024 * 1024
MAX_LEGACY_PDG_IMPORT_BYTES = 68 * 1024 * 1024
MAX_STATIC_BYTES = 8 * 1024 * 1024
MAX_RESPONSE_BYTES = 1024 * 1024
PRELOGIN_CSRF_SECONDS = 300
GLOBAL_RATE_WINDOW = 60
GLOBAL_RATE_REQUESTS = 240
GLOBAL_ALL_RATE_REQUESTS = 2000
LOGIN_RATE_WINDOW = 15 * 60
LOGIN_RATE_ATTEMPTS = 5
LOGIN_ALL_RATE_ATTEMPTS = 30
RATE_MAP_LIMIT = 1024
MAX_SESSIONS = 256
SOCKET_TIMEOUT_SECONDS = 10
HEADER_DEADLINE_SECONDS = 10
MAX_HEADER_BYTES = 32 * 1024
LOGIN_KDF_SLOTS = 2

_PERCENT_BAD_RE = re.compile(r"%(?![0-9A-Fa-f]{2})")
_PATH_TAG_RE = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")
_PATH_NAME_TOKEN_RE = re.compile(r"^~([A-Za-z0-9_-]{2,342})$")
_DANGEROUS_NAME_CODEPOINTS = frozenset({
    0x00AD, 0x034F, 0x061C, 0x115F, 0x1160, 0x17B4, 0x17B5,
    0x180E, 0x200B, 0x200E, 0x200F, 0x202A, 0x202B, 0x202C,
    0x202D, 0x202E, 0x2060, 0x2061, 0x2062, 0x2063, 0x2064,
    0x2066, 0x2067, 0x2068, 0x2069, 0x206A, 0x206B, 0x206C,
    0x206D, 0x206E, 0x206F, 0x3164, 0xFEFF, 0xFFA0,
})
_PATH_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?$"
)
_MIME_TYPES = {
    ".html": "text/html; charset=utf-8",
    ".js": "text/javascript; charset=utf-8",
    ".mjs": "text/javascript; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".json": "application/json; charset=utf-8",
    ".webmanifest": "application/manifest+json; charset=utf-8",
    ".svg": "image/svg+xml",
    ".png": "image/png",
    ".jpg": "image/jpeg",
    ".jpeg": "image/jpeg",
    ".gif": "image/gif",
    ".webp": "image/webp",
    ".ico": "image/x-icon",
    ".woff": "font/woff",
    ".woff2": "font/woff2",
    ".txt": "text/plain; charset=utf-8",
    ".yaml": "application/yaml; charset=utf-8",
    ".yml": "application/yaml; charset=utf-8",
}


class _HeaderLimitedReader:
    """Apply an absolute deadline and aggregate budget while parsing headers."""

    def __init__(
            self, stream, connection, *, deadline: float,
            maximum: int = MAX_HEADER_BYTES):
        self._stream = stream
        self._connection = connection
        self._deadline = deadline
        self._maximum = maximum
        self._header_bytes = 0
        self._request_line = True
        self._active = True
        self._expired = False
        self._state_lock = threading.Lock()
        delay = max(0.0, deadline - time.monotonic())
        self._watchdog = threading.Timer(delay, self._expire)
        self._watchdog.daemon = True
        self._watchdog.start()

    def _expire(self):
        with self._state_lock:
            if not self._active:
                return
            self._expired = True
        try:
            self._connection.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass

    def _check_expired(self):
        if time.monotonic() >= self._deadline:
            self._expire()
        with self._state_lock:
            expired = self._expired
        if expired:
            raise TimeoutError("request header deadline exceeded")

    def _apply_deadline(self):
        self._check_expired()
        remaining = self._deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("request header deadline exceeded")
        self._connection.settimeout(min(SOCKET_TIMEOUT_SECONDS, remaining))

    def readline(self, size: int = -1):
        if not self._active:
            return self._stream.readline(size)
        self._apply_deadline()
        if self._request_line:
            self._request_line = False
            try:
                line = self._stream.readline(size)
            except OSError:
                self._check_expired()
                raise
            self._check_expired()
            return line

        remaining = self._maximum - self._header_bytes
        if remaining <= 0:
            raise http.client.LineTooLong("aggregate request headers")
        permitted = remaining + 1
        requested = size if size >= 0 else permitted
        limited = min(requested, permitted)
        try:
            line = self._stream.readline(limited)
        except OSError:
            self._check_expired()
            raise
        self._check_expired()
        self._header_bytes += len(line)
        if self._header_bytes > self._maximum:
            raise http.client.LineTooLong("aggregate request headers")
        if (
                line and not line.endswith(b"\n")
                and limited == permitted and len(line) == limited):
            raise http.client.LineTooLong("aggregate request headers")
        if line in (b"\r\n", b"\n", b""):
            self.finish_headers()
        return line

    def finish_headers(self):
        with self._state_lock:
            if not self._active:
                return
            self._active = False
        self._watchdog.cancel()
        try:
            self._connection.settimeout(SOCKET_TIMEOUT_SECONDS)
        except OSError:
            pass

    def __getattr__(self, name):
        return getattr(self._stream, name)


@dataclasses.dataclass
class Session:
    csrf: str
    expires: float


class SecurityState:
    def __init__(self, config: WebConfig):
        self.config = config
        self._lock = threading.Lock()
        self._sessions: dict[bytes, Session] = {}
        self._global: dict[str, deque[float]] = defaultdict(deque)
        self._logins: dict[str, deque[float]] = defaultdict(deque)
        self._all_requests: deque[float] = deque()
        self._all_login_failures: deque[float] = deque()
        self._pending_logins: dict[str, int] = defaultdict(int)
        self._pending_login_total = 0
        self._password_slots = threading.BoundedSemaphore(LOGIN_KDF_SLOTS)

    def _session_key(self, token: str) -> bytes:
        return hmac.digest(self.config.session_secret, token.encode("ascii"), "sha256")

    @staticmethod
    def _prune(queue: deque[float], cutoff: float):
        while queue and queue[0] <= cutoff:
            queue.popleft()

    def _prune_map(
            self, mapping: dict[str, deque[float]], cutoff: float):
        for key in list(mapping):
            self._prune(mapping[key], cutoff)
            if not mapping[key]:
                mapping.pop(key, None)
        if len(mapping) > RATE_MAP_LIMIT:
            oldest = sorted(
                mapping, key=lambda key: mapping[key][-1])[:len(mapping) - RATE_MAP_LIMIT]
            for key in oldest:
                mapping.pop(key, None)

    def global_rate_allowed(self, ip: str, now: float | None = None) -> bool:
        now = time.time() if now is None else now
        with self._lock:
            self._prune(self._all_requests, now - GLOBAL_RATE_WINDOW)
            self._prune_map(self._global, now - GLOBAL_RATE_WINDOW)
            if len(self._all_requests) >= GLOBAL_ALL_RATE_REQUESTS:
                return False
            if ip not in self._global and len(self._global) >= RATE_MAP_LIMIT:
                oldest = min(self._global, key=lambda key: self._global[key][-1])
                self._global.pop(oldest, None)
            queue = self._global[ip]
            if len(queue) >= GLOBAL_RATE_REQUESTS:
                return False
            queue.append(now)
            self._all_requests.append(now)
            return True

    def login_rate_allowed(self, ip: str, now: float | None = None) -> bool:
        now = time.time() if now is None else now
        with self._lock:
            self._prune(self._all_login_failures, now - LOGIN_RATE_WINDOW)
            self._prune_map(self._logins, now - LOGIN_RATE_WINDOW)
            if (
                    len(self._all_login_failures) + self._pending_login_total
                    >= LOGIN_ALL_RATE_ATTEMPTS):
                return False
            queue = self._logins.get(ip, ())
            return len(queue) + self._pending_logins.get(ip, 0) < LOGIN_RATE_ATTEMPTS

    def reserve_login_attempt(self, ip: str, now: float | None = None) -> bool:
        """Atomically reserve rate-limit capacity before expensive password work."""

        now = time.time() if now is None else now
        with self._lock:
            self._prune(self._all_login_failures, now - LOGIN_RATE_WINDOW)
            self._prune_map(self._logins, now - LOGIN_RATE_WINDOW)
            if (
                    len(self._all_login_failures) + self._pending_login_total
                    >= LOGIN_ALL_RATE_ATTEMPTS):
                return False
            if (
                    len(self._logins.get(ip, ())) + self._pending_logins.get(ip, 0)
                    >= LOGIN_RATE_ATTEMPTS):
                return False
            self._pending_logins[ip] += 1
            self._pending_login_total += 1
            return True

    def _record_login_failure_locked(self, ip: str, now: float):
        self._prune(self._all_login_failures, now - LOGIN_RATE_WINDOW)
        self._prune_map(self._logins, now - LOGIN_RATE_WINDOW)
        if ip not in self._logins and len(self._logins) >= RATE_MAP_LIMIT:
            oldest = min(self._logins, key=lambda key: self._logins[key][-1])
            self._logins.pop(oldest, None)
        self._logins[ip].append(now)
        self._all_login_failures.append(now)

    def finish_login_attempt(
            self, ip: str, *, failed: bool, now: float | None = None):
        """Release one reservation and optionally turn it into a failed attempt."""

        now = time.time() if now is None else now
        with self._lock:
            pending = self._pending_logins.get(ip, 0)
            if pending:
                if pending == 1:
                    self._pending_logins.pop(ip, None)
                else:
                    self._pending_logins[ip] = pending - 1
                self._pending_login_total -= 1
            if failed:
                self._record_login_failure_locked(ip, now)

    def record_login_failure(self, ip: str, now: float | None = None):
        now = time.time() if now is None else now
        with self._lock:
            self._record_login_failure_locked(ip, now)

    def clear_login_failures(self, ip: str):
        with self._lock:
            self._logins.pop(ip, None)

    def verify_password(self, password: bytes) -> bool | None:
        """Return None rather than queueing workers when all KDF slots are busy."""

        if not self._password_slots.acquire(blocking=False):
            return None
        try:
            derived = hashlib.pbkdf2_hmac(
                "sha256", password, self.config.salt, self.config.iterations, dklen=32)
            return hmac.compare_digest(derived, self.config.password_hash)
        finally:
            self._password_slots.release()

    def create_session(self, now: float | None = None) -> tuple[str, Session]:
        now = time.time() if now is None else now
        token = secrets.token_urlsafe(32)
        session = Session(csrf=secrets.token_urlsafe(32), expires=now + self.config.session_seconds)
        with self._lock:
            self._cleanup_sessions(now)
            if len(self._sessions) >= MAX_SESSIONS:
                oldest = min(self._sessions, key=lambda key: self._sessions[key].expires)
                self._sessions.pop(oldest, None)
            self._sessions[self._session_key(token)] = session
        return token, session

    def _cleanup_sessions(self, now: float):
        expired = [key for key, value in self._sessions.items() if value.expires <= now]
        for key in expired:
            self._sessions.pop(key, None)

    def session(self, token: str | None, now: float | None = None) -> Session | None:
        if not token or len(token) > 256 or not re.fullmatch(r"[A-Za-z0-9_-]+", token):
            return None
        now = time.time() if now is None else now
        try:
            key = self._session_key(token)
        except (UnicodeEncodeError, ValueError):
            return None
        with self._lock:
            self._cleanup_sessions(now)
            value = self._sessions.get(key)
            return value if value is not None and value.expires > now else None

    def destroy_session(self, token: str | None):
        if not token or len(token) > 256:
            return
        try:
            key = self._session_key(token)
        except (UnicodeEncodeError, ValueError):
            return
        with self._lock:
            self._sessions.pop(key, None)

    def prelogin_csrf(self, ip: str, host: str, now: float | None = None) -> str:
        now = time.time() if now is None else now
        bucket = int(now // PRELOGIN_CSRF_SECONDS)
        message = f"login\0{ip}\0{host}\0{bucket}".encode()
        return base64.urlsafe_b64encode(
            hmac.digest(self.config.session_secret, message, "sha256")
        ).decode().rstrip("=")

    def verify_prelogin_csrf(
            self, token: str | None, ip: str, host: str, now: float | None = None) -> bool:
        if not token or len(token) > 128:
            return False
        now = time.time() if now is None else now
        for offset in (0, -PRELOGIN_CSRF_SECONDS):
            expected = self.prelogin_csrf(ip, host, now + offset)
            if hmac.compare_digest(expected, token):
                return True
        return False


def _socket_ip(value: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    ip = ipaddress.ip_address(value.split("%", 1)[0])
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        return ip.ipv4_mapped
    return ip


def _ip_trusted(config: WebConfig, socket_ip: str) -> bool:
    try:
        ip = _socket_ip(socket_ip)
    except ValueError:
        return False
    return any(ip.version == network.version and ip in network for network in config.trusted_cidrs)


def _strict_path_segment(raw: str, *, kind: str) -> str:
    if not raw or len(raw) > 768 or _PERCENT_BAD_RE.search(raw):
        raise ValidationError("Path identifier is invalid.")
    if kind == "tag" and raw.startswith("~"):
        match = _PATH_NAME_TOKEN_RE.fullmatch(raw)
        if match is None:
            raise ValidationError("Path identifier is invalid.")
        token = match.group(1)
        try:
            decoded_bytes = base64.urlsafe_b64decode(
                token + "=" * (-len(token) % 4))
            if base64.urlsafe_b64encode(decoded_bytes).decode("ascii").rstrip("=") != token:
                raise ValueError("non-canonical base64url")
            decoded = decoded_bytes.decode("utf-8", "strict")
            encoded = decoded.encode("utf-8", "strict")
        except (UnicodeDecodeError, UnicodeEncodeError, ValueError) as exc:
            raise ValidationError("Path identifier is invalid.") from exc
        if (not decoded or decoded.strip() != decoded
                or unicodedata.normalize("NFC", decoded) != decoded
                or len(decoded) > 64 or len(encoded) > 256):
            raise ValidationError("Path identifier is invalid.")
        for ch in decoded:
            codepoint = ord(ch)
            category = unicodedata.category(ch)
            if (codepoint < 0x20 or 0x7F <= codepoint <= 0x9F
                    or category in {"Cs", "Zl", "Zp"}
                    or (category == "Cf" and codepoint != 0x200D)
                    or codepoint in _DANGEROUS_NAME_CODEPOINTS):
                raise ValidationError("Path identifier is invalid.")
        return decoded
    try:
        decoded_bytes = urllib.parse.unquote_to_bytes(raw)
        decoded = decoded_bytes.decode("utf-8", "strict")
    except (UnicodeDecodeError, ValueError) as exc:
        raise ValidationError("Path identifier is invalid.") from exc
    if (not decoded or decoded in {".", ".."} or "/" in decoded or "\\" in decoded
            or any(ord(ch) < 32 or ord(ch) == 127 for ch in decoded)):
        raise ValidationError("Path identifier is invalid.")
    if kind == "domain":
        decoded = decoded.lower()
        if not _PATH_DOMAIN_RE.fullmatch(decoded):
            raise ValidationError("Path identifier is invalid.")
    elif not _PATH_TAG_RE.fullmatch(decoded):
        raise ValidationError("Path identifier is invalid.")
    return decoded


class LimitedThreadingHTTPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True
    request_queue_size = 64

    def __init__(
            self, server_address, handler, *, config: WebConfig, control: PDGControl,
            static_root: str, max_workers: int = 32):
        self.config = config
        self.control = control
        self.security = SecurityState(config)
        self.tls_context: ssl.SSLContext | None = None
        self.static_root = pathlib.Path(static_root).resolve(strict=True)
        if not self.static_root.is_dir():
            raise ConfigError("static root is not a directory")
        self._worker_slots = threading.BoundedSemaphore(max_workers)
        self._accept_times: dict[int, float] = {}
        self._accept_times_lock = threading.Lock()
        super().__init__(server_address, handler)

    def get_request(self):
        request, address = super().get_request()
        accepted_at = time.monotonic()
        try:
            request.settimeout(SOCKET_TIMEOUT_SECONDS)
            request.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
            if self.tls_context is not None:
                request = self.tls_context.wrap_socket(
                    request, server_side=True, do_handshake_on_connect=False)
                request.settimeout(SOCKET_TIMEOUT_SECONDS)
            with self._accept_times_lock:
                self._accept_times[id(request)] = accepted_at
            return request, address
        except BaseException:
            request.close()
            raise

    def verify_request(self, request, client_address):
        """Drop untrusted socket peers before TLS/HTTP parsing or worker admission."""

        del request
        try:
            client_ip = str(client_address[0])
        except (IndexError, TypeError):
            return False
        return _ip_trusted(self.config, client_ip)

    def accepted_at(self, request) -> float:
        with self._accept_times_lock:
            return self._accept_times.get(id(request), time.monotonic())

    def close_request(self, request):
        with self._accept_times_lock:
            self._accept_times.pop(id(request), None)
        super().close_request(request)

    def process_request(self, request, client_address):
        if not self._worker_slots.acquire(blocking=False):
            try:
                request.close()
            except OSError:
                pass
            return
        try:
            super().process_request(request, client_address)
        except BaseException:
            self._worker_slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._worker_slots.release()

    def handle_error(self, request, client_address):
        # Do not print exception text, request paths, headers, or bodies.
        print("pdg-web: request failed", file=sys.stderr, flush=True)


class IPv6LimitedThreadingHTTPServer(LimitedThreadingHTTPServer):
    address_family = socket.AF_INET6


def make_server(
        config: WebConfig, control: PDGControl | None = None, static_root: str | None = None,
        *, allow_http: bool = False):
    if allow_http and os.environ.get("PDG_WEB_TEST_ALLOW_HTTP") != "1":
        raise ConfigError("HTTP test bypass was not explicitly enabled")
    root = static_root or os.environ.get(
        "PDG_WEB_STATIC", os.path.join(os.path.dirname(__file__), "static"))
    family = IPv6LimitedThreadingHTTPServer if ":" in config.listen else LimitedThreadingHTTPServer
    server = family(
        (config.listen, config.port), PDGRequestHandler, config=config,
        control=control or PDGControl(), static_root=root)
    if not allow_http:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.options |= ssl.OP_NO_COMPRESSION
        try:
            context.load_cert_chain(config.cert, config.key)
        except (OSError, ssl.SSLError) as exc:
            server.server_close()
            raise ConfigError("cannot load TLS certificate") from exc
        server.tls_context = context
    return server


class PDGRequestHandler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "PDGWeb"
    sys_version = ""

    def setup(self):
        super().setup()
        accepted_at = self.server.accepted_at(self.request)
        self.rfile = _HeaderLimitedReader(
            self.rfile,
            self.connection,
            deadline=accepted_at + HEADER_DEADLINE_SECONDS,
        )

    def parse_request(self):
        try:
            return super().parse_request()
        finally:
            if isinstance(self.rfile, _HeaderLimitedReader):
                self.rfile.finish_headers()

    def finish(self):
        if isinstance(getattr(self, "rfile", None), _HeaderLimitedReader):
            self.rfile.finish_headers()
        super().finish()

    def log_message(self, _format, *_args):
        # Access logs can accidentally capture identifiers or future query values.
        return

    def log_error(self, _format, *_args):
        return

    def send_error(self, code, _message=None, _explain=None):
        """Keep parser/unknown-method errors inside the safe JSON envelope."""

        if code == 501:
            self._error(405, "method_not_allowed", "Method is not allowed.")
        else:
            status = code if isinstance(code, int) and 400 <= code <= 599 else 400
            self._error(status, "invalid_request", "Request could not be processed.")

    def version_string(self):
        return "PDGWeb"

    def do_GET(self):
        self._dispatch()

    def do_POST(self):
        self._dispatch()

    def do_PUT(self):
        self._dispatch()

    def do_PATCH(self):
        self._dispatch()

    def do_DELETE(self):
        self._dispatch()

    def do_HEAD(self):
        self._error(405, "method_not_allowed", "Method is not allowed.", allow="GET")

    def do_OPTIONS(self):
        self._error(405, "method_not_allowed", "Method is not allowed.")

    @property
    def config(self) -> WebConfig:
        return self.server.config

    @property
    def control(self) -> PDGControl:
        return self.server.control

    @property
    def security(self) -> SecurityState:
        return self.server.security

    def _security_headers(self):
        self.send_header("Cache-Control", "no-store, max-age=0")
        self.send_header("Pragma", "no-cache")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'self'; base-uri 'none'; object-src 'none'; "
            "frame-ancestors 'none'; form-action 'self'; "
            "script-src 'self'; style-src 'self'; img-src 'self' data:; "
            "font-src 'self'; connect-src 'self'; manifest-src 'self'; frame-src 'none'",
        )
        self.send_header("Strict-Transport-Security", "max-age=31536000")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header(
            "Permissions-Policy",
            "camera=(), microphone=(), geolocation=(), payment=(), usb=()")
        self.send_header("Cross-Origin-Opener-Policy", "same-origin")
        self.send_header("Cross-Origin-Resource-Policy", "same-origin")
        self.send_header("X-Robots-Tag", "noindex, nofollow")

    def _send(
            self, status: int, body: bytes, content_type: str, *,
            cookie: str | None = None, allow: str | None = None,
            headers: dict[str, str] | None = None,
            maximum: int = MAX_RESPONSE_BYTES):
        if len(body) > maximum:
            status = 500
            body = b'{"ok":false,"error":{"code":"response_too_large","message":"Response is too large."}}'
            content_type = "application/json; charset=utf-8"
        self.send_response(status)
        self._security_headers()
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        if cookie is not None:
            self.send_header("Set-Cookie", cookie)
        if allow is not None:
            self.send_header("Allow", allow)
        for name, value in (headers or {}).items():
            self.send_header(name, value)
        self.send_header("Connection", "close")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)
        self.close_connection = True

    def _json(
            self, status: int, data: Any, *, cookie: str | None = None,
            allow: str | None = None):
        body = json.dumps(
            data, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode("utf-8")
        self._send(status, body, "application/json; charset=utf-8", cookie=cookie, allow=allow)

    def _ok(self, data: Any, *, status: int = 200, cookie: str | None = None):
        self._json(status, {"ok": True, "data": data}, cookie=cookie)

    def _error(
            self, status: int, code: str, message: str, *, cookie: str | None = None,
            allow: str | None = None):
        self._json(
            status, {"ok": False, "error": {"code": code, "message": message}},
            cookie=cookie, allow=allow)

    def _request_host(self) -> str | None:
        values = self.headers.get_all("Host") or []
        if len(values) != 1:
            return None
        raw_host = values[0]
        try:
            host = _normalize_host(raw_host)
        except ConfigError:
            return None
        return (
            host
            if raw_host == host and host in self.config.allowed_hosts
            else None
        )

    def _origin_allowed(self, host: str, *, required: bool) -> bool:
        values = self.headers.get_all("Origin") or []
        if not values:
            return not required
        if len(values) != 1 or values[0] == "null":
            return False
        try:
            origin, origin_host = _normalize_origin(values[0])
        except ConfigError:
            return False
        return (
            values[0] == origin
            and origin in self.config.allowed_origins
            and origin_host == host
        )

    def _client_ip(self) -> str:
        return str(self.client_address[0])

    def _request_target(self) -> tuple[str, str] | None:
        if len(self.path) > 2048 or any(ord(ch) < 32 or ord(ch) == 127 for ch in self.path):
            return None
        try:
            target = urllib.parse.urlsplit(self.path)
        except ValueError:
            return None
        if target.scheme or target.netloc or target.fragment:
            return None
        return target.path, target.query

    def _cookie_token(self) -> str | None:
        values = self.headers.get_all("Cookie") or []
        if not values:
            return None
        if len(values) != 1 or len(values[0]) > 4096:
            return None
        # Reject duplicates rather than letting a parser choose one ambiguously.
        names = [part.split("=", 1)[0].strip() for part in values[0].split(";") if "=" in part]
        if names.count(COOKIE_NAME) != 1:
            return None
        jar = http.cookies.SimpleCookie()
        try:
            jar.load(values[0])
        except http.cookies.CookieError:
            return None
        morsel = jar.get(COOKIE_NAME)
        return morsel.value if morsel is not None else None

    def _session(self) -> tuple[str | None, Session | None]:
        token = self._cookie_token()
        return token, self.security.session(token)

    def _csrf_header(self) -> str | None:
        values = self.headers.get_all(CSRF_HEADER) or []
        if len(values) != 1 or not 1 <= len(values[0]) <= 128:
            return None
        return values[0]

    def _read_json(self, *, password: bool = False) -> dict[str, Any] | None:
        transfer = self.headers.get_all("Transfer-Encoding") or []
        if transfer:
            self._error(400, "invalid_request", "Request body is invalid.")
            return None
        types = self.headers.get_all("Content-Type") or []
        if len(types) != 1 or types[0].split(";", 1)[0].strip().lower() != "application/json":
            self._error(415, "unsupported_media_type", "Content-Type must be application/json.")
            return None
        lengths = self.headers.get_all("Content-Length") or []
        if len(lengths) != 1 or not re.fullmatch(r"[0-9]{1,10}", lengths[0]):
            self._error(411, "length_required", "A valid Content-Length is required.")
            return None
        size = int(lengths[0])
        maximum = MAX_PASSWORD_BYTES + 64 if password else MAX_JSON_BYTES
        if size <= 0 or size > maximum:
            self._error(413, "body_too_large", "Request body size is invalid.")
            return None
        data = self.rfile.read(size)
        if len(data) != size:
            self._error(400, "invalid_request", "Request body is invalid.")
            return None
        try:
            value = _json_loads(data)
        except Exception:
            self._error(400, "invalid_json", "Request body is not valid JSON.")
            return None
        if not isinstance(value, dict):
            self._error(400, "invalid_request", "Request body must be a JSON object.")
            return None
        return value

    def _binary_meta(self, maximum: int = MAX_IMPORT_BYTES) -> tuple[int, str] | None:
        if self.headers.get_all("Transfer-Encoding"):
            self._error(400, "invalid_request", "Request body is invalid.")
            return None
        types = self.headers.get_all("Content-Type") or []
        if len(types) != 1:
            self._error(415, "unsupported_media_type", "Content-Type is required.")
            return None
        content_type = types[0].split(";", 1)[0].strip().lower()
        if content_type not in {
                "application/octet-stream", "application/yaml", "text/yaml",
                "application/x-yaml", "application/zip", "application/gzip",
                "application/x-gzip", "application/json"}:
            self._error(415, "unsupported_media_type", "Upload type is not supported.")
            return None
        lengths = self.headers.get_all("Content-Length") or []
        if len(lengths) != 1 or not re.fullmatch(r"[0-9]{1,10}", lengths[0]):
            self._error(411, "length_required", "A valid Content-Length is required.")
            return None
        size = int(lengths[0])
        if not 0 < size <= maximum:
            self._error(413, "body_too_large", "Upload size is invalid.")
            return None
        return size, content_type

    def _new_cookie(self, token: str) -> str:
        return (
            f"{COOKIE_NAME}={token}; Path=/; Max-Age={self.config.session_seconds}; "
            "HttpOnly; Secure; SameSite=Strict"
        )

    @staticmethod
    def _expired_cookie() -> str:
        return (
            f"{COOKIE_NAME}=; Path=/; Max-Age=0; "
            "HttpOnly; Secure; SameSite=Strict"
        )

    def _dispatch(self):
        client_ip = self._client_ip()
        if not _ip_trusted(self.config, client_ip):
            self._error(403, "forbidden", "Request is not allowed.")
            return
        host = self._request_host()
        if host is None:
            self._error(421, "host_not_allowed", "Host is not allowed.")
            return
        mutation = self.command in {"POST", "PUT", "PATCH", "DELETE"}
        if not self._origin_allowed(host, required=mutation):
            self._error(403, "origin_not_allowed", "Origin is not allowed.")
            return
        if not self.security.global_rate_allowed(client_ip):
            self._error(429, "rate_limited", "Too many requests.")
            return
        target = self._request_target()
        if target is None:
            self._error(400, "invalid_target", "Request target is invalid.")
            return
        path, query = target
        logs_query = (
            self.command == "GET" and path == "/api/v1/logs")
        if query and not logs_query:
            self._error(400, "invalid_query", "Query parameters are not allowed.")
            return
        if path.startswith("/api/"):
            self._dispatch_api(path, query, client_ip, host)
        elif self.command == "GET":
            if query:
                self._error(400, "invalid_query", "Query parameters are not allowed.")
                return
            self._static(path)
        else:
            self._error(405, "method_not_allowed", "Method is not allowed.", allow="GET")

    def _dispatch_api(self, path: str, query: str, client_ip: str, host: str):
        if path == "/api/v1/session" and self.command == "GET":
            token, session = self._session()
            if session is None:
                self._ok({
                    "authenticated": False,
                    "csrf": self.security.prelogin_csrf(client_ip, host),
                }, cookie=self._expired_cookie() if token else None)
            else:
                self._ok({
                    "authenticated": True,
                    "csrf": session.csrf,
                    "expires_at": int(session.expires),
                })
            return
        if path == "/api/v1/login" and self.command == "POST":
            self._login(client_ip, host)
            return

        token, session = self._session()
        if session is None:
            self._error(
                401, "authentication_required", "Authentication is required.",
                cookie=self._expired_cookie() if token else None)
            return
        if self.command in {"POST", "PUT", "PATCH", "DELETE"}:
            csrf = self._csrf_header()
            if csrf is None or not hmac.compare_digest(csrf, session.csrf):
                self._error(403, "csrf_failed", "CSRF validation failed.")
                return
        if path == "/api/v1/logout" and self.command == "POST":
            body = self._read_json()
            if body is None:
                return
            if body:
                self._error(400, "invalid_request", "Request data is invalid.")
                return
            self.security.destroy_session(token)
            self._ok(
                {"authenticated": False, "csrf": self.security.prelogin_csrf(
                    self._client_ip(), self._request_host() or "")},
                cookie=self._expired_cookie())
            return

        match = re.fullmatch(r"/api/v1/exports/(pdg|mihomo|mosdns)", path)
        if match and self.command == "POST":
            self._export_config(match.group(1), client_ip)
            return
        match = re.fullmatch(r"/api/v1/imports/(pdg|mihomo|mosdns)/preview", path)
        if match and self.command == "POST":
            upload = self._binary_meta(
                MAX_LEGACY_PDG_IMPORT_BYTES if match.group(1) == "pdg"
                else MAX_IMPORT_BYTES)
            if upload is not None:
                size, content_type = upload
                self._call(lambda: self.control.preview_import_stream(
                    match.group(1), self.rfile, size, content_type), status=201)
            return
        match = re.fullmatch(r"/api/v1/imports/(imp-[a-f0-9]{32})/apply", path)
        if match and self.command == "POST":
            body = self._read_json()
            if body is not None:
                self._call(lambda: self.control.apply_import(
                    match.group(1), body), status=202)
            return
        match = re.fullmatch(r"/api/v1/imports/(imp-[a-f0-9]{32})", path)
        if match and self.command == "DELETE":
            self._call(lambda: self.control.cancel_import(match.group(1)))
            return

        get_routes = {
            "/api/v1/overview": self.control.overview,
            "/api/v1/exits": self.control.exits,
            "/api/v1/groups": self.control.groups,
            "/api/v1/policy-groups": self.control.policy_groups,
            "/api/v1/rules": self.control.rules,
            "/api/v1/rulesets": self.control.rulesets,
            "/api/v1/dns": self.control.dns,
            "/api/v1/settings": self.control.settings,
            "/api/v1/traffic": self.control.traffic,
            "/api/v1/runtime": self.control.runtime,
            "/api/v1/snapshots": self.control.snapshots,
            "/api/v1/jobs": self.control.jobs,
        }
        if self.command == "GET" and path in get_routes:
            self._call(get_routes[path])
            return
        if self.command == "GET" and path == "/api/v1/logs":
            line_limit = 100
            if query:
                match = re.fullmatch(r"lines=([1-9][0-9]{1,2})", query)
                if match is None:
                    self._error(400, "invalid_query", "Query parameters are invalid.")
                    return
                line_limit = int(match.group(1))
                if not 10 <= line_limit <= 200 or str(line_limit) != match.group(1):
                    self._error(400, "invalid_query", "Query parameters are invalid.")
                    return
            self._call(lambda: self.control.logs(line_limit))
            return

        if path == "/api/v1/exits" and self.command == "POST":
            self._call_body(self.control.add_exit, status=201)
            return
        if path == "/api/v1/exits/order" and self.command == "PUT":
            self._call_body(self.control.reorder_exits)
            return
        if path == "/api/v1/default-exit" and self.command == "PUT":
            self._call_body(self.control.set_default_exit)
            return
        if path == "/api/v1/direct-tag" and self.command == "PUT":
            self._call_body(self.control.set_direct_tag)
            return
        if path == "/api/v1/groups" and self.command == "POST":
            self._call_body(self.control.add_group, status=201)
            return
        if path == "/api/v1/policy-groups" and self.command == "POST":
            self._call_body(self.control.add_policy_group, status=201)
            return
        if path == "/api/v1/rules" and self.command == "POST":
            self._call_body(self.control.add_rule, status=201)
            return
        if path == "/api/v1/rulesets" and self.command == "POST":
            self._call_body(self.control.add_ruleset, status=201)
            return
        if path == "/api/v1/diagnostics/exits" and self.command == "POST":
            self._call_body(self.control.diagnose_exits)
            return
        if path == "/api/v1/diagnostics/domain" and self.command == "POST":
            self._call_body(self.control.diagnose_domain)
            return
        if path == "/api/v1/settings/tfo" and self.command == "PUT":
            self._call_body(self.control.set_tfo)
            return

        match = re.fullmatch(r"/api/v1/exits/([^/]+)", path)
        if match and self.command in {"PATCH", "PUT", "DELETE"}:
            operation = (
                self.control.rename_exit if self.command == "PATCH"
                else self.control.replace_exit if self.command == "PUT"
                else self.control.delete_exit
            )
            self._identifier_call(
                match.group(1), "tag",
                operation, body=self.command in {"PATCH", "PUT"})
            return
        match = re.fullmatch(r"/api/v1/groups/([^/]+)/runtime", path)
        if match and self.command == "PUT":
            self._identifier_call(
                match.group(1), "tag", self.control.select_group_runtime,
                body=True)
            return
        match = re.fullmatch(r"/api/v1/policy-groups/([^/]+)/runtime", path)
        if match and self.command == "PUT":
            self._identifier_call(
                match.group(1), "tag", self.control.select_group_runtime,
                body=True)
            return
        match = re.fullmatch(r"/api/v1/policy-groups/([^/]+)", path)
        if match and self.command in {"PATCH", "DELETE"}:
            self._identifier_call(
                match.group(1), "tag",
                self.control.patch_policy_group if self.command == "PATCH"
                else self.control.delete_policy_group,
                body=True)
            return
        match = re.fullmatch(r"/api/v1/groups/([^/]+)", path)
        if match and self.command in {"PATCH", "DELETE"}:
            if self.command == "DELETE":
                self._identifier_optional_body(
                    match.group(1), "tag", self.control.delete_group)
            else:
                self._identifier_call(
                    match.group(1), "tag", self.control.patch_group,
                    body=True)
            return
        match = re.fullmatch(r"/api/v1/rules/([^/]+)", path)
        if match and self.command in {"PATCH", "DELETE"}:
            self._identifier_call(
                match.group(1), "domain",
                self.control.patch_rule if self.command == "PATCH" else self.control.delete_rule,
                body=self.command == "PATCH")
            return
        match = re.fullmatch(r"/api/v1/rulesets/([^/]+)", path)
        if match and self.command in {"PATCH", "DELETE"}:
            self._identifier_call(
                match.group(1), "tag",
                self.control.patch_ruleset if self.command == "PATCH"
                else self.control.delete_ruleset,
                body=self.command == "PATCH")
            return
        match = re.fullmatch(r"/api/v1/rulesets/([^/]+)/target", path)
        if match and self.command == "PUT":
            self._identifier_call(
                match.group(1), "tag", self.control.set_ruleset_target,
                body=True)
            return
        match = re.fullmatch(r"/api/v1/jobs/([^/]+)", path)
        if match and self.command == "GET":
            self._identifier_call(
                match.group(1), "tag", self.control.job, body=False)
            return
        match = re.fullmatch(r"/api/v1/dns/(remote|local)", path)
        if match and self.command == "PUT":
            body = self._read_json()
            if body is not None:
                self._call(lambda: self.control.set_dns(match.group(1), body))
            return
        match = re.fullmatch(
            r"/api/v1/actions/(restart|rules-update|snapshot|rollback|software-update)", path)
        if match and self.command == "POST":
            body = self._read_json()
            if body is not None:
                self._call(lambda: self.control.action(match.group(1), body), status=202)
            return

        if path.startswith("/api/v1/"):
            self._error(404, "not_found", "Endpoint was not found.")
        else:
            self._error(404, "not_found", "Endpoint was not found.")

    def _login(self, client_ip: str, host: str):
        csrf = self._csrf_header()
        if not self.security.verify_prelogin_csrf(csrf, client_ip, host):
            self._error(403, "csrf_failed", "CSRF validation failed.")
            return
        if not self.security.reserve_login_attempt(client_ip):
            self._error(429, "rate_limited", "Too many login attempts.")
            return
        attempt_finished = False
        body = None
        password = b""
        try:
            body = self._read_json(password=True)
            if body is None:
                return
            if set(body) != {"password"} or not isinstance(body["password"], str):
                self._error(401, "invalid_credentials", "Invalid credentials.")
                return
            try:
                password = body["password"].encode("utf-8", "strict")
            except UnicodeError:
                password = b""
            if not 1 <= len(password) <= MAX_PASSWORD_BYTES:
                password = b""
            valid = self.security.verify_password(password)
            if valid is None:
                self.security.finish_login_attempt(client_ip, failed=False)
                attempt_finished = True
                self._error(429, "rate_limited", "Too many login attempts.")
                return
            self.security.finish_login_attempt(client_ip, failed=not valid)
            attempt_finished = True
            if not valid:
                self._error(401, "invalid_credentials", "Invalid credentials.")
                return
            self.security.clear_login_failures(client_ip)
            old_token = self._cookie_token()
            self.security.destroy_session(old_token)
            token, session = self.security.create_session()
            self._ok(
                {"authenticated": True, "csrf": session.csrf,
                 "expires_at": int(session.expires)},
                cookie=self._new_cookie(token))
        finally:
            password = b""
            if isinstance(body, dict) and isinstance(body.get("password"), str):
                body["password"] = ""
            if not attempt_finished:
                self.security.finish_login_attempt(client_ip, failed=True)

    def _export_config(self, kind: str, client_ip: str):
        """Password re-authenticated attachment response.

        Export passwords are never forwarded to the control layer, jobs or
        logs.  The login KDF slot/rate limiter is intentionally shared so an
        export endpoint cannot become a second unlimited password oracle.
        """
        if not self.security.reserve_login_attempt(client_ip):
            self._error(429, "rate_limited", "Too many authentication attempts.")
            return
        finished = False
        body = None
        password = b""
        try:
            body = self._read_json(password=True)
            if body is None:
                return
            if set(body) != {"password"} or not isinstance(body.get("password"), str):
                self.security.finish_login_attempt(client_ip, failed=True)
                finished = True
                self._error(401, "invalid_credentials", "Invalid credentials.")
                return
            try:
                password = body["password"].encode("utf-8", "strict")
            except UnicodeError:
                password = b""
            if not 1 <= len(password) <= MAX_PASSWORD_BYTES:
                password = b""
            valid = self.security.verify_password(password)
            if valid is None:
                self.security.finish_login_attempt(client_ip, failed=False)
                finished = True
                self._error(429, "rate_limited", "Too many authentication attempts.")
                return
            self.security.finish_login_attempt(client_ip, failed=not valid)
            finished = True
            if not valid:
                self._error(401, "invalid_credentials", "Invalid credentials.")
                return
            self.security.clear_login_failures(client_ip)
            try:
                data, filename, content_type = self.control.export_config(kind)
            except ValidationError as exc:
                self._error(exc.status, exc.code, exc.public_message)
                return
            except NotFoundError as exc:
                self._error(exc.status, exc.code, exc.public_message)
                return
            except ControlError as exc:
                self._error(exc.status, exc.code, exc.public_message)
                return
            except Exception:
                self._error(500, "internal_error", "Operation could not be completed.")
                return
            if (not isinstance(data, bytes) or not 0 < len(data) <= MAX_IMPORT_BYTES
                    or not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", filename)):
                self._error(500, "internal_error", "Operation could not be completed.")
                return
            self._send(
                200, data, content_type,
                headers={"Content-Disposition": f'attachment; filename="{filename}"'},
                maximum=MAX_IMPORT_BYTES)
        finally:
            password = b""
            if isinstance(body, dict) and isinstance(body.get("password"), str):
                body["password"] = ""
            if not finished:
                self.security.finish_login_attempt(client_ip, failed=True)

    def _call(self, fn, *, status: int = 200):
        try:
            result = fn()
        except ValidationError as exc:
            self._error(exc.status, exc.code, exc.public_message)
        except NotFoundError as exc:
            self._error(exc.status, exc.code, exc.public_message)
        except ConflictError as exc:
            self._error(exc.status, exc.code, exc.public_message)
        except BusyError as exc:
            self._error(exc.status, exc.code, exc.public_message)
        except UnavailableError as exc:
            self._error(exc.status, exc.code, exc.public_message)
        except ControlError as exc:
            self._error(exc.status, exc.code, exc.public_message)
        except Exception:
            self._error(500, "internal_error", "Operation could not be completed.")
        else:
            self._ok(result, status=status)

    def _call_body(self, fn, *, status: int = 200):
        body = self._read_json()
        if body is not None:
            self._call(lambda: fn(body), status=status)

    def _identifier_call(self, raw: str, kind: str, fn, *, body: bool):
        try:
            value = _strict_path_segment(raw, kind=kind)
        except ValidationError as exc:
            self._error(exc.status, exc.code, exc.public_message)
            return
        if body:
            request_body = self._read_json()
            if request_body is not None:
                self._call(lambda: fn(value, request_body))
        else:
            self._call(lambda: fn(value))

    def _identifier_optional_body(self, raw: str, kind: str, fn):
        try:
            value = _strict_path_segment(raw, kind=kind)
        except ValidationError as exc:
            self._error(exc.status, exc.code, exc.public_message)
            return
        if self.headers.get_all("Transfer-Encoding"):
            self._error(400, "invalid_request", "Request body is invalid.")
            return
        lengths = self.headers.get_all("Content-Length") or []
        if not lengths or (len(lengths) == 1 and lengths[0] == "0"):
            self._call(lambda: fn(value, None))
            return
        if len(lengths) != 1 or not re.fullmatch(r"[0-9]{1,10}", lengths[0]):
            self._error(411, "length_required", "A valid Content-Length is required.")
            return
        request_body = self._read_json()
        if request_body is not None:
            self._call(lambda: fn(value, request_body))

    def _static(self, path: str):
        if _PERCENT_BAD_RE.search(path) or len(path) > 1024:
            self._error(404, "not_found", "Resource was not found.")
            return
        try:
            decoded = urllib.parse.unquote_to_bytes(path).decode("utf-8", "strict")
        except (UnicodeDecodeError, ValueError):
            self._error(404, "not_found", "Resource was not found.")
            return
        if "\\" in decoded or "\x00" in decoded:
            self._error(404, "not_found", "Resource was not found.")
            return
        relative = decoded.lstrip("/") or "index.html"
        pieces = pathlib.PurePosixPath(relative).parts
        if any(piece in {"", ".", ".."} for piece in pieces):
            self._error(404, "not_found", "Resource was not found.")
            return
        root: pathlib.Path = self.server.static_root
        try:
            candidate = (root / pathlib.PurePosixPath(relative)).resolve(strict=True)
            candidate.relative_to(root)
        except (OSError, RuntimeError, ValueError):
            if "." not in pieces[-1]:
                try:
                    candidate = (root / "index.html").resolve(strict=True)
                    candidate.relative_to(root)
                except (OSError, RuntimeError, ValueError):
                    self._error(404, "not_found", "Resource was not found.")
                    return
            else:
                self._error(404, "not_found", "Resource was not found.")
                return
        try:
            info = candidate.stat()
            if not stat.S_ISREG(info.st_mode) or info.st_size < 0 or info.st_size > MAX_STATIC_BYTES:
                raise OSError("invalid static file")
            with candidate.open("rb") as handle:
                data = handle.read(MAX_STATIC_BYTES + 1)
            if len(data) > MAX_STATIC_BYTES:
                raise OSError("static file too large")
        except OSError:
            self._error(404, "not_found", "Resource was not found.")
            return
        mime = _MIME_TYPES.get(candidate.suffix.lower(), "application/octet-stream")
        self._send(200, data, mime)


def _arguments(argv=None):
    parser = argparse.ArgumentParser(description="PDG native HTTPS management server")
    parser.add_argument(
        "--config",
        default=os.environ.get("PDG_WEB_CONFIG", DEFAULT_CONFIG),
        help="canonical web.json path",
    )
    return parser.parse_args(argv)


def main(argv=None):
    args = _arguments(argv)
    try:
        config = load_config(args.config, testing=False)
        server = make_server(config, allow_http=False)
    except (ConfigError, OSError, RuntimeError):
        print("pdg-web: startup refused (invalid configuration)", file=sys.stderr)
        return 1
    try:
        server.serve_forever(poll_interval=0.5)
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

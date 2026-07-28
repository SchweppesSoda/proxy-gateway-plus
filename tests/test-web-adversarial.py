#!/usr/bin/env python3
"""Adversarial regressions for the native PDG Web management service.

These tests intentionally use the public server/control behavior instead of
asserting implementation text.  In particular, the slow-client test injects
accepted socket pairs through ``BaseServer._handle_request_noblock`` so it can
exercise peer verification and worker admission without relying on sleeps.
"""
from __future__ import annotations

import base64
import collections
import hashlib
import http.client
import importlib.util
import ipaddress
import io
import json
import os
import pathlib
import socket
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock


ROOT = pathlib.Path(__file__).resolve().parents[1]
WEB_DIR = ROOT / "deploy" / "web"
sys.path.insert(0, str(WEB_DIR))

import pdgcontrol  # noqa: E402


def _load_path(name: str, path: pathlib.Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load %s" % path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


web = _load_path("pdg_web_adversarial_test", WEB_DIR / "pdg-web.py")
setup = _load_path("pdg_web_setup_adversarial_test", WEB_DIR / "pdg-web-setup.py")


def _b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


class _NoopControl:
    """The tested login/static paths do not call the privileged adapter."""


class _FakeMainServer:
    def __init__(self):
        self.served = False
        self.closed = False

    def serve_forever(self, poll_interval=0.5):
        del poll_interval
        self.served = True

    def server_close(self):
        self.closed = True


class WebAdversarialTestCase(unittest.TestCase):
    password = "correct horse battery staple"

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.temp_path = pathlib.Path(self.temp.name)
        self.static = self.temp_path / "static"
        self.static.mkdir()
        (self.static / "index.html").write_text(
            "<!doctype html><title>PDG adversarial test</title>",
            encoding="utf-8",
        )
        self.servers = []

    def tearDown(self):
        for server, thread in reversed(self.servers):
            if thread is not None:
                server.shutdown()
            server.server_close()
            if thread is not None:
                thread.join(timeout=2)
        self.temp.cleanup()

    @staticmethod
    def _unused_port() -> int:
        probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
        probe.close()
        return port

    def _config(self, port: int, trusted_cidrs=None):
        salt = b"0123456789abcdef"
        password_hash = hashlib.pbkdf2_hmac(
            "sha256", self.password.encode(), salt, 1000, dklen=32
        )
        host = "pdg.example:%d" % port
        origin = "https://" + host
        return web.WebConfig(
            listen="127.0.0.1",
            port=port,
            trusted_cidrs=tuple(
                ipaddress.ip_network(value)
                for value in (
                    trusted_cidrs
                    or ("127.0.0.1/32", "::1/128")
                )
            ),
            allowed_hosts=frozenset({host}),
            allowed_origins=frozenset({origin}),
            origin_hosts=frozenset({(origin, host)}),
            session_seconds=3600,
            cert=str(self.temp_path / "unused-cert.pem"),
            key=str(self.temp_path / "unused-key.pem"),
            iterations=1000,
            salt=salt,
            password_hash=password_hash,
            session_secret=b"S" * 32,
        )

    def _server(self, *, max_workers=32, running=False):
        port = self._unused_port()
        config = self._config(port)
        server = web.LimitedThreadingHTTPServer(
            (config.listen, config.port),
            web.PDGRequestHandler,
            config=config,
            control=_NoopControl(),
            static_root=str(self.static),
            max_workers=max_workers,
        )
        thread = None
        if running:
            thread = threading.Thread(
                target=server.serve_forever,
                kwargs={"poll_interval": 0.01},
                daemon=True,
            )
            thread.start()
        self.servers.append((server, thread))
        return server

    @staticmethod
    def _socket_response(client: socket.socket) -> bytes:
        chunks = []
        client.settimeout(3)
        while True:
            try:
                chunk = client.recv(65536)
            except (ConnectionResetError, socket.timeout):
                break
            if not chunk:
                break
            chunks.append(chunk)
        return b"".join(chunks)

    def test_untrusted_slow_clients_never_enter_workers_or_block_trusted_peer(self):
        server = self._server(max_workers=32)
        queued = collections.deque()
        original_get_request = server.get_request
        clients = []

        def injected_get_request():
            return queued.popleft()

        server.get_request = injected_get_request
        try:
            partial = (
                "GET / HTTP/1.1\r\n"
                "Host: pdg.example:%d\r\n"
                "X-Slow: " % server.server_address[1]
            ).encode("ascii")
            for index in range(32):
                accepted, client = socket.socketpair()
                client.sendall(partial)
                clients.append(client)
                queued.append((
                    accepted,
                    ("198.51.100.%d" % (index + 1), 40000 + index),
                ))
                server._handle_request_noblock()

            accepted, trusted = socket.socketpair()
            trusted.sendall((
                "GET / HTTP/1.1\r\n"
                "Host: pdg.example:%d\r\n"
                "Connection: close\r\n\r\n" % server.server_address[1]
            ).encode("ascii"))
            queued.append((accepted, ("127.0.0.1", 50000)))
            server._handle_request_noblock()

            response = self._socket_response(trusted)
            trusted.close()
            self.assertTrue(
                response.startswith(b"HTTP/1.1 200 "),
                "32 untrusted partial requests consumed worker admission; "
                "trusted response was %r" % response[:120],
            )
        finally:
            server.get_request = original_get_request
            for client in clients:
                client.close()

    def test_trusted_request_headers_have_absolute_and_aggregate_limits(self):
        class FakeConnection:
            def __init__(self):
                self.timeouts = []
                self.shutdowns = []

            def settimeout(self, value):
                self.timeouts.append(value)

            def shutdown(self, how):
                self.shutdowns.append(how)

        connection = FakeConnection()
        reader = web._HeaderLimitedReader(
            io.BytesIO(b"GET / HTTP/1.1\r\nX: 1234567890123456\r\n"),
            connection,
            deadline=time.monotonic() + 10,
            maximum=16,
        )
        try:
            self.assertEqual(reader.readline(), b"GET / HTTP/1.1\r\n")
            with self.assertRaises(http.client.LineTooLong):
                reader.readline()
        finally:
            reader.finish_headers()

        expired = web._HeaderLimitedReader(
            io.BytesIO(b"GET / HTTP/1.1\r\n"),
            connection,
            deadline=time.monotonic() - 1,
        )
        try:
            with self.assertRaises(TimeoutError):
                expired.readline()
        finally:
            expired.finish_headers()

        accepted_drip, dripping = socket.socketpair()
        stream = accepted_drip.makefile("rb")
        stop_drip = threading.Event()
        prefix_sent = threading.Event()

        def drip_header():
            try:
                dripping.sendall(b"GET / HTTP/1.1\r\nX-Slow: ")
                prefix_sent.set()
                while not stop_drip.wait(0.01):
                    dripping.sendall(b"a")
            except OSError:
                prefix_sent.set()

        writer = threading.Thread(target=drip_header, daemon=True)
        writer.start()
        self.assertTrue(prefix_sent.wait(timeout=1))
        deadline = time.monotonic() + 0.25
        drip_reader = web._HeaderLimitedReader(
            stream, accepted_drip, deadline=deadline)
        started = time.monotonic()
        try:
            self.assertEqual(
                drip_reader.readline(), b"GET / HTTP/1.1\r\n")
            with self.assertRaises(TimeoutError):
                drip_reader.readline()
            self.assertLess(
                time.monotonic() - started,
                1.0,
                "a continuously dripping header exceeded its absolute deadline",
            )
        finally:
            stop_drip.set()
            drip_reader.finish_headers()
            stream.close()
            accepted_drip.close()
            dripping.close()
            writer.join(timeout=1)

        server = self._server()
        original_get_request = server.get_request
        accepted, client = socket.socketpair()
        try:
            client.sendall((
                "GET / HTTP/1.1\r\n"
                "Host: pdg.example:%d\r\n"
                "X-Large: %s\r\n\r\n"
                % (server.server_address[1], "a" * web.MAX_HEADER_BYTES)
            ).encode("ascii"))
            server.get_request = lambda: (accepted, ("127.0.0.1", 51000))
            server._handle_request_noblock()
            response = self._socket_response(client)
            self.assertTrue(response.startswith(b"HTTP/1.1 431 "))
            self.assertIn(b'"code":"invalid_request"', response)
        finally:
            server.get_request = original_get_request
            client.close()

    def test_concurrent_bad_logins_bound_kdf_before_password_work(self):
        server = self._server(max_workers=32, running=True)
        port = server.server_address[1]
        host = "pdg.example:%d" % port
        origin = "https://" + host

        connection = http.client.HTTPConnection("127.0.0.1", port, timeout=3)
        connection.request("GET", "/api/v1/session", headers={"Host": host})
        response = connection.getresponse()
        session = json.loads(response.read())
        connection.close()
        csrf = session["data"]["csrf"]

        active = 0
        maximum_active = 0
        state_lock = threading.Lock()
        violation = threading.Event()
        release = threading.Event()
        start = threading.Barrier(13)
        outcomes = []

        def blocked_kdf(_name, _password, _salt, _iterations, dklen):
            nonlocal active, maximum_active
            with state_lock:
                active += 1
                maximum_active = max(maximum_active, active)
                if active > web.LOGIN_RATE_ATTEMPTS:
                    violation.set()
            try:
                release.wait(timeout=5)
                return b"\x00" * dklen
            finally:
                with state_lock:
                    active -= 1

        def login():
            start.wait(timeout=3)
            conn = http.client.HTTPConnection("127.0.0.1", port, timeout=6)
            body = json.dumps({"password": "definitely wrong"}).encode("utf-8")
            headers = {
                "Host": host,
                "Origin": origin,
                web.CSRF_HEADER: csrf,
                "Content-Type": "application/json",
                "Content-Length": str(len(body)),
            }
            try:
                conn.request("POST", "/api/v1/login", body=body, headers=headers)
                result = conn.getresponse()
                result.read()
                outcomes.append(result.status)
            finally:
                conn.close()

        workers = [threading.Thread(target=login, daemon=True) for _ in range(12)]
        with mock.patch.object(web.hashlib, "pbkdf2_hmac", side_effect=blocked_kdf):
            for worker in workers:
                worker.start()
            start.wait(timeout=3)
            violation.wait(timeout=1)
            release.set()
            for worker in workers:
                worker.join(timeout=7)

        self.assertFalse(
            violation.is_set(),
            "more than the per-IP login allowance entered PBKDF2 concurrently",
        )
        self.assertLessEqual(maximum_active, web.LOGIN_RATE_ATTEMPTS)
        self.assertEqual(len(outcomes), len(workers))
        self.assertTrue(all(status in {401, 429} for status in outcomes))

    def test_equivalent_default_route_cidr_union_is_rejected(self):
        with self.assertRaises(setup.ConfigError):
            setup.parse_trusted_cidrs(["0.0.0.0/1", "128.0.0.0/1"])

        port = self._unused_port()
        config = self._config(port)
        raw = {
            "listen": config.listen,
            "port": config.port,
            "trusted_cidrs": [
                "0.0.0.0/1",
                "127.0.0.1/32",
                "128.0.0.0/1",
                "::1/128",
            ],
            "allowed_hosts": sorted(config.allowed_hosts),
            "allowed_origins": sorted(config.allowed_origins),
            "session_hours": 1,
            "tls": {"cert": config.cert, "key": config.key},
            "auth": {
                "algorithm": "pbkdf2_sha256",
                "iterations": config.iterations,
                "salt": _b64url(config.salt),
                "password_hash": _b64url(config.password_hash),
                "session_secret": _b64url(config.session_secret),
            },
        }
        path = self.temp_path / "aggregate-default-route.json"
        path.write_text(json.dumps(raw), encoding="utf-8")
        with self.assertRaises(web.ConfigError):
            web.load_config(str(path), testing=True)

    def test_server_side_log_redaction_covers_prefixed_secret_names(self):
        cases = {
            "CF_API_TOKEN": "cloudflare-token-value",
            "client_secret": "oauth-client-secret-value",
            "credential": "credential-value",
            "api_key": "api-key-value",
            "access_key": "access-key-value",
            "cookie": "cookie-value",
            "session": "session-value",
        }
        for key, secret in cases.items():
            with self.subTest(key=key):
                clean = pdgcontrol.sanitize_log_line("%s=%s" % (key, secret))
                self.assertNotIn(secret, clean)
                self.assertIn("<redacted>", clean)
        quoted_secret = "secret value containing spaces"
        clean = pdgcontrol.sanitize_log_line(
            'client_secret="%s"' % quoted_secret)
        self.assertNotIn(quoted_secret, clean)
        for header, secrets in (
            ("Authorization: Basic dXNlcjpwYXNz", ("dXNlcjpwYXNz",)),
            (
                "Authorization: Bearer abcdefghijklmnopqrstuvwxyz012345",
                ("abcdefghijklmnopqrstuvwxyz012345",),
            ),
            (
                "Cookie: pdg_session=session-secret; other=another-secret",
                ("session-secret", "another-secret"),
            ),
        ):
            with self.subTest(header=header.split(":", 1)[0]):
                clean = pdgcontrol.sanitize_log_line(header)
                for secret in secrets:
                    self.assertNotIn(secret, clean)
                self.assertIn("<redacted>", clean)

    def test_endpoint_summary_never_displays_opaque_path_token(self):
        token = "AbCdEfGhIjKlMnOpQrStUvWxYz012345"
        for path in (token, token + ".json"):
            with self.subTest(path=path):
                summary = pdgcontrol._safe_endpoint(
                    "https://dns.example/%s" % path
                )
                self.assertEqual(summary, "https://dns.example")
                self.assertNotIn(token, summary)
        self.assertEqual(
            pdgcontrol._safe_endpoint("https://dns.example/dns-query"),
            "https://dns.example/dns-query",
        )

    def test_production_main_cannot_enable_http_bypass_from_environment(self):
        fake_server = _FakeMainServer()
        fake_config = object()
        with (
            mock.patch.dict(
                os.environ, {"PDG_WEB_TEST_ALLOW_HTTP": "1"}, clear=False
            ),
            mock.patch.object(
                web, "load_config", return_value=fake_config
            ) as load_config,
            mock.patch.object(
                web, "make_server", return_value=fake_server
            ) as make_server,
        ):
            result = web.main(["--config", "/etc/privdns-gateway/web.json"])

        if load_config.called:
            self.assertFalse(
                load_config.call_args.kwargs.get("testing", False),
                "production main enabled relaxed config validation from env",
            )
        if make_server.called:
            self.assertFalse(
                make_server.call_args.kwargs.get("allow_http", False),
                "production main disabled TLS from a test environment variable",
            )
            self.assertTrue(fake_server.served)
            self.assertTrue(fake_server.closed)
        else:
            self.assertNotEqual(
                result, 0, "production main silently accepted the test bypass"
            )


if __name__ == "__main__":
    unittest.main(verbosity=2)

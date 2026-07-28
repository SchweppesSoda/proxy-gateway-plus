#!/usr/bin/env python3
"""Unit coverage for the two-connection DoT SSLSession probe and doctor verdict."""
import pathlib
import struct
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "deploy" / "bot"))
import dot_session_probe as probe  # noqa: E402
import checks  # noqa: E402


class FakeSession:
    def __init__(self, *, ticket=True, session_id=b"session"):
        self.has_ticket = ticket
        self.id = session_id
        self.ticket_lifetime_hint = 300 if ticket else 0


class FakeTLS:
    def __init__(self, session, *, reused=False):
        self.session = session
        self.session_reused = reused
        self.response = b""

    def __enter__(self):
        return self

    def __exit__(self, *_):
        return False

    def settimeout(self, _):
        pass

    def version(self):
        return "TLSv1.3"

    def cipher(self):
        return ("TLS_AES_128_GCM_SHA256", "TLSv1.3", 128)

    def sendall(self, framed_query):
        size = struct.unpack("!H", framed_query[:2])[0]
        query = framed_query[2:2 + size]
        answer = query[:2] + b"\x81\x80" + query[4:]
        self.response = struct.pack("!H", len(answer)) + answer

    def recv(self, size):
        chunk, self.response = self.response[:size], self.response[size:]
        return chunk


class FakeRaw:
    def __enter__(self):
        return self

    def __exit__(self, *_):
        return False


class FakeContext:
    accepted = True
    ticket = True
    sessions_offered = []

    def __init__(self, _):
        self.check_hostname = True
        self.verify_mode = None
        self.count = 0

    def wrap_socket(self, _raw, **kwargs):
        self.count += 1
        FakeContext.sessions_offered.append(kwargs.get("session"))
        if self.count == 1:
            session = FakeSession(ticket=self.ticket,
                                  session_id=b"session" if self.ticket else b"")
            return FakeTLS(session)
        return FakeTLS(FakeSession(ticket=self.ticket),
                       reused=self.accepted and kwargs.get("session") is not None)


real_context = probe.ssl.SSLContext
real_connect = probe.socket.create_connection
probe.ssl.SSLContext = FakeContext
probe.socket.create_connection = lambda *_args, **_kwargs: FakeRaw()
try:
    FakeContext.accepted = True
    FakeContext.ticket = True
    FakeContext.sessions_offered = []
    evidence = probe.probe("127.0.0.1", 853, "dot.example")
    assert evidence["first"]["has_ticket"] is True
    assert evidence["resumption_offered"] is True
    assert evidence["second"]["session_reused"] is True
    assert FakeContext.sessions_offered[1] is not None

    FakeContext.accepted = False
    evidence = probe.probe("127.0.0.1", 853, "dot.example")
    assert evidence["resumption_accepted"] is False

    FakeContext.ticket = False
    evidence = probe.probe("127.0.0.1", 853, "dot.example")
    assert evidence["resumption_offered"] is False
    assert evidence["second"]["session_reused"] is False
finally:
    probe.ssl.SSLContext = real_context
    probe.socket.create_connection = real_connect


real_domain = checks._dot_domain
real_probe = checks.dot_session_probe.probe
checks._dot_domain = lambda: "dot.example"
try:
    checks.dot_session_probe.probe = lambda *_a, **_k: {
        "resumption_offered": True,
        "resumption_accepted": True,
        "first": {"has_ticket": True},
        "second": {"tls_version": "TLSv1.3", "session_reused": True},
    }
    assert checks.check_deep_dot_no_resumption()[0] == "fail"
    checks.dot_session_probe.probe = lambda *_a, **_k: {
        "resumption_offered": False,
        "resumption_accepted": False,
        "first": {"has_ticket": False},
        "second": {"tls_version": "TLSv1.3", "session_reused": False},
    }
    assert checks.check_deep_dot_no_resumption()[0] == "ok"
finally:
    checks._dot_domain = real_domain
    checks.dot_session_probe.probe = real_probe

source = (ROOT / "deploy" / "bot" / "checks.py").read_text(encoding="utf-8")
assert "hostname_checks_common_name = False" in source
assert "check_deep_dot_no_resumption" in source
print("[OK] DoT two-handshake SSLSession probe + doctor verdict")

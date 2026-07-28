#!/usr/bin/env python3
"""Probe whether a DoT endpoint accepts TLS session resumption.

The first connection performs a real DNS-over-TLS query so OpenSSL processes
post-handshake TLS 1.3 NewSessionTicket messages.  A resumable SSLSession, when
one was issued, is then offered on a second connection made with the same
SSLContext.
"""

from __future__ import annotations

import argparse
import json
import secrets
import socket
import ssl
import struct
import sys
from typing import Any


def _recv_exact(sock: ssl.SSLSocket, size: int) -> bytes:
    chunks: list[bytes] = []
    remaining = size
    while remaining:
        chunk = sock.recv(remaining)
        if not chunk:
            raise ConnectionError("DoT peer closed the connection early")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def _dns_query(name: str) -> tuple[int, bytes]:
    labels = name.rstrip(".").split(".")
    if not labels or any(not label or len(label.encode("ascii")) > 63 for label in labels):
        raise ValueError(f"invalid DNS query name: {name!r}")
    qname = b"".join(bytes((len(label.encode("ascii")),)) + label.encode("ascii")
                     for label in labels) + b"\0"
    txid = secrets.randbits(16)
    # RD=1, QDCOUNT=1, QTYPE=A, QCLASS=IN.
    message = struct.pack("!HHHHHH", txid, 0x0100, 1, 0, 0, 0)
    message += qname + struct.pack("!HH", 1, 1)
    return txid, message


def _dot_exchange(sock: ssl.SSLSocket, query_name: str) -> int:
    txid, query = _dns_query(query_name)
    sock.sendall(struct.pack("!H", len(query)) + query)
    response_size = struct.unpack("!H", _recv_exact(sock, 2))[0]
    if response_size < 12 or response_size > 65535:
        raise ValueError(f"invalid DoT response size: {response_size}")
    response = _recv_exact(sock, response_size)
    response_txid = struct.unpack("!H", response[:2])[0]
    if response_txid != txid:
        raise ValueError("DoT response transaction ID does not match the query")
    return response[3] & 0x0F


def _session_details(sock: ssl.SSLSocket) -> dict[str, Any]:
    session = sock.session
    return {
        "tls_version": sock.version(),
        "cipher": (sock.cipher() or (None,))[0],
        "session_id": session.id.hex(),
        "has_ticket": bool(getattr(session, "has_ticket", False)),
        "ticket_lifetime_hint": int(getattr(session, "ticket_lifetime_hint", 0)),
        "session_reused": bool(sock.session_reused),
    }


def probe(host: str, port: int, server_name: str, *, timeout: float = 8.0,
          query_name: str = "example.com") -> dict[str, Any]:
    """Run two DoT handshakes and return ticket/resumption evidence."""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    # This probe tests session semantics. Certificate/domain correctness is a
    # separate doctor check, and localhost probing must work with a public cert.
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    with socket.create_connection((host, port), timeout=timeout) as raw:
        with context.wrap_socket(raw, server_hostname=server_name) as first:
            first.settimeout(timeout)
            first_rcode = _dot_exchange(first, query_name)
            first_details = _session_details(first)
            first_session = first.session

    resumable = bool(first_details["has_ticket"] or first_details["session_id"])
    wrap_kwargs: dict[str, Any] = {"server_hostname": server_name}
    if resumable:
        wrap_kwargs["session"] = first_session

    with socket.create_connection((host, port), timeout=timeout) as raw:
        with context.wrap_socket(raw, **wrap_kwargs) as second:
            second.settimeout(timeout)
            second_rcode = _dot_exchange(second, query_name)
            second_details = _session_details(second)

    return {
        "endpoint": f"{host}:{port}",
        "server_name": server_name,
        "query_name": query_name,
        "resumption_offered": resumable,
        "first": {**first_details, "dns_rcode": first_rcode},
        "second": {**second_details, "dns_rcode": second_rcode},
        "resumption_accepted": bool(second_details["session_reused"]),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("host")
    parser.add_argument("port", type=int)
    parser.add_argument("--servername", required=True)
    parser.add_argument("--query", default="example.com")
    parser.add_argument("--timeout", type=float, default=8.0)
    args = parser.parse_args(argv)
    try:
        result = probe(args.host, args.port, args.servername,
                       timeout=args.timeout, query_name=args.query)
    except Exception as exc:  # noqa: BLE001 - CLI must return structured evidence
        print(json.dumps({"error": f"{type(exc).__name__}: {exc}"},
                         ensure_ascii=False))
        return 2
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 1 if result["resumption_accepted"] else 0


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""Real Mihomo: rendered domain YAML must load and route exact/suffix requests."""
import ast
import functools
import http.server
import json
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "deploy/bot"))
import sb2mihomo

source = ROOT / "deploy/bot/pdg-bot.py"
tree = ast.parse(source.read_text(encoding="utf-8"))
ns = {}
exec(compile(ast.Module(body=[n for n in tree.body if isinstance(n, ast.FunctionDef)
    and n.name == "_mihomo_rulesets"], type_ignores=[]), str(source), "exec"), ns)


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


class Handler(http.server.SimpleHTTPRequestHandler):
    def log_message(self, *args):
        pass


def read_exact(sock, count):
    data = b""
    while len(data) < count:
        part = sock.recv(count - len(data))
        if not part:
            raise OSError("SOCKS connection closed")
        data += part
    return data


def request(port, domain, target_port):
    with socket.create_connection(("127.0.0.1", port), timeout=5) as sock:
        sock.sendall(b"\x05\x01\x00")
        assert read_exact(sock, 2) == b"\x05\x00"
        host = domain.encode("ascii")
        sock.sendall(b"\x05\x01\x00\x03" + bytes([len(host)]) + host
                     + target_port.to_bytes(2, "big"))
        response = read_exact(sock, 4)
        if response[1] != 0:
            return False
        address_size = {1: 4, 4: 16}.get(response[3])
        if response[3] == 3:
            address_size = read_exact(sock, 1)[0]
        assert address_size is not None, "invalid SOCKS response address"
        read_exact(sock, address_size + 2)
        sock.sendall(b"GET /marker HTTP/1.0\r\nHost: " + host + b"\r\n\r\n")
        data = b""
        while True:
            part = sock.recv(4096)
            if not part:
                break
            data += part
        return b"domain-provider-matched" in data


def main():
    with tempfile.TemporaryDirectory(prefix="pdg-domain-runtime-") as tmp:
        work = Path(tmp)
        (work / "ai.yaml").write_text("payload:\n  - ai.google.dev\n  - '+.openai.com'\n")
        (work / "marker").write_text("domain-provider-matched")
        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0),
            functools.partial(Handler, directory=tmp))
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        process = None
        try:
            port, controller = free_port(), free_port()
            base = "http://127.0.0.1:%d" % server.server_port
            meta = {"test-ai": {"url": base + "/ai.yaml", "outbound": "AI",
                                 "format": "source", "behavior": "domain"}}
            model = {"outbounds": [{"tag": "AI", "type": "direct"}],
                     "route": {"rules": [{"rule_set": "test-ai", "outbound": "AI"}],
                               "final": "AI"}}
            cfg, _ = sb2mihomo.singbox_to_mihomo(model,
                controller="127.0.0.1:%d" % controller, rulesets=ns["_mihomo_rulesets"](meta))
            cfg.pop("redir-port", None)
            cfg.pop("tproxy-port", None)
            cfg["mixed-port"] = port
            cfg["bind-address"] = "127.0.0.1"
            cfg["rules"][-1] = "MATCH,REJECT"
            cfg["hosts"] = {host: "127.0.0.1" for host in (
                "ai.google.dev", "api.openai.com", "unmatched.example.com")}
            path = work / "config.json"
            path.write_text(json.dumps(cfg))
            with (work / "mihomo.log").open("w+") as log:
                process = subprocess.Popen([sys.argv[1], "-d", tmp, "-f", str(path)],
                    stdout=log, stderr=subprocess.STDOUT)
                try:
                    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
                    deadline = time.monotonic() + 15
                    while True:
                        try:
                            with opener.open("http://127.0.0.1:%d/providers/rules" % controller,
                                             timeout=1) as response:
                                provider = json.load(response)["providers"]["test-ai"]
                            if provider["ruleCount"] == 2:
                                break
                        except (OSError, KeyError):
                            pass
                        assert process.poll() is None, "Mihomo exited before provider loaded"
                        assert time.monotonic() < deadline, "domain YAML loaded no usable rules"
                        time.sleep(0.1)
                    assert provider["behavior"] == "Domain", provider
                    assert request(port, "ai.google.dev", server.server_port), "exact rule missed"
                    assert request(port, "api.openai.com", server.server_port), "suffix rule missed"
                    try:
                        matched = request(port, "unmatched.example.com", server.server_port)
                    except OSError:
                        matched = False
                    assert not matched, "unmatched domain bypassed the default reject rule"
                    print("[OK] Real Mihomo: 2 domain rules, exact/suffix matched, default rejected")
                except Exception:
                    log.flush()
                    print((work / "mihomo.log").read_text()[-3000:])
                    raise
        finally:
            if process is not None:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)


if __name__ == "__main__":
    main()

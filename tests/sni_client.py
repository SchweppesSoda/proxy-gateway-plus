#!/usr/bin/env python3
"""向 sing-box direct 入口发一个带指定 SNI 的 TLS ClientHello, 触发 SNI 嗅探。

对端是 mock SOCKS5(不会完成 TLS), 所以握手必然失败 —— 我们只需要把 ClientHello 发出去
让 sing-box 嗅到 SNI 并据此分流。用法: sni_client.py <host> <port> <sni>
"""
import socket
import ssl
import sys


def main():
    host, port, sni = sys.argv[1], int(sys.argv[2]), sys.argv[3]
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    raw = socket.create_connection((host, port), timeout=5)
    raw.settimeout(5)
    s = ctx.wrap_socket(raw, server_hostname=sni, do_handshake_on_connect=False)
    try:
        s.do_handshake()                 # 发出 ClientHello(含 SNI)
    except (ssl.SSLError, OSError):
        pass                             # 预期失败: 对端非真 TLS 服务
    finally:
        try:
            s.close()
        except OSError:
            pass


if __name__ == "__main__":
    main()

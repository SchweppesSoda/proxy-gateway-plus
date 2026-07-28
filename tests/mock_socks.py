#!/usr/bin/env python3
"""极简 SOCKS5 出口桩: 接受 sing-box 的 socks 出站, 记录它要 CONNECT 的目标(host:port)到日志文件。

只为功能测试断言"分流去了哪个出口", 不做真正转发: 完成握手 → 记录目标 → 读掉首包 → 关闭。
用法: mock_socks.py <port> <logfile>
"""
import socket
import sys
import threading


def handle(conn, logf):
    try:
        conn.settimeout(5)
        hdr = conn.recv(2)                       # VER, NMETHODS
        if len(hdr) < 2 or hdr[0] != 0x05:
            return
        conn.recv(hdr[1])                        # METHODS
        conn.sendall(b"\x05\x00")                # 选 no-auth
        req = conn.recv(4)                       # VER CMD RSV ATYP
        if len(req) < 4 or req[1] != 0x01:       # 只处理 CONNECT
            return
        atyp = req[3]
        if atyp == 0x01:                         # IPv4
            addr = socket.inet_ntoa(conn.recv(4))
        elif atyp == 0x03:                       # 域名(sniff 出来的 SNI)
            ln = conn.recv(1)[0]
            addr = conn.recv(ln).decode("utf-8", "replace")
        elif atyp == 0x04:                       # IPv6
            addr = socket.inet_ntop(socket.AF_INET6, conn.recv(16))
        else:
            return
        port = int.from_bytes(conn.recv(2), "big")
        with open(logf, "a") as f:
            f.write(f"{addr}:{port}\n")
        conn.sendall(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")  # 成功, BND 0.0.0.0:0
        try:
            conn.recv(4096)                      # 读掉客户端首包(TLS ClientHello), 丢弃
        except OSError:
            pass
    except OSError:
        pass
    finally:
        try:
            conn.close()
        except OSError:
            pass


def main():
    port = int(sys.argv[1])
    logf = sys.argv[2]
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", port))
    srv.listen(16)
    print(f"mock-socks :{port} -> {logf}", flush=True)
    while True:
        conn, _ = srv.accept()
        threading.Thread(target=handle, args=(conn, logf), daemon=True).start()


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""PrivDNS Gateway — iOS OnDemand 探测端点。
监听 0.0.0.0:81, GET 返回 HTTP 200(iOS URLStringProbe 要求 200 才算探测成功)。
配合 nftables 只放行「内网卡来源段」→ :81: 普通卡探不通(被 drop)、内网卡探得通 →
iOS OnDemand 据此只在内网卡(蜂窝)激活 DoT, 实现双卡区分。
"""
from http.server import BaseHTTPRequestHandler, HTTPServer

class H(BaseHTTPRequestHandler):
    def do_GET(self):
        body = b"ok"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def do_HEAD(self):
        self.send_response(200)
        self.send_header("Content-Length", "0")
        self.end_headers()
    def log_message(self, *a):  # 静音
        pass

if __name__ == "__main__":
    HTTPServer(("0.0.0.0", 81), H).serve_forever()

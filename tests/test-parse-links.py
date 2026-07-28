#!/usr/bin/env python3
"""parse_link 回归: 各类代理链接 + Surge ss 行 → 正确 sing-box 出站 dict。纯 stdlib, CI 可跑。
嵌套字段用 __ 表示层级, 如 tls__server_name → tls.server_name。"""
import base64
import importlib.util
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
spec = importlib.util.spec_from_file_location("pdgbot", os.path.join(ROOT, "deploy/bot/pdg-bot.py"))
m = importlib.util.module_from_spec(spec)
try:
    spec.loader.exec_module(m)
except SystemExit:
    pass

fails = 0


def _deep(d, path):
    cur = d
    for k in path.split("."):
        if not isinstance(cur, dict):
            return None
        cur = cur.get(k)
    return cur


def check(name, got, **want):
    global fails
    bad = {}
    for k, v in want.items():
        key = k.replace("__", ".")
        if _deep(got, key) != v:
            bad[key] = (_deep(got, key), v)
    if bad:
        print("[FAIL]", name, bad); fails += 1
    else:
        print("[OK]  ", name)


# Surge ss 行(SS2022 + tfo + udp-relay)
check("Surge ss 行",
      m.parse_link('🇭🇰 X = ss, 1.2.3.4, 11111, encrypt-method=2022-blake3-aes-128-gcm, '
                   'password="ab+C/9==", tfo=true, udp-relay=true'),
      type="shadowsocks", server="1.2.3.4", server_port=11111,
      method="2022-blake3-aes-128-gcm", password="ab+C/9==", tcp_fast_open=True)

# ss:// SIP002
ui = base64.urlsafe_b64encode(b"aes-256-gcm:pass123").decode().rstrip("=")
check("ss:// (b64 用户信息)", m.parse_link("ss://%s@5.6.7.8:8388#name" % ui),
      type="shadowsocks", server="5.6.7.8", server_port=8388, method="aes-256-gcm", password="pass123")

# hysteria2
check("hysteria2://",
      m.parse_link("hysteria2://mypass@h2.example.com:8443?sni=h2.example.com&insecure=1&"
                   "obfs=salamander&obfs-password=ob#HY2"),
      type="hysteria2", server="h2.example.com", server_port=8443, password="mypass",
      tls__server_name="h2.example.com", tls__insecure=True, obfs__type="salamander", obfs__password="ob")

# tuic
check("tuic://",
      m.parse_link("tuic://uuid-1234:tpass@tuic.example.com:443?sni=tuic.example.com&"
                   "congestion_control=bbr&alpn=h3#TUIC"),
      type="tuic", server="tuic.example.com", server_port=443, uuid="uuid-1234", password="tpass",
      tls__server_name="tuic.example.com", tls__alpn=["h3"], congestion_control="bbr")

# vless reality
check("vless:// reality",
      m.parse_link("vless://uuid-9@r.example.com:443?security=reality&pbk=PUBKEY&sid=ab12&"
                   "fp=chrome&flow=xtls-rprx-vision&type=tcp&sni=www.microsoft.com#REALITY"),
      type="vless", server="r.example.com", server_port=443, uuid="uuid-9", flow="xtls-rprx-vision",
      tls__server_name="www.microsoft.com", tls__reality__enabled=True, tls__reality__public_key="PUBKEY",
      tls__reality__short_id="ab12", tls__utls__fingerprint="chrome")

# vless gRPC: serviceName= 要进 transport.service_name(不是只看 path)
check("vless:// grpc serviceName",
      m.parse_link("vless://11111111-2222-3333-4444-555555555555@g.example.com:443?"
                   "security=tls&type=grpc&serviceName=mygrpc&sni=g.example.com#GRPC"),
      type="vless", transport__type="grpc", transport__service_name="mygrpc")

# anytls
check("anytls://", m.parse_link("anytls://atpass@a.example.com:443?sni=a.example.com#ANYTLS"),
      type="anytls", server="a.example.com", server_port=443, password="atpass", tls__server_name="a.example.com")

# socks5
check("socks5://", m.parse_link("socks5://user:pass@1.2.3.4:1080#SOCKS"),
      type="socks", server="1.2.3.4", server_port=1080, version="5", username="user", password="pass")

# http
check("http://", m.parse_link("http://user:pass@1.2.3.4:8080#HTTP"),
      type="http", server="1.2.3.4", server_port=8080, username="user", password="pass")

# 非法
try:
    m.parse_link("garbage no scheme")
    print("[FAIL] 非法输入未报错"); fails += 1
except ValueError:
    print("[OK]   非法输入正确报错")

print("─" * 40)
print("失败 %d" % fails)
sys.exit(1 if fails else 0)

#!/usr/bin/env python3
"""极简 UDP DNS mock(仅供 tests/dns-policy-test.sh 当"上游"用):
A→固定 IP, AAAA→固定 IPv6, HTTPS(type65)→一条最小 SVCB 记录(都返回**非空**应答),
其它类型回 NOERROR 空应答。不依赖任何第三方库。
返回非空 AAAA/HTTPS 是有意为之: 这样"代理域名被 mosdns 置空"的断言才有意义
(否则 mock 本身就空, 删掉 mosdns 抑制逻辑测试也会假阳性通过)。
用法: mock_dns.py <listen_port> <answer_ip>
"""
import socket
import struct
import sys

ANSWER_AAAA = "2001:db8::1"


def build_response(query, answer_ip):
    if len(query) < 12:
        return None
    qid = query[:2]
    # 跳过 header(12B)解析问题段: QNAME(labels..0) + QTYPE(2) + QCLASS(2)
    i = 12
    while i < len(query) and query[i] != 0:
        i += query[i] + 1
    i += 1
    if i + 4 > len(query):
        return None
    qtype = struct.unpack(">H", query[i:i + 2])[0]
    question = query[12:i + 4]
    flags = b"\x81\x80"                       # QR=1, RD=1, RA=1, RCODE=0(NOERROR)
    ptr = b"\xc0\x0c"                         # name → 指回问题里的 qname
    if qtype == 1:                            # A
        rdata = socket.inet_aton(answer_ip)
    elif qtype == 28:                         # AAAA
        rdata = socket.inet_pton(socket.AF_INET6, ANSWER_AAAA)
    elif qtype == 65:                         # HTTPS/SVCB: SvcPriority=1 + TargetName=root(.)
        rdata = struct.pack(">H", 1) + b"\x00"
    else:                                     # 其它类型: 空应答
        rdata = None
    if rdata is None:
        answer = b""; ancount = 0
    else:
        answer = ptr + struct.pack(">HHIH", qtype, 1, 60, len(rdata)) + rdata; ancount = 1
    header = qid + flags + struct.pack(">HHHH", 1, ancount, 0, 0)
    return header + question + answer


def main():
    port = int(sys.argv[1])
    answer_ip = sys.argv[2]
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", port))
    while True:
        try:
            data, addr = s.recvfrom(2048)
        except OSError:
            break
        resp = build_response(data, answer_ip)
        if resp:
            s.sendto(resp, addr)


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""把 v2ray geosite.dat 解析成 mosdns domain_set 文本规则 (纯标准库, 手写 protobuf 解码)。

用法: parse-geosite.py <geosite.dat> <输出目录>
产出: geosite_cn.txt / geosite_geolocation-!cn.txt / geosite_apple.txt / geosite_gfw.txt
"""
import os
import sys


def _rv(b, i):
    s = 0; r = 0
    while True:
        x = b[i]; i += 1; r |= (x & 0x7f) << s
        if not x & 0x80:
            return r, i
        s += 7


def _fields(b):
    i = 0; n = len(b); o = []
    while i < n:
        k, i = _rv(b, i); fn = k >> 3; wt = k & 7
        if wt == 0:
            v, i = _rv(b, i); o.append((fn, wt, v))
        elif wt == 2:
            ln, i = _rv(b, i); o.append((fn, wt, bytes(b[i:i + ln]))); i += ln
        elif wt == 5:
            o.append((fn, wt, bytes(b[i:i + 4]))); i += 4
        elif wt == 1:
            o.append((fn, wt, bytes(b[i:i + 8]))); i += 8
        else:
            raise ValueError("bad wiretype")
    return o


def main():
    dat, outdir = sys.argv[1], sys.argv[2]
    want = {"CN": "geosite_cn.txt",
            "GEOLOCATION-!CN": "geosite_geolocation-!cn.txt",
            "APPLE": "geosite_apple.txt",
            "GFW": "geosite_gfw.txt"}          # GFWList: 只劫持真被墙的域名(gfw 劫持模式用)
    res = {k: [] for k in want}
    data = open(dat, "rb").read()
    for fn, wt, val in _fields(data):           # GeoSiteList.entry = 1
        if fn != 1 or wt != 2:
            continue
        cc = None; doms = []
        for f2, w2, v2 in _fields(val):          # GeoSite
            if f2 == 1 and w2 == 2:
                cc = v2.decode("utf-8", "ignore").upper()
            elif f2 == 2 and w2 == 2:            # Domain
                dt = 2; dv = None
                for f3, w3, v3 in _fields(v2):
                    if f3 == 1 and w3 == 0:
                        dt = v3
                    elif f3 == 2 and w3 == 2:
                        dv = v3.decode("utf-8", "ignore")
                if dv is not None:
                    doms.append((dt, dv))
        if cc in want:
            res[cc] = doms
    pref = {0: "keyword:", 1: "regexp:", 2: "domain:", 3: "full:"}
    os.makedirs(outdir, exist_ok=True)
    for cc, fname in want.items():
        with open(os.path.join(outdir, fname), "w") as f:
            for dt, dv in res[cc]:
                f.write(pref.get(dt, "domain:") + dv + "\n")
        print(fname, len(res[cc]))


if __name__ == "__main__":
    main()

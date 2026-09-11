#!/usr/bin/env python3
"""把 v2ray geosite.dat 解析成 mosdns domain_set 文本规则 (纯标准库, 手写 protobuf 解码)。

用法: parse-geosite.py <geosite.dat> <输出目录>
产出: geosite_cn.txt / geosite_geolocation-!cn.txt / geosite_apple.txt / geosite_gfw.txt
"""
import os
import sys


def _rv(b, i):
    result = 0
    for shift in range(0, 70, 7):
        if i >= len(b):
            raise ValueError("truncated protobuf varint")
        value = b[i]
        i += 1
        if shift == 63 and value > 1:
            raise ValueError("protobuf varint exceeds 64 bits")
        result |= (value & 0x7f) << shift
        if not value & 0x80:
            return result, i
    raise ValueError("protobuf varint exceeds 64 bits")


def _fields(b):
    i = 0
    fields = []
    while i < len(b):
        key, i = _rv(b, i)
        number, wire_type = key >> 3, key & 7
        if not 1 <= number < (1 << 29):
            raise ValueError("invalid protobuf field number")
        if wire_type == 0:
            value, i = _rv(b, i)
        else:
            if wire_type == 2:
                length, i = _rv(b, i)
            elif wire_type in (1, 5):
                length = 8 if wire_type == 1 else 4
            else:
                raise ValueError("unsupported protobuf wire type")
            if length > len(b) - i:
                raise ValueError("truncated protobuf field")
            value = bytes(b[i:i + length])
            i += length
        fields.append((number, wire_type, value))
    return fields


def main():
    dat, outdir = sys.argv[1], sys.argv[2]
    want = {"CN": "geosite_cn.txt",
            "GEOLOCATION-!CN": "geosite_geolocation-!cn.txt",
            "APPLE": "geosite_apple.txt",
            "GFW": "geosite_gfw.txt"}          # GFWList: 只劫持真被墙的域名(gfw 劫持模式用)
    res = {k: [] for k in want}
    seen = set()
    with open(dat, "rb") as source:
        data = source.read()
    for fn, wt, val in _fields(data):           # GeoSiteList.entry = 1
        if fn != 1 or wt != 2:
            continue
        cc = None; doms = []
        for f2, w2, v2 in _fields(val):          # GeoSite
            if f2 == 1 and w2 == 2:
                cc = v2.decode("utf-8").upper()
            elif f2 == 2 and w2 == 2:            # Domain
                # proto3 omits the zero enum value: Plain means keyword.
                dt = 0; dv = None
                for f3, w3, v3 in _fields(v2):
                    if f3 == 1 and w3 == 0:
                        dt = v3
                    elif f3 == 2 and w3 == 2:
                        dv = v3.decode("utf-8")
                if dv is not None:
                    doms.append((dt, dv))
        if cc in want:
            seen.add(cc)
            res[cc] = doms
    bad = [cc for cc in want if cc not in seen or not res[cc]]
    if bad:
        raise ValueError("geosite.dat 缺失或类别为空: " + ", ".join(bad))
    pref = {0: "keyword:", 1: "regexp:", 2: "domain:", 3: "full:"}
    for cc, domains in res.items():
        if any(dt not in pref for dt, _dv in domains):
            raise ValueError("geosite.dat 包含不支持的域名类型: " + cc)
    os.makedirs(outdir, exist_ok=True)
    for cc, fname in want.items():
        with open(os.path.join(outdir, fname), "w", encoding="utf-8") as f:
            for dt, dv in res[cc]:
                f.write(pref[dt] + dv + "\n")
        print(fname, len(res[cc]))


if __name__ == "__main__":
    main()

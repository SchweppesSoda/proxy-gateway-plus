#!/usr/bin/env python3
"""Apple WLOC 位置改写插件(Feature B / iOS)。

截 gs-loc.apple.com / gs-loc-cn.apple.com 的 Wi-Fi 定位请求(设备问"我周围这些 BSSID 在哪"), 回一个把
每个被问的 BSSID 都指到设定坐标的响应 → 设备定位落在该点。

wire 格式(苹果私有, 逆向公开): 头部(locale/identifier 长度前缀)+ protobuf。
  请求 protobuf: field 2 (repeated) = {field 1 = BSSID(MAC 串)}
  响应 protobuf: field 2 (repeated) = {field 1 = BSSID, field 2 = {1=纬度×1e8, 2=经度×1e8, 3=精度}}
  经纬度是 int64 ×1e8(负数按 protobuf int64 两补码 varint)。

⚠️ 头部确切字节需真 iPhone 抓包核对(_HEADER/_split_header 是当前最佳猜测, 留口子在阶段5校准)。
纯 stdlib 手写 protobuf(沿用 parse-geosite.py 的路子), 不引入依赖。
"""

import collections
import json
import os
import tempfile
import threading
import time

_LOCALE = b"en_US"
_IDENT = b"com.apple.locationd"

MITM_CONFIG = os.environ.get("PDG_MITM_CONFIG", "/etc/privdns-gateway/mitm.json")
# 最近一次 WLOC 命中的运行时状态(bot 据此告诉用户"手机真的来过请求了")。
# 放 /run: 重启即清, 不进备份, 也不该被当成配置。
STATUS_FILE = os.environ.get("PDG_WLOC_STATUS", "/run/privdns-gateway/wloc-status.json")

# 一次请求处理期间用的**不可变**目标快照 —— 中途配置换了也不影响本次, 绝不半新半旧。
Snapshot = collections.namedtuple("Snapshot", "active lat lon generation")


def _active_loc(w):
    """取激活地点; 兼容老单坐标格式 {lat,lon}。"""
    locs = w.get("locations")
    if locs:
        for loc in locs:
            if loc.get("name") == w.get("active"):
                return loc
        return locs[0]
    if "lat" in w and "lon" in w:
        return {"name": w.get("active") or "默认", "lat": w["lat"], "lon": w["lon"]}
    return None


class WlocConfig:
    """mitm.json 的读取口 —— pdg-mitm 不重启也能换坐标。

    **每次请求整份读**, 不做 mtime 缓存。原先按 mtime_ns 判"变没变", 但 mtime 的分辨率不是
    无限的: bot 连着两次 os.replace(改坐标本来就快)完全可能落在同一个 mtime_ns 上, 于是第二
    次改动被当成"没变"而漏掉 —— 手机拿到的还是上一个坐标, 且这种漏读没有任何征兆。
    mitm.json 只有几百字节, 一次 WLOC 请求本来就要跟 Apple 走一个来回, 省这一次 read 毫无意义。

    读不到 / 坏档时**保留上一次的有效快照**并记下错误类型: 配置正在被原子替换、或者临时被
    写坏, 都不该让正在进来的定位请求突然用一个空坐标。半读取的内容一律不用。"""

    def __init__(self, path=None):
        self.path = path or MITM_CONFIG
        self._lock = threading.Lock()
        self._snap = None                             # last-known-good
        self._error = ""

    def _load(self):
        """(snapshot, error_type)。整份读 —— os.replace 保证读到的要么是旧文件要么是新文件,
        不会是半个。"""
        try:
            with open(self.path, "rb") as f:
                cfg = json.loads(f.read().decode("utf-8"))
        except Exception as e:  # noqa: BLE001
            return None, type(e).__name__
        w = ((cfg or {}).get("wloc") or {}) if isinstance(cfg, dict) else {}
        loc = _active_loc(w)
        if not loc:
            return None, "NoActiveLocation"
        try:
            snap = Snapshot(str(w.get("active") or loc.get("name") or ""),
                            float(loc["lat"]), float(loc["lon"]),
                            int(w.get("generation") or 0))
        except (TypeError, ValueError, KeyError) as e:
            return None, type(e).__name__
        return snap, ""

    def snapshot(self):
        """(Snapshot 或 None, error_type)。None = 从来没读到过有效配置。"""
        snap, err = self._load()
        with self._lock:
            if snap is not None:
                self._snap, self._error = snap, ""
            else:
                self._error = err                     # 保留 last-known-good, 只记错误
            return self._snap, self._error


_status_lock = threading.Lock()                       # 进程内串行化状态更新(每连接一个线程)


def write_status(generation, target_name, upstream_ok, patched, error_type="", path=None):
    """写最近一次 WLOC 命中状态(原子替换, 0600)。

    只记这几项 —— BSSID、请求头、Apple 请求正文、设备标识一概不落盘: 这个文件是给 bot 看
    "手机来过没有"的, 不是抓包记录。

    两条并发纪律(pdg-mitm 每个连接一个线程, 慢请求会跨过快请求):
      · 临时文件用**同目录唯一名**再 replace —— 固定的 .tmp 会被另一个线程边写边替换掉,
        replace 过去的可能是半份内容;
      · **旧 generation 不许覆盖新 generation** —— 上一个目标的请求晚几秒才结束, 一落盘就
        把新目标的命中记录冲掉, bot 那边看到的就是"刚切的地点没人来过"。"""
    p = path or STATUS_FILE
    try:
        gen = int(generation)
    except (TypeError, ValueError):
        gen = 0
    doc = {"generation": gen, "target_name": str(target_name or ""),
           "received_at": time.time(), "upstream_ok": bool(upstream_ok),
           "patched": bool(patched), "error_type": str(error_type or ""),
           "pid": os.getpid()}
    with _status_lock:
        try:
            cur = json.load(open(p, encoding="utf-8"))
            if isinstance(cur, dict) and int(cur.get("generation") or 0) > gen:
                return doc                            # 已有更新的一代 → 不回退
        except Exception:  # noqa: BLE001             # 没有/坏档: 当作没有, 照写
            pass
        try:
            d = os.path.dirname(p)
            if d:
                os.makedirs(d, mode=0o700, exist_ok=True)
            fd, t = tempfile.mkstemp(prefix=os.path.basename(p) + ".", dir=d or ".")
            try:
                with os.fdopen(fd, "w", encoding="utf-8") as f:
                    json.dump(doc, f, ensure_ascii=False)
                os.chmod(t, 0o600)
                os.replace(t, p)
            except Exception:  # noqa: BLE001
                try:
                    os.remove(t)                      # 失败别把半份临时文件留在目录里
                except OSError:
                    pass
                raise
        except OSError:
            pass                                      # 状态文件写不了不该影响定位改写本身
    return doc


# ── protobuf 编码 ──
def _uvarint(n):
    n &= (1 << 64) - 1                       # 负数 → 64 位两补码(protobuf int64 负数编码)
    out = bytearray()
    while True:
        b = n & 0x7f
        n >>= 7
        if n:
            out.append(b | 0x80)
        else:
            out.append(b)
            return bytes(out)


def _tag(field, wt):
    return _uvarint((field << 3) | wt)


def _f_varint(field, n):
    return _tag(field, 0) + _uvarint(n)


def _f_bytes(field, data):
    return _tag(field, 2) + _uvarint(len(data)) + data


# ── protobuf 解码(手写, 同 parse-geosite.py)──
def _rv(b, i):
    s = r = 0
    while True:
        x = b[i]; i += 1; r |= (x & 0x7f) << s
        if not x & 0x80:
            return r, i
        s += 7


def _fields(b):
    i, n, o = 0, len(b), []
    while i < n:
        k, i = _rv(b, i); fn, wt = k >> 3, k & 7
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


def _svar(n):
    """无符号 varint 值 → 有符号 int64。"""
    return n - (1 << 64) if n >= (1 << 63) else n


# ── 头部 ──
def _header():
    return (b"\x00\x01"
            + len(_LOCALE).to_bytes(2, "big") + _LOCALE
            + len(_IDENT).to_bytes(2, "big") + _IDENT
            + b"\x00\x00\x00\x01\x00\x00")


def _pb_has_wifi(pb):
    """pb 能解析且含 field 2(WiFi 列表)= 认为是有效的 wloc protobuf。"""
    try:
        return any(fn == 2 and wt == 2 for fn, wt, _ in _fields(pb))
    except Exception:                         # noqa: BLE001
        return False


def _split_header(body):
    """跳过头部返回 protobuf。格式待真机核对; 结构化偏移不成立则扫首个能解析出 WiFi 列表的位置。"""
    try:                                      # 结构化: 2 + locale + identifier + 6(0x00000001 0x0000)
        i = 2
        for _ in range(2):
            ln = int.from_bytes(body[i:i + 2], "big"); i += 2 + ln
        i += 6
        if 0 < i <= len(body) and _pb_has_wifi(body[i:]):
            return body[i:]
    except Exception:                         # noqa: BLE001
        pass
    pos = 0                                    # 回退: 扫首个 field-2 tag(0x12) 且能解析出 WiFi 列表
    while True:
        pos = body.find(b"\x12", pos)
        if pos < 0:
            return body
        if _pb_has_wifi(body[pos:]):
            return body[pos:]
        pos += 1


# ── 请求解析 / 响应构造 ──
def parse_request(body):
    """从请求体解析出被问的 BSSID 列表。"""
    pb = _split_header(body)
    bssids = []
    for fn, wt, val in _fields(pb):
        if fn == 2 and wt == 2:              # 每个 WiFi 项
            for f2, w2, v2 in _fields(val):
                if f2 == 1 and w2 == 2:
                    bssids.append(v2.decode("utf-8", "ignore"))
    return bssids


def build_request(bssids):
    """构造一个请求(供测试用, 模拟设备)。"""
    pb = b""
    for m in bssids:
        pb += _f_bytes(2, _f_bytes(1, m.encode()))
    pb += _f_varint(3, 100)                  # numberOfResults
    return _header() + pb


def build_response(bssids, lat, lon, accuracy=50):
    """把每个 BSSID 都指到 (lat, lon) 的响应体。"""
    lat_e8 = int(round(lat * 1e8))
    lon_e8 = int(round(lon * 1e8))
    pb = b""
    for m in bssids:
        loc = _f_varint(1, lat_e8) + _f_varint(2, lon_e8) + _f_varint(3, accuracy)
        pb += _f_bytes(2, _f_bytes(1, m.encode()) + _f_bytes(2, loc))
    return _header() + pb


def parse_response(body):
    """解析响应体 → {bssid: (lat, lon, acc)}(供测试)。"""
    pb = _split_header(body)
    out = {}
    for fn, wt, val in _fields(pb):
        if fn == 2 and wt == 2:
            mac = None; loc = None
            for f2, w2, v2 in _fields(val):
                if f2 == 1 and w2 == 2:
                    mac = v2.decode("utf-8", "ignore")
                elif f2 == 2 and w2 == 2:
                    lat = lon = acc = 0
                    for f3, w3, v3 in _fields(v2):
                        if f3 == 1:
                            lat = _svar(v3)
                        elif f3 == 2:
                            lon = _svar(v3)
                        elif f3 == 3:
                            acc = _svar(v3)
                    loc = (lat / 1e8, lon / 1e8, acc)
            if mac and loc:
                out[mac] = loc
    return out


# ── forward+patch: 转发真请求给 Apple、只把响应里的坐标改成目标点(格式 100% 对, 不再自造)──
import socket as _socket                         # noqa: E402
import ssl as _ssl                               # noqa: E402

_RESOLVERS = ["8.8.8.8", "1.1.1.1", "223.5.5.5"]
_ipcache = {}                                     # host -> (ip, ts)
_ssl_ctx = _ssl.create_default_context()          # 复用一个 TLS 上下文(线程安全), 别每次转发都重建(重复加载 CA)


def _try_fields(data):
    """能无损解析成 protobuf(恒等重编码字节一致)才返回字段, 否则 None(视作不透明字节, 如 BSSID 串)。"""
    if not data:
        return None
    try:
        flds = _fields(data)
    except Exception:                             # noqa: BLE001
        return None
    chk = b""
    for fn, wt, val in flds:
        if wt == 0:
            chk += _f_varint(fn, val)
        elif wt == 2:
            chk += _f_bytes(fn, val)
        elif wt == 5:
            chk += _tag(fn, 5) + val
        elif wt == 1:
            chk += _tag(fn, 1) + val
        else:
            return None
    return flds if chk == data else None


def _has_loc(data):
    """递归判断是否含 location 子消息(同时有 field1+field2 varint)。"""
    flds = _try_fields(data)
    if not flds:
        return False
    fnos = {(fn, wt) for fn, wt, _ in flds}
    if (1, 0) in fnos and (2, 0) in fnos:
        return True
    return any(wt == 2 and _has_loc(val) for fn, wt, val in flds)


def _split_resp(body):
    """响应体可能带非 protobuf 头部前缀; 扫出 protobuf 起点, 返回 (prefix, pb)。"""
    for i in range(min(len(body), 64)):
        if _try_fields(body[i:]) is not None and _has_loc(body[i:]):
            return body[:i], body[i:]
    return body, b""


def _patch_pb(data, lat_e8, lon_e8):
    """递归重编码: location 子消息(含 field1+field2 varint)里 field1/2 换成目标坐标; 其余原样。
    ⚠️ 只动经纬度、**不碰 field3(精度)**——实测收紧精度会触发 iOS 反作弊(过度精确+瞬移)、
    判为伪造并退回真实定位, 适得其反。"""
    flds = _try_fields(data)
    if flds is None:
        return data
    fnos = {(fn, wt) for fn, wt, _ in flds}
    is_loc = (1, 0) in fnos and (2, 0) in fnos
    out = b""
    for fn, wt, val in flds:
        if wt == 0:
            if is_loc and fn == 1:
                out += _f_varint(1, lat_e8)
            elif is_loc and fn == 2:
                out += _f_varint(2, lon_e8)
            else:
                out += _f_varint(fn, val)
        elif wt == 2:
            out += _f_bytes(fn, _patch_pb(val, lat_e8, lon_e8))
        elif wt == 5:
            out += _tag(fn, 5) + val
        else:                                     # wt == 1
            out += _tag(fn, 1) + val
    return out


def patch_response(body, lat, lon):
    """把 Apple 真响应里所有坐标改成 (lat, lon), 保留头部/结构; 找不到 protobuf 则原样返回。"""
    prefix, pb = _split_resp(body)
    if not pb:
        return body
    return prefix + _patch_pb(pb, int(round(lat * 1e8)), int(round(lon * 1e8)))


def _dns_a(host, server, timeout=4):
    import struct
    pkt = (b"\xab\xcd\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
           + b"".join(bytes([len(p)]) + p.encode() for p in host.split(".")) + b"\x00\x00\x01\x00\x01")
    s = _socket.socket(_socket.AF_INET, _socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        s.sendto(pkt, (server, 53))
        d, _ = s.recvfrom(1024)
    finally:
        s.close()
    if len(d) < 12:
        return None
    i = 12
    while i < len(d) and d[i]:                      # 跳过 QNAME(带长度前缀)——带边界, 畸形响应不越界
        i += 1 + d[i]
    i += 5                                          # 0 结尾 + QTYPE(2) + QCLASS(2)
    while i + 12 <= len(d):                         # 每条 answer: NAME 指针(2)+TYPE(2)+CLASS(2)+TTL(4)+RDLEN(2)
        typ = struct.unpack(">H", d[i + 2:i + 4])[0]
        rdlen = struct.unpack(">H", d[i + 10:i + 12])[0]
        i += 12
        if typ == 1 and rdlen == 4 and i + 4 <= len(d):
            return ".".join(map(str, d[i:i + 4]))
        i += rdlen
    return None


def _resolve(host):
    import time
    ip, ts = _ipcache.get(host, (None, 0))
    if ip and time.time() - ts < 300:
        return ip
    for r in _RESOLVERS:
        try:
            ip = _dns_a(host, r)
        except Exception:                         # noqa: BLE001
            ip = None
        if ip:
            _ipcache[host] = (ip, time.time())
            return ip
    return None


def _dechunk(body):
    out = b""
    while body:
        nl = body.find(b"\r\n")
        if nl < 0:
            break
        try:
            n = int(body[:nl].split(b";")[0], 16)
        except ValueError:
            return body
        if n == 0:
            break
        out += body[nl + 2:nl + 2 + n]
        body = body[nl + 2 + n + 2:]
    return out


def _forward(host, head, body):
    """转发手机的原始请求(保留 User-Agent 等所有头, 只换 Host/Connection)给真 gs-loc。
    先试原 host, 失败回落 gs-loc.apple.com。返回 (resp_ctype, resp_body) 或 None。"""
    import sys
    lines = head.split(b"\r\n")
    reqline = lines[0]                             # POST /clls/wloc HTTP/1.1
    keep = [ln for ln in lines[1:] if ln.strip() and not ln.lower().startswith(
        (b"host:", b"connection:", b"content-length:", b"accept-encoding:"))]   # 去 AE → 拿明文
    seen = []
    for up in dict.fromkeys([host, "gs-loc.apple.com"]):
        ip = _resolve(up)
        if not ip:
            seen.append("%s=解析失败" % up); continue
        req = (reqline + b"\r\nHost: " + up.encode() + b"\r\n"
               + (b"\r\n".join(keep) + b"\r\n" if keep else b"")
               + b"Content-Length: " + str(len(body)).encode()
               + b"\r\nConnection: close\r\n\r\n" + body)
        raw = None
        try:
            raw = _socket.create_connection((ip, 443), timeout=10)
            tls = _ssl_ctx.wrap_socket(raw, server_hostname=up)
            tls.sendall(req)
            buf = b""                              # 先读到响应头结束
            while b"\r\n\r\n" not in buf:
                d = tls.recv(8192)
                if not d:
                    break
                buf += d
            rhead, _, rbody = buf.partition(b"\r\n\r\n")
            rlines = rhead.split(b"\r\n")
            if b" 200" not in rlines[0]:
                seen.append("%s→%s" % (up, rlines[0][:40].decode("latin1", "ignore"))); continue
            if b"chunked" in rhead.lower():        # 按 chunked / Content-Length 读完就停(不等 close)
                while b"0\r\n\r\n" not in rbody[-16:]:
                    d = tls.recv(8192)
                    if not d:
                        break
                    rbody += d
                rbody = _dechunk(rbody)
            else:
                clen = 0
                for ln in rlines[1:]:
                    if ln.lower().startswith(b"content-length:"):
                        try:
                            clen = int(ln.split(b":", 1)[1].strip())
                        except ValueError:
                            clen = 0
                while len(rbody) < clen:
                    d = tls.recv(8192)
                    if not d:
                        break
                    rbody += d
        except Exception as e:                    # noqa: BLE001
            seen.append("%s(%s)异常:%s" % (up, ip, type(e).__name__)); continue
        finally:
            if raw is not None:
                try:
                    raw.close()
                except Exception:                 # noqa: BLE001
                    pass
        ctype = b"application/x-protobuf"
        for ln in rlines[1:]:
            if ln.lower().startswith(b"content-type:"):
                ctype = ln.split(b":", 1)[1].strip()
        return ctype, rbody
    sys.stderr.write("[pdg-wloc] 转发全失败: %s\n" % " | ".join(seen))
    return None


class WLOCPlugin:
    """接管 Apple 网络定位查询(/clls/wloc), 把定位改写成设定坐标。
    截 gs-loc.apple.com / gs-loc-cn.apple.com(与 Yu9191/OpenHRTT wloc 同源);
    不碰 gspe*-ssl.ls.apple.com —— 那是 Apple 地图瓦片, 劫了会砸地图。"""
    domains = ["gs-loc.apple.com", "gs-loc-cn.apple.com"]

    def __init__(self, lat=None, lon=None, accuracy=50, config=None):
        """config=WlocConfig → 每次请求按 mitm.json 取最新坐标(热加载);
        给 lat/lon 则是固定坐标(单测/旧调用方)。"""
        self.accuracy = accuracy
        self._config = config
        self._static = None if config is not None else Snapshot("", float(lat), float(lon), 0)
        # 兼容旧属性访问(只读取当前值; 热加载模式下反映最近一次快照)
        self.lat = None if config is not None else float(lat)
        self.lon = None if config is not None else float(lon)

    def snapshot(self):
        """本次请求要用的目标 —— **取一次**, 整个请求都用它, 不会半新半旧。"""
        if self._config is None:
            return self._static, ""
        snap, err = self._config.snapshot()
        if snap is not None:
            self.lat, self.lon = snap.lat, snap.lon
        return snap, err

    def handle(self, tls, host, port):
        data = b""
        while b"\r\n\r\n" not in data:
            chunk = tls.recv(4096)
            if not chunk:
                break
            data += chunk
        head, _, body = data.partition(b"\r\n\r\n")
        clen = 0
        for line in head.split(b"\r\n"):
            if line.lower().startswith(b"content-length:"):
                try:
                    clen = int(line.split(b":", 1)[1].strip())
                except ValueError:
                    clen = 0
        while len(body) < clen:
            chunk = tls.recv(4096)
            if not chunk:
                break
            body += chunk
        import sys
        reqline = head.split(b"\r\n", 1)[0].decode("latin1", "ignore")[:60]
        # 目标快照取一次: 同一个请求里绝不能混用新旧坐标(切换正好落在转发中途也一样)
        snap, cfg_err = self.snapshot()
        if snap is None:                          # 从没读到过有效配置 → 不猜坐标, 502 让 iOS 回落
            sys.stderr.write("[pdg-wloc] %s <= %s | 无可用目标配置(%s)\n" % (host, reqline, cfg_err))
            sys.stderr.flush()
            write_status(0, "", upstream_ok=False, patched=False, error_type=cfg_err or "NoConfig")
            tls.sendall(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            return
        try:
            fwd = _forward(host, head, body)      # 转发手机原始请求 → 真响应(格式 100% 对)
        except Exception as e:                    # noqa: BLE001
            fwd = None
            sys.stderr.write("[pdg-wloc] 转发异常 %s: %s\n" % (host, e))
        if fwd is None:                           # 转发失败: 502 让 iOS 回落(不给坏格式)
            sys.stderr.write("[pdg-wloc] %s <= %s | body=%d 转发失败\n" % (host, reqline, len(body)))
            sys.stderr.flush()
            write_status(snap.generation, snap.active, upstream_ok=False, patched=False,
                         error_type="ForwardFailed")
            tls.sendall(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            return
        rctype, rbody = fwd
        # 只改坐标, 保留 Apple 原本精度: 收紧精度会触发 iOS 反作弊(过度精确+瞬移)→ 退回真实定位, 实测适得其反。
        patched = patch_response(rbody, snap.lat, snap.lon)
        sys.stderr.write("[pdg-wloc] %s <= %s | req=%d resp=%d patched=%d %s → (%s, %s) gen=%d\n"
                         % (host, reqline, len(body), len(rbody), len(patched),
                            "改写OK" if patched != rbody else "未命中坐标",
                            snap.lat, snap.lon, snap.generation))
        sys.stderr.flush()
        # cfg_err 不为空 = 这次用的是 last-known-good(配置正被替换或临时坏掉)。请求本身照常
        # 完成, 但要如实记下来 —— 否则"配置坏了却一直按旧坐标应答"从状态上完全看不出来。
        write_status(snap.generation, snap.active, upstream_ok=True, patched=patched != rbody,
                     error_type=cfg_err or ("" if patched != rbody else "NoCoordsInResponse"))
        tls.sendall(b"HTTP/1.1 200 OK\r\nContent-Type: " + rctype
                    + b"\r\nContent-Length: " + str(len(patched)).encode()
                    + b"\r\nConnection: close\r\n\r\n" + patched)

#!/usr/bin/env python3
"""Bot「恢复备份」走**统一配置事务**(5.1B)。

以前是手写事务: 自己暂存一份 before、自己 copy 回去、rs 目录 rmtree+copytree、崩了就只剩
/tmp 里的备份目录。现在整条链路是一笔 pdgtx(mode=repair):
  锁外 —— 安全解包 + 白名单/限额校验 + 组装候选(身份替换、面板与平台净化、规则集并集计划);
  锁内 —— model / mosdns 配置 / direct·hijack / rs_meta / 受管规则集 + 派生 mihomo 配置一起
          校验、一起落盘, 再 restart mihomo + mosdns, 失败整体回滚, 崩了能 recover。

这里用真沙箱跑真事务, 故障注入在"外部世界"(服务起不来、候选校验不过、别人改了现网、锁被占),
不 mock 事务核心。
"""
import importlib.util as u
import io
import json
import os
import subprocess
import sys
import tarfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tests"))
sys.path.insert(0, str(ROOT / "deploy" / "bot"))
from txbox import Box, load_tx  # noqa: E402

pass_n = 0
fail_n = 0


def ok(m):
    global pass_n
    print("[OK]  ", m); pass_n += 1


def bad(m):
    global fail_n
    print("[FAIL]", m); fail_n += 1


BEFORE_SB = {
    "experimental": {"clash_api": {"external_controller": "127.0.0.1:9090"}},
    "outbounds": [
        {"type": "shadowsocks", "tag": "old-hk", "server": "1.1.1.1", "server_port": 8388,
         "method": "aes-256-gcm", "password": "OLD-PASSWORD-1"},
        {"type": "direct", "tag": "direct"},
    ],
    "route": {"rules": [{"ip_cidr": ["203.0.113.9/32"], "action": "reject"}], "final": "old-hk"},
    "inbounds": [{"type": "direct", "tag": "in"}],
}
AFTER_SB = json.loads(json.dumps(BEFORE_SB))
AFTER_SB["outbounds"][0]["tag"] = "new-tw"
AFTER_SB["outbounds"][0]["password"] = "BACKUP-PASSWORD-2"
AFTER_SB["route"]["rules"][0]["ip_cidr"] = ["198.51.100.7/32"]     # 备份来自另一台机器
AFTER_SB["route"]["final"] = "new-tw"

CUR_MOS = 'log: {level: info}\nips: [ "172.22.0.0/16" ]\ncert: "/etc/mosdns/certs/fullchain.pem"\n'
BAK_MOS = 'log: {level: debug}\nips: [ "10.9.0.0/16" ]\ncert: "/etc/other/certs/fullchain.pem"\n'


def make_box():
    box = Box()
    load_tx(box.env)
    for m in list(sys.modules):
        if m == "pdgtx":
            del sys.modules[m]
    spec = u.spec_from_file_location("pdg_bot_rs_%d" % id(box), ROOT / "deploy/bot/pdg-bot.py")
    bot = u.module_from_spec(spec); spec.loader.exec_module(bot)
    bot.SB = box.path("/etc/sing-box/config.json")
    bot.MOSDNS_CONF = box.path("/etc/mosdns/config.yaml")
    bot.MOSDNS_DIRECT = box.path("/etc/mosdns/rules/custom_direct.txt")
    bot.MOSDNS_HIJACK = box.path("/etc/mosdns/rules/custom_hijack.txt")
    bot.RS_DIR = box.path("/etc/sing-box/rs")
    bot.RS_META = box.path("/opt/pdg-bot/rulesets.json")
    bot.MIHOMO_DIR = box.path("/etc/mihomo")
    bot.MIHOMO_CFG = box.path("/etc/mihomo/config.yaml")
    bot.LOCKFILE = box.env["PDG_LOCKFILE"]
    bot._platform = lambda: "ios"
    bot._core_backend = lambda: "mihomo"
    box.put("/etc/sing-box/config.json", json.dumps(BEFORE_SB).encode())
    box.put("/etc/mosdns/config.yaml", CUR_MOS.encode(), 0o644)
    box.put("/etc/mosdns/rules/custom_direct.txt", b"before-direct.com\n", 0o644)
    box.put("/etc/mosdns/rules/custom_hijack.txt", b"before-hijack.com\n", 0o644)
    box.put("/opt/pdg-bot/rulesets.json", json.dumps({
        "rs_before": {"url": "https://x/before.list", "outbound": "old-hk", "format": "source",
                      "path": box.path("/etc/sing-box/rs/rs_before.json"), "count": 3}}).encode(), 0o644)
    box.put("/etc/sing-box/rs/rs_before.json", b'{"rules":["DOMAIN,before.com"]}', 0o644)
    box.put("/etc/sing-box/rs/user-own.json", b'{"rules":["DOMAIN,mine.com"]}', 0o644)   # 用户自放
    box.put("/etc/mihomo/config.yaml", b"{}\n")
    box.up("mosdns"); box.up("mihomo")
    tx = bot._pdgtx()
    tx.VALIDATORS["mosdns_probe"] = lambda path, data, ctx: (True, "")   # 沙箱里没有真 mosdns
    return box, bot


def blob(members):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as t:
        for name, data in members:
            i = tarfile.TarInfo(name); i.size = len(data)
            t.addfile(i, io.BytesIO(data))
    return buf.getvalue()


def full_backup(meta=None, rs=None, with_mos=True, with_direct=True, with_hijack=True):
    meta = {"rs_after": {"url": "https://x/after.list", "outbound": "new-tw", "format": "source",
                         "path": "/etc/sing-box/rs/rs_after.json", "count": 9}} if meta is None else meta
    members = [("etc/sing-box/config.json", json.dumps(AFTER_SB).encode())]
    if with_mos:
        members.append(("etc/mosdns/config.yaml", BAK_MOS.encode()))
    if with_direct:
        members.append(("etc/mosdns/rules/custom_direct.txt", b"after-direct.com\n"))
    if with_hijack:
        members.append(("etc/mosdns/rules/custom_hijack.txt", b"after-hijack.com\n"))
    if meta is not None:
        members.append(("opt/pdg-bot/rulesets.json", json.dumps(meta).encode()))
    for name, data in (rs if rs is not None else [("rs_after.json", b'{"rules":["DOMAIN,after.com"]}')]):
        members.append(("etc/sing-box/rs/" + name, data))
    return blob(members)


def snap(box):
    keys = ["/etc/sing-box/config.json", "/etc/mosdns/config.yaml",
            "/etc/mosdns/rules/custom_direct.txt", "/etc/mosdns/rules/custom_hijack.txt",
            "/opt/pdg-bot/rulesets.json", "/etc/sing-box/rs/rs_before.json",
            "/etc/sing-box/rs/rs_after.json", "/etc/sing-box/rs/user-own.json",
            "/etc/mihomo/config.yaml"]
    return {k: box.read(k) for k in keys}


def unchanged(box, before, label):
    now = snap(box)
    diff = [k for k in before if before[k] != now[k]]
    if diff:
        bad("%s: 生产文件被动过了: %s" % (label, diff))
        return False
    return True


def main():
    # ── 1. 正常恢复: 受管目标全换, 用户自放文件不动 ──
    box, bot = make_box()
    okr, msg = bot.restore_from(full_backup())
    if not okr:
        bad("正常恢复失败: %s" % msg)
    else:
        ok("正常恢复: 事务提交成功")
    sb = json.loads(box.read("/etc/sing-box/config.json").decode())
    if sb["outbounds"][0]["tag"] == "new-tw":
        ok("model 已换成备份里的出口")
    else:
        bad("model 没换: %s" % sb["outbounds"][0]["tag"])
    if sb["route"]["rules"][0]["ip_cidr"] == ["203.0.113.9/32"]:
        ok("跨机导入: 本机 server_ip 被保留(没把备份机器的 IP 搬过来)")
    else:
        bad("本机身份没保住: %s" % sb["route"]["rules"][0])
    mos = box.read("/etc/mosdns/config.yaml").decode()
    if "172.22.0.0/16" in mos and "/etc/mosdns/certs" in mos and "level: debug" in mos:
        ok("跨机导入: 内网段与证书目录保留本机, 其余按备份恢复")
    else:
        bad("mosdns 身份替换不对: %r" % mos)
    if box.read("/etc/mosdns/rules/custom_direct.txt") == b"after-direct.com\n":
        ok("custom_direct 按备份恢复")
    else:
        bad("custom_direct 没恢复")
    if box.read("/etc/sing-box/rs/rs_after.json") == b'{"rules":["DOMAIN,after.com"]}':
        ok("备份里的规则集被写入")
    else:
        bad("规则集没写入")
    if box.read("/etc/sing-box/rs/rs_before.json") is None:
        ok("现网受管、备份里已删除的规则集被删掉(恢复到备份那一刻)")
    else:
        bad("旧规则集还在")
    if box.read("/etc/sing-box/rs/user-own.json") == b'{"rules":["DOMAIN,mine.com"]}':
        ok("两份元数据都不管的文件(用户自己放的)原样保留")
    else:
        bad("用户自放的文件被动了")
    if b"proxies" in (box.read("/etc/mihomo/config.yaml") or b""):
        ok("mihomo 配置由候选 model+rs_meta 派生并落盘")
    else:
        bad("mihomo 配置没更新")
    if "OLD-PASSWORD-1" not in msg and "BACKUP-PASSWORD-2" not in msg and "198.51.100.7" not in msg:
        ok("回执不回显备份里的密码/UUID/服务器地址")
    else:
        bad("回执泄露了凭据: %s" % msg)
    audit = os.path.join(box.env["PDG_TX_ROOT"], "index.jsonl")
    araw = open(audit, encoding="utf-8").read() if os.path.exists(audit) else ""
    if "OLD-PASSWORD-1" not in araw and "BACKUP-PASSWORD-2" not in araw:
        ok("审计日志里没有凭据")
    else:
        bad("审计泄露了凭据")
    box.clean()

    # ── 1b. 平台净化: iOS 上恢复带 GMS 入站的备份, 落盘的 model 不能留下 5228-5230 ──
    box, bot = make_box()
    gms = json.loads(json.dumps(AFTER_SB))
    gms["inbounds"] = [{"type": "direct", "tag": "in-gms-5228", "listen_port": 5228},
                       {"type": "direct", "tag": "in"}]
    okr, msg = bot.restore_from(blob([
        ("etc/sing-box/config.json", json.dumps(gms).encode()),
        ("opt/pdg-bot/rulesets.json", b"{}")]))
    landed = json.loads(box.read("/etc/sing-box/config.json").decode())
    tags = [i.get("tag") for i in landed.get("inbounds", [])]
    if okr and "in-gms-5228" not in tags:
        ok("iOS 恢复: 备份里的 GMS 入站在进候选前被净化(落盘的 model 里没有 5228)")
    else:
        bad("平台净化没生效: ok=%s tags=%s" % (okr, tags))
    box.clean()

    # ── 2. 可选文件缺失 → 保持现网, 不清空 ──
    box, bot = make_box()
    before = snap(box)
    okr, msg = bot.restore_from(full_backup(with_direct=False, with_hijack=False, with_mos=False))
    if okr and box.read("/etc/mosdns/rules/custom_direct.txt") == before["/etc/mosdns/rules/custom_direct.txt"] \
            and box.read("/etc/mosdns/config.yaml") == before["/etc/mosdns/config.yaml"]:
        ok("备份里缺 mosdns 配置/自定义规则 → 保持现网(不擅自清空)")
    else:
        bad("可选文件缺失时的行为不对: %s" % msg)
    box.clean()

    # ── 3. 规则集白名单: .srs / 目录 / 穿越 / 重复 / 格式错配 / 缺文件 全部在落盘前拒 ──
    cases = [
        ("老 .srs 备份",
         {"rs_old": {"url": "https://x/a.srs", "outbound": "new-tw", "format": "binary",
                     "path": "/etc/sing-box/rs/rs_old.srs", "count": 1}},
         [("rs_old.srs", b"SRSbinary")]),
        ("扩展名与格式对不上",
         {"rs_x": {"url": "https://x/a", "outbound": "new-tw", "format": "mrs",
                   "path": "/etc/sing-box/rs/rs_x.json", "count": 1}},
         [("rs_x.json", b"{}")]),
        ("元数据里带目录",
         {"rs_d": {"url": "https://x/a", "outbound": "new-tw", "format": "source",
                   "path": "/etc/sing-box/rs/sub/rs_d.json", "count": 1}},
         [("rs_d.json", b"{}")]),
        ("两个规则集抢同一个文件名",
         {"rs_a": {"url": "https://x/a", "outbound": "new-tw", "format": "source",
                   "path": "/etc/sing-box/rs/same.json", "count": 1},
          "rs_b": {"url": "https://x/b", "outbound": "new-tw", "format": "source",
                   "path": "/etc/sing-box/rs/same.json", "count": 1}},
         [("same.json", b"{}")]),
        ("元数据引用了归档里没有的文件",
         {"rs_missing": {"url": "https://x/a", "outbound": "new-tw", "format": "source",
                         "path": "/etc/sing-box/rs/rs_missing.json", "count": 1}},
         []),
    ]
    for label, meta, rs in cases:
        box, bot = make_box()
        before = snap(box)
        okr, msg = bot.restore_from(full_backup(meta=meta, rs=rs))
        if okr:
            bad("%s 却恢复成功了" % label)
        elif unchanged(box, before, label):
            ok("%s → 在落盘前拒绝, 生产零改动" % label)
        box.clean()

    # ── 4. 备份缺 config.json → 在动任何东西之前就拒 ──
    box, bot = make_box()
    before = snap(box)
    okr, msg = bot.restore_from(blob([("etc/mosdns/config.yaml", b"log: {}\n")]))
    if not okr and unchanged(box, before, "缺 config.json"):
        ok("备份缺网关配置 → 拒绝, 现网一个字节都没动")
    else:
        bad("缺 config.json 却恢复了: %s" % msg)
    box.clean()

    # ── 5. 候选校验不过(model 里有 mihomo 翻译不了的规则集)→ 拒绝, 零改动 ──
    box, bot = make_box()
    before = snap(box)
    ghost = json.loads(json.dumps(AFTER_SB))
    ghost["route"]["rules"].append({"rule_set": "rs_ghost", "outbound": "new-tw"})
    okr, msg = bot.restore_from(blob([
        ("etc/sing-box/config.json", json.dumps(ghost).encode()),
        ("opt/pdg-bot/rulesets.json", b"{}")]))
    if not okr and "rs_ghost" in msg and unchanged(box, before, "dropped"):
        ok("备份里的规则进不了 mihomo 运行配置 → 点名 rs_ghost 并拒绝, 生产零改动")
    else:
        bad("dropped 判据没生效: %s" % msg)
    box.clean()

    # ── 6. 服务重启失败 → 整体回滚(逐字节) ──
    for unit in ("mihomo", "mosdns"):
        box, bot = make_box()
        before = snap(box)
        box._systemctl([unit], False)
        okr, msg = bot.restore_from(full_backup())
        if okr:
            bad("%s 重启失败却报恢复成功" % unit)
        elif unchanged(box, before, "%s 重启失败" % unit):
            ok("%s 重启失败 → 全部目标(含规则集与 mihomo 配置)逐字节回滚" % unit)
        box.clean()

    # ── 7. repair 语义: 操作前就坏的允许保留并告警; 操作后新增退化必须回滚 ──
    box, bot = make_box()
    tx = bot._pdgtx()
    real_dns = tx._dns_answers
    tx._dns_answers = lambda *a, **k: False      # 操作前不通, 操作后仍不通(恢复救不了上游)
    try:
        okr, msg = bot.restore_from(full_backup())
    finally:
        tx._dns_answers = real_dns
    if okr and ("操作前" in msg or "未修复" in msg):
        ok("repair: 操作前就坏的硬门 → 允许恢复并在回执里告警")
    else:
        bad("repair 在旧故障下的行为不对: ok=%s msg=%s" % (okr, msg))
    box.clean()

    box, bot = make_box()
    before = snap(box)
    tx = bot._pdgtx()
    real_dns, calls = tx._dns_answers, []

    def _dns(*a, **k):
        calls.append(1); return len(calls) <= 1          # 基线好, 观察期坏
    tx._dns_answers = _dns
    try:
        okr, msg = bot.restore_from(full_backup())
    finally:
        tx._dns_answers = real_dns
    if not okr and unchanged(box, before, "新增 DNS 退化"):
        ok("repair: 恢复导致 DNS 退化 → 回滚(修复模式不许制造新故障)")
    else:
        bad("新增退化却提交了: %s" % msg)
    box.clean()

    # ── 8. 并发: 现网 model 在候选生成后被改 → PRECONDITION_FAILED ──
    box, bot = make_box()
    before = snap(box)
    real_derive = bot._mihomo_derive

    def _derive(staged, box=box):
        box.put("/etc/sing-box/config.json",
                json.dumps({**BEFORE_SB, "route": {"rules": [], "final": "direct"}}).encode())
        return real_derive(staged)
    bot._mihomo_derive = _derive
    try:
        okr, msg = bot.restore_from(full_backup())
    finally:
        bot._mihomo_derive = real_derive
    if not okr and "PRECONDITION_FAILED" in msg:
        ok("候选生成后现网被改 → PRECONDITION_FAILED(不覆盖别人的修改)")
    else:
        bad("并发修改没被拦: %s" % msg)
    box.clean()

    # ── 9. 事务锁被别的进程占着 → BUSY, 生产零改动 ──
    box, bot = make_box()
    before = snap(box)
    holder = subprocess.Popen(
        [sys.executable, "-c",
         "import fcntl, sys\nf = open(sys.argv[1], 'w')\nfcntl.flock(f, fcntl.LOCK_EX)\n"
         "sys.stdout.write('READY\\n'); sys.stdout.flush()\nsys.stdin.readline()\n",
         box.env["PDG_LOCKFILE"]],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, universal_newlines=True)
    try:
        if (holder.stdout.readline() or "").strip() != "READY":
            bad("占锁进程没拿到锁, 前提不成立")
        okr, msg = bot.restore_from(full_backup())
        if okr is False and msg == bot.BUSY_MSG and unchanged(box, before, "锁被占"):
            ok("事务锁被占 → BUSY 且生产零改动")
        else:
            bad("锁被占时行为不对: %s / %r" % (okr, msg))
    finally:
        try:
            holder.stdin.write("go\n"); holder.stdin.flush()
        except Exception:  # noqa: BLE001
            holder.kill()
        holder.wait(timeout=10)
    box.clean()

    # ── 10. 崩在 APPLYING → 事务可被 pdg tx recover 逐字节收尾 ──
    box, bot = make_box()
    before = snap(box)
    tx = bot._pdgtx()
    real_do = tx.Tx._do_actions
    tx.Tx._do_actions = lambda self: (_ for _ in ()).throw(SystemExit("模拟落盘后断电"))
    try:
        bot.restore_from(full_backup())
    except SystemExit:
        pass
    finally:
        tx.Tx._do_actions = real_do
    pend = tx.pending_recovery()
    if pend and pend[0]["state"] == tx.APPLYING:
        ok("恢复崩在 APPLYING → 事务停在 APPLYING 并被 pending 点名")
    else:
        bad("崩溃后的状态不对: %s" % pend)
    r = tx.recover(pend[0]["txid"]) if pend else {"ok": False}
    if r.get("ok") and unchanged(box, before, "recover"):
        ok("pdg tx recover → 全部目标逐字节回到恢复前")
    else:
        bad("recover 没能收尾: %s" % r)
    box.clean()

    # ── 10b. 候选阶段被拒的恢复必须自己收尾: ABORTED + 材料删净 + 无凭据残留 ──
    def tx_rows(box):
        root = box.env["PDG_TX_ROOT"]
        rows = []
        for d in sorted(os.listdir(root)) if os.path.isdir(root) else []:
            mp = os.path.join(root, d, "meta.json")
            if os.path.isfile(mp):
                rows.append((d, json.load(open(mp, encoding="utf-8")).get("state"),
                             os.path.isdir(os.path.join(root, d, "candidate"))))
        return rows

    bad_json = blob([("etc/sing-box/config.json", b"{ not json at all"),
                     ("opt/pdg-bot/rulesets.json", b"{}")])
    bad_meta = blob([("etc/sing-box/config.json", json.dumps(AFTER_SB).encode()),
                     ("opt/pdg-bot/rulesets.json", b"{ broken")])
    miss_rs = full_backup(meta={"rs_x": {"url": "https://x/a", "outbound": "new-tw",
                                         "format": "source",
                                         "path": "/etc/sing-box/rs/rs_x.json", "count": 1}},
                          rs=[])
    for label, data in (("备份 model 不是合法 JSON", bad_json),
                        ("规则集元数据坏了", bad_meta),
                        ("元数据引用的规则集文件缺失", miss_rs)):
        box, bot = make_box()
        before = snap(box)
        okr, msg = bot.restore_from(data)
        rows = tx_rows(box)
        leftover = [r for r in rows if r[1] in ("PREPARING", "VALIDATED") or r[2]]
        if okr is False and rows and not leftover and all(r[1] == "ABORTED" for r in rows):
            ok("%s → 事务收尾为 ABORTED, 候选/before 材料已删" % label)
        else:
            bad("%s 之后事务残留: %s" % (label, rows))
        metas = "".join(open(os.path.join(box.env["PDG_TX_ROOT"], d, "meta.json"),
                             encoding="utf-8").read() for d, _s, _c in rows)
        au = open(os.path.join(box.env["PDG_TX_ROOT"], "index.jsonl"), encoding="utf-8").read() \
            if os.path.exists(os.path.join(box.env["PDG_TX_ROOT"], "index.jsonl")) else ""
        if "BACKUP-PASSWORD-2" not in metas + au + msg and "OLD-PASSWORD-1" not in metas + au + msg:
            ok("%s: meta / 审计 / 回执都没有凭据" % label)
        else:
            bad("%s: 凭据泄露了" % label)
        unchanged(box, before, label)
        box.clean()

    # ── 10c. 规则集路径的各种绕过写法都要拒(且拒在落盘之前) ──
    for label, path in (("../rs/foo.json", "/etc/sing-box/rs/../rs/foo.json"),
                        ("别处的绝对路径", "/tmp/rs/foo.json"),
                        ("前缀伪装(/evil/etc/sing-box/rs)", "/evil/etc/sing-box/rs/foo.json"),
                        ("双斜杠", "/etc/sing-box//rs/foo.json"),
                        ("反斜杠", "\\etc\\sing-box\\rs\\foo.json")):
        box, bot = make_box()
        before = snap(box)
        okr, msg = bot.restore_from(full_backup(
            meta={"rs_p": {"url": "https://x/a", "outbound": "new-tw", "format": "source",
                           "path": path, "count": 1}},
            rs=[("foo.json", b'{"rules":[]}')]))
        if not okr and unchanged(box, before, label):
            ok("规则集路径 %s → 拒绝且生产零改动" % label)
        else:
            bad("规则集路径 %s 被接受了: %s" % (label, msg))
        box.clean()

    # 合法沙箱映射(path 指向本机 RS_DIR)也必须通过 —— 收紧不能把镜像树的合法备份挡掉
    box, bot = make_box()
    okr, msg = bot.restore_from(full_backup(
        meta={"rs_ok": {"url": "https://x/a", "outbound": "new-tw", "format": "source",
                        "path": os.path.join(bot.RS_DIR, "rs_ok.json"), "count": 1}},
        rs=[("rs_ok.json", b'{"rules":["DOMAIN,ok.com"]}')]))
    if okr and box.read("/etc/sing-box/rs/rs_ok.json") == b'{"rules":["DOMAIN,ok.com"]}':
        ok("合法沙箱映射路径(本机 RS_DIR)仍被接受并落盘")
    else:
        bad("收紧误伤了合法沙箱路径: %s" % msg)
    box.clean()

    # 同一个 tar 成员出现两次 → 整包拒绝(不采用"后一个覆盖前一个")
    box, bot = make_box()
    before = snap(box)
    dup = blob([("etc/sing-box/config.json", json.dumps(AFTER_SB).encode()),
                ("etc/sing-box/config.json", json.dumps(BEFORE_SB).encode())])
    okr, msg = bot.restore_from(dup)
    if not okr and "两次" in msg and unchanged(box, before, "重复成员"):
        ok("同一成员在归档里出现两次 → 整包拒绝, 生产零改动")
    else:
        bad("重复成员没被拒: %s" % msg)
    box.clean()

    # ── 11. 手写事务的遗留物必须消失 ──
    src = (ROOT / "deploy/bot/pdg-bot.py").read_text(encoding="utf-8")
    gone = [n for n in ("_stage_restore_targets", "_rollback_restore_targets",
                        "_RestoreAbort", "pre-restore-") if n in src]
    if not gone:
        ok("手写 before/回滚与 .pre-restore-* 生产写路径已删除(改由 before-image 接管)")
    else:
        bad("旧手写路径还在: %s" % gone)

    print("\n通过 %d, 失败 %d" % (pass_n, fail_n))
    return 1 if fail_n else 0


if __name__ == "__main__":
    sys.exit(main())

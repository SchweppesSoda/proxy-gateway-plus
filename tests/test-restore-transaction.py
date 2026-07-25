#!/usr/bin/env python3
"""Bot「恢复备份」必须是完整事务(P1)。

旧行为只把 `config.json` 备份成 `.pre-restore-<ts>`, 但恢复会覆盖**一整组**目标:
  · /etc/mosdns/config.yaml
  · /etc/mosdns/rules/custom_direct.txt、custom_hijack.txt
  · /opt/pdg-bot/rulesets.json(规则集元数据)
  · /etc/sing-box/rs/ 整个目录(先 rmtree 再 copytree —— 直接毁掉现网规则集)
  · /etc/mihomo/config.yaml(由 model 重新渲染)
一旦后续校验失败, 只有 config.json 被换回去, 其余全部停在"半恢复"状态: model 与 mosdns/
规则集互相错位, 而 bot 只回一句"已回滚"。mosdns 重启结果也从不检查, 起不来照样算成功。

本测试在每个阶段注入失败, 断言: 返回失败 + **所有目标文件逐字节回到恢复前**。
"""
import hashlib
import importlib.util
import io
import json
import os
import sys
import tarfile
import tempfile
import types
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "deploy" / "bot"))
spec = importlib.util.spec_from_file_location("pdg_bot", ROOT / "deploy/bot/pdg-bot.py")
bot = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bot)

pass_n = 0


def ok(msg):
    global pass_n
    print("[OK]  ", msg)
    pass_n += 1


def bad(msg):
    print("[FAIL]", msg)
    sys.exit(1)


BEFORE_SB = {
    "experimental": {"clash_api": {"external_controller": "127.0.0.1:9090"}},
    "outbounds": [
        {"type": "shadowsocks", "tag": "old-hk", "server": "1.1.1.1", "server_port": 8388,
         "method": "aes-256-gcm", "password": "pw"},
        {"type": "direct", "tag": "jp"},
    ],
    "route": {"rules": [{"ip_cidr": ["127.0.0.0/8"], "action": "reject"}], "final": "jp"},
}
AFTER_SB = json.loads(json.dumps(BEFORE_SB))
AFTER_SB["outbounds"][0]["tag"] = "new-tw"
AFTER_SB["route"]["final"] = "jp"


class FakeSh:
    """systemctl/mihomo 打桩; 各阶段的失败由外部开关控制。"""
    def __init__(self):
        self.calls = []
        self.mihomo_t_rc = 0

    def __call__(self, cmd):
        self.calls.append(list(cmd))
        rc = 0
        if cmd and cmd[0] in ("mihomo", bot.MIHOMO_BIN) and "-t" in cmd:
            rc = self.mihomo_t_rc
        return types.SimpleNamespace(returncode=rc, stdout="", stderr="boom" if rc else "")


def sha(p):
    if os.path.isdir(p):
        h = hashlib.sha256()
        for dirpath, _dirnames, filenames in os.walk(p):
            for n in sorted(filenames):
                fp = os.path.join(dirpath, n)
                h.update(os.path.relpath(fp, p).encode())
                h.update(open(fp, "rb").read())
        return h.hexdigest()
    if os.path.exists(p):
        return hashlib.sha256(open(p, "rb").read()).hexdigest()
    return "<missing>"


def setup(tmp):
    """造出一台"有现网配置"的机器。"""
    bot.SB = os.path.join(tmp, "etc/sing-box/config.json")
    bot.RS_DIR = os.path.join(tmp, "etc/sing-box/rs")
    bot.MOSDNS_CONF = os.path.join(tmp, "etc/mosdns/config.yaml")
    bot.MOSDNS_DIRECT = os.path.join(tmp, "etc/mosdns/rules/custom_direct.txt")
    bot.MOSDNS_HIJACK = os.path.join(tmp, "etc/mosdns/rules/custom_hijack.txt")
    bot.RS_META = os.path.join(tmp, "opt/pdg-bot/rulesets.json")
    bot.MIHOMO_DIR = os.path.join(tmp, "etc/mihomo")
    bot.MIHOMO_CFG = os.path.join(bot.MIHOMO_DIR, "config.yaml")
    bot.LOCKFILE = os.path.join(tmp, "lock")
    bot.RESTORE_MAP = {
        "etc/sing-box/config.json": bot.SB,
        "etc/mosdns/config.yaml": bot.MOSDNS_CONF,
        "etc/mosdns/rules/custom_direct.txt": bot.MOSDNS_DIRECT,
        "etc/mosdns/rules/custom_hijack.txt": bot.MOSDNS_HIJACK,
        "opt/pdg-bot/rulesets.json": bot.RS_META,
    }
    for p in (bot.SB, bot.MOSDNS_CONF, bot.MOSDNS_DIRECT, bot.MOSDNS_HIJACK,
              bot.RS_META, bot.MIHOMO_CFG):
        os.makedirs(os.path.dirname(p), exist_ok=True)
    os.makedirs(bot.RS_DIR, exist_ok=True)
    json.dump(BEFORE_SB, open(bot.SB, "w"))
    open(bot.MOSDNS_CONF, "w").write("log: {level: info}   # BEFORE-MOSDNS\n")
    open(bot.MOSDNS_DIRECT, "w").write("before-direct.com\n")
    open(bot.MOSDNS_HIJACK, "w").write("before-hijack.com\n")
    json.dump({"rs_before": {"url": "https://x/before.list", "outbound": "old-hk",
                             "format": "source", "path": os.path.join(bot.RS_DIR, "before.json"),
                             "count": 3}}, open(bot.RS_META, "w"))
    open(os.path.join(bot.RS_DIR, "before.json"), "w").write('{"rules":["DOMAIN,before.com"]}')
    fake = FakeSh()
    bot.sh = fake
    bot._svc_active = lambda unit, **k: True
    # mihomo 配置在生产上**永远是 model 的渲染产物**, 这里也照真渲染一份 —— 拿手写的假内容
    # 当基线会假失败: 回滚后是按还原回来的 model 重新渲染的, 与手写串本就不同。
    bot._render_mihomo_file()
    return fake


def targets():
    return {
        "config.json": bot.SB,
        "mosdns/config.yaml": bot.MOSDNS_CONF,
        "custom_direct.txt": bot.MOSDNS_DIRECT,
        "custom_hijack.txt": bot.MOSDNS_HIJACK,
        "rulesets.json": bot.RS_META,
        "rs/": bot.RS_DIR,
        "mihomo/config.yaml": bot.MIHOMO_CFG,
    }


def snapshot():
    return {k: sha(v) for k, v in targets().items()}


def backup_blob():
    """一份"内容全都不一样"的备份包 —— 恢复若半途失败, 这些内容一个都不该留下。"""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as t:
        def add(name, data):
            i = tarfile.TarInfo(name)
            i.size = len(data)
            t.addfile(i, io.BytesIO(data))
        add("etc/sing-box/config.json", json.dumps(AFTER_SB).encode())
        add("etc/mosdns/config.yaml", b"log: {level: debug}   # AFTER-MOSDNS\n")
        add("etc/mosdns/rules/custom_direct.txt", b"after-direct.com\n")
        add("etc/mosdns/rules/custom_hijack.txt", b"after-hijack.com\n")
        add("opt/pdg-bot/rulesets.json", json.dumps({"rs_after": {"url": "https://x/after.list",
            "outbound": "new-tw", "format": "source", "path": "/x/after.json", "count": 9}}).encode())
        add("etc/sing-box/rs/after.json", b'{"rules":["DOMAIN,after.com"]}')
    return buf.getvalue()


def check_all_restored(before, label):
    now = snapshot()
    diff = [k for k in before if before[k] != now[k]]
    if diff:
        bad(f"{label}: 这些目标没回到恢复前状态: {diff}")


def main():
    blob = backup_blob()

    # ── 0. 前置: 确认这些目标确实都在恢复范围内(否则后面的断言是空的) ──
    with tempfile.TemporaryDirectory() as tmp:
        setup(tmp)
        before = snapshot()
        okr, msg = bot.restore_from(blob)
        if not okr:
            bad(f"正常恢复居然失败了: {msg}")
        now = snapshot()
        changed = [k for k in before if before[k] != now[k]]
        for must in ("config.json", "mosdns/config.yaml", "custom_direct.txt",
                     "custom_hijack.txt", "rulesets.json", "rs/"):
            if must not in changed:
                bad(f"恢复成功却没动 {must} —— 说明它根本不在恢复范围内, 后面的回滚断言会失真")
        ok("正常恢复: config/mosdns/direct/hijack/规则集元数据/rs 目录 全部被替换")

    # ── 1. 内核配置校验失败(mihomo -t 不过)→ 全部目标必须回到恢复前 ──
    with tempfile.TemporaryDirectory() as tmp:
        fake = setup(tmp)
        before = snapshot()
        fake.mihomo_t_rc = 1
        okr, msg = bot.restore_from(blob)
        if okr:
            bad("mihomo -t 失败却报恢复成功")
        check_all_restored(before, "内核校验失败")
        ok("阶段①内核校验失败 → 返回失败 + 全部目标逐字节还原(含 mosdns/rs/元数据)")

    # ── 2. 规则集进不了运行配置(dropped)→ 同样必须整体回滚 ──
    with tempfile.TemporaryDirectory() as tmp:
        setup(tmp)
        before = snapshot()
        # 备份里带一条指向"不存在的 rule-provider"的规则 → 渲染时被 dropped
        buf = io.BytesIO()
        m = json.loads(json.dumps(AFTER_SB))
        m["route"]["rules"].append({"rule_set": "rs_ghost", "outbound": "new-tw"})
        with tarfile.open(fileobj=buf, mode="w:gz") as t:
            data = json.dumps(m).encode()
            i = tarfile.TarInfo("etc/sing-box/config.json"); i.size = len(data)
            t.addfile(i, io.BytesIO(data))
            for name, d in (("etc/mosdns/config.yaml", b"log: {}\n"),
                            ("opt/pdg-bot/rulesets.json", b"{}")):
                i = tarfile.TarInfo(name); i.size = len(d)
                t.addfile(i, io.BytesIO(d))
        okr, msg = bot.restore_from(buf.getvalue())
        if okr:
            bad("备份里有进不了运行配置的规则集, 却报恢复成功(那条分流其实不存在)")
        if "rs_ghost" not in msg:
            bad(f"未点名被丢弃的规则集: {msg}")
        check_all_restored(before, "dropped")
        ok("阶段②规则集被丢弃 → 失败并点名 + 全部目标还原")

    # ── 3. mosdns 起不来 → 不得报成功, 且全部还原 ──
    with tempfile.TemporaryDirectory() as tmp:
        setup(tmp)
        before = snapshot()
        bot._svc_active = lambda unit, **k: unit != "mosdns"      # 只有 mosdns 起不来
        okr, msg = bot.restore_from(blob)
        if okr:
            bad("mosdns 未 active 却报恢复成功")
        if "mosdns" not in msg:
            bad(f"失败信息没指出是 mosdns: {msg}")
        check_all_restored(before, "mosdns 起不来")
        ok("阶段③mosdns 未 active → 返回失败并指名 + 全部目标还原")

    # ── 4. 内核起不来 → 不得报成功, 且全部还原 ──
    with tempfile.TemporaryDirectory() as tmp:
        setup(tmp)
        before = snapshot()
        bot._svc_active = lambda unit, **k: unit != "mihomo"
        okr, msg = bot.restore_from(blob)
        if okr:
            bad("mihomo 未 active 却报恢复成功")
        check_all_restored(before, "内核起不来")
        ok("阶段④内核未 active → 返回失败 + 全部目标还原")

    # ── 5. 备份缺 config.json → 在动任何现网文件之前就该拒 ──
    with tempfile.TemporaryDirectory() as tmp:
        setup(tmp)
        before = snapshot()
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w:gz") as t:
            d = b"log: {}\n"
            i = tarfile.TarInfo("etc/mosdns/config.yaml"); i.size = len(d)
            t.addfile(i, io.BytesIO(d))
        okr, msg = bot.restore_from(buf.getvalue())
        if okr:
            bad("缺 config.json 的备份却恢复成功")
        check_all_restored(before, "缺 config.json")
        ok("备份缺网关配置 → 拒绝, 且现网一个文件都没动")

    print(f"\n通过 {pass_n} 项断言")


if __name__ == "__main__":
    main()

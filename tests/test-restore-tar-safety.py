#!/usr/bin/env python3
"""恢复备份的解包必须是安全解包(P0)。

备份包是**外部输入** —— bot 从 Telegram 收文件, 谁都能发一个。旧实现只挡了成员名里的
绝对路径与 `..`, 然后直接 `tar.extract()`, 于是这些一概放行:
  · 符号链接(先放 `etc/x -> /etc`, 后续成员即可经它写到解压目录之外);
  · 硬链接(linkname 可指向解压根之外的文件);
  · 设备文件 / FIFO 等特殊成员;
  · 没有任何体积与数量上限(压缩炸弹)。
而解出来的 rs/ 目录随后会被 copytree 到 /etc/sing-box/rs —— 链接会一并搬进现网。

本测试直接打被测函数 _safe_extract: 造出各类恶意成员, 断言**解压根之外一个字节都没被写**,
且合法备份仍能正常解出。
"""
import io
import json
import os
import shutil
import sys
import tarfile
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "deploy", "bot"))

import importlib.util
spec = importlib.util.spec_from_file_location("bot", os.path.join(ROOT, "deploy/bot/pdg-bot.py"))
bot = importlib.util.module_from_spec(spec)
try:
    spec.loader.exec_module(bot)
except SystemExit:
    pass

pass_n = 0


def ok(msg):
    global pass_n
    pass_n += 1
    print(f"[OK]   {msg}")


def bad(msg):
    print(f"[FAIL] {msg}")
    sys.exit(1)


def mktar(build):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as t:
        build(t)
    return buf.getvalue()


def addfile(t, name, data=b"x"):
    i = tarfile.TarInfo(name)
    i.size = len(data)
    t.addfile(i, io.BytesIO(data))


def extract(data, dest):
    """跑被测的安全解包; 返回 (是否抛错, 错误文本)。"""
    tar = tarfile.open(fileobj=io.BytesIO(data), mode="r:gz")
    try:
        bot._safe_extract(tar, dest)
        return False, ""
    except Exception as e:  # noqa: BLE001
        return True, str(e)


def run_case(label, build):
    """解包到隔离目录, 断言解压根之外没有任何写入, 根内不留链接/特殊文件。"""
    base = tempfile.mkdtemp(prefix="pdgsafe")
    dest = os.path.join(base, "root")
    os.makedirs(dest)
    outside = os.path.join(base, "OUTSIDE")
    os.makedirs(outside)
    victim = os.path.join(outside, "victim.txt")
    with open(victim, "w") as f:
        f.write("ORIGINAL")
    try:
        extract(mktar(build), dest)
        if open(victim).read() != "ORIGINAL":
            bad(f"{label}: 解压根之外的文件被改写了!")
        stray = [n for n in os.listdir(outside) if n != "victim.txt"]
        if stray:
            bad(f"{label}: 解压根之外多出了文件 {stray}")
        for dirpath, dirnames, filenames in os.walk(dest):
            for n in dirnames + filenames:
                p = os.path.join(dirpath, n)
                if os.path.islink(p):
                    bad(f"{label}: 解出了符号链接 {p} -> {os.readlink(p)}")
                if os.path.exists(p) and not (os.path.isfile(p) or os.path.isdir(p)):
                    bad(f"{label}: 解出了特殊文件 {p}")
    finally:
        shutil.rmtree(base, ignore_errors=True)


def main():
    if not hasattr(bot, "_safe_extract"):
        bad("bot 里没有 _safe_extract —— 恢复仍在用不受限的 tar.extract")

    run_case("绝对路径", lambda t: addfile(t, "/etc/passwd-pwned"))
    ok("绝对路径成员被拒(未写到解压根外)")

    run_case("..逃逸", lambda t: addfile(t, "../../OUTSIDE/pwned.txt"))
    ok("`..` 逃逸成员被拒")

    def symlink_attack(t):
        i = tarfile.TarInfo("etc/sing-box/rs")
        i.type = tarfile.SYMTYPE
        i.linkname = "/tmp"                       # 指向解压根之外
        t.addfile(i)
        addfile(t, "etc/sing-box/rs/pwned.txt", b"pwned")
    run_case("符号链接", symlink_attack)
    ok("符号链接成员被拒(不给两段式写穿的机会)")

    def symlink_out(t):
        i = tarfile.TarInfo("escape")
        i.type = tarfile.SYMTYPE
        i.linkname = "../../OUTSIDE"
        t.addfile(i)
    run_case("外指符号链接", symlink_out)
    ok("指向解压根之外的符号链接被拒")

    def hardlink(t):
        addfile(t, "etc/sing-box/config.json", b"{}")
        i = tarfile.TarInfo("etc/sing-box/hard")
        i.type = tarfile.LNKTYPE
        i.linkname = "../../../../etc/passwd"
        t.addfile(i)
    run_case("硬链接", hardlink)
    ok("硬链接成员被拒")

    def devs(t):
        for name, ty in (("dev/zero", tarfile.CHRTYPE), ("dev/loop", tarfile.BLKTYPE),
                         ("dev/pipe", tarfile.FIFOTYPE)):
            i = tarfile.TarInfo(name)
            i.type = ty
            i.devmajor = 1
            i.devminor = 3
            t.addfile(i)
    run_case("设备/FIFO", devs)
    ok("设备文件与 FIFO 被拒")

    # ── 白名单之外的普通文件不得落地 ──
    base = tempfile.mkdtemp(prefix="pdgsafe")
    dest = os.path.join(base, "root")
    os.makedirs(dest)
    try:
        def mixed(t):
            addfile(t, "etc/sing-box/config.json", b"{}")
            addfile(t, "root/.ssh/authorized_keys", b"ssh-rsa AAA")
            addfile(t, "etc/cron.d/pwn", b"* * * * * root sh")
        extract(mktar(mixed), dest)
        if os.path.exists(os.path.join(dest, "root/.ssh/authorized_keys")) \
           or os.path.exists(os.path.join(dest, "etc/cron.d/pwn")):
            bad("白名单之外的成员被解出来了")
        if not os.path.exists(os.path.join(dest, "etc/sing-box/config.json")):
            bad("白名单内的成员没解出来")
        ok("只解白名单内成员(白名单外的 authorized_keys / cron.d 一概不落地)")
    finally:
        shutil.rmtree(base, ignore_errors=True)

    # ── 体积 / 数量上限(压缩炸弹) ──
    base = tempfile.mkdtemp(prefix="pdgsafe")
    try:
        d1 = os.path.join(base, "r1")
        os.makedirs(d1)
        big = b"A" * (bot.RESTORE_MAX_FILE_BYTES + 1024)
        raised, _ = extract(mktar(lambda t: addfile(t, "etc/sing-box/config.json", big)), d1)
        if not raised:
            bad("超大单文件未被拒")
        ok(f"单文件体积上限生效({bot.RESTORE_MAX_FILE_BYTES} 字节)")

        d2 = os.path.join(base, "r2")
        os.makedirs(d2)

        def many(t):
            for i in range(bot.RESTORE_MAX_MEMBERS + 5):
                addfile(t, f"etc/sing-box/rs/r{i}.list", b"x")
        raised, _ = extract(mktar(many), d2)
        if not raised:
            bad("成员数量上限未生效")
        ok(f"成员数量上限生效({bot.RESTORE_MAX_MEMBERS} 个)")
    finally:
        shutil.rmtree(base, ignore_errors=True)

    # ── 合法备份仍能正常解出(保护不能把功能弄坏) ──
    base = tempfile.mkdtemp(prefix="pdgsafe")
    dest = os.path.join(base, "root")
    os.makedirs(dest)
    try:
        def good(t):
            addfile(t, "etc/sing-box/config.json", b'{"outbounds":[]}')
            addfile(t, "etc/mosdns/config.yaml", b"log: {}")
            addfile(t, "etc/mosdns/rules/custom_direct.txt", b"a.com\n")
            addfile(t, "etc/mosdns/rules/custom_hijack.txt", b"b.com\n")
            addfile(t, "opt/pdg-bot/rulesets.json", b"{}")
            addfile(t, "etc/sing-box/rs/my.list", b"DOMAIN,x.com\n")
        raised, err = extract(mktar(good), dest)
        if raised:
            bad(f"合法备份被误拒: {err}")
        for rel in ("etc/sing-box/config.json", "etc/mosdns/config.yaml",
                    "etc/mosdns/rules/custom_direct.txt", "etc/mosdns/rules/custom_hijack.txt",
                    "opt/pdg-bot/rulesets.json", "etc/sing-box/rs/my.list"):
            if not os.path.exists(os.path.join(dest, rel)):
                bad(f"合法成员未解出: {rel}")
        ok("合法备份(含 rs/ 规则集)完整解出, 保护没误伤正常恢复")
    finally:
        shutil.rmtree(base, ignore_errors=True)

    # ── 守卫: 备份产出的成员必须全部在恢复白名单内 ──
    # _safe_extract 的白名单是硬编码的; 将来往 BACKUP_FILES 里加了文件却忘了同步白名单,
    # 那份文件会在恢复时被**静默跳过** —— 备份看着有、恢复回来却没有, 且没有任何报错。
    # 这条守卫把"备份写什么"与"恢复认什么"钉在一起。
    base = tempfile.mkdtemp(prefix="pdgsync")
    try:
        os.makedirs(os.path.join(base, "etc/mosdns/rules"), exist_ok=True)
        os.makedirs(os.path.join(base, "opt/pdg-bot"), exist_ok=True)
        os.makedirs(os.path.join(base, "etc/sing-box/rs"), exist_ok=True)
        bot.SB = os.path.join(base, "etc/sing-box/config.json")
        bot.MOSDNS_CONF = os.path.join(base, "etc/mosdns/config.yaml")
        bot.MOSDNS_DIRECT = os.path.join(base, "etc/mosdns/rules/custom_direct.txt")
        bot.MOSDNS_HIJACK = os.path.join(base, "etc/mosdns/rules/custom_hijack.txt")
        bot.RS_META = os.path.join(base, "opt/pdg-bot/rulesets.json")
        bot.RS_DIR = os.path.join(base, "etc/sing-box/rs")
        bot.BACKUP_FILES = [bot.SB, bot.MOSDNS_CONF, bot.MOSDNS_DIRECT, bot.MOSDNS_HIJACK, bot.RS_META]
        json.dump({"outbounds": [], "route": {"rules": []}}, open(bot.SB, "w"))
        for p in (bot.MOSDNS_CONF, bot.MOSDNS_DIRECT, bot.MOSDNS_HIJACK):
            open(p, "w").write("x\n")
        json.dump({}, open(bot.RS_META, "w"))
        open(os.path.join(bot.RS_DIR, "a.list"), "w").write("DOMAIN,a.com\n")
        blob = bot.backup_blob()
        tar = tarfile.open(fileobj=io.BytesIO(blob), mode="r:gz")
        missed = []
        for m in tar.getmembers():
            if not m.isreg():
                continue
            # 备份用的是本机绝对路径去头; 测试里路径被重定向过, 换算回归档相对形态再判
            rel = m.name.lstrip("./")
            rel = rel.replace(base.lstrip("/") + "/", "")
            if not bot._restore_member_allowed(rel):
                missed.append(rel)
        if missed:
            bad(f"备份产出的成员不在恢复白名单内(恢复时会被静默跳过): {missed}")
        ok("守卫: backup_blob 产出的每个成员都在恢复白名单内(备份/恢复不会脱节)")
    finally:
        shutil.rmtree(base, ignore_errors=True)

    print(f"\n通过 {pass_n} 项断言")


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""bot 内核后端切换层回归(pdg-bot.py 的 mihomo 分支)。

不起真核心/真 systemd: 把 sh/_svc_active/路径常量打桩, 验证:
  - _core_backend 标记识别 + 默认 singbox
  - _panel_render_args 把 clash_api 面板状态透传给渲染器
  - _render_mihomo_file 从 model 渲染 mihomo 配置落盘(chmod 600)
  - _core_apply 三态: 成功 / 校验失败(未重启) / 重启失败(已重启)
  - apply_sb 事务: mihomo 模式下成功写入; 校验失败还原 model 且不残留坏渲染、不误重启
"""
import importlib.util
import json
import os
import stat
import sys
import tempfile
import types
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "deploy" / "bot"))    # 供 pdg-bot 内部 `import sb2mihomo`
spec = importlib.util.spec_from_file_location("pdg_bot", ROOT / "deploy/bot/pdg-bot.py")
bot = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bot)

SAMPLE = {
    "experimental": {"clash_api": {"external_controller": "127.0.0.1:9090"}},
    "outbounds": [
        {"type": "shadowsocks", "tag": "ss1", "server": "1.1.1.1", "server_port": 8388,
         "method": "aes-256-gcm", "password": "pw"},
        {"type": "direct", "tag": "jp"},
    ],
    "route": {"rules": [{"ip_cidr": ["127.0.0.0/8"], "action": "reject"}], "final": "jp"},
}

pass_n = 0


def ok(msg):
    global pass_n
    print("[OK]  ", msg); pass_n += 1


class FakeSh:
    """记录命令; mihomo -t / sing-box check 返回码可控; 其它一律 rc0。"""
    def __init__(self):
        self.calls = []
        self.mihomo_t_rc = 0
        self.mihomo_t_err = "boom"
        self.sbcheck_rc = 0

    def __call__(self, cmd):
        self.calls.append(list(cmd))
        rc, out, err = 0, "", ""
        if cmd and cmd[0] == "mihomo" and "-t" in cmd:
            rc, err = self.mihomo_t_rc, (self.mihomo_t_err if self.mihomo_t_rc else "")
        elif cmd[:2] == ["sing-box", "check"]:
            rc, err = self.sbcheck_rc, ("bad" if self.sbcheck_rc else "")
        return types.SimpleNamespace(returncode=rc, stdout=out, stderr=err)

    def has(self, prefix):
        return any(c[:len(prefix)] == prefix for c in self.calls)


def setup(tmp, backend="mihomo", svc_active=True):
    # 5.1 起 apply_sb 走统一事务, 事务的目标白名单是**镜像的 /etc 结构**(根可换, 结构不可换),
    # 所以这里按镜像树铺路径, 并把事务根/锁一并指进沙箱。
    for d in ("/etc/sing-box", "/etc/mihomo", "/etc/mosdns/rules", "/run",
              "/var/lib/privdns-gateway"):
        os.makedirs(tmp + d, exist_ok=True)
    os.environ["PDG_TX_FSROOT"] = tmp
    os.environ["PDG_TX_ROOT"] = tmp + "/var/lib/privdns-gateway/tx"
    os.environ["PDG_LOCKFILE"] = tmp + "/run/pdg.lock"
    os.environ["PDG_STABLE_SAMPLES"] = "1"
    for m in list(sys.modules):
        if m.startswith("pdgtx"):
            del sys.modules[m]                       # 让事务核心按新的沙箱根重新加载
    bot.SB = tmp + "/etc/sing-box/config.json"
    bot.MIHOMO_DIR = tmp + "/etc/mihomo"
    bot.MIHOMO_CFG = bot.MIHOMO_DIR + "/config.yaml"
    bot.BACKEND_MARKER = os.path.join(tmp, "backend")
    bot.LOCKFILE = os.environ["PDG_LOCKFILE"]
    with open(bot.SB, "w") as f:
        json.dump(SAMPLE, f)
    with open(bot.BACKEND_MARKER, "w") as f:
        f.write(backend)
    fake = FakeSh()
    bot.sh = fake
    bot._svc_active = lambda unit, **k: svc_active
    # 事务的观察期/基线走真 systemctl 与真探针; 单测里用最小桩顶上(与 FakeSh 同样的取向:
    # 本文件验的是 backend 分支与渲染, 服务动力学由 test-config-transaction*.py 覆盖)
    import importlib
    tx = importlib.import_module("pdgtx") if "pdgtx" in sys.modules else None
    if tx is None:
        sys.path.insert(0, str(ROOT / "deploy" / "bot"))
        tx = importlib.import_module("pdgtx")
    tx.svc_stable = lambda unit, **k: (svc_active, "" if svc_active else "%s 未稳定" % unit)
    tx.health_snapshot = lambda services: {"svc:" + u: svc_active for u in services}
    tx._run = lambda cmd, timeout=60: (0, "")
    # 候选校验沿用本文件既有的注入口 fake.mihomo_t_rc(=1 表示 mihomo -t 判不过)
    tx.VALIDATORS["mihomo_check"] = lambda path, data, ctx: (
        (False, "mihomo 配置校验失败") if getattr(fake, "mihomo_t_rc", 0) else (True, ""))
    return fake


def main():
    # ── _core_backend: v1.6.0 起恒 mihomo(唯一内核), 与 backend 标记内容无关 ──
    with tempfile.TemporaryDirectory() as tmp:
        setup(tmp, backend="mihomo")
        assert bot._core_backend() == "mihomo"; ok("_core_backend 恒 mihomo")
        with open(bot.BACKEND_MARKER, "w") as f:
            f.write("singbox")                          # 旧机器标记里可能还写着 singbox
        assert bot._core_backend() == "mihomo"; ok("_core_backend 忽略旧 singbox 标记, 仍 mihomo")
        os.remove(bot.BACKEND_MARKER)
        assert bot._core_backend() == "mihomo"; ok("_core_backend 缺标记也 mihomo")

    # ── _panel_render_args ──
    args = bot._panel_render_args({"experimental": {"clash_api": {
        "external_controller": "0.0.0.0:9090", "secret": "S",
        "external_ui": "/etc/sing-box/ui/dist", "external_ui_download_url": "https://x/z.zip"}}})
    assert args == {"controller": "0.0.0.0:9090", "secret": "S",
                    "external_ui": "/etc/sing-box/ui/dist", "external_ui_url": "https://x/z.zip"}
    ok("_panel_render_args 透传面板 clash_api")
    args0 = bot._panel_render_args({})
    assert args0["controller"] == "127.0.0.1:9090" and args0["secret"] is None
    ok("_panel_render_args 缺省本地控制器/无 secret")

    # ── _render_mihomo_file: 落盘 + 内容 + 权限 ──
    with tempfile.TemporaryDirectory() as tmp:
        setup(tmp)
        meta = bot._render_mihomo_file()
        cfg = json.load(open(bot.MIHOMO_CFG))
        assert cfg["redir-port"] == 7893
        assert any(p["name"] == "ss1" and p["type"] == "ss" for p in cfg["proxies"])
        assert cfg["rules"][-1] == "MATCH,DIRECT"
        assert "IP-CIDR,127.0.0.0/8,REJECT,no-resolve" in cfg["rules"]
        mode = stat.S_IMODE(os.stat(bot.MIHOMO_CFG).st_mode)
        assert mode == 0o600, oct(mode)
        assert meta["unknown_proxies"] == []
        ok("_render_mihomo_file 渲染落盘 + chmod 600")

    # ── _core_apply: 成功 ──
    with tempfile.TemporaryDirectory() as tmp:
        fake = setup(tmp, svc_active=True)
        ret = bot._core_apply()
        assert ret == (True, "", True), ret
        assert fake.has(["mihomo", "-t"]) and fake.has(["systemctl", "restart", "mihomo"])
        ok("_core_apply mihomo 成功 → (True,'',True) 且校验+重启 mihomo")

    # ── _core_apply: 校验失败(核心未重启) ──
    with tempfile.TemporaryDirectory() as tmp:
        fake = setup(tmp, svc_active=True)
        fake.mihomo_t_rc = 1
        okr, err, restarted = bot._core_apply()
        assert okr is False and restarted is False and "校验失败" in err
        assert not fake.has(["systemctl", "restart", "mihomo"]), "校验失败不该重启核心"
        ok("_core_apply mihomo 校验失败 → 未重启")

    # ── _core_apply: 重启失败(已重启) ──
    with tempfile.TemporaryDirectory() as tmp:
        fake = setup(tmp, svc_active=False)     # 重启后 svc 起不来
        okr, err, restarted = bot._core_apply()
        assert okr is False and restarted is True and "重启 mihomo 失败" in err
        ok("_core_apply mihomo 重启失败 → restarted=True")

    # ── apply_sb: mihomo 成功写入 ──
    with tempfile.TemporaryDirectory() as tmp:
        setup(tmp, svc_active=True)
        okr, msg = bot.apply_sb(lambda cc: cc["route"]["rules"].insert(
            0, {"domain_suffix": ["openai.com"], "outbound": "ss1"}))
        assert okr is True, msg
        model = json.load(open(bot.SB))
        assert any("openai.com" in r.get("domain_suffix", []) for r in model["route"]["rules"])
        cfg = json.load(open(bot.MIHOMO_CFG))
        assert "DOMAIN-SUFFIX,openai.com,ss1" in cfg["rules"]
        ok("apply_sb mihomo 成功: model 改动 + mihomo 配置同步")

    # ── apply_sb: 校验失败回滚(model 还原, 不留坏渲染, 不误重启) ──
    with tempfile.TemporaryDirectory() as tmp:
        fake = setup(tmp, svc_active=True)
        before = json.load(open(bot.SB))
        bot._render_mihomo_file()               # 先有一份 good 渲染
        fake.calls.clear(); fake.mihomo_t_rc = 1
        okr, msg = bot.apply_sb(lambda cc: cc["route"]["rules"].insert(
            0, {"domain_suffix": ["bad.example"], "outbound": "ss1"}))
        assert okr is False and "校验失败" in msg
        after = json.load(open(bot.SB))
        assert after == before, "校验失败必须把 model 还原"
        cfg = json.load(open(bot.MIHOMO_CFG))
        assert not any("bad.example" in r for r in cfg["rules"]), "回滚后不该残留坏渲染"
        assert not fake.has(["systemctl", "restart", "mihomo"]), "校验失败不该重启核心"
        ok("apply_sb mihomo 校验失败: model 还原 + 渲染同步回 good + 未重启")

    # ── _mihomo_rulesets: 分类 + 跳过 .srs; 渲染出 rule-providers/RULE-SET ──
    with tempfile.TemporaryDirectory() as tmp:
        setup(tmp)
        bot.RS_META = os.path.join(tmp, "rulesets.json")
        json.dump({
            "rs_a": {"url": "https://x/netflix.list", "outbound": "ss1"},
            "rs_b": {"url": "https://x/geo.yaml", "outbound": "ss1"},
            # .mrs 的 behavior 必须**显式记录**才渲染 —— 它是编译后的二进制, 判不出来就不能猜
            "rs_c": {"url": "https://x/set.mrs", "outbound": "ss1", "behavior": "domain"},
            "rs_d": {"url": "https://x/legacy.srs", "outbound": "ss1"},
            "rs_e": {"url": "https://x/nobehavior.mrs", "outbound": "ss1"},
        }, open(bot.RS_META, "w"))
        rs = bot._mihomo_rulesets()
        assert rs["rs_a"] == {"url": "https://x/netflix.list", "behavior": "classical", "format": "text"}
        assert rs["rs_b"]["format"] == "yaml"
        assert rs["rs_c"]["format"] == "mrs" and rs["rs_c"]["behavior"] == "domain"
        assert "rs_d" not in rs, ".srs(sing-box 二进制)应跳过"
        assert "rs_e" not in rs, "没记 behavior 的 .mrs 不该被猜成 domain, 应跳过(交由 dropped 报错)"
        ok("_mihomo_rulesets 分类 text/yaml/mrs(behavior 须显式) + 跳过 .srs 与无 behavior 的 .mrs")
        # model 带 rule_set 规则 → 渲染出 rule-providers + RULE-SET
        model = json.load(open(bot.SB))
        model["route"]["rules"].insert(1, {"rule_set": "rs_a", "outbound": "ss1"})
        json.dump(model, open(bot.SB, "w"))
        bot._render_mihomo_file()
        cfg = json.load(open(bot.MIHOMO_CFG))
        assert "rs_a" in cfg.get("rule-providers", {}), "应渲染出 rule-providers"
        assert "RULE-SET,rs_a,ss1" in cfg["rules"]
        ok("_render_mihomo_file 从 RS_META 产出 rule-providers + RULE-SET")

    # ── _core_apply: v1.6.0 唯一路径就是 mihomo(渲染 + mihomo -t + restart mihomo) ──
    with tempfile.TemporaryDirectory() as tmp:
        fake = setup(tmp, backend="mihomo", svc_active=True)
        ret = bot._core_apply()
        assert ret == (True, "", True), ret
        assert fake.has(["mihomo", "-t", "-d", bot.MIHOMO_DIR, "-f", bot.MIHOMO_CFG])
        assert fake.has(["systemctl", "restart", "mihomo"])
        assert os.path.exists(bot.MIHOMO_CFG), "应渲染出 mihomo 配置"
        assert not fake.has(["sing-box", "check", "-c", bot.SB]), "不该再碰 sing-box"
        ok("_core_apply → 渲染 + mihomo -t + restart mihomo(不碰 sing-box)")

    print(f"\n通过 {pass_n} 项断言")


if __name__ == "__main__":
    main()

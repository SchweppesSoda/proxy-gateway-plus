#!/usr/bin/env python3
"""事务测试用的一次性沙箱(供 test-config-transaction*.py 共用)。

不是 mock 事务逻辑, 而是给它造一个**真实的外部世界**: 沙箱文件树 + 假 systemctl/nft/mihomo
(会把调用记进日志, 也能按需装成失败或"起来即崩")+ 真的 UDP DNS 应答器与 TCP 监听 ——
硬门探针因此有真实落点, 判据本身一行都没关掉。
"""
import importlib.util
import os
import shutil
import socket
import tempfile
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def load_tx(env):
    """按给定环境变量加载事务核心(模块级常量会读环境, 故每个沙箱重新导入一次)。"""
    for k, v in env.items():
        os.environ[k] = v
    spec = importlib.util.spec_from_file_location("pdgtx_%d" % time.time_ns(),
                                                  ROOT / "deploy/bot/pdgtx.py")
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


class Box:
    """一次性沙箱: 假文件树 + 假 systemctl/nft/mihomo/mosdns/sysctl。"""

    def __init__(self, svc_fail=None, restart_crash=False, healthy=True):
        self.root = tempfile.mkdtemp(prefix="pdgtx-box.")
        self.bin = os.path.join(self.root, "stub-bin")
        os.makedirs(self.bin)
        self.calls = os.path.join(self.root, "calls.log")
        self.state = os.path.join(self.root, "svcstate")
        os.makedirs(self.state)
        self._systemctl(svc_fail or [], restart_crash)
        self._simple("nft", 0)
        self._simple("mihomo", 0)
        self._simple("sysctl", 0)
        self._simple("openssl", 0)
        for d in ("/etc/sing-box/rs", "/etc/mosdns/rules", "/etc/mihomo",
                  "/etc/privdns-gateway", "/opt/pdg-bot", "/run", "/etc/systemd/system"):
            os.makedirs(self.root + d, exist_ok=True)
        # 硬门探针的真实落点: 一个真 UDP DNS 应答器 + 一个真 TCP 监听。
        # 判据没有被关掉 —— 把它们停掉, 健康检查就会真的判失败(见"退化"用例)。
        self._probes = []
        self.dns_port = self._start_dns() if healthy else 1
        self.redir_port = self._start_tcp() if healthy else 1
        self.env = {
            "PDG_TX_DNS_PROBE": "127.0.0.1:%d" % self.dns_port,
            "PDG_TX_REDIR_PORT": str(self.redir_port),
            "PDG_TX_FSROOT": self.root,
            "PDG_TX_ROOT": self.root + "/var/lib/privdns-gateway/tx",
            "PDG_LOCKFILE": self.root + "/run/privdns-gateway.lock",
            "PDG_STABLE_SAMPLES": "1",
            "PATH": self.bin + os.pathsep + os.environ["PATH"],
        }

    def _start_dns(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
        self._probes.append(s)
        def loop():
            while True:
                try:
                    data, addr = s.recvfrom(512)
                except OSError:
                    return
                try:
                    s.sendto(data[:2] + b"\x81\x83" + data[4:12], addr)   # 回一个 NXDOMAIN
                except OSError:
                    return
        threading.Thread(target=loop, daemon=True).start()
        return port

    def _start_tcp(self):
        s = socket.socket()
        s.bind(("127.0.0.1", 0)); s.listen(8)
        port = s.getsockname()[1]
        self._probes.append(s)
        def loop():
            while True:
                try:
                    c, _ = s.accept(); c.close()
                except OSError:
                    return
        threading.Thread(target=loop, daemon=True).start()
        return port

    def stop_probes(self):
        for s in self._probes:
            try:
                s.close()
            except OSError:
                pass
        self._probes = []

    def _write(self, name, body):
        p = os.path.join(self.bin, name)
        with open(p, "w") as f:
            f.write(body)
        os.chmod(p, 0o755)

    def _systemctl(self, fail_units, crash):
        # is-active 读 <state>/<unit>; restart 写 active(或按 fail 列表失败)。
        # crash=True 时模拟"坏配置起来即崩": restart 时看 config.json 里有没有 CRASH_MARK ——
        # 有就进入崩溃循环(NRestarts 每问一次涨一次), 换回旧配置再 restart 就恢复正常。
        # 这样回滚是否**真的解决问题**才有意义, 而不是让桩无条件永远崩。
        self._write("systemctl", """#!/bin/bash
echo "systemctl $*" >> %s
S=%s
case "$1" in
  is-active) [[ -f "$S/$2.active" ]] && { echo active; exit 0; }; echo inactive; exit 3;;
  show)  # show -p PROP --value UNIT
    U="${!#}"; P="$3"; [[ "$2" != "-p" ]] && P="$2"
    case "$P" in
      NRestarts) n=$(cat "$S/$U.nr" 2>/dev/null || echo 0)
                 if [[ -f "$S/$U.crash" ]]; then n=$((n+1)); echo $n > "$S/$U.nr"; fi
                 echo "$n";;
      UnitFileState) echo enabled;;
      LoadState) echo loaded;;
      *) echo "";;
    esac; exit 0;;
  restart)
    for f in %s; do [[ "$2" == "$f" ]] && { echo "restart refused"; exit 1; }; done
    touch "$S/$2.active"; %s
    exit 0;;
  stop) rm -f "$S/$2.active"; exit 0;;
  reset-failed|daemon-reload|enable|disable) exit 0;;
esac
exit 0
""" % (self.calls, self.state, " ".join(fail_units) or "__none__",
        ('if grep -q CRASHME %s/etc/sing-box/config.json 2>/dev/null; '
         'then touch "$S/$2.crash"; else rm -f "$S/$2.crash" "$S/$2.nr"; fi' % self.root)
        if crash else ":"))

    def _simple(self, name, rc):
        self._write(name, '#!/bin/bash\necho "%s $*" >> %s\nexit %d\n' % (name, self.calls, rc))

    def fail_cmd(self, name):
        self._simple(name, 1)

    def up(self, unit):
        open(os.path.join(self.state, unit + ".active"), "w").close()

    def path(self, rel):
        return self.root + rel

    def put(self, rel, data, mode=0o600):
        p = self.path(rel)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "wb") as f:
            f.write(data if isinstance(data, bytes) else data.encode())
        os.chmod(p, mode)
        return p

    def read(self, rel):
        try:
            with open(self.path(rel), "rb") as f:
                return f.read()
        except OSError:
            return None

    def clean(self):
        self.stop_probes()
        shutil.rmtree(self.root, ignore_errors=True)



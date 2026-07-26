#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# 端到端: 事务在 APPLYING 阶段被强杀(等价于断电)之后的行为。
#   1. 现网留在"改了一半"的状态, 事务停在 APPLYING;
#   2. 下一次写操作**被拒绝**并指向 pdg tx recover(不静默删证据, 也不接着写);
#   3. doctor 报告未完成事务(只报告, 不代为恢复 —— 自检必须只读);
#   4. pdg tx recover 用 before-image 还原并验证; 恢复后写操作恢复正常;
#   5. 漂移保护: 事务外被人手工改过 → 默认停手报冲突, --force 才覆盖。
# ─────────────────────────────────────────────────────────────────────────────
set -uo pipefail
E2E_ROOT="${E2E_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
# shellcheck source=tests/e2e-lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/e2e-lib.sh"
e2e_enter "$@"

e2e_stub_system
e2e_seed_install
e2e_seed_mosdns all
e2e_seed_singbox_model
# 事务目录与本用例的临时产物不在 e2e 沙箱的 overlay 里(它们在 /var/lib 与 /tmp), 上一次
# 跑剩的"未完成事务"会正确地挡住这一次 —— 那是产品行为, 但会让用例测不到自己想测的东西。
rm -rf /var/lib/privdns-gateway/tx /tmp/tx-crash.out /tmp/tx-crash2.out /tmp/tx-race.out /tmp/tx-winner.txt
printf 'mihomo\n' > /etc/privdns-gateway/backend
printf 'android\n' > /etc/privdns-gateway/platform

TX=/opt/privdns-gateway/deploy/bot/pdgtx.py
export PDG_STABLE_SAMPLES=1
HIJ=/etc/mosdns/rules/custom_hijack.txt
printf 'domain:before.example\n' > "$HIJ"
BEFORE_SHA="$(sha256sum "$HIJ" | cut -d' ' -f1)"

# 硬门探针落点(与 e2e-config-transaction.sh 同法): 真 DNS 应答 + 真 TCP 监听
python3 - >/dev/null 2>&1 <<'PY' &
import socket, threading
u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); u.bind(("127.0.0.1", 5399))
t = socket.socket(); t.bind(("127.0.0.1", 7893)); t.listen(8)
def dns():
    while True:
        d, a = u.recvfrom(512); u.sendto(d[:2] + b"\x81\x83" + d[4:12], a)
threading.Thread(target=dns, daemon=True).start()
while True:
    c, _ = t.accept(); c.close()
PY
PROBE=$!
sleep 0.5
export PDG_TX_DNS_PROBE=127.0.0.1:5399
trap 'kill "$PROBE" 2>/dev/null' EXIT

# ══ 1. 造一笔"应用到一半被 kill -9"的事务 ═════════════════════════════════
echo "── 1. APPLYING 阶段被强杀 ──"
python3 - "$TX" <<'PY' >/tmp/tx-crash.out 2>&1
import importlib.util, os, signal, sys
spec = importlib.util.spec_from_file_location("pdgtx", sys.argv[1])
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)

# 文件已经落盘、服务动作还没做完的那一刻把自己打死 —— 与断电同形态
real = m.Tx._do_actions
def die(self):
    print(self.txid, flush=True)
    os.kill(os.getpid(), signal.SIGKILL)
m.Tx._do_actions = die
t = m.Tx("cli", "e2e_crash")
t.stage("mosdns_rule:custom_hijack.txt", b"domain:half-applied.example\n")
t.commit()
PY
CRASH_TX="$(head -1 /tmp/tx-crash.out | tr -d '\r')"
[[ -n "$CRASH_TX" ]] && ok "造出一笔被强杀的事务: $CRASH_TX" || bad "没拿到事务 ID: $(cat /tmp/tx-crash.out)"
grep -q 'half-applied' "$HIJ" && ok "现网确实停在改了一半的状态(文件已换, 服务动作没做完)" \
  || bad "文件没被改, 场景不成立"
STATE="$(python3 "$TX" show "$CRASH_TX" | python3 -c 'import json,sys; print(json.load(sys.stdin)["state"])')"
[[ "$STATE" == APPLYING ]] && ok "事务状态停在 APPLYING" || bad "状态是 $STATE"

# ══ 2. 下一次写操作必须被拒绝 ═════════════════════════════════════════════
echo; echo "── 2. 未完成事务挡住后续写 ──"
out=$(python3 - "$TX" <<'PY' 2>&1
import importlib.util, sys
spec = importlib.util.spec_from_file_location("pdgtx", sys.argv[1])
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
t = m.Tx("bot", "e2e_after_crash")
t.stage("mosdns_rule:custom_direct.txt", b"domain:new.example\n")
try:
    t.commit(); print("COMMITTED")
except m.TxRefused as e:
    print("REFUSED:", e)
PY
)
{ grep -q '^REFUSED' <<<"$out" && grep -q 'recover' <<<"$out"; } \
  && ok "有未完成事务时新的写被拒绝, 并指向 tx recover" || bad "没挡住: $out"
python3 "$TX" pending >/dev/null 2>&1 && bad "pending 没报出未完成事务" \
  || ok "pdgtx pending 以非 0 退出报告未完成事务(供定时任务/脚本判断)"

# ══ 3. doctor 只报告, 不代为恢复 ══════════════════════════════════════════
echo; echo "── 3. doctor 报告 ──"
SHA_BEFORE_DOCTOR="$(sha256sum "$HIJ" | cut -d' ' -f1)"
dout="$(pdg doctor 2>&1)"
grep -q '配置事务' <<<"$dout" && ok "doctor 里出现「配置事务」检查项" || bad "doctor 没有事务项"
grep -q "$CRASH_TX" <<<"$dout" && ok "doctor 点名了未完成事务的 ID" || bad "doctor 没点名: $(grep -c . <<<"$dout") 行"
[[ "$(sha256sum "$HIJ" | cut -d' ' -f1)" == "$SHA_BEFORE_DOCTOR" ]] \
  && ok "doctor 全程只读(没有顺手把现网改回去)" || bad "doctor 动了现网文件"

# ══ 4. recover: 用 before-image 还原并验证 ════════════════════════════════
echo; echo "── 4. pdg tx recover ──"
rout="$(pdg tx recover "$CRASH_TX" 2>&1)"
grep -q '"ok": true' <<<"$rout" && ok "recover 返回成功" || bad "recover 失败: $(tail -2 <<<"$rout")"
[[ "$(sha256sum "$HIJ" | cut -d' ' -f1)" == "$BEFORE_SHA" ]] \
  && ok "现网逐字节回到事务开始前" || bad "内容没还原: $(cat "$HIJ")"
STATE="$(python3 "$TX" show "$CRASH_TX" | python3 -c 'import json,sys; print(json.load(sys.stdin)["state"])')"
[[ "$STATE" == ROLLED_BACK ]] && ok "事务状态收敛为 ROLLED_BACK" || bad "恢复后状态是 $STATE"
rout2="$(pdg tx recover "$CRASH_TX" 2>&1)"
grep -q '"ok": true' <<<"$rout2" && ok "recover 幂等(再跑一次仍成功且不再改动)" || bad "重复 recover 出错: $rout2"

out=$(python3 - "$TX" <<'PY' 2>&1
import importlib.util, sys
spec = importlib.util.spec_from_file_location("pdgtx", sys.argv[1])
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
t = m.Tx("bot", "e2e_after_recover")
t.stage("mosdns_rule:custom_direct.txt", b"domain:new.example\n")
t.service("restart:mosdns")
print(t.commit()["state"])
PY
)
grep -q COMMITTED <<<"$out" && ok "恢复之后写操作恢复正常" || bad "恢复后仍写不了: $out"

# ══ 5. 漂移保护 ═══════════════════════════════════════════════════════════
echo; echo "── 5. 恢复时的漂移保护 ──"
python3 - "$TX" <<'PY' >/tmp/tx-crash2.out 2>&1
import importlib.util, os, signal, sys
spec = importlib.util.spec_from_file_location("pdgtx", sys.argv[1])
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
def die(self):
    print(self.txid, flush=True)
    os.kill(os.getpid(), signal.SIGKILL)
m.Tx._do_actions = die
t = m.Tx("cli", "e2e_crash2")
t.stage("mosdns_rule:custom_hijack.txt", b"domain:half2.example\n")
t.commit()
PY
CRASH2="$(head -1 /tmp/tx-crash2.out | tr -d '\r')"
printf 'domain:hand-fixed.example\n' > "$HIJ"        # 运维手工救场
rout="$(pdg tx recover "$CRASH2" 2>&1)"
{ grep -q '"ok": false' <<<"$rout" && grep -q 'conflicts' <<<"$rout" \
  && grep -q 'hand-fixed' "$HIJ"; } \
  && ok "事务外被手工改过 → 报冲突且**不覆盖**人工修复" || bad "漂移保护失效: $rout"
rout="$(pdg tx recover "$CRASH2" --force 2>&1)"
{ grep -q '"ok": true' <<<"$rout" && [[ "$(sha256sum "$HIJ" | cut -d' ' -f1)" == "$BEFORE_SHA" ]]; } \
  && ok "--force 显式覆盖才会用 before-image 还原" || bad "force 恢复没生效: $rout"

e2e_summary

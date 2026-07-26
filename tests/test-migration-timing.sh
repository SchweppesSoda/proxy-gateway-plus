#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# 迁移时机回归(5.1 P0): 迁移不得发生在"用户没要求"或"快照之前"。
#
# 旧实现在命令分派**之前**对所有管理类命令跑一遍 run_all_migrations —— 那时既没上锁, 也在
# cmd_update 打快照之前。于是: 点个菜单就悄悄改了 unit/nft/mosdns; 更新失败回滚只能回到
# "已被迁移改过"的现网, 而用户以为回到了操作前。
#
# 本用例抽真身执行(不是 grep 源码): 用假的 run_all_migrations 记录调用次序, 跑真实的分派逻辑。
# ─────────────────────────────────────────────────────────────────────────────
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT
pass=0; nfail=0
ok(){ echo "[OK]   $1"; pass=$((pass+1)); }
bad(){ echo "[FAIL] $1"; nfail=$((nfail+1)); }

# ── 1. 分派前不再有隐藏迁移 ──
# 取 pdg.sh 里"分派段"的真实代码(case 之前到 case 之间), 确认它不再调用 run_all_migrations。
disp="$(sed -n '/^# 5.1: \*\*取消命令分派前的隐藏迁移/,/^case "\${1:-menu}" in/p' "$ROOT/deploy/bot/pdg.sh")"
[[ -n "$disp" ]] || bad "找不到分派段(pdg.sh 结构变了?)"
# 只看**可执行行**(注释里会提到这个函数名, 那是说明为什么取消了它)
grep -vE '^\s*#' <<<"$disp" | grep -q 'run_all_migrations' \
  && bad "分派前仍然会跑 run_all_migrations" \
  || ok "命令分派前不再有隐藏迁移(菜单/restart 等不会暗中改配置)"

# ── 2. 真跑一遍: 普通命令不触发迁移 ──
# 造一个只保留"函数定义 + 分派"的可执行副本, 把会真动系统的函数打桩。
build(){
  {
    echo 'run_all_migrations(){ echo "MIGRATE" >> "$WORK/order"; }'
    echo 'cmd_status(){ echo "STATUS" >> "$WORK/order"; }'
    echo 'cmd_restart(){ echo "RESTART" >> "$WORK/order"; }'
    echo 'menu(){ echo "MENU" >> "$WORK/order"; }'
    echo 'cmd_snapshot(){ echo "SNAPSHOT" >> "$WORK/order"; _PDG_SNAP_CREATED="$WORK/snap"; mkdir -p "$WORK/snap"; }'
    echo 'need_root(){ :; }'
    echo '_lock(){ echo "LOCK" >> "$WORK/order"; }'
    echo 'c_g(){ :; }; c_y(){ :; }'
    echo '_tx_audit(){ echo "AUDIT:$3" >> "$WORK/order"; }'
    sed -n '/^# 5.1: \*\*取消命令分派前的隐藏迁移/,$p' "$ROOT/deploy/bot/pdg.sh" \
      | grep -v '^cmd_migrate(){' > /dev/null   # 分派段本身在下面整体取
    sed -n '/^cmd_migrate(){/,/^}/p' "$ROOT/deploy/bot/pdg.sh"
    sed -n '/^case "\${1:-menu}" in/,/^esac/p' "$ROOT/deploy/bot/pdg.sh"
  } > "$WORK/disp.sh"
}
build
export WORK
run(){ : > "$WORK/order"; bash "$WORK/disp.sh" "$@" >/dev/null 2>&1; tr '\n' ' ' < "$WORK/order" 2>/dev/null; }

out="$(run status)"
grep -q MIGRATE <<<"$out" && bad "status 触发了迁移: $out" || ok "pdg status 不触发迁移(只读语义)"
out="$(run restart)"
grep -q MIGRATE <<<"$out" && bad "restart 触发了迁移: $out" || ok "pdg restart 不触发迁移"
out="$(run menu)"
grep -q MIGRATE <<<"$out" && bad "menu 触发了迁移: $out" || ok "pdg 菜单不触发迁移"

# ── 3. 显式迁移: 必须先上锁、先快照, 再迁移, 并记审计 ──
out="$(run migrate)"
if [[ "$out" == *"LOCK"*"SNAPSHOT"*"MIGRATE"* ]]; then
  ok "pdg migrate: 锁 → 快照 → 迁移(顺序正确)"
else
  bad "pdg migrate 顺序不对: $out"
fi
grep -q 'AUDIT:COMMITTED' <<<"$out" && ok "pdg migrate 成功后写入审计" || bad "迁移没记审计: $out"

# ── 4. 内部入口 __migrate 仍然可用(cmd_update 装好新脚本后靠它跑新版迁移)──
out="$(run __migrate)"
grep -q MIGRATE <<<"$out" && ok "pdg __migrate 仍执行迁移(更新流程的内部入口)" || bad "__migrate 不迁移了"

echo "────────────────────────────────────────"
echo "通过 $pass, 失败 $nfail"
[[ "$nfail" == 0 ]]

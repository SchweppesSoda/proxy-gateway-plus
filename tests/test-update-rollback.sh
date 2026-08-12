#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# 更新快照 + 精确回滚回归(Item 10)。
#   A. cmd_rollback --dir 精确指定快照: 即使有更新的快照(index 0)也回滚到**指定**那份;
#      不带 --dir 时仍按 index 0(最近)。
#   B. cmd_rollback --git <ref>: 回滚后把 REPO_DIR 复位到该提交(还原仓库版本)。
#   C. 部分恢复失败(git ref 不存在)→ 不谎报"完全回滚", 打印"未完全回滚"并返回 1。
#   D. 静态: cmd_update 快照失败即中止; 用 --dir "$snap_dir" --git "$pre_sha"(非 cmd_rollback 0);
#      快照 cand 覆盖已装脚本 + 全部 unit; 越界守卫放行 usr/local/bin。
# 沙箱化: 覆写 apply、定向绝对写路径，打桩 systemctl/nft/内核 check；不碰真 /。
# ─────────────────────────────────────────────────────────────────────────────
set -uo pipefail

# cmd_rollback intentionally contains real absolute-path cleanup for managed
# assets. Refuse privileged or already-deployed hosts before extracting it;
# this unit test never needs either environment.
if (( EUID == 0 )); then
  echo "[FAIL] test-update-rollback.sh refuses to run as root" >&2
  exit 1
fi
if [[ -e /usr/local/libexec/pdg-quic-routing.sh \
   || -e /etc/privdns-gateway || -e /opt/pdg-bot || -e /opt/pdg-web ]]; then
  echo "[FAIL] test-update-rollback.sh refuses to run on a deployed PDG host" >&2
  exit 1
fi

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT
pass=0; nfail=0
ok(){ echo "[OK]   $1"; pass=$((pass+1)); }
bad(){ echo "[FAIL] $1"; nfail=$((nfail+1)); }

# ── 造两份快照(旧 A=OLD / 新 B=NEW), 各含 backend + 判别标记 ──────────────────
SNAP="$WORK/snaps"; mkdir -p "$SNAP"
mksnap(){ # $1=目录名 $2=标记
  local d="$SNAP/$1"; mkdir -p "$d/tree/etc/privdns-gateway"
  printf 'singbox\n' > "$d/tree/etc/privdns-gateway/backend"
  printf '%s\n' "$2" > "$d/tree/etc/privdns-gateway/snapid"
  tar czf "$d/snap.tar.gz" -C "$d/tree" etc 2>/dev/null; rm -rf "$d/tree"
}
mksnap A OLD; sleep 1; mksnap B NEW    # B 更新(mtime 更晚 → ls -t 里 index 0)

# ── 沙箱 REPO_DIR: 两提交的 git 仓库 ─────────────────────────────────────────
REPO="$WORK/repo"; mkdir -p "$REPO"
( cd "$REPO" && git init -q && git config user.email t@t && git config user.name t \
  && echo v1 > f && git add f && git commit -qm c1 && echo v2 > f && git add f && git commit -qm c2 )
GOOD_REF=$(git -C "$REPO" rev-parse HEAD~1)   # 第一提交
HEAD_REF=$(git -C "$REPO" rev-parse HEAD)
# ruleset_direct 重建助手会从 REPO_DIR 读取可信 Bot 实现；给假仓库补齐该只读依赖。
mkdir -p "$REPO/deploy/bot"
cp "$ROOT/deploy/bot/pdg-bot.py" "$REPO/deploy/bot/pdg-bot.py"
cp "$ROOT/deploy/bot/pdgtx.py" "$REPO/deploy/bot/pdgtx.py"
mkdir -p "$REPO/deploy/web"
cp "$ROOT/deploy/web/pdg-web-job.py" "$REPO/deploy/web/pdg-web-job.py"
cp "$ROOT/deploy/web/pdgconfigio.py" "$REPO/deploy/web/pdgconfigio.py"

# ── 抽取 cmd_rollback + 打桩 ──────────────────────────────────────────────────
for fn in _pdg_clear_web_import_staging _pdg_clear_legacy_config_import_jobs \
          _pdg_snapshot_rederive_ruleset_direct _pdg_rollback_restore_quic \
          cmd_rollback; do
  sed -n "/^${fn}(){/,/^}/p" "$ROOT/deploy/bot/pdg.sh"
done | sed \
  -e 's#^\([[:space:]]*local cur_qhelper=\)/usr/local/libexec/pdg-quic-routing[.]sh#\1"$SB/usr/local/libexec/pdg-quic-routing.sh"#' \
  -e 's#^\([[:space:]]*\)/usr/local/libexec/pdg-quic-routing[.]sh #\1"$SB/usr/local/libexec/pdg-quic-routing.sh" #' \
  -e 's#> /etc/privdns-gateway/backend#> "$SB/etc/privdns-gateway/backend"#' \
  -e 's# /etc/nftables\.conf# "$SB/etc/nftables.conf"#g' \
  -e 's# /etc/mihomo/config\.yaml# "$SB/etc/mihomo/config.yaml"#g' \
  -e 's# /etc/sing-box/config\.json# "$SB/etc/sing-box/config.json"#g' \
  -e 's#install -d -m700 /etc/mihomo#install -d -m700 "$SB/etc/mihomo"#' \
  -e 's#rm -f -- "/$mp"#rm -f -- "$SB/$mp"#' \
  -e 's#rmdir /opt/pdg-web/static/templates /opt/pdg-web/static /opt/pdg-web#rmdir "$SB/opt/pdg-web/static/templates" "$SB/opt/pdg-web/static" "$SB/opt/pdg-web"#' \
  > "$WORK/rollback.sh"
if grep -Eq '(^|[[:space:]])rmdir[[:space:]]+/opt/' "$WORK/rollback.sh"; then
  echo "[FAIL] rollback harness 残留真实 /opt rmdir" >&2
  exit 1
fi
# 快照里不含 etc/sing-box/config.json 与 etc/nftables.conf → 内核/nft 校验分支被跳过,
# 无需真 sing-box/mihomo/nft 二进制(也就不必打桩带连字符的函数名)。
SB="$WORK/root"; mkdir -p "$SB/etc/privdns-gateway"
cat > "$WORK/harness.sh" <<EOF
SNAP_DIR="$SNAP"
REPO_DIR="$REPO"
SB="$SB"
PDG_ROOT_PREFIX="$SB"
PROFILE_ENV="$SB/etc/privdns-gateway/profile.env"
need_root(){ :; }; _lock(){ :; }
c_g(){ echo "\$*"; }; c_y(){ echo "\$*"; }
_pdg_core(){ echo singbox; }
_pdg_core_svc(){ echo sing-box; }
_pdg_mktemp_dir(){ mktemp -d; }
_sb_panel_managed_on(){ return 1; }
_core_kernel_activate(){ return 0; }
_pdg_nft_bin(){ return 1; }
_pdg_snapshot_abort(){
  echo "unexpected rollback abort: \${7:-missing reason}" >&2
  return 1
}
# cmd_rollback 会用到的 units.sh / 归属助手: 沙箱里没有真 /etc, 一并打桩(与 systemctl/nft 同理)
pdg_write_unit(){ return 0; }
pdg_unit_mihomo(){ echo "[Unit]"; }
_pdg_drop_singbox_files(){ :; }
_pdg_singbox_is_ours(){ return 1; }
systemctl(){
  [[ -n "\${QUIC_LOG:-}" ]] && printf 'systemctl %s\n' "\$*" >>"\$QUIC_LOG"
  if [[ "\${1:-}" == restart && "\${2:-}" == pdg-quic-routing \
        && "\${FAIL_QUIC_RESTART:-0}" == 1 ]]; then
    return 1
  fi
  return 0
}
nft(){ return 0; }
command_not_found_handle(){ printf '%s\n' "\${1:-unknown}" > "$WORK/command-not-found.log"; return 127; }
# 覆写落盘: 不碰真 /, 把被应用快照的判别标记抄到沙箱, 供断言"回滚到了哪份"
APPLIED="$WORK/applied_snapid"
_pdg_apply_snapshot_tree(){ cat "\$1/etc/privdns-gateway/snapid" > "\$APPLIED" 2>/dev/null; return 0; }
EOF

run(){ bash -c "source '$WORK/harness.sh'; source '$WORK/rollback.sh'; cmd_rollback $1" 2>&1; }

# ── A. --dir 精确回滚(指到旧的 A, 而非 index0 的 B) ─────────────────────────
rm -f "$WORK/applied_snapid"; out=$(run "--dir '$SNAP/A'")
[[ "$(cat "$WORK/applied_snapid" 2>/dev/null)" == OLD ]] \
  && ok "--dir 指定旧快照 A → 精确回滚到 A(未被 index0 的 B 顶掉)" || bad "A: applied=$(cat "$WORK/applied_snapid" 2>/dev/null) out=$out"

# 不带 --dir → index 0(最近 = B)
rm -f "$WORK/applied_snapid"; out=$(run "0")
[[ "$(cat "$WORK/applied_snapid" 2>/dev/null)" == NEW ]] \
  && ok "无 --dir → 默认 index0 仍回滚到最近 B" || bad "A2: applied=$(cat "$WORK/applied_snapid" 2>/dev/null) out=$out"

# 首次升级失败：更新后的 CLI 必须能回滚“有规则集、但 MosDNS 尚未声明
# ruleset_hijack”的旧快照。无关的 proxy source 元数据故意不放文件，证明旧契约
# 只重建 direct，不会拿升级后的新聚合 schema 反向否决旧好档。
LEGACY="$SNAP/LEGACY"; LT="$LEGACY/tree"
mkdir -p "$LT/etc/privdns-gateway" "$LT/etc/mosdns/rules" \
  "$LT/etc/sing-box/rs" "$LT/opt/pdg-bot"
printf 'singbox\n' > "$LT/etc/privdns-gateway/backend"
printf 'LEGACY\n' > "$LT/etc/privdns-gateway/snapid"
cat > "$LT/etc/mosdns/config.yaml" <<'EOF'
plugins:
  - tag: geosite_cn
    type: domain_set
    args: { files: ["/etc/mosdns/rules/geosite_cn.txt","/etc/mosdns/rules/ruleset_direct.txt"] }
  - tag: explicit_hijack
    type: domain_set
    args: { files: ["/etc/mosdns/rules/custom_hijack.txt"] }
  - tag: force_hijack_seq
    type: sequence
    args:
      - matches: qtype 1
        exec: black_hole 203.0.113.10
  - tag: internal_sequence
    type: sequence
    args:
      - matches: qname $explicit_hijack
        exec: goto force_hijack_seq
      - matches: qname $geosite_cn
        exec: $local_upstream
EOF
cat > "$LT/opt/pdg-bot/rulesets.json" <<'EOF'
{
  "rs_direct": {
    "url": "https://x/direct.list",
    "outbound": "direct",
    "format": "source",
    "path": "/etc/sing-box/rs/rs_direct.json"
  },
  "rs_unrelated_proxy": {
    "url": "https://x/proxy.list",
    "outbound": "US",
    "format": "source",
    "path": "/etc/sing-box/rs/rs_unrelated_proxy.json"
  }
}
EOF
printf '%s\n' \
  '{"version":1,"rules":[{"domain_suffix":["legacy.example"]}]}' \
  > "$LT/etc/sing-box/rs/rs_direct.json"
printf 'domain:poison.example\n' > "$LT/etc/mosdns/rules/ruleset_direct.txt"
printf 'domain:poison.example\n' > "$LT/etc/mosdns/rules/ruleset_hijack.txt"
tar czf "$LEGACY/snap.tar.gz" -C "$LT" etc opt 2>/dev/null
rm -rf "$LT"
rm -f "$WORK/applied_snapid"
out=$(run "--dir '$LEGACY'") || rc=$?
[[ "${rc:-0}" == 0 && "$(cat "$WORK/applied_snapid" 2>/dev/null)" == LEGACY \
   && "$out" != *TxRefused* ]] \
  && ok "首次升级失败 → 新 CLI 可按旧 MosDNS 契约回滚旧规则集快照" \
  || bad "A3: rc=${rc:-0} applied=$(cat "$WORK/applied_snapid" 2>/dev/null) out=$out"
unset rc

# ── B. --git 复位仓库 ────────────────────────────────────────────────────────
git -C "$REPO" reset --hard -q "$HEAD_REF"
out=$(run "--dir '$SNAP/A' --git '$GOOD_REF'")
[[ "$(git -C "$REPO" rev-parse HEAD)" == "$GOOD_REF" ]] \
  && echo "$out" | grep -q '已回滚并重启服务' && ok "--git: REPO_DIR 复位到指定提交 + 报完全回滚" || bad "B: HEAD=$(git -C "$REPO" rev-parse HEAD) out=$out"

# ── C. git ref 不存在 → 不谎报完全回滚, 返回 1 ───────────────────────────────
rc=0; out=$(run "--dir '$SNAP/A' --git 'deadbeefdeadbeef'") || rc=$?
{ echo "$out" | grep -q '未完全回滚' && [[ "$rc" == 1 ]]; } \
  && ok "git ref 失效 → 打印'未完全回滚'并返回 1(不谎报成功)" || bad "C: rc=$rc out=$out"
# 但快照本身仍已恢复(apply 成功)
[[ "$(cat "$WORK/applied_snapid" 2>/dev/null)" == OLD ]] && ok "  部分失败下配置快照仍已落盘(只是 git 未复位)" || bad "C2"

# ── C3. 跨内核回滚: _core_kernel_activate 失败 → 计入 unrestored, 非0 + "未完全回滚" ──
# 造"回滚前是 mihomo, 快照是 singbox"的跨内核场景: _pdg_core 首调(pre_core)返 mihomo, 之后返 singbox。
cat > "$WORK/xcore.sh" <<EOF
PRE="$WORK/precore"; : > "\$PRE"
_pdg_core(){ if [[ -s "\$PRE" ]]; then echo singbox; else echo mihomo; printf x > "\$PRE"; fi; }
pdg_write_unit(){ return 0; }
_core_kernel_activate(){ return 1; }        # 注入: 快照核激活失败
EOF
runx(){ bash -c "source '$WORK/harness.sh'; source '$WORK/xcore.sh'; source '$WORK/rollback.sh'; cmd_rollback $1" 2>&1; }
rc=0; out=$(runx "--dir '$SNAP/A'") || rc=$?
{ [[ "$rc" != 0 ]] && grep -q '未完全回滚' <<<"$out" && ! grep -q '✅ 已回滚并重启服务' <<<"$out"; } \
  && ok "跨内核回滚: 内核激活失败 → 非0 + '未完全回滚' + 不报'✅ 已回滚'" || bad "C3: rc=$rc out=$out"
grep -q '内核激活' <<<"$out" && ok "  未恢复项明确列出'内核激活'" || bad "C3b: 未列出失败项 out=$out"

# ── C4. 校验快照旧配置要用**快照自带的内核**, 不能用当前(新)内核 ──────────────
# 场景: 新内核拒绝旧配置(正是要回滚的原因)。若拿当前新内核去校验快照里的旧配置, 它当然
# 说"不合法", 回滚就被自己挡住了 —— 旧内核和旧配置本该一起回去。
mkmihomo_snap(){  # $1=目录名 $2=快照内核的 check 退出码
  local d="$SNAP/$1"; rm -rf "$d"; mkdir -p "$d/tree/etc/privdns-gateway" "$d/tree/etc/mihomo" "$d/tree/usr/local/bin"
  printf 'mihomo\n' > "$d/tree/etc/privdns-gateway/backend"
  printf 'SNAP-M\n'  > "$d/tree/etc/privdns-gateway/snapid"
  printf 'mixed-port: 7890\n' > "$d/tree/etc/mihomo/config.yaml"
  printf '#!/bin/sh\nexit %s\n' "$2" > "$d/tree/usr/local/bin/mihomo"; chmod 755 "$d/tree/usr/local/bin/mihomo"
  # 按 cmd_snapshot 的方式打**显式成员路径**: 递归打 usr 会带出 usr/ 目录项, 触发越界守卫
  tar czf "$d/snap.tar.gz" -C "$d/tree" etc/privdns-gateway etc/mihomo usr/local/bin/mihomo 2>/dev/null
  rm -rf "$d/tree"
}
# 当前内核一律拒绝旧配置(模拟"新内核不认旧配置")
cat > "$WORK/curkernel.sh" <<'EOF'
mihomo(){ return 1; }
_pdg_core(){ echo mihomo; }
_pdg_core_svc(){ echo mihomo; }
EOF
runm(){ bash -c "source '$WORK/harness.sh'; source '$WORK/curkernel.sh'; source '$WORK/rollback.sh'; cmd_rollback $1" 2>&1; }

mkmihomo_snap M_OK 0            # 快照自带的 mihomo 接受旧配置
rm -f "$WORK/applied_snapid"; rc=0; out=$(runm "--dir '$SNAP/M_OK'") || rc=$?
{ [[ "$rc" == 0 ]] && [[ "$(cat "$WORK/applied_snapid" 2>/dev/null)" == SNAP-M ]]; } \
  && ok "快照内核接受旧配置 → 回滚成功落盘(不被当前新内核挡住)" || bad "C4a: rc=$rc out=$out"

mkmihomo_snap M_BAD 1           # 快照自带的 mihomo 也拒绝 → 这份快照真的不可用
rm -f "$WORK/applied_snapid"; rc=0; out=$(runm "--dir '$SNAP/M_BAD'") || rc=$?
{ [[ "$rc" != 0 ]] && [[ ! -e "$WORK/applied_snapid" ]]; } \
  && ok "快照内核也拒绝旧配置 → 落盘前中止(不写坏现网)" || bad "C4b: rc=$rc applied=$(cat "$WORK/applied_snapid" 2>/dev/null)"

# ── C5. QUIC oneshot 必须显式 restart；restart/status 失败均为未完全回滚 ─────
Q="$SNAP/Q"; QT="$Q/tree"
mkdir -p "$QT/etc/privdns-gateway" "$QT/etc/systemd/system" \
  "$QT/usr/local/libexec" "$QT/opt/pdg-bot"
printf 'singbox\n' > "$QT/etc/privdns-gateway/backend"
printf 'Q\n' > "$QT/etc/privdns-gateway/snapid"
printf 'PDG_QUIC_MODE=tproxy\n' > "$QT/etc/privdns-gateway/profile.env"
printf '[Unit]\nDescription=test\n' > "$QT/etc/systemd/system/pdg-quic-routing.service"
printf '#!/bin/sh\nexit 0\n' > "$QT/usr/local/libexec/pdg-quic-routing.sh"
printf '# test profile tool\n' > "$QT/opt/pdg-bot/pdgprofile.py"
chmod 755 "$QT/usr/local/libexec/pdg-quic-routing.sh"
tar czf "$Q/snap.tar.gz" -C "$QT" \
  etc/privdns-gateway/backend etc/privdns-gateway/snapid \
  etc/privdns-gateway/profile.env \
  etc/systemd/system/pdg-quic-routing.service \
  usr/local/libexec/pdg-quic-routing.sh opt/pdg-bot/pdgprofile.py \
  2>/dev/null
rm -rf "$QT"

# 现网 helper 映射到沙箱；早期 cleanup-status/remove 均成功，最终 status 可独立注错。
mkdir -p "$SB/usr/local/libexec"
cat > "$SB/usr/local/libexec/pdg-quic-routing.sh" <<'EOF'
#!/usr/bin/env bash
printf 'helper %s\n' "${1:-}" >>"${QUIC_LOG:?}"
if [[ "${1:-}" == status && "${FAIL_QUIC_STATUS:-0}" == 1 ]]; then
  exit 1
fi
exit 0
EOF
chmod 755 "$SB/usr/local/libexec/pdg-quic-routing.sh"
export QUIC_LOG="$WORK/quic.log"

export FAIL_QUIC_RESTART=0 FAIL_QUIC_STATUS=0
: >"$QUIC_LOG"; rc=0; out=$(run "--dir '$Q'") || rc=$?
enable_line="$(grep -n '^systemctl enable pdg-quic-routing$' "$QUIC_LOG" | tail -1 | cut -d: -f1)"
restart_line="$(grep -n '^systemctl restart pdg-quic-routing$' "$QUIC_LOG" | tail -1 | cut -d: -f1)"
status_line="$(grep -n '^helper status$' "$QUIC_LOG" | tail -1 | cut -d: -f1)"
{ [[ "$rc" == 0 && -n "$enable_line" && -n "$restart_line" && -n "$status_line" ]] \
  && (( enable_line < restart_line && restart_line < status_line )); } \
  && ok "QUIC rollback: enable 后显式 restart oneshot，再执行 helper status" \
  || bad "C5a: rc=$rc enable=$enable_line restart=$restart_line status=$status_line out=$out log=$(cat "$QUIC_LOG")"

export FAIL_QUIC_RESTART=1 FAIL_QUIC_STATUS=0
: >"$QUIC_LOG"; rc=0; out=$(run "--dir '$Q'") || rc=$?
{ [[ "$rc" == 1 ]] && grep -q '未完全回滚' <<<"$out" \
  && grep -q 'QUIC routing恢复(enable/restart/status)' <<<"$out" \
  && grep -q '^systemctl restart pdg-quic-routing$' "$QUIC_LOG" \
  && ! grep -q '^helper status$' "$QUIC_LOG"; } \
  && ok "QUIC rollback: restart 失败 → 非0 + 未完全回滚，且不继续伪验 status" \
  || bad "C5b: rc=$rc out=$out log=$(cat "$QUIC_LOG")"

export FAIL_QUIC_RESTART=0 FAIL_QUIC_STATUS=1
: >"$QUIC_LOG"; rc=0; out=$(run "--dir '$Q'") || rc=$?
{ [[ "$rc" == 1 ]] && grep -q '未完全回滚' <<<"$out" \
  && grep -q 'QUIC routing恢复(enable/restart/status)' <<<"$out" \
  && grep -q '^systemctl restart pdg-quic-routing$' "$QUIC_LOG" \
  && grep -q '^helper status$' "$QUIC_LOG"; } \
  && ok "QUIC rollback: restart 后 status 失败 → 非0 + 未完全回滚" \
  || bad "C5c: rc=$rc out=$out log=$(cat "$QUIC_LOG")"
unset FAIL_QUIC_RESTART FAIL_QUIC_STATUS QUIC_LOG

# ── D. 静态断言: cmd_update / cmd_snapshot / 越界守卫 ─────────────────────────
u="$ROOT/deploy/bot/pdg.sh"
grep -q '更新前快照失败, 中止更新' "$u" && ok "cmd_update: 快照失败即中止(不在无法回滚下继续)" || bad "D1: 缺快照失败中止"
grep -q 'cmd_rollback --dir "\$snap_dir" --git "\$pre_sha"' "$u" && ok "cmd_update: 回滚用精确 --dir+--git(非 cmd_rollback 0)" || bad "D2"
grep -q "pre_sha=.*git -C .*rev-parse HEAD" "$u" && ok "cmd_update: 记录升级前 Git SHA" || bad "D3"
for p in 'usr/local/bin/pdg' 'usr/local/bin/pdg-set-token' 'etc/systemd/system/mihomo.service' 'etc/systemd/system/pdg-mitm.service' '99-pdg-cert.sh'; do
  grep -q "$p" "$u" || bad "D4: 快照 cand 缺 $p"
done
grep -q "etc/systemd/system/mihomo.service etc/systemd/system/sing-box.service" "$u" && ok "cmd_snapshot cand: 覆盖已装脚本 + 内核/mitm/probe/health 全部 unit + cert hook" || bad "D4 汇总"
grep -q 'usr/local/bin)(/|$)' "$u" && ok "回滚越界守卫放行 usr/local/bin(否则装的脚本进不了快照)" || bad "D5: 守卫未放行 usr/local/bin"
grep -q '^_pdg_clear_web_import_staging(){' "$WORK/rollback.sh" \
  && grep -q '^_pdg_clear_legacy_config_import_jobs(){' "$WORK/rollback.sh" \
  && ok "rollback harness 包含旧 snapshot 的 staging/job cleanup 依赖" \
  || bad "D6: rollback helper 抽取不完整"
[[ ! -e "$WORK/command-not-found.log" ]] \
  && ok "rollback harness 无 command-not-found 假失败" \
  || bad "D7: 未注入命令 $(cat "$WORK/command-not-found.log" 2>/dev/null)"

echo "────────────────────────────────────────"
echo "通过 $pass, 失败 $nfail"
[[ "$nfail" == 0 ]]

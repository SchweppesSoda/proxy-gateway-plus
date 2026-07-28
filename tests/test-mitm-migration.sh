#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# v1.4.x(WLOC 之前)→ 当前版 的 MITM 接管结构升级迁移回归(Item 3)。
#   A. 升级: 老 mosdns 配置(无 force_hijack)→ 迁移补 force_hijack domain_set + force_hijack_seq
#      + internal_sequence 优先级规则(在 geosite_cn 之前)+ 空 mitm_hijack.txt; 迁移后真起 mosdns 通过。
#   B. 幂等: 再跑不变(已有 force_hijack 即退)。
#   C. 自定义配置(无 internal_sequence/ecs_china 锚点)→ 跳过不动。
#   D. 失败还原: 生成阶段失败(锚点不唯一)→ 配置原样还原, 不留半截。
# 退出码 0=全过。
# ─────────────────────────────────────────────────────────────────────────────
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
# shellcheck source=lib/versions.sh
source "$ROOT/lib/versions.sh"
WORK="$(mktemp -d)"; PIDS=()
cleanup(){ for p in "${PIDS[@]:-}"; do kill "$p" 2>/dev/null; done; rm -rf "$WORK"; }
trap cleanup EXIT
pass=0; nfail=0
ok(){ echo "[OK]   $1"; pass=$((pass+1)); }
bad(){ echo "[FAIL] $1"; nfail=$((nfail+1)); }

# ── 抽取被测迁移函数 + 打桩 ──────────────────────────────────────────────────
c_g(){ :; }; c_y(){ :; }
eval "$(sed -n '/^migrate_mosdns_mitm(){/,/^}/p' "$ROOT/deploy/bot/pdg.sh")"

# ── 规则 fixture(都在 $WORK/rules, 迁移从 geosite_cn 路径推导目录)──
mkdir -p "$WORK/rules"
echo "qq.com" > "$WORK/rules/geosite_cn.txt"
: > "$WORK/rules/geosite_apple.txt"; : > "$WORK/rules/custom_direct.txt"; : > "$WORK/rules/custom_hijack.txt"; : > "$WORK/rules/ruleset_direct.txt"; : > "$WORK/rules/unlock.txt"
echo "example.com" > "$WORK/rules/geosite_geolocation-!cn.txt"
# (mitm_hijack.txt 故意不建: 迁移应自动补)

# ── 渲染当前 config，端口换高位、去 DoT、rules 指向 $WORK/rules ───────────
render_full(){
  sed -e "s/__SERVER_IP__/10.9.9.9/g" -e "s#__INTERNAL_CIDR__#127.0.0.0/8#g" -e "s#__CERT_DIR__#$WORK#g" \
      -e "s#__MOSDNS_CACHE__#8192#g" -e "s#__HIJACK_SET_FILE__#geosite_geolocation-!cn.txt#g" \
      -e "s#/etc/mosdns/rules/#$WORK/rules/#g" -e "s#0.0.0.0:53#127.0.0.1:15997#g" \
      -e "/- tag: dot_server/,\$d" "$ROOT/deploy/mosdns/config.yaml"
}
render_full > "$WORK/full.yaml"

# 本单测只验证 MITM force 迁移。explicit_hijack 是更晚加入、由 migrate_custom_hijack
# 独立负责的功能；legacy 当时两者都不存在。先从当前完整版精确移除 explicit plugin/rule，
# 得到“当前 canonical 的 MITM 投影”，再从该投影剥掉 force 三件套构造真实 legacy fixture。
# 迁移结果应逐结构恢复到投影中的 canonical 顺序，而不是把 unrelated explicit 功能算作
# migrate_mosdns_mitm 的职责。
python3 - "$WORK/full.yaml" "$WORK/expected.yaml" "$WORK/v14.yaml" <<'PY'
import re
import sys

source, expected, legacy = sys.argv[1:]
s = open(source, encoding="utf-8").read()

def remove_once(text, pattern, label):
    result, count = re.subn(pattern, "", text, count=1, flags=re.MULTILINE)
    assert count == 1, "%s 结构不唯一或缺失" % label
    return result

# Later explicit-hijack feature: outside this migration's contract.
s = remove_once(
    s,
    r"^  - tag: explicit_hijack\n"
    r"    type: domain_set\n"
    r"    args: \{ files: \[[^\n]*custom_hijack\.txt[^\n]*\] \}\n",
    "explicit_hijack plugin",
)
s = remove_once(
    s,
    r"^      - matches: qname \$explicit_hijack\n"
    r"        exec: goto force_hijack_seq\n",
    "explicit_hijack rule",
)
open(expected, "w", encoding="utf-8").write(s)

# v1.4.x had none of the MITM force mechanism.
s = remove_once(
    s,
    r"^  - tag: force_hijack\n"
    r"    type: domain_set\n"
    r"    args:[^\n]*\n",
    "force_hijack plugin",
)
s = remove_once(
    s,
    r"^  - tag: force_hijack_seq\n"
    r"(?:.*\n)*?"
    r"^      - matches: qtype 1\n"
    r"        exec: black_hole [0-9.]+\n",
    "force_hijack_seq",
)
s = remove_once(
    s,
    r"^      # MITM 接管域名[^\n]*\n"
    r"      - matches: qname \$force_hijack\n"
    r"        exec: goto force_hijack_seq\n",
    "force_hijack rule",
)
active = "\n".join(line.split("#", 1)[0] for line in s.splitlines())
assert "force_hijack" not in active, "legacy fixture 仍含 force 机制"
assert "explicit_hijack" not in active, "legacy fixture 仍含 explicit 关联"
open(legacy, "w", encoding="utf-8").write(s)
PY
if grep -Eq '^[[:space:]]*(- tag: force_hijack(_seq)?|- matches: qname \$(force|explicit)_hijack|exec: goto force_hijack_seq)' \
    "$WORK/v14.yaml"; then
  bad "v1.4.x fixture 构造失败(仍含 force/explicit 机制)"
else
  ok "构造 v1.4.x fixture(无 force/explicit 机制)"
fi

start_mosdns(){   # 起 mosdns 加载 $1, 成功返回0
  "$MD" start -c "$1" -d "$WORK" > "$WORK/mos.out" 2>&1 & PIDS+=($!)
  local p=$!
  for _ in $(seq 1 30); do
    dig +short +time=1 +tries=1 @127.0.0.1 -p 15997 rdy.test A >/dev/null 2>&1 && return 0
    kill -0 "$p" 2>/dev/null || break
    sleep 0.1
  done
  kill "$p" 2>/dev/null; return 1
}

# ── 取 mosdns ──
if command -v mosdns >/dev/null; then MD="$(command -v mosdns)"; else
  case "$(uname -m)" in x86_64) A=amd64;; aarch64|arm64) A=arm64;; *) A="";; esac
  if [[ -n "$A" ]] && curl -fsSL "https://github.com/IrineSistiana/mosdns/releases/download/${MOSDNS_VER}/mosdns-linux-${A}.zip" -o "$WORK/m.zip" 2>/dev/null \
     && pdg_verify_sha256 "$WORK/m.zip" "${PDG_SHA256[mosdns-$A]:-}" mosdns >/dev/null 2>&1 \
     && (cd "$WORK" && unzip -q m.zip); then MD="$WORK/mosdns"; chmod +x "$MD"; fi
fi

# ── A. 升级迁移 ──────────────────────────────────────────────────────────────
cp "$WORK/v14.yaml" "$WORK/mig.yaml"
migrate_mosdns_mitm "$WORK/mig.yaml"
grep -q '  - tag: force_hijack$' "$WORK/mig.yaml" && ok "迁移: 补 force_hijack domain_set" || bad "缺 force_hijack domain_set"
grep -q '  - tag: force_hijack_seq' "$WORK/mig.yaml" && ok "迁移: 补 force_hijack_seq" || bad "缺 force_hijack_seq"
grep -q 'exec: goto force_hijack_seq' "$WORK/mig.yaml" && ok "迁移: 补优先级规则(goto force_hijack_seq)" || bad "缺优先级规则"
[[ -e "$WORK/rules/mitm_hijack.txt" ]] && ok "迁移: 自动补空 mitm_hijack.txt" || bad "未补 mitm_hijack.txt"
# 顺序: force_hijack 规则必须在第一条 geosite_cn 之前
python3 - "$WORK/mig.yaml" <<'PY' && ok "优先级规则在 geosite_cn 之前(CN 判定前强制接管)" || { echo "顺序错"; exit 1; }
import sys
s = open(sys.argv[1]).read()
b = s[s.index('- tag: internal_sequence'):s.index('- tag: main_sequence')]
assert b.index('qname $force_hijack') < b.index('qname $geosite_cn'), '顺序不对'
PY
# 与当前 canonical 的 MITM 投影结构一致(忽略注释)。这也阻断 force 规则被插到 CN
# 判断之后等“内容齐全但优先级错误”的假绿。
if diff <(grep -vE '^\s*#' "$WORK/mig.yaml") <(grep -vE '^\s*#' "$WORK/expected.yaml") >/dev/null; then
  ok "迁移结果与当前 canonical MITM 顺序一致(byte 对齐, 忽略注释)"
else
  bad "迁移结果与当前 canonical MITM 投影不一致"
  diff -u <(grep -vE '^\s*#' "$WORK/expected.yaml") \
    <(grep -vE '^\s*#' "$WORK/mig.yaml") | head -40
fi
# 真起 mosdns 加载迁移后配置
if [[ -n "${MD:-}" ]] && command -v dig >/dev/null; then
  start_mosdns "$WORK/mig.yaml" && ok "迁移后 mosdns 真实加载通过(force_hijack 生效)" \
    || { bad "迁移后 mosdns 加载失败"; sed 's/^/  /' "$WORK/mos.out" | head -5; }
else
  echo "[SKIP] 无 mosdns/dig, 跳过真实加载(结构断言已覆盖)"
fi

# ── B. 幂等 ──────────────────────────────────────────────────────────────────
snap="$(cat "$WORK/mig.yaml")"
migrate_mosdns_mitm "$WORK/mig.yaml"
[[ "$(cat "$WORK/mig.yaml")" == "$snap" ]] && ok "幂等: 二跑不变(已有 force_hijack 即退)" || bad "二跑改动了文件"
[[ "$(grep -c 'tag: force_hijack$' "$WORK/mig.yaml")" == 1 ]] && ok "无重复 force_hijack" || bad "force_hijack 重复"

# ── C. 自定义配置 → 跳过 ──────────────────────────────────────────────────────
printf 'plugins:\n  - tag: foo\n    type: sequence\n    args: []\n' > "$WORK/custom.yaml"
snap="$(cat "$WORK/custom.yaml")"
migrate_mosdns_mitm "$WORK/custom.yaml"
[[ "$(cat "$WORK/custom.yaml")" == "$snap" ]] && ok "自定义配置(无锚点)→ 跳过不动" || bad "误改了自定义配置"

# ── D. 失败还原: 锚点不唯一(两个 ecs_china)→ 生成失败, 原样还原 ──────────────
# 用 v1.4.x fixture 复制一份并制造重复 ecs_china(python assert count==1 会失败)
sed '0,/  - tag: ecs_china/s//  - tag: ecs_china\n    type: ecs_handler\n    args: {}\n  - tag: ecs_china/' "$WORK/v14.yaml" > "$WORK/dup.yaml"
[[ "$(grep -c '  - tag: ecs_china' "$WORK/dup.yaml")" == 2 ]] || bad "构造重复 ecs_china 失败"
snap="$(cat "$WORK/dup.yaml")"
migrate_mosdns_mitm "$WORK/dup.yaml"
[[ "$(cat "$WORK/dup.yaml")" == "$snap" ]] && ok "生成失败(锚点不唯一)→ 配置原样还原(不留半截)" || bad "失败未还原"
grep -q 'tag: force_hijack$' "$WORK/dup.yaml" && bad "失败却注入了 force_hijack" || ok "失败: 未注入 force_hijack"
ls "$WORK"/dup.yaml.premitm.* >/dev/null 2>&1 && rm -f "$WORK"/dup.yaml.premitm.*   # 清备份

echo "────────────────────────────────────────"
echo "通过 $pass, 失败 $nfail"
[[ "$nfail" == 0 ]]

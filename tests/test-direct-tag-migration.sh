#!/usr/bin/env bash
# 锁内 jp→JP 三文件候选事务：成功提交与重启失败回滚。
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

pass=0
fail=0
ok(){ echo "[OK]   $1"; pass=$((pass + 1)); }
bad(){ echo "[FAIL] $1"; fail=$((fail + 1)); }
c_g(){ :; }
c_y(){ echo "$*" >&2; }

extract(){
  sed -n "/^$1(){/,/^}/p" "$ROOT/deploy/bot/pdg.sh"
}
for fn in _pdg_atomic_restore_file migrate_default_direct_tag; do
  body="$(extract "$fn")"
  [[ -n "$body" ]] || { echo "[FAIL] 无法抽取 $fn()" >&2; exit 1; }
  eval "$body"
done

REAL_PYTHON="${PDG_TEST_PYTHON:-$(command -v python3 2>/dev/null || true)}"
[[ -n "$REAL_PYTHON" ]] || { echo "[FAIL] 找不到 python3" >&2; exit 1; }
python3(){ "$REAL_PYTHON" "$@"; }

mkdir -p "$WORK/runtime"
cat >"$WORK/runtime/bot.py" <<'PY'
import json

DEFAULT_DIRECT_TAG = "JP"

def _direct_anchor_tag(c):
    tags = [o.get("tag") for o in c.get("outbounds", [])
            if o.get("type") == "direct" and o.get("tag")]
    return tags[0] if len(tags) == 1 else None

def _normalize_default_direct_tag(c):
    direct = [o for o in c.get("outbounds", []) if o.get("type") == "direct"]
    if len(direct) != 1 or direct[0].get("tag") != "jp":
        return False
    if any(o is not direct[0] and o.get("tag") == "JP"
           for o in c.get("outbounds", [])):
        raise ValueError("JP collision")
    direct[0]["tag"] = "JP"
    for outbound in c.get("outbounds", []):
        if outbound.get("type") == "urltest":
            outbound["outbounds"] = [
                "JP" if tag == "jp" else tag for tag in outbound.get("outbounds", [])]
    for rule in c.get("route", {}).get("rules", []):
        if rule.get("outbound") == "jp":
            rule["outbound"] = "JP"
    if c.get("route", {}).get("final") == "jp":
        c["route"]["final"] = "JP"
    return True

def _normalize_default_direct_meta(meta):
    changed = False
    for item in meta.values():
        if item.get("outbound") == "jp":
            item["outbound"] = "JP"
            changed = True
    return changed

def _model_bytes(c):
    return json.dumps(c, ensure_ascii=False, indent=2).encode()

def _mihomo_derive(staged):
    model = json.loads(staged["model"])
    assert any(o.get("type") == "direct" and o.get("tag") == "JP"
               for o in model["outbounds"])
    if "rs_meta" in staged:
        meta = json.loads(staged["rs_meta"])
        assert all(item.get("outbound") != "jp" for item in meta.values())
    return b"proxies: []\nrules:\n  - MATCH,DIRECT\n"
PY

_pdg_core_svc(){ echo mihomo; }
systemctl(){ return 0; }
mihomo(){ return 0; }
STABLE_CALLS=0
FAIL_STABLE_ONCE=0
_core_kernel_stable(){
  STABLE_CALLS=$((STABLE_CALLS + 1))
  if [[ "$FAIL_STABLE_ONCE" == 1 && "$STABLE_CALLS" == 1 ]]; then
    return 1
  fi
  return 0
}

PDG_SB_MODEL="$WORK/etc/sing-box/config.json"
PDG_MIHOMO_CFG="$WORK/etc/mihomo/config.yaml"
PDG_RS_META="$WORK/opt/pdg-bot/rulesets.json"
PDG_STATE_DIR="$WORK/state"
PDG_BOT_PY="$WORK/runtime/bot.py"
export PDG_SB_MODEL PDG_MIHOMO_CFG PDG_RS_META PDG_STATE_DIR PDG_BOT_PY

reset_tree(){
  rm -rf "$WORK/etc" "$WORK/opt" "$WORK/state"
  mkdir -p "$(dirname "$PDG_SB_MODEL")" "$(dirname "$PDG_MIHOMO_CFG")" \
           "$(dirname "$PDG_RS_META")" "$PDG_STATE_DIR"
  cat >"$PDG_SB_MODEL" <<'JSON'
{"outbounds":[
  {"type":"direct","tag":"jp"},
  {"type":"shadowsocks","tag":"hk"},
  {"type":"urltest","tag":"auto","outbounds":["jp","hk"]}
],"route":{"rules":[{"domain_suffix":["example.test"],"outbound":"jp"}],"final":"jp"}}
JSON
  printf '{"legacy":{"outbound":"jp"},"phone":{"outbound":"direct"}}\n' >"$PDG_RS_META"
  printf 'proxies: old\n' >"$PDG_MIHOMO_CFG"
  chmod 600 "$PDG_SB_MODEL" "$PDG_MIHOMO_CFG"
  chmod 644 "$PDG_RS_META"
}

reset_tree
if migrate_default_direct_tag; then
  if grep -q '"tag": "JP"' "$PDG_SB_MODEL" \
     && grep -q '"final": "JP"' "$PDG_SB_MODEL" \
     && grep -q '"outbound": "JP"' "$PDG_RS_META" \
     && ! grep -q '"outbound": "jp"' "$PDG_RS_META" \
     && grep -q 'MATCH,DIRECT' "$PDG_MIHOMO_CFG"; then
    ok "成功路径原子提交 model/meta/Mihomo 候选"
  else
    bad "成功路径存在未迁移引用"
  fi
  [[ "$(stat -c '%a' "$PDG_RS_META")" == 644 ]] \
    && ok "成功路径保留 metadata 权限" || bad "metadata 权限被改变"
else
  bad "成功路径返回非 0"
fi

reset_tree
sed -i 's/"jp"/"JP"/g' "$PDG_SB_MODEL"  # 模拟进程在 model 落盘后被中断，metadata 仍是旧引用。
if migrate_default_direct_tag; then
  if grep -q '"tag": "JP"' "$PDG_SB_MODEL" \
     && grep -q '"outbound": "JP"' "$PDG_RS_META" \
     && ! grep -q '"outbound": "jp"' "$PDG_RS_META"; then
    ok "再次迁移可收敛 model 已是 JP、metadata 仍是 jp 的中断现场"
  else
    bad "中断现场没有收敛为一致的 JP"
  fi
else
  bad "中断现场自愈返回非 0"
fi

reset_tree
before_model="$(sha256sum "$PDG_SB_MODEL" | awk '{print $1}')"
before_meta="$(sha256sum "$PDG_RS_META" | awk '{print $1}')"
before_mihomo="$(sha256sum "$PDG_MIHOMO_CFG" | awk '{print $1}')"
STABLE_CALLS=0
FAIL_STABLE_ONCE=1
if migrate_default_direct_tag >/dev/null 2>&1; then
  bad "稳定门失败却返回成功"
else
  after_model="$(sha256sum "$PDG_SB_MODEL" | awk '{print $1}')"
  after_meta="$(sha256sum "$PDG_RS_META" | awk '{print $1}')"
  after_mihomo="$(sha256sum "$PDG_MIHOMO_CFG" | awk '{print $1}')"
  if [[ "$before_model" == "$after_model" && "$before_meta" == "$after_meta" \
        && "$before_mihomo" == "$after_mihomo" ]]; then
    ok "Mihomo 稳定门失败时三文件完整回滚"
  else
    bad "稳定门失败后 before-image 未完整恢复"
  fi
fi

echo "通过 $pass，失败 $fail"
(( pass >= 4 && fail == 0 ))

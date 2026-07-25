#!/usr/bin/env bash
# shellcheck shell=bash
# ─────────────────────────────────────────────────────────────────────────────
# sing-box 归属判定 —— install.sh / uninstall.sh / pdg 三处共用的单一事实源。
#
# v1.6 起本项目不再安装 sing-box, 但老机器上可能还有一份, 而迁移与卸载都要去删它的 unit、
# 二进制乃至 /etc/sing-box。问题是: 机器上那份**未必是我们装的** —— 用户完全可能自己手工
# 装一个跑别的东西, 而手工安装最常见的写法恰恰就是
#     ExecStart=/usr/local/bin/sing-box run -c /etc/sing-box/config.json
# 与本项目历史模板逐字一致。只凭这一条认亲, 等于把别人的东西当自家的删掉, 不可逆。
#
# 故判据收紧为(满足其一):
#   ① **可信归属标记**: /etc/privdns-gateway/singbox.pdg-owned 且首行是约定 token
#      (空文件/乱写不算 —— 否则任何人 touch 一下就能骗过);
#   ② **完整匹配**历史 PDG unit 形态(v1.4.2 起逐字未变), **并且**现场另有本项目特征:
#      /etc/sing-box/config.json 确实是我们的数据模型(特征入站 in-https + in-http + tg-proxy
#      齐全), 且存在 backend 标记(说明这台机器确实装过本项目)。
# 两条都不成立 = 证明不了 → 一律保留 unit、二进制与**整个 /etc/sing-box**, 只提示, 绝不代
# 用户决定。
#
# PDG_ROOT_PREFIX: 仅供测试把判定重定向到沙箱根; 生产恒为空。
# ─────────────────────────────────────────────────────────────────────────────

PDG_SINGBOX_OWNED_TOKEN="PDG-SINGBOX-OWNED v1"

pdg_singbox_paths(){   # 回显本函数族用到的路径(带测试前缀)
  local p="${PDG_ROOT_PREFIX:-}"
  echo "$p/etc/systemd/system/sing-box.service|$p/usr/local/bin/sing-box|$p/etc/sing-box|$p/etc/privdns-gateway"
}

# 历史上本项目生成的 sing-box unit(v1.4.2 起逐字未变: 早期 install.sh 内联, v1.5.8+ 由
# lib/units.sh 的 pdg_unit_singbox 生成 —— 两者内容相同)。用于"完整匹配"判据。
pdg_singbox_canonical_unit(){ cat <<'EOF'
[Unit]
Description=sing-box
After=network-online.target
Wants=network-online.target
[Service]
ExecStart=/usr/local/bin/sing-box run -c /etc/sing-box/config.json
Restart=on-failure
RestartSec=3
LimitNOFILE=1048576
[Install]
WantedBy=multi-user.target
EOF
}

# 归一化 unit 文本以便比对: 去掉空行与行首尾空白(用户可能重排过空行, 但不该改内容)
_pdg_unit_norm(){ sed -e 's/[[:space:]]*$//' -e 's/^[[:space:]]*//' -e '/^$/d' "$1" 2>/dev/null; }

# config.json 是不是**本项目的数据模型**(而非第三方自己的配置)。
# 判据: 三个特征入站 tag 同时存在 —— 它们由本项目模板生成, 第三方配置不会恰好都有。
# shellcheck disable=SC2120  # $1 可选(默认取 PDG_ROOT_PREFIX 下的标准路径)
pdg_singbox_config_is_ours(){
  local f="${1:-${PDG_ROOT_PREFIX:-}/etc/sing-box/config.json}"
  [[ -f "$f" ]] || return 1
  python3 - "$f" <<'PY' 2>/dev/null
import json, sys
try:
    c = json.load(open(sys.argv[1], encoding="utf-8"))
except Exception:
    sys.exit(1)
tags = {i.get("tag") for i in (c.get("inbounds") or []) if isinstance(i, dict)}
sys.exit(0 if {"in-https", "in-http", "tg-proxy"} <= tags else 1)
PY
}

# 归属标记是否可信(存在且首行是约定 token)
pdg_singbox_marker_ok(){
  local m="${PDG_ROOT_PREFIX:-}/etc/privdns-gateway/singbox.pdg-owned"
  [[ -f "$m" ]] || return 1
  [[ "$(head -1 "$m" 2>/dev/null)" == "$PDG_SINGBOX_OWNED_TOKEN" ]]
}

# 机器上的 sing-box 是不是本项目装的。证明不了一律返回非 0(保守: 保留)。
pdg_singbox_is_ours(){
  local pfx="${PDG_ROOT_PREFIX:-}"
  local unit="${1:-$pfx/etc/systemd/system/sing-box.service}"
  pdg_singbox_marker_ok && return 0
  [[ -f "$unit" ]] || return 1
  # 完整形态匹配(归一化后逐字比对), 而不是抓某一行
  [[ "$(_pdg_unit_norm "$unit")" == "$(pdg_singbox_canonical_unit | sed -e 's/[[:space:]]*$//' -e '/^$/d')" ]] || return 1
  # 还要有本项目其它特征: 数据模型是我们的 + 这台机器确实装过本项目
  pdg_singbox_config_is_ours || return 1
  [[ -f "$pfx/etc/privdns-gateway/backend" ]] || return 1
  return 0
}

# 确认归属后**落一份可信标记**再动手: 中途崩了下次也还认得出是自家的, 不至于退化成"证明不了"。
pdg_singbox_mark_owned(){
  local pfx="${PDG_ROOT_PREFIX:-}" d="${PDG_ROOT_PREFIX:-}/etc/privdns-gateway"
  [[ -d "$d" ]] || install -d -m700 "$d" 2>/dev/null || return 1
  printf '%s\ncreated=%s\n' "$PDG_SINGBOX_OWNED_TOKEN" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    > "$pfx/etc/privdns-gateway/singbox.pdg-owned" 2>/dev/null
}

#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# systemd unit 单一事实源。install.sh(装机)与 pdg 的 sing-box→mihomo 迁移都从这里
# 生成内核 / pdg-mitm 的 unit, 杜绝两处手写漂移 —— 历史坑: 换核时生成的
# mihomo.service 漏了 Environment=SAFE_PATHS, 与装机版不一致。
#
# 各函数把 unit 内容打到 stdout, 由调用方重定向落盘, 例:
#   pdg_unit_mihomo > /etc/systemd/system/mihomo.service
# 或用 pdg_write_unit 一步写入并 chmod 644。
# ─────────────────────────────────────────────────────────────────────────────

pdg_unit_mihomo(){ cat <<'EOF'
[Unit]
Description=mihomo (PrivDNS Gateway core)
After=network-online.target mosdns.service
Wants=network-online.target
[Service]
ExecStart=/usr/local/bin/mihomo -d /etc/mihomo -f /etc/mihomo/config.yaml
Environment=SAFE_PATHS=/etc/sing-box/ui/dist
Restart=on-failure
RestartSec=3
LimitNOFILE=1048576
[Install]
WantedBy=multi-user.target
EOF
}

pdg_unit_pdg_mitm(){ cat <<'EOF'
[Unit]
Description=pdg-mitm (PrivDNS Gateway MITM plugins)
After=network-online.target
Wants=network-online.target
[Service]
ExecStart=/usr/bin/python3 /opt/pdg-bot/mitm_server.py 7894
Restart=on-failure
RestartSec=3
[Install]
WantedBy=multi-user.target
EOF
}

# 内核 svc 名 → 对应 unit 生成函数(mihomo 为唯一内核; 保留此壳以便将来扩展/调用方不改)。
pdg_unit_for_core_svc(){
  case "$1" in
    mihomo)   pdg_unit_mihomo ;;
    *) return 1 ;;
  esac
}

# 写入 unit 并置 644(幂等)。$1=生成函数名 $2=目标路径。
#
# 必须原子: 先渲染到同目录临时文件, 确认生成函数成功**且产出非空**, 再 mv 落位。
# 旧写法 `"$fn" > "$path"` 会让 shell **先把目标截断**再去解析命令 —— 生成函数不存在
# (跨版本回滚: 旧 updater 调新版 units.sh 里已删除的 pdg_unit_singbox)时, 目标就成了
# 0 字节, 而调用方还可能照报成功。宁可不写, 也不能把现成的 unit 毁掉。
pdg_write_unit(){
  local fn="$1" path="$2" tmp
  command -v "$fn" >/dev/null 2>&1 || {
    echo "pdg_write_unit: 生成函数 $fn 不存在, 拒绝写 $path(保留原文件)" >&2; return 1; }
  tmp="$(mktemp "$(dirname "$path")/.pdg-unit.XXXXXX")" || return 1
  if ! "$fn" > "$tmp" 2>/dev/null || [[ ! -s "$tmp" ]]; then
    rm -f "$tmp"
    echo "pdg_write_unit: $fn 生成失败或产出为空, 拒绝写 $path(保留原文件)" >&2; return 1
  fi
  chmod 644 "$tmp" && mv -f "$tmp" "$path" || { rm -f "$tmp"; return 1; }
}

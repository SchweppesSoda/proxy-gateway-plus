#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# 端到端: 迁移不得动**不属于本项目**的防火墙配置(P0)。
#
# 现场: migrate_firewall_to_pdg() 认出自定义防火墙会主动跳过(好的), 但紧随其后的
# _switchcore_nft() 直接 `渲染模板 > /etc/nftables.conf` —— **整文件覆盖**。于是用户的
# 额外 table、VPN/NAT/转发规则、自定义开放端口全被抹掉, 而且是在"迁移成功"的提示之下。
#
# 本项目只该管自己的 `table inet pdg`。这里造一份带真实自定义内容的 nftables.conf,
# 跑完整迁移后逐字节比对: 项目管理区之外的内容必须原样不动。
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
printf 'android\n' > /etc/privdns-gateway/platform
printf 'singbox\n' > /etc/privdns-gateway/backend
. "$E2E_ROOT/lib/versions.sh"
printf '#!/bin/sh\ncase "$1" in -v|version) echo "Mihomo Meta %s linux amd64";; -t) exit 0;; esac\nexit 0\n' \
  "$MIHOMO_VER" > /usr/local/bin/mihomo; chmod 755 /usr/local/bin/mihomo
# 老版装机形态的 sing-box(让归属判定认得出是本项目的, 迁移才会走完整路径)
printf '#!/bin/sh\nexit 0\n' > /usr/local/bin/sing-box; chmod 755 /usr/local/bin/sing-box
cat > /etc/systemd/system/sing-box.service <<'U'
[Unit]
Description=sing-box
[Service]
ExecStart=/usr/local/bin/sing-box run -c /etc/sing-box/config.json
U

# ── 造一份"本项目的 pdg 表 + 用户自定义内容"共存的 nftables.conf ────────────
cat > /etc/nftables.conf <<'NFT'
#!/usr/sbin/nft -f
# ==== 用户自己的东西(本项目不该碰) ====
table inet myfilter {
    chain input {
        type filter hook input priority 0; policy drop;
        iif "lo" accept
        ct state established,related accept
        tcp dport { 9443, 9444 } accept      # 自定义开放端口(用户的业务)
        udp dport 51820 accept               # WireGuard VPN
    }
    chain forward {
        type filter hook forward priority 0; policy accept;
        iifname "wg0" oifname "eth0" accept  # VPN 转发
        oifname "wg0" iifname "eth0" ct state established,related accept
    }
}

table ip mynat {
    chain postrouting {
        type nat hook postrouting priority srcnat; policy accept;
        ip saddr 10.66.0.0/24 oifname "eth0" masquerade   # VPN 出网 NAT
    }
}

# ==== 以下是 PrivDNS Gateway 管理区 ====
table inet pdg
delete table inet pdg

table inet pdg {
    chain input {
        type filter hook input priority 0; policy drop;
        iif "lo" accept
        ct state established,related accept
        tcp dport { 22 } accept
        ip saddr 127.0.0.0/8 tcp dport { 53, 80, 81, 443, 853, 8445 } accept
    }
}
NFT
# 取"项目管理区之前"的全部内容; 迁移后必须逐字节一致(前后用同一表达式, 才是同一段)
CUSTOM_BEFORE="$(awk '/table inet pdg/{exit} {print}' /etc/nftables.conf)"
CUSTOM_SHA="$(printf '%s' "$CUSTOM_BEFORE" | sha256sum | cut -d' ' -f1)"
[[ -n "$CUSTOM_BEFORE" ]] && ok "现场就位: nftables.conf 含自定义 table/VPN/NAT/转发/开放端口" || bad "fixture 没造对"

# ── 跑真实迁移 ──────────────────────────────────────────────────────────────
echo; echo "── 跑 pdg __migrate(含 sing-box→mihomo 迁移, 会重渲染 nft) ──"
out=$(bash /usr/local/bin/pdg __migrate 2>&1); rc=$?
[[ "$rc" == 0 ]] && ok "迁移成功(rc=0)" || bad "迁移失败 rc=$rc: $(tail -5 <<<"$out")"

# ── 核心断言: 自定义内容逐字节未变 ──────────────────────────────────────────
echo; echo "── 迁移后 ──"
CUSTOM_AFTER="$(awk '/table inet pdg/{exit} {print}' /etc/nftables.conf)"
for probe in 'table inet myfilter' 'table ip mynat' '9443, 9444' '51820' 'wg0' 'masquerade' '10.66.0.0/24'; do
  grep -qF "$probe" /etc/nftables.conf \
    && ok "自定义内容保留: $probe" || bad "自定义内容被抹掉: $probe"
done
[[ "$(printf '%s' "$CUSTOM_AFTER" | sha256sum | cut -d' ' -f1)" == "$CUSTOM_SHA" ]] \
  && ok "项目管理区之外的内容逐字节未变" \
  || { bad "自定义区被改写了"; diff <(printf '%s\n' "$CUSTOM_BEFORE") <(printf '%s\n' "$CUSTOM_AFTER") | head -10; }

# ── 项目管理区确实被更新成了 mihomo 形态(保护不能把迁移变成空操作) ──────────
grep -q 'redirect to :7893' /etc/nftables.conf \
  && ok "项目管理区已换成 mihomo REDIRECT 入站(迁移真做了事)" || bad "pdg 区没更新成 mihomo 形态"
[[ "$(grep -c '^table inet pdg {' /etc/nftables.conf)" == 1 ]] \
  && ok "pdg 表只有一份(没有重复拼接)" || bad "pdg 表重复了 $(grep -c '^table inet pdg {' /etc/nftables.conf) 份"
grep -q 'tcp dport { 22 } accept' /etc/nftables.conf \
  && ok "SSH 端口仍放行(没把自己锁在门外)" || bad "SSH 放行没了"

e2e_summary

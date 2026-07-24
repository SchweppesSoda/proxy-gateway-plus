#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# 真功能测试(非静态): 真起 mihomo, 验证本项目的核心链路 ——
#   「单入口 + 按 TLS SNI 把流量分到不同出口」。
#
# 做法(全本地、可在 CI / 干净机跑, 仅需 python3 + 官方 mihomo):
#   1) 起 3 个本地 mock SOCKS5 当"出口", 各自记录收到的目标域名;
#   2) 用 redir 入口(开 sniffer + override-destination, 与生产同款)起 mihomo,
#      按域名规则分到出口 A/B、其余走 MATCH 兜底;
#   3) 按不同 SNI 发 TLS ClientHello 到入口, 断言每个 SNI 被嗅探并路由到正确出口。
#
# 生产上 80/443/5228-5230 由 nft REDIRECT 进这个 redir 端口(见 deploy/firewall/nftables-mihomo.conf);
# 测试里直接连该端口即可 —— sniffer 的 override-destination 会用嗅到的 SNI 顶掉原目的地,
# 正是生产中"手机连过来 → 嗅 SNI → 按域名选出口"那条路。
#
# 退出码 0 = 通过; 非 0 = 失败(并打印 mihomo 输出便于排查)。
# ─────────────────────────────────────────────────────────────────────────────
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
# shellcheck source=lib/versions.sh
source "$ROOT/lib/versions.sh"

WORK="$(mktemp -d)"
PIDS=()
cleanup(){ for p in "${PIDS[@]:-}"; do kill "$p" 2>/dev/null; done; rm -rf "$WORK"; }
trap cleanup EXIT
fail(){ echo "[FAIL] $*" >&2; exit 1; }
note(){ echo "[*] $*"; }

case "$(uname -m)" in
  x86_64) ARCH=amd64 ;; aarch64|arm64) ARCH=arm64 ;;
  *) fail "不支持的架构: $(uname -m)" ;;
esac

# ── 1. 取 mihomo(优先用 PATH 里的钉死版; 否则按钉死 SHA256 下载)──
if command -v mihomo >/dev/null && mihomo -v 2>/dev/null | grep -q "$MIHOMO_VER"; then
  MH="$(command -v mihomo)"; note "用现有 mihomo: $MH ($(mihomo -v 2>/dev/null | head -1))"
else
  note "下载 mihomo $MIHOMO_VER ($ARCH)…"
  curl -fsSL "https://github.com/MetaCubeX/mihomo/releases/download/${MIHOMO_VER}/mihomo-linux-${ARCH}-${MIHOMO_VER}.gz" \
       -o "$WORK/m.gz" || fail "mihomo 下载失败"
  pdg_verify_sha256 "$WORK/m.gz" "${PDG_SHA256[mihomo-$ARCH]:-}" "mihomo $MIHOMO_VER ($ARCH)" \
    || fail "mihomo SHA256 校验失败"
  gunzip -c "$WORK/m.gz" > "$WORK/mihomo" || fail "mihomo 解压失败"
  chmod 755 "$WORK/mihomo"; MH="$WORK/mihomo"
fi

# ── 2. 起 3 个 mock SOCKS5 出口 ──
LOGA="$WORK/a.log"; LOGB="$WORK/b.log"; LOGD="$WORK/d.log"
: > "$LOGA"; : > "$LOGB"; : > "$LOGD"
python3 "$HERE/mock_socks.py" 11080 "$LOGA" & PIDS+=($!)
python3 "$HERE/mock_socks.py" 11081 "$LOGB" & PIDS+=($!)
python3 "$HERE/mock_socks.py" 11082 "$LOGD" & PIDS+=($!)

# ── 3. 写 mihomo 测试配置: redir 入口 + sniffer 覆盖目的地, 按域名分流, 其余走 MATCH ──
# (JSON 即合法 YAML —— 与生产渲染出的 /etc/mihomo/config.yaml 同一形态)
cat > "$WORK/cfg.yaml" <<'JSON'
{
  "log-level": "warning",
  "redir-port": 18443,
  "sniffer": {
    "enable": true,
    "override-destination": true,
    "sniff": { "TLS": { "ports": [443, 5228, 18443] } }
  },
  "proxies": [
    { "name": "exitA",       "type": "socks5", "server": "127.0.0.1", "port": 11080 },
    { "name": "exitB",       "type": "socks5", "server": "127.0.0.1", "port": 11081 },
    { "name": "exitDefault", "type": "socks5", "server": "127.0.0.1", "port": 11082 }
  ],
  "rules": [
    "DOMAIN-SUFFIX,alpha.test,exitA",
    "DOMAIN-SUFFIX,beta.test,exitB",
    "DOMAIN-SUFFIX,mtalk.google.com,exitB",
    "MATCH,exitDefault"
  ]
}
JSON

"$MH" -t -d "$WORK" -f "$WORK/cfg.yaml" || fail "mihomo -t 未通过(配置无效)"
"$MH" -d "$WORK" -f "$WORK/cfg.yaml" > "$WORK/mh.out" 2>&1 & PIDS+=($!)

# 等入口端口就绪
ready=0
for _ in $(seq 1 50); do
  if python3 -c 'import socket,sys; s=socket.socket(); s.settimeout(.2); sys.exit(0 if s.connect_ex(("127.0.0.1",18443))==0 else 1)'; then ready=1; break; fi
  sleep 0.1
done
[[ "$ready" == 1 ]] || { cat "$WORK/mh.out" >&2; fail "mihomo 入口 :18443 未就绪"; }

# ── 4. 各 SNI 断言落到正确出口(只比对 host, 端口随入口口子) ──
check_case(){  # $1=SNI $2=期望日志文件 $3=出口名
  local sni="$1" log="$2" name="$3"
  python3 "$HERE/sni_client.py" 127.0.0.1 18443 "$sni"
  for _ in $(seq 1 30); do grep -q "^${sni}:" "$log" 2>/dev/null && { note "  $sni → $name ✓"; return 0; }; sleep 0.1; done
  echo "---- mihomo 输出 ----" >&2; cat "$WORK/mh.out" >&2
  fail "SNI=$sni 未按预期到达 $name (A='$(tr '\n' ' ' <"$LOGA")' B='$(tr '\n' ' ' <"$LOGB")' D='$(tr '\n' ' ' <"$LOGD")')"
}

note "用例: 按 SNI 分流"
check_case alpha.test "$LOGA" "exitA(域名规则)"
check_case beta.test  "$LOGB" "exitB(域名规则)"
check_case gamma.test "$LOGD" "exitDefault(MATCH 兜底)"

note "用例: GMS 推送(mtalk 经嗅探按域名分流; 生产中 5228-5230 由 nft REDIRECT 进同一入口)"
check_case mtalk.google.com "$LOGB" "exitB(GMS 域名规则)"

# 反向断言: 命中规则的 SNI 不应串到别的出口
grep -q alpha.test "$LOGB" "$LOGD" 2>/dev/null && fail "alpha.test 串到了错误出口"
grep -q beta.test  "$LOGA" "$LOGD" 2>/dev/null && fail "beta.test 串到了错误出口"
grep -q mtalk.google.com "$LOGA" "$LOGD" 2>/dev/null && fail "mtalk.google.com 串到了错误出口"

echo
echo "✅ 功能测试通过: TLS SNI 嗅探 + 按域名多出口分流 + MATCH 兜底 + GMS 域名分流 均正确。"

#!/usr/bin/env bash
# End-to-end managed configuration import in a disposable root namespace.
# Real Mihomo/MosDNS validate candidates; all production paths live on overlayfs.
set -uo pipefail
E2E_ROOT="${E2E_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
# shellcheck source=tests/e2e-lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/e2e-lib.sh"
e2e_enter "$@"

# shellcheck source=lib/versions.sh
source "$E2E_ROOT/lib/versions.sh"
IMPORT_TMP_ROOT="$(cd "${TMPDIR:-/tmp}" 2>/dev/null && pwd -P)" \
  || { bad "无法解析 E2E 临时目录"; e2e_summary; exit 1; }
IMPORT_BIN_WORK="$(mktemp -d "$IMPORT_TMP_ROOT/pdg-config-import.XXXXXX")" \
  || { bad "无法创建 config-import E2E 临时目录"; e2e_summary; exit 1; }
case "$IMPORT_BIN_WORK" in
  "$IMPORT_TMP_ROOT"/pdg-config-import.*)
    [[ -d "$IMPORT_BIN_WORK" ]] \
      || { bad "config-import E2E 临时目录未创建"; e2e_summary; exit 1; }
    ;;
  *) bad "config-import E2E 临时目录形态不可信"; e2e_summary; exit 1 ;;
esac
config_import_bin_cleanup(){
  # 递归删除前再次证明目标非空、确实是本测试在指定临时根下创建的目录。
  case "${IMPORT_BIN_WORK:-}" in
    "$IMPORT_TMP_ROOT"/pdg-config-import.*)
      [[ -d "$IMPORT_BIN_WORK" ]] || return 0
      rm -rf -- "$IMPORT_BIN_WORK"
      ;;
    *) echo "[FAIL] 拒绝清理不可信的 config-import 临时路径" >&2; return 1 ;;
  esac
}
e2e_add_exit_hook config_import_bin_cleanup

e2e_stub_system
e2e_seed_install
e2e_seed_mosdns all
e2e_seed_singbox_model
e2e_seed_cert || { bad "无法建立 MosDNS E2E 证书夹具"; e2e_summary; exit 1; }
printf 'mihomo\n' > /etc/privdns-gateway/backend
printf 'android\n' > /etc/privdns-gateway/platform

mkdir -p /opt/pdg-web /etc/mihomo/providers \
  /var/lib/privdns-gateway/web-imports /var/lib/privdns-gateway/web-jobs
install -m755 "$E2E_ROOT/deploy/bot/pdgmodel.py" /opt/pdg-bot/pdgmodel.py
install -m755 "$E2E_ROOT/deploy/web/pdgconfigio.py" /opt/pdg-web/pdgconfigio.py
install -m755 "$E2E_ROOT/deploy/web/pdg-web-job.py" /opt/pdg-web/pdg-web-job.py
chmod 700 /etc/mihomo/providers /var/lib/privdns-gateway/web-imports \
  /var/lib/privdns-gateway/web-jobs
rm -rf /var/lib/privdns-gateway/tx

# Never trust binaries left by another E2E (or the size-only e2e fetch helper).
# Download both exact release artifacts and verify the repository-pinned SHA256
# before installing them into the disposable namespace.
case "$(uname -m)" in
  x86_64) IMPORT_ARCH=amd64 ;;
  aarch64|arm64) IMPORT_ARCH=arm64 ;;
  *) bad "不支持的 E2E 架构: $(uname -m)"; e2e_summary; exit 1 ;;
esac

if ! curl -fsSL --retry 2 -m 120 \
  "https://github.com/MetaCubeX/mihomo/releases/download/${MIHOMO_VER}/mihomo-linux-${IMPORT_ARCH}-${MIHOMO_VER}.gz" \
  -o "$IMPORT_BIN_WORK/mihomo.gz" \
  || ! pdg_verify_sha256 "$IMPORT_BIN_WORK/mihomo.gz" \
       "${PDG_SHA256[mihomo-$IMPORT_ARCH]:-}" "Mihomo config-import E2E" \
  || ! gunzip -c "$IMPORT_BIN_WORK/mihomo.gz" > "$IMPORT_BIN_WORK/mihomo" \
  || ! install -m755 "$IMPORT_BIN_WORK/mihomo" /usr/local/bin/mihomo \
  || ! pdg_mihomo_is_version "$MIHOMO_VER" \
  || ! e2e_mihomo_is_real; then
  bad "Mihomo 下载、SHA256、精确版本或正反配置能力校验失败"
  e2e_summary
  exit 1
fi

# The official stock MosDNS release is used only for configuration ABI and
# isolated-start validation.  Production uses the separately tested patched
# no-ticket build.  Remove the seed fixture's attestation because its bytes no
# longer describe the stock binary and must never make this E2E look like a
# production flavor/provenance test.
rm -f /etc/privdns-gateway/mosdns-build.env
if [[ -e /etc/privdns-gateway/mosdns-build.env ]]; then
  bad "stock MosDNS ABI 测试仍残留 production attestation"
  e2e_summary
  exit 1
fi

if ! curl -fsSL --retry 2 -m 120 \
  "https://github.com/IrineSistiana/mosdns/releases/download/${MOSDNS_VER}/mosdns-linux-${IMPORT_ARCH}.zip" \
  -o "$IMPORT_BIN_WORK/mosdns.zip" \
  || ! pdg_verify_sha256 "$IMPORT_BIN_WORK/mosdns.zip" \
       "${PDG_SHA256[mosdns-$IMPORT_ARCH]:-}" "MosDNS config-import E2E" \
  || ! unzip -qo "$IMPORT_BIN_WORK/mosdns.zip" mosdns -d "$IMPORT_BIN_WORK" \
  || ! install -m755 "$IMPORT_BIN_WORK/mosdns" /usr/local/bin/mosdns \
  || ! pdg_mosdns_is_version "$MOSDNS_VER"; then
  bad "MosDNS 下载、SHA256 或精确版本校验失败"
  e2e_summary
  exit 1
fi

export PDG_STABLE_SAMPLES=1
export PDG_TX_MOSDNS_PROBE_MODE=port
export PDG_TX_MOSDNS_PROBE_SECS=0.5
export PDG_IMPORT_STAGING_DIR=/var/lib/privdns-gateway/web-imports
export PDG_WEB_JOB_STATE_DIR=/var/lib/privdns-gateway/web-jobs
export PDG_CONFIG_IO_RUNNER=/opt/pdg-web/pdgconfigio.py
export PDG_E2E_STOCK_MOSDNS_ABI_ONLY=1

if python3 "$E2E_ROOT/tests/e2e-config-import.py"; then
  ok "普通/归档/PDG v3/MosDNS 导入均经过真实事务，CAS/回滚/JobStore 恢复清理均通过"
else
  bad "配置导入真实 apply E2E 失败"
fi

if mihomo -t -d /etc/mihomo -f /etc/mihomo/config.yaml \
  >"$IMPORT_BIN_WORK/final-mihomo.log" 2>&1; then
  ok "最终派生 Mihomo 配置通过真实 mihomo -t"
else
  bad "最终 Mihomo 配置无效: $(tail -n 3 "$IMPORT_BIN_WORK/final-mihomo.log" | tr '\n' ' ')"
fi

e2e_summary

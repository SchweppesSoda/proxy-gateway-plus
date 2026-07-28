#!/usr/bin/env bash
# MosDNS no-ticket patch/build/artifact supply-chain contract.
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT
pass=0; nfail=0
ok(){ echo "[OK]   $1"; pass=$((pass+1)); }
bad(){ echo "[FAIL] $1"; nfail=$((nfail+1)); }

# shellcheck source=lib/versions.sh
source "$ROOT/lib/versions.sh"
# shellcheck source=lib/mosdns-artifact.sh
source "$ROOT/lib/mosdns-artifact.sh"

PATCH="$ROOT/$MOSDNS_PATCH_FILE"
pdg_verify_sha256 "$PATCH" "${PDG_SHA256[mosdns-patch]}" "MosDNS patch" \
  && grep -Fq 'SessionTicketsDisabled: true' "$PATCH" \
  && ok "patch 内容与仓库钉死 SHA256 一致" || bad "patch 缺失/哈希不符"
[[ "$MOSDNS_UPSTREAM_COMMIT" == b7323188bab1ea742538aeccb31b692bc4967d1b \
   && "$MOSDNS_GO_VERSION" == 1.24.9 \
   && "$MOSDNS_BUILD_VERSION" == v5.3.4-pdg-notickets.1 ]] \
  && ok "官方 commit、Go 与 flavor marker 均精确 pin" || bad "provenance pin 漂移"

cat >"$WORK/stock" <<'EOF'
#!/bin/sh
[ "$1" = version ] && echo v5.3.4
EOF
chmod 755 "$WORK/stock"
pdg_mosdns_binary_is_target "$WORK/stock" \
  && bad "stock v5.3.4 被目标 flavor 接受" || ok "stock v5.3.4 必然被拒绝"

cat >"$WORK/patched" <<EOF
#!/bin/sh
[ "\$1" = version ] && echo "$MOSDNS_BUILD_VERSION"
EOF
chmod 755 "$WORK/patched"
RAW_SHA="$(sha256sum "$WORK/patched" | awk '{print $1}')"
REPO_PIN="${PDG_SHA256[mosdns-pdg-amd64]}"
mkdir "$WORK/candidate"
export PDG_MOSDNS_ARTIFACT="$WORK/patched"
export PDG_MOSDNS_ARTIFACT_SHA256="$RAW_SHA"
unset PDG_MOSDNS_BINARY_SHA256
PDG_SHA256[mosdns-pdg-amd64]="$RAW_SHA"
pdg_prepare_mosdns_candidate amd64 "$WORK/candidate" \
  && [[ "$(_pdg_mosdns_sha256 "$PDG_MOSDNS_PREPARED_BIN")" == "$RAW_SHA" ]] \
  && [[ "$PDG_MOSDNS_PREPARED_CHANNEL" == local ]] \
  && ok "本地 raw 产物须显式 hash，候选字节/marker 双校验" \
  || bad "合法本地产物未通过"

rm -rf "$WORK/candidate"; mkdir "$WORK/candidate"
PDG_SHA256[mosdns-pdg-amd64]="$REPO_PIN"
pdg_prepare_mosdns_candidate amd64 "$WORK/candidate" >/dev/null 2>&1 \
  && bad "调用方自报 hash 未匹配仓库 pin 仍被接受" \
  || ok "本地自报 hash 必须同时匹配仓库架构 pin"

rm -rf "$WORK/candidate"; mkdir "$WORK/candidate"
PDG_MOSDNS_ARTIFACT_SHA256="0000000000000000000000000000000000000000000000000000000000000000"
pdg_prepare_mosdns_candidate amd64 "$WORK/candidate" >/dev/null 2>&1 \
  && bad "错误 raw SHA256 仍被接受" || ok "错误 raw SHA256 fail closed"

rm -rf "$WORK/candidate"; mkdir "$WORK/candidate"
unset PDG_MOSDNS_ARTIFACT PDG_MOSDNS_ARTIFACT_SHA256
pdg_prepare_mosdns_candidate amd64 "$WORK/candidate" >/dev/null 2>&1 \
  && bad "无自有 release asset 时回退下载 stock" \
  || ok "无 release asset/本地产物时 fail closed，不回退 stock"

grep -Fq -- '-buildvcs=false' "$ROOT/tools/build-mosdns-patched.sh" \
  && grep -Fq -- '-buildid=' "$ROOT/tools/build-mosdns-patched.sh" \
  && grep -Fq 'go mod verify' "$ROOT/tools/build-mosdns-patched.sh" \
  && grep -Fq 'diff -ru' "$ROOT/.github/workflows/build-mosdns-patched.yml" \
  && ok "构建脚本锁定输入，Actions 双构建逐字节复现" \
  || bad "可复现构建/Actions 契约不完整"

! grep -Fq 'IrineSistiana/mosdns/releases/download' "$ROOT/install.sh" \
  && grep -Fq 'pdg_mosdns_is_project_build' "$ROOT/install.sh" \
  && grep -Fq 'usr/local/bin/mosdns' "$ROOT/deploy/bot/pdg.sh" \
  && ok "installer 不再取 stock，update snapshot 覆盖 MosDNS 二进制" \
  || bad "installer/update 仍有来源或回滚缺口"

echo "────────────────────────────────────────"
echo "通过 $pass, 失败 $nfail"
[[ "$nfail" == 0 ]]

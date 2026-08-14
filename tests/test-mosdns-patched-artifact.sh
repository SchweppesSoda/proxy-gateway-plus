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

EXPECTED_RELEASE_BASE="https://github.com/SchweppesSoda/proxy-gateway-plus/releases/download/v1.11.1"
AMD64_ASSET="mosdns-v5.3.4-pdg-notickets.1-linux-amd64"
ARM64_ASSET="mosdns-v5.3.4-pdg-notickets.1-linux-arm64"
[[ "$MOSDNS_PDG_ASSET_BASE_URL" == "$EXPECTED_RELEASE_BASE" \
   && "$(pdg_mosdns_asset_name amd64)" == "$AMD64_ASSET" \
   && "$(pdg_mosdns_asset_name arm64)" == "$ARM64_ASSET" \
   && $(grep -Fc 'ASSET="mosdns-${MOSDNS_VER}-${MOSDNS_PATCH_REV}-linux-${ARCH}"' \
        "$ROOT/tools/build-mosdns-patched.sh") == 1 ]] \
  && ok "v1.11.1 Release 目录、helper 与构建产物名精确一致" \
  || bad "Release 目录或 MosDNS asset 命名漂移"

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

unset PDG_MOSDNS_ARTIFACT PDG_MOSDNS_ARTIFACT_SHA256
cat >"$WORK/patched-arm64" <<EOF
#!/bin/sh
# distinct arm64 fixture bytes
[ "\$1" = version ] && echo "$MOSDNS_BUILD_VERSION"
EOF
chmod 755 "$WORK/patched-arm64"
AMD64_FIXTURE_SHA="$RAW_SHA"
ARM64_FIXTURE_SHA="$(sha256sum "$WORK/patched-arm64" | awk '{print $1}')"
ARM64_REPO_PIN="${PDG_SHA256[mosdns-pdg-arm64]}"
PDG_SHA256[mosdns-pdg-amd64]="$AMD64_FIXTURE_SHA"
PDG_SHA256[mosdns-pdg-arm64]="$ARM64_FIXTURE_SHA"
export PDG_TEST_RELEASE_BASE="$EXPECTED_RELEASE_BASE"
export PDG_TEST_AMD64_SOURCE="$WORK/patched"
export PDG_TEST_ARM64_SOURCE="$WORK/patched-arm64"
export PDG_TEST_CURL_LOG="$WORK/curl.urls"
: >"$PDG_TEST_CURL_LOG"
curl(){
  local src=""
  [[ "$#" == 4 && "$1" == -fsSL && "$3" == -o ]] || return 90
  printf '%s\n' "$2" >>"$PDG_TEST_CURL_LOG"
  case "$2" in
    "$PDG_TEST_RELEASE_BASE/$AMD64_ASSET") src="$PDG_TEST_AMD64_SOURCE";;
    "$PDG_TEST_RELEASE_BASE/$ARM64_ASSET") src="$PDG_TEST_ARM64_SOURCE";;
    *) return 91;;
  esac
  cp -- "$src" "$4"
}

mkdir "$WORK/release-amd64" "$WORK/release-arm64"
release_ok=1
pdg_prepare_mosdns_candidate amd64 "$WORK/release-amd64" \
  && [[ "$PDG_MOSDNS_PREPARED_CHANNEL" == release \
        && "$(basename "$PDG_MOSDNS_PREPARED_BIN")" == "$AMD64_ASSET" \
        && "$(_pdg_mosdns_sha256 "$PDG_MOSDNS_PREPARED_BIN")" == "$AMD64_FIXTURE_SHA" ]] \
  || release_ok=0
pdg_prepare_mosdns_candidate arm64 "$WORK/release-arm64" \
  && [[ "$PDG_MOSDNS_PREPARED_CHANNEL" == release \
        && "$(basename "$PDG_MOSDNS_PREPARED_BIN")" == "$ARM64_ASSET" \
        && "$(_pdg_mosdns_sha256 "$PDG_MOSDNS_PREPARED_BIN")" == "$ARM64_FIXTURE_SHA" ]] \
  || release_ok=0
[[ "$release_ok" == 1 \
   && $(grep -Fxc "$EXPECTED_RELEASE_BASE/$AMD64_ASSET" "$PDG_TEST_CURL_LOG") == 1 \
   && $(grep -Fxc "$EXPECTED_RELEASE_BASE/$ARM64_ASSET" "$PDG_TEST_CURL_LOG") == 1 ]] \
  && ok "amd64/arm64 均只从精确 tag asset URL 下载并校验" \
  || bad "双架构 Release 下载 URL、命名或候选校验失败"

# CI validates a commit before v1.11.1 assets can exist.  Its explicit guard
# must stop release-channel I/O, while the same guard must not disable the
# hash-pinned local artifact channel used by install E2E.
rm -rf "$WORK/candidate"; mkdir "$WORK/candidate"
: >"$PDG_TEST_CURL_LOG"
export PDG_MOSDNS_RELEASE_FETCH_FORBIDDEN=1
PDG_SHA256[mosdns-pdg-amd64]="$AMD64_FIXTURE_SHA"
pdg_prepare_mosdns_candidate amd64 "$WORK/candidate" >/dev/null 2>&1 \
  && bad "CI release-fetch guard 仍允许读取未发布 asset" \
  || { [[ ! -s "$PDG_TEST_CURL_LOG" ]] \
       && ok "PR/CI 禁止 Release 取件，不依赖尚未创建的 tag assets" \
       || bad "CI release-fetch guard 失败后仍发起下载"; }
rm -rf "$WORK/candidate"; mkdir "$WORK/candidate"
export PDG_MOSDNS_ARTIFACT="$WORK/patched"
export PDG_MOSDNS_ARTIFACT_SHA256="$AMD64_FIXTURE_SHA"
pdg_prepare_mosdns_candidate amd64 "$WORK/candidate" \
  && [[ "$PDG_MOSDNS_PREPARED_CHANNEL" == local ]] \
  && ok "PR/CI guard 下显式本地 pin 通道仍可验证装机" \
  || bad "PR/CI guard 误禁止显式本地 pin 通道"
unset PDG_MOSDNS_ARTIFACT PDG_MOSDNS_ARTIFACT_SHA256 \
  PDG_MOSDNS_RELEASE_FETCH_FORBIDDEN

rm -rf "$WORK/candidate"; mkdir "$WORK/candidate"
PDG_SHA256[mosdns-pdg-amd64]="0000000000000000000000000000000000000000000000000000000000000000"
pdg_prepare_mosdns_candidate amd64 "$WORK/candidate" >/dev/null 2>&1 \
  && bad "Release raw SHA256 不符仍被接受" \
  || ok "Release raw SHA256 不符时 fail closed"

rm -rf "$WORK/candidate"; mkdir "$WORK/candidate"
PDG_SHA256[mosdns-pdg-amd64]="$AMD64_FIXTURE_SHA"
MOSDNS_PDG_ASSET_BASE_URL=""
: >"$PDG_TEST_CURL_LOG"
pdg_prepare_mosdns_candidate amd64 "$WORK/candidate" >/dev/null 2>&1 \
  && bad "空 Release URL 仍产生候选" \
  || { [[ ! -s "$PDG_TEST_CURL_LOG" ]] \
       && ok "空 Release URL 时下载前 fail closed" \
       || bad "空 Release URL 仍触发了下载"; }
unset -f curl
MOSDNS_PDG_ASSET_BASE_URL="$EXPECTED_RELEASE_BASE"
PDG_SHA256[mosdns-pdg-amd64]="$REPO_PIN"
PDG_SHA256[mosdns-pdg-arm64]="$ARM64_REPO_PIN"

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

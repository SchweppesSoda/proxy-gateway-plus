#!/usr/bin/env bash
# MosDNS 修补产物获取、候选校验与安装证明。调用前须 source lib/versions.sh。
# shellcheck disable=SC2034
# 上述候选输出变量由 source 本库的 install.sh / pdg.sh 在函数返回后读取。

PDG_MOSDNS_ATTESTATION="${PDG_MOSDNS_ATTESTATION:-/etc/privdns-gateway/mosdns-build.env}"

pdg_mosdns_asset_name(){
  local arch="$1"
  printf 'mosdns-%s-%s-linux-%s\n' "$MOSDNS_VER" "$MOSDNS_PATCH_REV" "$arch"
}

pdg_mosdns_arch(){
  local arch=""
  command -v dpkg >/dev/null 2>&1 && arch="$(dpkg --print-architecture 2>/dev/null || true)"
  case "$arch" in
    amd64|arm64) printf '%s\n' "$arch"; return 0;;
  esac
  case "$(uname -m 2>/dev/null)" in
    x86_64) printf 'amd64\n';;
    aarch64|arm64) printf 'arm64\n';;
    *) return 1;;
  esac
}

_pdg_mosdns_sha256(){
  sha256sum "$1" 2>/dev/null | awk '{print $1}'
}

_pdg_mosdns_hash_is_valid(){
  [[ "$1" =~ ^[[:xdigit:]]{64}$ ]]
}

pdg_mosdns_binary_is_target(){
  local bin="${1:-/usr/local/bin/mosdns}" got
  [[ -f "$bin" && ! -L "$bin" ]] || return 1
  got="$("$bin" version 2>/dev/null | head -1)" || return 1
  [[ "$got" == "$MOSDNS_BUILD_VERSION" ]]
}

_pdg_mosdns_attest_get(){
  local file="$1" key="$2"
  awk -F= -v key="$key" '
    $1 == key {
      n++
      value = substr($0, length(key) + 2)
    }
    END {
      if (n != 1) exit 1
      print value
    }
  ' "$file" 2>/dev/null
}

pdg_mosdns_is_project_build(){
  local bin="${1:-/usr/local/bin/mosdns}"
  local attest="${2:-$PDG_MOSDNS_ATTESTATION}"
  local arch="${3:-}" got pinned value uid mode
  [[ -n "$arch" ]] || arch="$(pdg_mosdns_arch)" || return 1
  pdg_mosdns_binary_is_target "$bin" || return 1
  got="$(_pdg_mosdns_sha256 "$bin")"
  _pdg_mosdns_hash_is_valid "$got" || return 1

  # Published builds can be recognized directly by their repository-pinned
  # binary hash. Local/KFC builds require a root-owned attestation that binds
  # the installed bytes to the same source/patch/toolchain provenance.
  pinned="${PDG_SHA256[mosdns-pdg-$arch]:-}"
  if [[ -n "$pinned" && "$got" == "$pinned" ]]; then
    return 0
  fi
  [[ -f "$attest" && ! -L "$attest" ]] || return 1
  uid="$(stat -c %u "$attest" 2>/dev/null)" || return 1
  mode="$(stat -c %a "$attest" 2>/dev/null)" || return 1
  [[ "$uid" == 0 && "$mode" =~ ^[0-7]{3,4}$ ]] || return 1
  (( (8#$mode & 8#022) == 0 )) || return 1
  value="$(_pdg_mosdns_attest_get "$attest" format)" && [[ "$value" == 1 ]] || return 1
  value="$(_pdg_mosdns_attest_get "$attest" arch)" && [[ "$value" == "$arch" ]] || return 1
  value="$(_pdg_mosdns_attest_get "$attest" version)" \
    && [[ "$value" == "$MOSDNS_BUILD_VERSION" ]] || return 1
  value="$(_pdg_mosdns_attest_get "$attest" upstream_commit)" \
    && [[ "$value" == "$MOSDNS_UPSTREAM_COMMIT" ]] || return 1
  value="$(_pdg_mosdns_attest_get "$attest" patch_sha256)" \
    && [[ "$value" == "${PDG_SHA256[mosdns-patch]:-}" ]] || return 1
  value="$(_pdg_mosdns_attest_get "$attest" go_version)" \
    && [[ "$value" == "$MOSDNS_GO_VERSION" ]] || return 1
  value="$(_pdg_mosdns_attest_get "$attest" binary_sha256)" \
    && [[ "$value" == "$got" ]] || return 1
  value="$(_pdg_mosdns_attest_get "$attest" artifact_sha256)" \
    && [[ "$value" == "$got" ]] || return 1
  value="$(_pdg_mosdns_attest_get "$attest" channel)" \
    && [[ "$value" == local || "$value" == release ]] || return 1
}

# Globals set on success:
#   PDG_MOSDNS_PREPARED_BIN / _ARTIFACT_SHA256 / _BINARY_SHA256 / _CHANNEL
pdg_prepare_mosdns_candidate(){
  local arch="$1" work="$2" asset candidate expected pinned channel
  case "$arch" in amd64|arm64) ;; *) echo "[x] 不支持的 MosDNS 架构: $arch" >&2; return 1;; esac
  [[ -d "$work" ]] || { echo "[x] MosDNS 候选目录不存在: $work" >&2; return 1; }
  asset="$(pdg_mosdns_asset_name "$arch")"
  candidate="$work/$asset"

  if [[ -n "${PDG_MOSDNS_ARTIFACT:-}" || -n "${PDG_MOSDNS_ARTIFACT_SHA256:-}" \
        || -n "${PDG_MOSDNS_BINARY_SHA256:-}" ]]; then
    [[ -n "${PDG_MOSDNS_ARTIFACT:-}" \
       && -n "${PDG_MOSDNS_ARTIFACT_SHA256:-}" ]] || {
      echo "[x] 本地 MosDNS 通道必须同时提供 ARTIFACT/ARTIFACT_SHA256" >&2
      return 1
    }
    [[ "$PDG_MOSDNS_ARTIFACT" == /* && -f "$PDG_MOSDNS_ARTIFACT" \
       && ! -L "$PDG_MOSDNS_ARTIFACT" ]] || {
      echo "[x] PDG_MOSDNS_ARTIFACT 必须是绝对路径下的普通文件(拒绝符号链接)" >&2
      return 1
    }
    expected="${PDG_MOSDNS_ARTIFACT_SHA256,,}"
    _pdg_mosdns_hash_is_valid "$expected" || {
      echo "[x] 本地 MosDNS SHA256 必须是 64 位十六进制" >&2
      return 1
    }
    pinned="${PDG_SHA256[mosdns-pdg-$arch]:-}"
    if [[ -z "$pinned" || "$expected" != "$pinned" ]]; then
      echo "[x] 本地 MosDNS SHA256 与 lib/versions.sh 的架构 pin 不符" >&2
      echo "    期望 ${pinned:-<未配置>}，实际 $expected" >&2
      return 1
    fi
    if [[ -n "${PDG_MOSDNS_BINARY_SHA256:-}" \
          && "${PDG_MOSDNS_BINARY_SHA256,,}" != "$expected" ]]; then
      echo "[x] raw MosDNS 产物的 ARTIFACT/BINARY SHA256 必须相同" >&2
      return 1
    fi
    cp -- "$PDG_MOSDNS_ARTIFACT" "$candidate" || return 1
    channel="local"
  else
    expected="${PDG_SHA256[mosdns-pdg-$arch]:-}"
    if [[ -z "$MOSDNS_PDG_ASSET_BASE_URL" || -z "$expected" ]]; then
      echo "[x] 当前发布尚无仓库钉死的 MosDNS 修补产物($arch); 拒绝下载官方 stock v5.3.4。" >&2
      echo "    请按 docs/MOSDNS-PATCHED-BUILD.md 构建，并显式提供两个 PDG_MOSDNS_* 变量。" >&2
      return 1
    fi
    _pdg_mosdns_hash_is_valid "$expected" || {
      echo "[x] lib/versions.sh 中 MosDNS 修补产物哈希格式非法" >&2
      return 1
    }
    curl -fsSL "$MOSDNS_PDG_ASSET_BASE_URL/$asset" -o "$candidate" || return 1
    channel="release"
  fi

  pdg_verify_sha256 "$candidate" "$expected" "MosDNS 修补产物 $asset" || return 1
  [[ -s "$candidate" ]] || { echo "[x] MosDNS 修补候选为空" >&2; return 1; }
  chmod 0755 "$candidate" || return 1
  pdg_mosdns_binary_is_target "$candidate" || {
    echo "[x] MosDNS 候选 build marker 不符(期望 $MOSDNS_BUILD_VERSION)" >&2
    return 1
  }

  PDG_MOSDNS_PREPARED_BIN="$candidate"
  PDG_MOSDNS_PREPARED_ARTIFACT_SHA256="$expected"
  PDG_MOSDNS_PREPARED_BINARY_SHA256="$expected"
  PDG_MOSDNS_PREPARED_CHANNEL="$channel"
}

pdg_write_mosdns_attestation(){
  local file="$1" arch="$2" artifact_sha="$3" binary_sha="$4" channel="$5"
  local dir tmp
  _pdg_mosdns_hash_is_valid "$artifact_sha" && _pdg_mosdns_hash_is_valid "$binary_sha" \
    || return 1
  case "$arch" in amd64|arm64) ;; *) return 1;; esac
  case "$channel" in local|release) ;; *) return 1;; esac
  dir="$(dirname "$file")"
  install -d -m700 "$dir" || return 1
  tmp="$(mktemp "$dir/.mosdns-build.env.XXXXXX")" || return 1
  if ! (
    umask 077
    printf 'format=1\n'
    printf 'arch=%s\n' "$arch"
    printf 'version=%s\n' "$MOSDNS_BUILD_VERSION"
    printf 'upstream_commit=%s\n' "$MOSDNS_UPSTREAM_COMMIT"
    printf 'patch_sha256=%s\n' "${PDG_SHA256[mosdns-patch]:-}"
    printf 'go_version=%s\n' "$MOSDNS_GO_VERSION"
    printf 'artifact_sha256=%s\n' "$artifact_sha"
    printf 'binary_sha256=%s\n' "$binary_sha"
    printf 'channel=%s\n' "$channel"
  ) >"$tmp" || ! chmod 0600 "$tmp" || ! mv -f "$tmp" "$file"; then
    rm -f "$tmp"
    return 1
  fi
}

#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
rules="$(cat "${root}/update-rules.sh")"
readme="$(cat "${root}/README.md")"

if [[ "${rules}" != *"上游文件是 Base64 编码，先解码再抽取域名"* ]]; then
    echo "update-rules.sh should explain that GFWList is Base64-decoded before parsing." >&2
    exit 1
fi

if [[ "${readme}" != *"GFWList 上游文件本身是 Base64 编码"* ]]; then
    echo "README should explain why raw GFWList looks unreadable." >&2
    exit 1
fi

echo "GFWList decode notice OK"

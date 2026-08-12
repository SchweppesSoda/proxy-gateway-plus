# MosDNS v5.3.4 no-ticket 修补版

## 为什么不能直接安装官方二进制

MosDNS v5.3.4 的 `tcp_server` 只加载证书，没有关闭 Go TLS session ticket。stock 与本项目
修补版都属于上游 v5.3.4，单看语义版本无法区分。本项目把 flavor 固定为
`v5.3.4-pdg-notickets.1`，并在 `tls.Config` 设置
`SessionTicketsDisabled: true`。安装、更新和 doctor 都要求这个精确 marker，以及仓库
钉死的发布哈希或本地构建证明；绝不回退到官方 stock v5.3.4。

构建信任锚位于 `lib/versions.sh`：

- 上游仓库：`IrineSistiana/mosdns`
- 上游 v5.3.4 commit：`b7323188bab1ea742538aeccb31b692bc4967d1b`
- Go：`1.24.9`
- patch：`patches/mosdns/v5.3.4-session-tickets-disabled.patch`，SHA256 同样钉死
- 构建参数：CGO 关闭、`-trimpath`、`-buildvcs=false`、空 linker build ID

KFC 按仓库脚本完成的最终 raw SHA256 已写入 `lib/versions.sh`：

- amd64：`601788797260769d7dda5aef0041f77ff6981aa4141730cfa14169a32b9411e7`
- arm64：`e2c81dea12e0beab8d17581c73a44db7594175f1b652f3d5dfb9f92688939a72`

## 在本机或 KFC 构建

构建机需要 Git 和精确的 Go 1.24.9；VPS 不需要也不应临时安装 Go。若要自行下载 Linux
amd64 Go 工具链，官方 tarball SHA256 为：

```text
5b7899591c2dd6e9da1809fde4a2fad842c45d3f6b9deb235ba82216e31e34a6
```

在本仓库运行：

```bash
git clone https://github.com/IrineSistiana/mosdns.git /path/to/mosdns
git -C /path/to/mosdns checkout --detach b7323188bab1ea742538aeccb31b692bc4967d1b

bash tools/build-mosdns-patched.sh \
  --arch amd64 \
  --source /path/to/mosdns \
  --out ./dist/mosdns

sha256sum -c ./dist/mosdns/mosdns-v5.3.4-pdg-notickets.1-linux-amd64.sha256
```

arm64 将两处 `amd64` 改为 `arm64`。脚本会重新克隆指定 source，不修改原 checkout；随后
校验 commit、patch hash、`go mod verify`、目标包测试、build marker，并输出 raw binary、
`.sha256`、环境片段和 provenance JSON。

`.github/workflows/build-mosdns-patched.yml` 提供同一产物接口。它校验官方 Go tarball，
amd64 / arm64 各构建两次并用 `diff` 要求逐字节一致，再上传 14 天 release-candidate
artifact。Actions artifact 不是长期安装源，不能把临时下载 URL 写进 installer。

## 发版前或离线部署 KFC 产物

先通过可信通道把对应架构的 raw binary 传到目标机，例如
`/root/pdg-artifacts/mosdns-v5.3.4-pdg-notickets.1-linux-amd64`。从构建机的 `.sha256`
独立复制哈希，不在目标机下载后“现算现信”。

发版前全新安装验证（标准入口会自动切换到最新 `v*` Release）：

```bash
sudo env \
  PDG_MOSDNS_ARTIFACT=/root/pdg-artifacts/mosdns-v5.3.4-pdg-notickets.1-linux-amd64 \
  PDG_MOSDNS_ARTIFACT_SHA256=<构建机记录的64位SHA256> \
  ./install.sh
```

已有部署在离线环境升级到包含本修复的正式项目 tag：

```bash
sudo env \
  PDG_MOSDNS_ARTIFACT=/root/pdg-artifacts/mosdns-v5.3.4-pdg-notickets.1-linux-amd64 \
  PDG_MOSDNS_ARTIFACT_SHA256=<构建机记录的64位SHA256> \
  pdg update
```

本地通道只接受绝对路径的普通文件，拒绝符号链接；复制到事务临时目录后再次比较显式
SHA256；该值还必须等于 `lib/versions.sh` 对应架构的 `mosdns-pdg-*` pin，不能用任意
自报哈希绕过仓库信任锚。随后执行候选的精确 build marker。安装成功后会原子写入 root-only
`/etc/privdns-gateway/mosdns-build.env`，绑定架构、二进制 SHA256、上游 commit、patch
SHA256 与 Go 版本。覆盖前保留旧二进制；写证明、重启或稳定性复核任一步失败都会恢复旧
二进制和旧证明。`pdg update` 的整机快照也包含 MosDNS 二进制和证明。

部署后运行：

```bash
sudo pdg doctor
sudo pdg doctor --deep
```

常规 doctor 校验 flavor/provenance。deep doctor 先用系统 CA 验证 DoT chain 和 DNS SAN
（不接受 CN fallback），再完成两次真实 DoT 查询；若第二次握手接受第一次的 SSLSession，
`DoT 会话恢复` 项判 fail。

## 发布自有 asset

v1.9.0 的长期目录已精确钉死为
`https://github.com/SchweppesSoda/proxy-gateway-plus/releases/download/v1.9.0`。正式发布前：

1. 用 KFC 和 Actions 分别运行仓库构建脚本，确认同架构 raw SHA256 一致。
2. 把两个 raw binary 以脚本定义的精确文件名上传到 v1.9.0 GitHub Release；同时附上各自
   的 `.sha256` 和 `.provenance.json`（`.env` 只是离线部署便利文件，不是信任锚）。
3. 确认 base URL 与项目 tag 一致，amd64 / arm64 raw SHA256 与 `lib/versions.sh` 完全一致。
4. 从 Release URL 实际下载两架构 raw asset 并复核 SHA256，再运行供应链测试和安装/更新
   故障回滚测试，最后才允许生产部署消费该 tag。

不要发布一个 hash 尚未写入 `lib/versions.sh` 的默认下载通道，也不要在下载失败时回退到
上游 stock asset。

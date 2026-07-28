# 当前生产架构与部署约定

本文记录当前根架构的生产约定。导入前的实现保存在
[`legacy/current-architecture/`](../legacy/current-architecture/)，上游固定基线与同步策略见
[`UPSTREAM_BASE.md`](../UPSTREAM_BASE.md)。历史架构不能作为当前端口、QUIC 或防火墙行为的操作手册。

## 运行时边界

当前运行时由 MosDNS 和单个 Mihomo（clash.meta）组成：

- MosDNS 负责按客户端来源段和域名分类，直连域名返回真实地址；代理域名把 A 记录改写为
  网关地址，并按策略抑制 AAAA / HTTPS 记录。
- `/etc/sing-box/config.json` 只是沿用的核无关出口与规则数据模型，不代表机器仍运行
  sing-box。Bot 从该模型事务化派生 `/etc/mihomo/config.yaml`。
- 一台机器只运行一个 Mihomo。没有 TUN、第二 Mihomo、第二透明监听器或 OUTPUT catch-all。
- 本仓库负责网关应用生命周期；SSH、其他应用、整机通用防火墙和跨主机发布由
  `vps-toolkit` 编排。

## 三条数据路径

| 路径 | 当前行为 |
|---|---|
| DNS 判为直连 | MosDNS 返回真实 IP，手机直接访问目标，不经过网关 Mihomo |
| DNS 判为代理的 TCP | 手机连接网关地址上的原始目的端口；nft 仅匹配内网卡来源段和配置端口，REDIRECT 到 Mihomo `:7893` |
| DNS 判为代理的 UDP/443 | 默认经 source-scoped nft TPROXY、fwmark 和专用 policy route 进入同一 Mihomo 的 `:7895` |

TCP 原始目的端口由 `PDG_HIJACK_TLS_TCP_PORTS` 与
`PDG_HIJACK_HTTP_TCP_PORTS` 定义。安装器使用一个严格 profile 同时生成 nft 端口集合和
Mihomo sniffer 端口，避免“防火墙接管了但内核不嗅探”或相反的半配置状态。

`PDG_QUIC_MODE=tproxy` 是默认值，Mihomo 同时声明 `tproxy-port :7895` 和 QUIC sniffer。
`PDG_QUIC_MODE=reject` 会移除 TPROXY 条件块、停止声明该监听并清理项目自有 policy route。
在 `managed` 模式下，input policy 会拒绝内网卡来源 UDP/443，使支持的客户端回落 TCP；
`external` 模式不创建 input hook，拒绝、丢弃或放行由外部防火墙决定。

## 直连漏分流与非标准端口

非标准端口打不开时，先判断路径，不要直接扩大透明接管范围。

假设一个本应直连的测试站点使用 TLS `:10443`，但 MosDNS 劫持模式把它解析成网关地址。
正确修复是在 Bot 分流管理中把域名指到 `direct`。该操作通过配置事务写入
`/etc/mosdns/rules/custom_direct.txt`、撤销冲突的自定义劫持，手机重新查询后得到真实 IP。
把 `:10443` 加入劫持端口反而会把原本的手机直连变成网关出站，可能引入来源限制或额外故障。

只有业务明确要求经过代理、目标和所选出口也支持该端口时，才扩展
`PDG_HIJACK_TLS_TCP_PORTS` 或 `PDG_HIJACK_HTTP_TCP_PORTS`。两个变量都是完整端口集合；
扩展时必须保留平台所需默认端口，并避开 SSH、DNS、Mihomo API 与其他本地监听。非法范围、
TLS/HTTP 重叠、重复 profile 键和本地监听冲突都会 fail closed。

## 防火墙模式

| 模式 | 本仓库拥有的范围 | 上层责任 |
|---|---|---|
| `managed`（默认） | owned `inet pdg` 数据面和 source-aware input hook；input `policy drop`，按实际 SSH 端口及内网卡来源允许应用入口 | 云安全组仍须与主机策略一致 |
| `external` | 仅 owned、source-scoped REDIRECT / TPROXY 数据面；无 input hook | `vps-toolkit` 或管理员负责主机 input policy、公网暴露、SSH 与 ACME 放行 |

两种模式都通过 ownership marker 识别自己的 `inet pdg` 表。foreign、markerless 或结构错误的
同名表不会被替换或删除；候选无法安全合并或校验时，部署中止并保留原配置。

## 保留的管理能力

当前架构继续使用 Misaka 项目的管理模型与用户能力：

- 多个代理出口、Mihomo `url-test` 故障组、默认出口和出口改名级联；
- 单域名规则、域名关键词、IP CIDR、远程规则集及 MosDNS 劫持同步；
- Telegram Bot 的出口、分流、测速、流量、DNS、TFO、观测面板和平台相关入口；
- 默认禁用的 HTTPS Web 管理面；使用 `pdg web setup|enable|disable|status|password`
  显式管理，独立 root-only 配置会被快照、更新和回滚清单跟踪；
- 配置备份/恢复、手动快照、更新前快照和失败回滚；
- `pdg doctor` 的只读检查、JSON 输出和可选 deep 检查；
- 配置事务锁、候选校验、原子落盘、观察门、失败回滚与显式 recover。

备份可能包含出口凭据，只应交给受信任的管理员保存。恢复包按成员数、单文件大小、总大小、
路径和链接类型做白名单检查；候选模型与 Mihomo 配置校验通过后才应用。

Telegram Bot 在验证授权用户前先拒绝非私聊消息和回调；Zashboard 临时观测/控制面板只允许
开放 10 或 30 分钟。可选 Web 服务安装后仍保持 disabled/inactive，setup 才会创建
`/etc/privdns-gateway/web.json`（父目录 0700、文件 0600、root 所有）。它只接受 HTTPS，
精确限制 Host、Origin 与可信来源，密码使用至少 600,000 次 PBKDF2-SHA256，最长会话 8
小时。证书 deploy hook 仅在 Web 已配置且 active 时重启验证，不会把禁用服务带起。

Web 默认 loopback 监听适合 SSH 隧道。浏览器仍必须使用证书覆盖的配置域名；直接访问
`https://127.0.0.1:<port>` 通常会遇到证书名称错误，可用本机 hosts 映射或证书名称一致的
私有域名入口。loopback CIDR 必须保留在可信来源中。Web 忽略 `X-Forwarded-For`，loopback
反向代理必须自行执行客户端来源 ACL，不能把 Web 的可信 CIDR 当作代理后的安全边界。需要
非 loopback 直连时，本仓库只输出实际监听端口和可信 CIDR，不修改 input policy；该入口
只在 `external` 模式由外部防火墙/管理员显式接入。`managed` 模式的默认支持路径仍为
loopback + SSH 隧道，不能把 setup 的默认端口当成机器常量。

## 标准部署接口

上层编排应调用本仓库接口，不应复制一套平行模板：

- 新机使用带 `PDG_NONINTERACTIVE=1` 的 `install.sh`，显式传入平台、来源段、防火墙模式和
  所需数据面参数；
- 发布更新使用 `pdg update`，它先留快照，再安装发布 tag、运行显式迁移与健康门；
- 不升级代码时使用 `pdg migrate` 执行上锁、留快照的幂等迁移；
- 发布前后使用 `pdg doctor --json` 作为机器可读检查，并保留 `pdg report` 供人工排障；
- 使用 `pdg snapshot` / `pdg rollback` 做人工维护窗口的恢复点。

`status`、`doctor`、`log`、`traffic` 和 `report` 是只读命令，不会暗中迁移生产配置。

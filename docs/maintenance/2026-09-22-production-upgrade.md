# 2026-09-22 现役 PDG 升级验收

现役 `kfc-pdg` 已从 **v1.11.5** 升级到 **v1.11.6**，最终 `pdg doctor --deep` 为 **0 失败 / 0 警告**。本记录基于本次现场重验，不沿用历史实例状态作为验收结论。

## 版本、发布与安装

| 对象 | 已验证结果 |
|---|---|
| 升级前安装提交 | `14aadd0ccb5d2eecbb150abd565d499f34009447`，精确 `v1.11.5`，工作树干净 |
| 维护基线 | `1e791de5da5269827fd04f35bd9adb6f6817b5d8`，本地与 origin/main 一致 |
| 发布准备提交 | `16f0287c112f26b80a483118767b1608f57c42a4`，只修改版本下载目录、供应链测试的版本断言及发布文档 |
| 正式 Release/tag | [v1.11.6](https://github.com/SchweppesSoda/proxy-gateway-plus/releases/tag/v1.11.6)，2026-09-22 12:54:51 UTC 发布；tag 解引用到 `16f0287c112f26b80a483118767b1608f57c42a4` |
| 实际安装提交 | `16f0287c112f26b80a483118767b1608f57c42a4`，唯一精确 tag 为 `v1.11.6`，工作树干净 |
| 部署入口 | 仓库原有 `tools/deploy-release.sh`，明确 `PDG_EXPECTED_VERSION=v1.11.6`，helper 返回 0 |
| 源码 main | 发布准备提交之后只有本部署记录的独立文档提交；此记录不改变 Release 或生产安装版本 |

维护基线的 [CI 35689531370](https://github.com/SchweppesSoda/proxy-gateway-plus/actions/runs/35689531370) 已重新核对成功；正式候选的 [CI 35728996036](https://github.com/SchweppesSoda/proxy-gateway-plus/actions/runs/35728996036) **16/16 job 成功**，包括 lint、真实组件 functional、独立 E2E 与串行 E2E。

[构建 35729090913](https://github.com/SchweppesSoda/proxy-gateway-plus/actions/runs/35729090913) 基于同一候选，两架构各构建两次并逐字节一致。仅上传明确的六个 raw/SHA256/provenance 附件；未上传 `.env`。正式发布后已从该 tag 的精确 Release URL 回下载两个 raw binary，复核 SHA256：

- amd64：`601788797260769d7dda5aef0041f77ff6981aa4141730cfa14169a32b9411e7`
- arm64：`e2c81dea12e0beab8d17581c73a44db7594175f1b652f3d5dfb9f92688939a72`

MosDNS 保持 `v5.3.4-pdg-notickets.1`，Mihomo 保持 `v1.19.29`；无配置 schema 变更。

## 现场验收

- 平台/核心/模式仍为 **Android / Mihomo / external / tproxy**。只通过现有 `kfc-pdg` alias 访问，主机密钥校验保持严格；部署使用经过核验的非登录 Git Bash 环境。
- `checks.expected_services()` 实际返回 `pdg-quic-routing`、`mosdns`、`mihomo`、`pdg-bot`，逐项 active；QUIC oneshot 为 active/exited。Bot 凭据完整。上述服务及 Web 的 `NRestarts=0`。
- Web 升级前 enabled/active，升级后继续 enabled/active；原页面 TLS 证书验证成功，HTTP 200。
- 四个现有出口均经现有 Mihomo Clash API 完成实际连通探测，4/4 成功，未使用 TCP fallback、未更换当前出口。
- `pdg doctor --deep` 验证本机 DNS、国内 DNS、两组上游、DoT chain/SAN、两次真实 DoT 握手与会话恢复拒绝、核心配置、透明数据面、GMS 和事务状态。最终 **0 失败 / 0 警告**。
- 实际安装的 CLI、Bot、checks、healthcheck、rule_status、update-rules、pdgtx 与 Web 代码逐字节匹配 Release checkout。
- 与受保护升级前快照逐字节比较：权威模型、Mihomo/MosDNS 配置、Bot/Web 配置、profile 和 nftables 配置均未变化；现有 MosDNS 规则文件摘要也全部保持一致。
- 最终现存 20 个事务均为 COMMITTED，`pending_recovery=0`，无终态敏感材料残留。没有根据旧 index 的历史失败执行恢复。

## 新状态与 WLOC 退役

helper 首次深检只有一项规则新鲜度 warning：旧版不存在新收据。随后通过原有 `pdg-rules-update.service` 完成一次真实事务刷新，geosite 与 rulesets 均记录全量成功，`failure=null`、`failureCount=0`、`running=false`，新鲜度为 ok；没有伪造或手工补写成功时间。

原健康 timer 虽 active，但处于 elapsed、下一次触发为 infinity，health service 没有本次系统管理器记忆中的执行时间。单独 restart timer 未使它调度；复核后原业务仍健康。确认 ALERT 无异常、没有旧问题或待发通知后，启动原有健康 service 的正常周期。该周期于 **2026-09-22 13:00:03 UTC** 成功退出，生成 **schema 2、0600** 状态文件；收件人状态正常、pending=0，timer 转为 active/waiting 并有下一次触发时间。没有调用测试 Telegram 发送接口或制造故障。

升级前后均检查：WLOC 启用标志、两 Apple 定位域名在 MITM DNS 清单、模型、Mihomo 配置及实时规则中的接管均不存在；Android 上 `pdg-mitm` / `pdg-probe81` unit 与 WLOC/iOS 专属模块不存在。没有为了停用而启动旧功能，也没有重启退役进程。共享普通 DNS/代理、CA 与私密历史均保留。

## 恢复材料与回退条件

恢复材料仅留在目标主机的 root-only 目录：

`/var/lib/privdns-gateway/upgrade-recovery/20260922-v1.11.6`

其中包含升级前精确配置/脚本/核心二进制快照、已验证的旧仓库 Git bundle、私密事务历史与证书目标归档、原有十份快照副本及 SHA256 清单。目录 0700；内置快照归档 0600；归档列表、必要成员、Git bundle 与清单均已验证。没有把凭据或原始恢复包下载到本机、写入仓库或报告。

内置快照轮替可能移出旧快照，因此先保全原十份，轮替后再无覆盖恢复其原目录；最终原十份与本次两份新快照共十二份均在。未清理其他备份、事务历史或快照。

精确恢复目录为 `.../20260922-v1.11.6/pre-upgrade-snapshot`；旧 Git 提交为 `14aadd0ccb5d2eecbb150abd565d499f34009447`。若今后出现与本升级有关的服务/业务退化，先保存当前证据和状态，用原有 `pdg rollback --dir <精确恢复目录> --git <旧提交>` 合同处理，再重验必需服务、既有 Web、普通 DNS/代理和深度 doctor。不得按变化的快照序号猜测恢复点。

降级前还须暂停健康 writer、保存当前状态，并核对所有收件人 pending 为空、delivered 一致且与顶层 problems 一致；规则收据与实际内容须单独核验。任何备份恢复都必须重新过 WLOC 残留门，不能启用旧定位接管。旧软件恢复只代表历史回退，不代表当前安全发布。本次没有制造生产故障或演练回滚。

## 边界

未测试手机经内网卡的完整透明转发、真实 GMS 推送、Web 登录/写入操作、Telegram 故障消息送达与重试、iOS 真机或 iOS 27 定位兼容性；服务端出口探测不冒充手机端验收。通知失败分支由候选 Linux CI 离线回归覆盖，现场只验证正常周期和状态持久化。CI 的隔离 E2E 包含服务桩，不冒充全部真实系统/设备场景。

未修改 Router/Gateway、VM102、家庭 PVE、Cloudflare、Windows 客户端或个人 skill；未轮换凭据。实际升级、现场验收及恢复资料保全已完成。

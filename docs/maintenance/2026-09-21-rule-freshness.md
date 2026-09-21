# 2026-09-21 规则刷新新鲜度维护

本次在 T03 通知送达修复 `c66df72` 上继续本地维护；尚未 push、Release 或部署，没有请求
真实规则来源、发送 Telegram 消息或访问设备。运行版本号不变。

## 范围与实现

每日 `scheduled-update.sh` 原本已按 geosite、规则集两个阶段返回失败；但健康通知只检查
服务/DNS/证书等项目，长期沿用旧规则可能不会触发告警。更新入口还包括 Bot、CLI 和 Web，
所以状态记录放在共用的 `update-rules.sh` 与 `bot.refresh_rulesets()`，没有再造更新器。

新增 `rule_status.py`，在 `/opt/pdg-bot/rule-status/` 分别保存 `geosite.json` 和 `rulesets.json`：

- `lastAttempt` 在尝试前落盘；`running` 表示尝试尚未结束。
- `lastSuccess` 仅在 geosite 事务及服务门成功，或所有已配置规则集完整刷新并提交后更新。
  下载部分成功、全失败、事务回滚或状态持久化失败不会被当成全量成功。
- `sourceVersion` 为最近整批成功内容的 SHA256 标识，不冒充上游提交/tag。geosite 对已部署
  的固定四类规则内容求摘要；规则集对事务成功候选的内容集合求摘要。相同内容的成功获取也
  会刷新 `lastSuccess`，表示重新验证/获取成功，不表示上游一定有新版本。
- `failure` 仅存固定结果类别，`failureCount` 是连续失败计数；不保存来源 URL、规则名称、
  订阅正文或异常正文。部分提交继续保留上一份完整成功时间/摘要，不能把它作为当前每个
  文件都一致的版本清单。

状态写入复用 `pdgtx.atomic_write()`，组件各有一把贯穿尝试的非阻塞 `flock`。规则配置仍由
既有全局事务锁、候选校验及回滚拥有；本模块不替换它们。新状态目录 0700、文件 0600；
拒绝不可信路径或损坏状态，不自动清空。安装、更新及旧版回退的 helper 清单同步加入模块。

geosite 的常规入口经记录包装器运行 `--recorded-live` 内部步骤。`--bootstrap` 保留原本
安装器 PPID/marker、exact inactive 与事务 guard，不经过包装；离线落盘不能证明运行时已
接收新库，因此首次 live 更新成功以前新鲜度显示未知。没有配置规则集时只检查 geosite。

## 检查与通知

`checks.ALL` 的诊断详情显示精确 `ageSeconds`、时间与成功内容标识；`checks.ALERT` 复用
相同判据，但只输出稳定状态，交给 T03 的送达去重处理。连续失败计数、时间和年龄每次变化
不会让告警刷屏。

- 最近尝试失败/部分失败：warn，保留旧成功时间。
- 距整批成功至少 48 小时：warn；至少 7 天：fail。每日调度及最多 30 分钟随机延迟下，
  48 小时允许单次调度延迟，7 天表示持续陈旧；这是一组明确默认阈值，后续可按实际更新 SLA
  重新评估，不需要引入配置平台。
- running 超过 1 小时：warn，可能是中断或卡住；状态缺失/非法或时钟明显回退：warn。
- 成功恢复后下一轮通知按 T03 正常恢复语义处理，不在更新器里直接发送消息。

年龄来自成功记录而非文件 mtime；记录只是控制流程完成的证据，不能证明上游内容正确、
业务规则命中正确，亦不替代真实客户端验证。恢复旧快照可能恢复旧收据，应单列规则内容与
收据的现场一致性核验；本轮未调整恢复点或执行恢复演练。

## 本地验证与限制

- 新 `test-rule-status.py`：13 项，其中 12 通过、1 项真实 POSIX flock/权限验证在 Windows
  明确 skip。使用真实刷新函数与既有原子写函数，模拟下载、事务、子进程、时钟；Windows
  只替换不可用的 flock 和目录 fsync，禁止真实 socket/subprocess。
- 原 `test-update-rules-bootstrap.sh` 9/9 通过，保持 normal/restart、首装 PPID/marker、四类
  非空及 apply 后 inactive 门；测试的 wrapper mock 仅转发内部 worker。
- 修改的 shell 语法、Python AST、工作流 YAML、文档链接与 diff 检查通过。新回归加入现有
  CI lint job。Linux 完整规则事务、安装/更新/回滚、目录 fsync 与真实服务/来源仍未运行，
  不能作为已部署或完整 Linux 门禁通过的证据。

## 回退条件

本轮仅本地代码可撤销该 scoped commit，保留 T03 提交。未来上线需单独授权，部署前先跑
Linux 相关门禁并保存旧代码/规则/受保护恢复材料。旧检查器不消费新增状态；回退应将
`checks.py`、`pdg-bot.py`、`update-rules.sh` 与 helper 安装清单作为同一组恢复，避免留下
新 caller 却缺 helper。状态文件可保留，不主动删除；旧版本没有这项新鲜度监控，恢复后需
人工确认成功更新时间与实际规则内容。

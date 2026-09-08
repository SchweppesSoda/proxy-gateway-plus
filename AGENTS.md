# Repository agent instructions

## Production PDG deployment

- Address the production PDG only through the opaque SSH alias `kfc-pdg`. Its real host, port,
  user and identity file belong in the maintainer's local `~/.ssh/config`, never in this repository.
- Do not infer a deployment target from a provider name, VPS label, an IP address, or the word
  "KFC". Do not substitute another host when the alias is missing or its identity check fails.
- Do not use a browser login, email address or password for deployment. Production release updates
  use SSH and the installed `pdg` CLI.
- After the requested GitHub Release exists, deploy it from this checkout with:

  ```bash
  PDG_EXPECTED_VERSION=vX.Y.Z bash tools/deploy-release.sh
  ```

- Treat any helper failure as blocking. A successful run must confirm the expected GitHub repository
  origin, exact clean release tag, all four core services (`pdg-web`, `pdg-bot`, `mihomo`, `mosdns`),
  and `pdg doctor --deep`.

## 日常维护与收尾

- 日常在本仓主目录的 `main` 工作；同仓一次只允许一个任务写入，只读检查可以并行。
- 开始前核对仓库、分支、工作树、未提交/未跟踪改动和远程状态。执行 `git fetch --tags --prune`，落后时在辨认遗留改动后使用 fast-forward；分叉先查明原因，不重置或强推。
- 只有用户明确要求并行或隔离才建立临时分支/工作树。验证后将适用改动收回主目录，检查未跟踪及忽略文件，再清理临时工作树；必要备份放仓库外。
- 已验证的改动在本仓源码主分支留下范围明确的本地提交。提交前再次核对远程和 staged 范围；推送、Release 和部署按用户已有授权执行，结束时说明本地/远程状态及剩余工作。
- `.tmp/` 只放可重建的构建、测试和临时核验输出；现场备份与长期维护资料另行保管。历史 tag、冻结归档和兼容入口按既有合同保留。
- 只忽略 `.codex/visualizations/`、`.codex/show-me-*.html` 等本地预览，不整目录忽略可能共享的 `.codex/` 配置。

本仓拥有独立网关实现与发布；VPS-Toolkit 的代理栈入口只负责调用本仓组件。`legacy/current-architecture/` 是冻结历史，遵守 [UPSTREAM_BASE.md](./UPSTREAM_BASE.md)；整理文档不触发生产部署。

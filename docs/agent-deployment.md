# Production PDG deployment

仅在用户要求且会话已授权生产发布/部署时读取。本地源码、文档修改不触发部署。

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
  origin, exact clean release tag, every service from `checks.expected_services()`,
  and `pdg doctor --deep`. The required set follows the active core and platform;
  Bot is required only with complete credentials (partial credentials fail). Web
  remains optional and disabled by default. The helper captures whether Web was
  enabled or active before updating and requires it active afterward when either
  was true; it never enables Web. Doctor separately reports enabled-but-inactive Web.

## WLOC retirement gate

Source retirement does not clean or stop a running server. Before replacing live code, the authorized
operator must preserve rollback material, disable the existing WLOC plugin using the old validated
transaction, verify both Apple domains are absent from the active DNS/core interception and confirm
normal DNS/proxy service. Stop the old WLOC-serving process before replacing it. If cleanup fails,
stop deployment; do not report source retirement as runtime completion. Do not delete locations/CA
or disable shared force-hijack/proxy features. A later backup restore must pass the same residue gate.
An old full-software rollback remains historical code and is not evidence of a safe current release.

Restored enabled flags or Apple location interception are invalid current configuration. Retained locations, CA material, snapshots and frozen history remain separate recovery assets; shared DNS/proxy features must stay intact.

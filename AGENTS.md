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

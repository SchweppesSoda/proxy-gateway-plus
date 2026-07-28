# Upstream Base

This repository's current root architecture was mechanically imported from:

- Upstream: <https://github.com/misaka-cpu/privdns-gateway>
- Fixed upstream commit: `eff3668c5873a7fce6b2c1663056b7d7bf1a7beb`
- Import date: 2026-07-28

The import was produced with `git archive` from a reviewed local Git object for
that fixed, pinned upstream commit. No working tree was restored or used as an
import source, and no `.git` directory was copied.

The previous tracked architecture is preserved byte-for-byte under
`legacy/current-architecture/`.

## Upstream synchronization policy

- Keep project-specific patches separate from mechanical upstream sync
  changes so that both can be reviewed independently.
- Select and review an exact upstream commit before every sync; do not import
  an unpinned branch tip.
- Import only the reviewed commit's tree, without its `.git` directory.
- Never use `git reset` or another wholesale overwrite to synchronize this
  repository.
- Never overwrite or delete `legacy/current-architecture/` during an upstream
  sync.

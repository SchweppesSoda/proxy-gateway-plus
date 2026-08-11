# PDG v1.6.4 updater fixture

`pdg-v1.6.4.fixture` is the complete, unmodified `deploy/bot/pdg.sh` blob from the
supported fork release `v1.6.4`. It is stored as non-executable test data so a
shallow, tag-less CI checkout can verify the legacy update parser without any
network fetch.

- Repository: `https://github.com/SchweppesSoda/proxy-gateway-plus.git`
- Tag object: `2ab5a7dfcd8b53c3c0960bd23553f39a582ca258`
- Peeled commit: `e070a9f5f0a463170e73f74c4505eba97300137d`
- Source path: `deploy/bot/pdg.sh`
- Git blob: `35e99a58707e448b206189162ca0b7446a09c204`
- Size: `253360` bytes
- SHA-256: `0068d5bc8e9f3b1e59ab5cc6791626a7d410461b1cd8b04ec1ecaed68575042e`
- Fixture mode: `100644` (must not be executable)
- Checkout attributes: `text eol=lf` via the exact `.gitattributes` path rule

The release-helper test independently locks the size, unfiltered Git blob ID,
SHA-256, legacy single-argument dispatcher, and absence of the `--target)`
parser branch.

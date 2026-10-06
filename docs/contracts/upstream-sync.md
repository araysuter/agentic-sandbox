# Upstream Sync — A2A protocol

This fork implements A2A wire behavior in the executor's JSON protocol adapter
and golden fixtures. The original manifest listed three Rust SDK crates from a
private Gitea mirror, but no production or test code imported them. Those unused
dependencies have been removed so a fresh checkout can build without access to
the upstream maintainer's private infrastructure.

`ci/a2a-sdk-baseline.json` records the original SDK provenance for historical
reference; it is not a dependency pin for this fork. The build guard in
`scripts/lint-a2a-dependency-source.sh` checks that private SDK dependencies do
not return. Protocol changes should be reviewed against the adapter and its
conformance fixtures. Adding an SDK requires a new explicit dependency review,
a publicly accessible pinned source, and conformance validation.

See [A2A protocol compatibility](../a2a-protocol-compatibility.md) for the
supported versions and fixtures.

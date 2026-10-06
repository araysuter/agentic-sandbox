# Portable disposable policy checks

Run `cargo test --locked --manifest-path tests/disposable-rust/Cargo.toml`.
The harness imports the **production** controller, gateway, and HTTP handler
source files by path. Its core/gateway tests use actual public Rust dependencies
and fixture runtime/model/MCP services, without the full management workspace's
private Gitea A2A dependency. The lockfile starts from the management lock's
public package versions and adds the public timezone/archive dependencies.

The HTTP seam supplies a minimal `AppState` and operator-role type to compile
and exercise the real router/handlers. Those dependency doubles do not test the
full management auth middleware, binary wiring or private A2A implementation.
The normal workspace build remains a required independent check on a machine
with access to the existing Gitea dependency. This harness does not replace it.

No KVM, host firewall edits, real credentials, Studio requests, or GitHub issue
publication occur in portable tests. Use the opt-in Ubuntu acceptance harness
for actual guest/network/runtime evidence.

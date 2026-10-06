# Ubuntu PC deployment

The checkout is `~/agentic-sandbox`. Root executes a reviewed, root-owned copy in
`/opt/agentic-sandbox/releases/RELEASE_ID`, rather than mutable home code. State and
baseline live in `/var/lib/agentic-sandbox`; configuration in `/etc/agentic-sandbox`.
No host Docker is needed. Run each stage deliberately:

```sh
sudo bash deploy/local-ubuntu/host-packages.sh
# Build as the ordinary user, not root.
cargo build --locked --release --manifest-path management/Cargo.toml --bin agentic-mgmt
sudo bash deploy/local-ubuntu/stage-release.sh "$PWD" \
  "$PWD/management/target/release/agentic-mgmt" RELEASE_ID
sudo python3 /opt/agentic-sandbox/current/deploy/local-ubuntu/configure-service.py
sudo systemctl enable --now agentic-local.service
```

Dashboard: `127.0.0.1:8122`. Agent listeners remain loopback-only; the separate,
authenticated guest gateway uses 8123. Publish only a new HTTPS port through
Tailscale Serve after inspecting existing routes; preserve them. Do not use Funnel
or reset Serve. The root-only admin token is `/etc/agentic-sandbox/operator-token`;
setup never prints it. Existing configuration is refused unless `--replace-config`
is explicit. Enter `TENSORFOLD_API_KEY=...` privately into root-owned mode-0600
`/etc/agentic-sandbox/model-secret.env` and restart the service. The configured
`studio` preset uses exactly `swift-1.5` at `https://ai-api.ashersuter.com/v1`.
Never put secrets in Git or terminal arguments. Exa MCP is built in; optional
GitHub tokens are saved through the authenticated UI.

## Baseline after BIOS SVM enablement

The dashboard can run before `/dev/kvm` and the baseline exist. VM startup fails
closed; there is no container or emulation fallback. After enabling BIOS SVM:

```sh
sudo python3 /opt/agentic-sandbox/current/deploy/local-ubuntu/build-baseline.py
sudo env DISPOSABLE_BASE_IMAGE=/var/lib/agentic-sandbox/baselines/ubuntu-24.04-opencode.qcow2 \
  bash /opt/agentic-sandbox/current/scripts/disposable-vm.sh check
```

Preparation uses one 4-GiB/two-vCPU guest with QEMU user-mode internet, without
starting libvirt NAT or changing global firewall rules. Downloads pin Ubuntu,
OpenCode 1.18.35, Gitleaks 8.30.1, Trivy 0.75.0 and Semgrep rules by checksum.
Semgrep 1.179.0 is installed from PyPI. Ubuntu packages, Semgrep dependencies,
BusyBox and Trivy databases are captured at preparation time: this is a fixed
recipe, not a bit-identical build. Package inventory/container digest are recorded.

The read-only standalone qcow2 has OpenCode's bundled OpenAI-compatible adapter,
Docker, Git, scanners/rules/databases and cached `busybox:1.36`. OpenCode model
configuration initializes in the runtime HOME/XDG layout with a fake local
endpoint; preparation sends no model request and embeds no real secrets.
Each VM receives an 80-GiB sparse overlay. Temporary preparation disks are removed
on success/failure; a bounded root-only `/var/log/agentic-sandbox-baseline.log`
remains. Existing baseline replacement is refused; stop/delete its VMs first.
Runtime guests cannot download arbitrary packages; cache extra dependencies in a
future baseline. Real offline TUI/provider behavior still requires KVM acceptance.

## Removal

```sh
sudo python3 /opt/agentic-sandbox/current/deploy/local-ubuntu/uninstall.py --delete-data
```

Stops this app, confirms its VM/bridge/firewall cleanup, then removes the service,
trusted releases, baseline, audit data and tokens. Cleanup failure preserves
containment policy/disks and aborts removal. Omit `--delete-data` to retain data.
Shared packages, unrelated networks and other services remain. Remove
`~/agentic-sandbox` yourself, and disable only this app's Tailscale Serve port.

Acceptance requires KVM, a prepared baseline, usable model key, actual guest
PTY/OpenCode interaction, cached Docker execution, host/LAN denial and verified
overlay cleanup. An authenticated dashboard or portable tests alone do not prove
these VM properties.

# Ubuntu VM runtime

The runtime boots Small **8 GiB / two shared vCPU**, Medium **12 GiB / four shared vCPU**
workspaces or Security
**16 GiB / six shared vCPU** audits. Each gets an 80 GiB writable qcow2 overlay
on the same prepared Ubuntu base image. TensorFold/model inference stays on the
Mac Studio. Guests have OpenCode, broad shell/root tools, their own Docker daemon,
scanners and tests; no GPU passthrough, host home/project mounts, shared host
Docker/libvirt sockets or host SSH credentials.

## Controller, guest and cleanup

The Rust controller owns resource admission, lifecycle and endpoint grants.
`scripts/disposable-vm.sh` invokes the trusted host Python helper for libvirt,
bridges and nftables. Only controller UUID directories beneath its state root
are accepted. Never use runtime scripts or a base image supplied by an audited
repository.

Before boot, the runtime installs the host network policy. **Timed workspaces and
audits** also arm an independent root-owned systemd watchdog for their absolute
UTC deadline; timer failure rejects startup. **Keep until deleted** interactive
VMs have no automatic deadline/watchdog. The runtime creates a fresh overlay and
cloud-init seed, waits for qemu-guest-agent, and transfers bounded source/config
through that control channel. No general filesystem share or SSH service is used.
Boot readiness requires OpenCode and scanner binaries plus a functioning guest
Docker daemon; a booted kernel alone is not reported ready.

Interactive OpenCode runs on a real guest PTY. A guest HTTP console agent relays
bounded terminal output and input through the host gateway; the administrator
browser receives authenticated SSE. Detaching the browser preserves the guest
processes. Terminal restart launches OpenCode again inside the same VM. The
legacy HTTP `POST /messages` path sends bracketed-paste input through this console
rather than uploading a prompt file and invoking a separate agent.

Exa MCP is granted by default. An optional creation-time GitHub PAT enables
GitHub MCP through host-only credential injection. Grants refresh the guest
configuration; **restart the OpenCode TUI to load changed endpoint configuration**.
An audit does not reload grants while executing. Gateway revocation takes effect
immediately, including active streams, independently of TUI configuration. It
cannot retract requests already delivered to an upstream service.

Cleanup quiesces an interrupted provisioner using a Linux pidfd and recorded
process start-time before querying libvirt. A libvirt query failure is a cleanup
failure, never evidence that a VM vanished. After confirmed destruction it removes
the definition, bridge, nft tables, overlay, seed and staging files. Interactive
deletion additionally purges terminal/workspace/output/credential content, retaining
only bounded metadata. The base image remains. Audit reports are separately
bounded and retained for host validation; guest success alone cannot bypass
cleanup or establish complete coverage. Failed cleanup retries and blocks new
admissions until containment is confirmed.

## Host-enforced network boundary

Four network slots use separate /30 bridges by default:

| Slot | Host gateway | Guest |
| --- | --- | --- |
| 0 | 192.0.2.1 | 192.0.2.2 |
| 1 | 192.0.2.5 | 192.0.2.6 |
| 2 | 192.0.2.9 | 192.0.2.10 |
| 3 | 192.0.2.13 | 192.0.2.14 |

There is no general DHCP, DNS, NAT or forwarding. Host nft bridge policy allows
ARP and guest IPv4 TCP only to its distinct workload gateway port (default 8123).
Other frames, including IPv6, are dropped; host inet rules deny other services
and routed traffic on those bridges. Guest root can flush its own firewall but
cannot change host policy. Existing host rules may reject even permitted relay
traffic; that fails closed.

The gateway separately enforces capabilities, exact destination/method/path
policy, DNS pinning, redirect rejection, credentials and stream revocation.
Model/MCP upstream secrets remain on the host. The guest receives only its scoped
capability. Timed capabilities expire with the session; until-deleted capabilities
remain valid until explicit revoke/deletion. The management API is separate from
the guest workload port. MCP transport access does not constrain the upstream
server's tool semantics or the PAT's permissions.

## Prepared baseline and acceptance

The host needs Linux KVM/libvirt, nftables, systemd, Python 3 with pidfd support and
the tools checked by `disposable-vm.sh check`. Its administrator-owned immutable
Ubuntu baseline must contain cloud-init, qemu-guest-agent, pinned OpenCode with its
OpenAI-compatible adapter, Docker and scanners. Cache approved Semgrep rules,
Trivy databases and required dependency/container images: guests cannot download
arbitrary packages from the internet. OpenCode starts with a fresh HOME and a
host-generated configuration disabling provider fallback, sharing, updates and
subagents. These settings are not protection against guest root; host policy is.

Portable runtime tests perform no host operations:

```sh
python3 scripts/test-disposable-runtime.py
```

For real acceptance, use the designated Ubuntu PC with no production run and stop
the controller while the harness owns its state root. Start an operator-owned
HTTP fixture reachable from the host. The blocked target must actually respond
on the host; the indicated Docker image must already be cached in the baseline.
Keep workload port 8123 free for the temporary fake-token fixture.

```sh
sudo -E scripts/disposable-vm.sh check
sudo -E python3 scripts/disposable-kvm-acceptance.py \
  --acknowledge-test-vm \
  --blocked-target http://OPERATOR_FIXTURE_IP:18080/ \
  --docker-image busybox:1.36
```

The opt-in harness creates/removes only its own `asd-*` VM and policy resources.
It checks guest Docker/tools, permitted fixture traffic, blocked host/LAN,
management/metadata/direct IPv4/IPv6 traffic after guest root flushes its firewall,
and repeated VM/disk/network cleanup. It does not prove protection against a
hypervisor escape. Inspect host nft counters/packets independently when assessing
isolation; a compromised guest agent can misreport guest checks.

The actual Ubuntu PC, real guest PTY/OpenCode compatibility and Studio model
behavior remain untested by Mac fixture previews. Portable tests are not measured
KVM isolation evidence. Unused private SDK dependencies have been removed and
the full management native type-check passes. Linux compilation remains an
independent requirement. Deployment scripts are in `deploy/local-ubuntu`.

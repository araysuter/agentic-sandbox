# Disposable Ubuntu runtime

The new profile uses **16 GiB RAM, six shared vCPUs and an 80 GiB writable disk**.
The Studio serves TensorFold/model inference. This guest runs OpenCode, its broad
shell/root tools, guest Docker, scanners and tests. There is no GPU passthrough,
host checkout/home sharing, agentshare, host Docker socket, SSH host key or
GitHub token in the guest. Existing persistent VM profiles keep their behavior.

## How the runtime fits the controller

The Rust disposable-session controller owns admission, the absolute deadline,
endpoint grants and cleanup reconciliation. Its configured runtime command is
`scripts/disposable-vm.sh`. The trusted Linux host service needs permission to
manage libvirt, bridges and nftables; do not grant audited repository code those
permissions. Only controller-generated UUID directories directly beneath
`DISPOSABLE_STATE_ROOT` are accepted. Keep the entry point, Python helper,
baseline and state root administrator-owned. Never point this runtime at an
untrusted checkout's script.

`start` creates a new qcow2 overlay and cloud-init seed over an immutable prepared
Ubuntu baseline. Before creating a disk or booting, it arms a root-owned host systemd timer for
the absolute UTC deadline. Every cleanup path uses a Linux pidfd plus recorded start-time to kill an
interrupted provisioner and wait for its exit before querying libvirt. This
avoids PID-reuse signaling and restart/provisioning races. Its callback retries confirmed VM containment/cleanup even if the
management process has died. Failed cleanup restarts under systemd until it
succeeds; it does not release a false-success gate. It installs host bridge/nft policy **before boot**, defines a
KVM domain, waits for qemu-guest-agent and transfers bounded source/config files
through that guest control channel. No general filesystem mounts or SSH service
are used. The source archive has no `.git` credentials and is extracted only in
the guest. `status` reports actual harness completion; an OpenCode zero exit code
alone does not establish that its security report is complete. `collect` reads
only the fixed report name, with a 2 MiB bound. Host publication validates and
redacts that report separately.

Interactive prompts use `message`: the controller writes a bounded prompt file,
then the runtime transfers it atomically. The guest invokes one primary
OpenCode agent and continues the saved session. `logs` collects its bounded JSON
event transcript. Events and findings are separate formats. `grants` refreshes
the guest endpoint configuration for the next prompt; gateway revoke/expiry
terminates current streams independently. A newly added MCP is available on the
next prompt. Audit processes do not automatically reload newly added MCP config.

`stop` first queries libvirt successfully and confirms destruction. A daemon
query error is a cleanup failure, never proof that the guest disappeared. It
then removes this run's VM definition, bridge, nft tables, disk, seed and guest
state. It removes source and workload capability staging files; only explicitly
collected reports/transcripts and controller metadata remain. Errors are visible
and ownership stays held until the controller can reconcile them.

## Enforced network boundary

Each admitted run gets a dedicated bridge: host `192.0.2.1`, guest `192.0.2.2`,
`/30` by default. There is no DHCP/DNS/NAT forwarding. Host nft bridge prerouting
allows ARP and only guest IPv4 TCP to the **distinct workload gateway port 8123**;
other frames including IPv6 are dropped. Host inet input/forward chains deny
other host services, routing and return forwarding on that bridge. Guest root
can flush its own firewall, but cannot alter these host tables. An existing host
firewall may additionally reject the allowed gateway; that fails closed.

The gateway separately authenticates the guest capability and enforces approved
URL/grant scope, DNS pinning, redirect rejection, upstream credential delivery
and stream revocation. Network filtering is not the URL policy. No raw upstream
model/MCP secrets are written to cloud-init or argv. The scoped workload token
is delivered over the guest-agent channel; it grants only approved endpoints for
this session and expires at the controller deadline. Upstream model/MCP access
requires the gateway, including explicit grants for private Studio endpoints.
The management API remains separate from the workload port.

## Baseline and host configuration

Set `DISPOSABLE_BASE_IMAGE` to an absolute, standalone, root-owned qcow2 with no
writable group/world permissions. It must be readable by `libvirt-qemu` (or the
configured `DISPOSABLE_QEMU_USER`) through its parent directories. Prepare it
once, outside audit sessions, with Ubuntu cloud-init, Python 3, qemu-guest-agent,
Docker and pinned OpenCode, Semgrep CE, Gitleaks and Trivy versions. Enable
qemu-guest-agent and Docker; remove build credentials and machine/session state
before freezing it. Cache the approved offline Semgrep rules at
`/opt/disposable/semgrep-rules`, Trivy databases and any Docker image/test
packages required by your repo. Audit guests cannot install dependencies from
the public internet: pre-cache them or grant an explicitly mediated dependency
service. Do not enable a generic proxy or host package mount to work around this.

OpenCode runs from `/var/lib/disposable`, outside repository configuration
search, with a fresh HOME and inline configuration that selects only the exact
TensorFold model, disables sharing/updates/provider discovery and denies task
subagent delegation. Repository `.opencode` plugins are not loaded at startup.
These settings prevent accidental fallback, but are not a boundary against
malicious guest root; host policies provide that boundary. The prepared OpenCode
build must include its OpenAI-compatible adapter so it does not fetch a provider
package during an audit. Compatibility with the actual chosen model needs a
Studio acceptance run.

The host requires Linux pidfds (kernel 5.3+, Python 3.9+) and an active systemd system manager; timer arming failure prevents
VM startup. The host needs KVM/libvirt, qemu-img, cloud-localds, nft, iproute2, runuser and Python 3.
The state root/ancestor directories must allow qemu execute traversal (state
root 0711, session 0711); sensitive host files are 0600. The runtime verifies
that the qemu user can read the overlay and baseline before boot.
`DISPOSABLE_GATEWAY_IP`/`DISPOSABLE_GATEWAY_PORT` must match the workload listener;
use a dedicated otherwise-unused `/30`, first usable address, and a port other
than 8120–8122. The gateway listens on its configured workload address/port and
must be reachable after the bridge is created. `DISPOSABLE_STATE_ROOT` defaults
to `/var/lib/agentic-sandbox/disposable`. `disposable-vm.sh check` fails clearly
when required Linux/KVM/baseline support is absent; it never falls back to a
container. This PR does not configure the user's actual PC or Studio.

## Verification

Portable tests (no host operations):

```sh
python3 scripts/test-disposable-runtime.py
```

On the designated Ubuntu host, after configuration and with no production run,
stop the disposable controller (the harness exclusively locks its state root),
start an **operator-owned disposable HTTP fixture** on a reachable LAN address,
then run the acceptance harness. The `--blocked-target` must be reachable from
the host, so a blocked guest result cannot be credited merely to an absent
service. The baseline must cache the indicated Docker image. Port 8123 must be
free for this temporary fake-token fixture.

```sh
sudo -E scripts/disposable-vm.sh check
sudo -E python3 scripts/disposable-kvm-acceptance.py \
  --acknowledge-test-vm \
  --blocked-target http://OPERATOR_FIXTURE_IP:18080/ \
  --docker-image busybox:1.36
```

The opt-in harness creates/removes only its own `asd-*` VM and policy resources.
It checks guest Docker/tools, allowed fixture access, blocked host/LAN,
management, metadata and direct IPv4/IPv6 access after guest root flushes its
firewall, then repeated VM/disk/network cleanup and removal of its test UUID state, so
controller startup does not encounter an incomplete acceptance record. It does not prove resistance to
a hypervisor escape. A compromised qemu-guest-agent could lie about guest tests;
for stronger acceptance also inspect host nft counters and packets independently.
The portable tests are not evidence of measured KVM isolation. KVM acceptance,
real Studio inference, actual Orca tool-call quality and long-context memory
remain unverified on the development Mac.

OpenCode configuration/CLI contracts follow the official
[configuration](https://opencode.ai/docs/config/),
[agent](https://opencode.ai/docs/agents/) and
[CLI](https://opencode.ai/docs/cli/) documentation; pin and verify your baseline
version rather than assuming the model repository name proves compatibility.

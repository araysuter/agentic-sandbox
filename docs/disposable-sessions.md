# Local OpenCode workspaces and repository audits

The dashboard has two local flows. **Small workspaces** default to 8 GiB RAM,
two shared vCPUs. **Medium workspaces** use 12 GiB and four shared vCPUs and “Keep until deleted.” **Security audits** use 16 GiB, six
shared vCPUs and a scheduled deadline. The Ubuntu PC runs the VMs; TensorFold
and model weights stay on the Mac Studio. No guest GPU passthrough is needed.

## Interactive workspaces

Create a named workspace and open its browser terminal. It is a real guest PTY,
with keyboard input, resizing and streamed output over authenticated HTTP/SSE.
OpenCode and shell commands execute in the guest. Closing or detaching the
browser leaves the guest processes running; reconnect to continue. A terminal
process that exits can be restarted without replacing the VM.

One prepared Ubuntu base image backs separate writable overlays. Creating a
workspace creates a fresh disk, workspace and OpenCode home. “Keep until deleted”
preserves that VM until explicit deletion. A timed workspace is also available,
up to five hours. Deletion is destructive: the UI asks for confirmation, then
revokes access, stops the VM and purges its overlay, workspace, terminal output
and session credential. Only a bounded deletion receipt remains. The reusable
base image is kept.

Exa MCP is available by default through the host relay. Supply an optional GitHub
PAT when creating a workspace to enable GitHub MCP. The PAT is held on the host,
separately from session metadata, and injected only into the approved upstream
request. It does not become a guest environment variable or OpenCode secret.
MCP access can perform whatever tools the upstream server and token permit;
choose token permissions accordingly. Restart OpenCode to load added/changed
endpoint configuration; revocation is immediate at the host relay. Studio
credentials also stay on the host.

## Capacity and recovery

The global VM budget is **32 GiB RAM and eight shared vCPUs**:

| Active VMs | Fits? |
| --- | --- |
| Four Small workspaces: 32 GiB / 8 vCPUs | Yes |
| Two Medium workspaces: 24 GiB / 8 vCPUs | Yes |
| One audit: 16 GiB / 6 vCPUs | Yes |
| Small workspace + audit: 24 GiB / 8 vCPUs | Yes |
| Medium workspace + audit: 28 GiB / 10 vCPUs | No |

Admission fails immediately when the budget is unavailable, with no queue or
preemption. A scheduled audit is recorded as busy/skipped; delete a workspace
before its audit night if it would consume the required CPUs. Cleanup failures
block admissions until containment is confirmed. VM capacity does not promise
parallel model throughput: the Studio inference relay still bounds requests.

A running “Keep until deleted” interactive VM survives a management restart only
when the runtime and saved gateway state can be verified and restored. If recovery or guest tools fail, the workspace is marked unavailable and its disk and capacity stay reserved until explicit deletion. Timed/partial sessions and
interrupted audits are cleaned up rather than resumed.

## Scheduled repository audits

Add a repository, save its fine-grained GitHub token on the Ubuntu host, and place
a recurring event in the weekly calendar. Defaults are America/Detroit
01:00–06:00 on separate nights. No audit workflow, GitHub Actions runner or
submodule is needed.

```mermaid
sequenceDiagram
    participant UI as Dashboard calendar
    participant Host as Ubuntu management service
    participant GitHub
    participant VM as Fresh audit VM
    participant Studio as TensorFold
    UI->>Host: Save repository, host token and weekly event
    Host->>Host: Event due: reserve capacity or record busy skip
    Host->>GitHub: Resolve default branch to commit; download data
    Host->>VM: Pinned source and guest audit profile
    VM->>Studio: One OpenCode investigator through scoped relay
    VM->>VM: Scanners, tests and guest Docker
    VM-->>Host: Bounded report and coverage
    Host->>Host: Revoke access, destroy overlay, confirm cleanup
    Host->>Host: Validate and redact findings
    Host->>GitHub: Optionally publish 0–5 new deduplicated issues
    Host-->>UI: Status, sanitized report and issue links
```

Guest root cannot control the host firewall, management API or credentials. There
are no host project/home mounts, host Docker/libvirt sockets or persistent shared
agent homes. Model/MCP transport uses exact host-defined destinations; direct
host/LAN/internet access remains blocked by the runtime network policy.

Read [calendar timing and reporting](weekly-security-audits.md),
[API behavior](disposable-api.md), and
[Ubuntu runtime acceptance](disposable-runtime.md).

## Verification boundary

Mac previews and portable tests use fixture services. They do not establish real
Ubuntu KVM isolation, guest Docker/tool availability, PTY/OpenCode compatibility,
Studio checkpoint behavior or measured vulnerability-finding quality. The full
management native type-check passes after removing unused private SDK
dependencies. Linux compilation and actual Ubuntu/Studio acceptance are required
before operational use. The opt-in installer is in `deploy/local-ubuntu`.

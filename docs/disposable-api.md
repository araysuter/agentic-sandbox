# Disposable session API

The new profile is opt-in. It shares the existing Rust management server and dashboard, but uses a dedicated KVM runtime and a separate guest-only HTTP gateway. Existing persistent VM/container routes do not participate in this admission gate.

The default VM has **16 GiB RAM and six shared vCPUs**. This version fixes those resources instead of accepting arbitrary VM definitions. OpenCode, Docker and tests run in the guest; TensorFold and model weights remain on the Studio. There are no host filesystem mounts, host Docker sockets or guest GPU devices.

## Host-owned configuration

Set `DISPOSABLE_ENABLED=1`, an absolute `DISPOSABLE_RUNTIME_SCRIPT` pointing to this fork's `scripts/disposable-vm.sh`, `DISPOSABLE_STATE_ROOT`, and `DISPOSABLE_BASE_IMAGE`. The runtime preflight must succeed before an admission is reserved. The prepared base image contains the guest tooling described in the runtime guide; the controller does not install or configure the real host automatically.

The administrator API defaults to loopback when this profile is enabled. The guest plane defaults to `0.0.0.0:8123`, has **only gateway routes**, and uses session capabilities. The isolated VM bridge admits only that port. `DISPOSABLE_GATEWAY_BIND_IP` and `DISPOSABLE_GATEWAY_PORT` configure the listener; `DISPOSABLE_GATEWAY_IP` identifies its address on the isolated bridge (default `192.0.2.1`). Keep the administrative and guest ports different.

`AGENTIC_DISPOSABLE_ENDPOINTS_FILE` identifies an administrator-owned JSON array of endpoint presets. For example (replace both the Studio address and the actual served model alias):

```json
[
  {
    "id": "studio",
    "kind": "model",
    "model_name": "your-served-model-alias",
    "base_url": "http://192.168.1.20:8000/v1",
    "path_prefixes": ["/v1/chat/completions"],
    "methods": ["POST"],
    "allow_private": true,
    "credential_env": "STUDIO_API_KEY"
  },
  {
    "id": "research-mcp",
    "kind": "mcp",
    "base_url": "https://mcp.example.com/mcp",
    "path_prefixes": ["/mcp"],
    "methods": ["GET", "POST", "DELETE"],
    "allow_private": false,
    "credential_env": "RESEARCH_MCP_KEY"
  }
]
```

`model_id` in a session request selects the preset (`studio`); `model_name` is the exact alias OpenCode sends to TensorFold. Credentials are loaded on the host, injected by the relay, and never serialized into the guest configuration. A granted MCP URL is not a guarantee that its tools are read-only: use appropriate server-side tool and credential scopes.

Weekly audits require a separate administrator-owned `AUDIT_REPOSITORIES_FILE`. Missing configuration denies all audit repositories. Each entry selects permitted workflow refs and guest-only commands as **argv arrays**:

```json
{
  "araysuter/TensorFold": {
    "allowed_refs": ["refs/heads/main"],
    "audit_profile": {
      "scanners": ["semgrep", "gitleaks", "trivy"],
      "test_commands": [["python3", "-m", "pytest", "tests/portable"]],
      "scope": [],
      "exclusions": []
    }
  }
}
```

An omitted scanner list defaults to all three tools. Commands execute only in the guest. The host also checks the submitted repository/ref; the trusted workflow and host runner authenticate the GitHub run context. Do not expose this administrator token to arbitrary workflows or fork pull requests.

## Routes and records

All the following routes start at `/api/v2/disposable-sessions` and require an explicit authenticated **administrator** identity. The legacy behavior that allows unauthenticated administrators when no token file exists is rejected here.

| Method and suffix | Behavior |
| --- | --- |
| `GET /` | Enabled status, session records and active admission ID. |
| `GET /presets` | Sanitized preset metadata, resource defaults and duration limit. |
| `POST /` | Reserve a session; `202` on admission, `409` immediately when another session owns the gate. |
| `GET /{id}` | State, deadline, error and profile policy status. |
| `DELETE /{id}` | Request cancellation; repeated calls are safe. |
| `PUT /{id}/source` | Upload an uncompressed tar archive for a reserved repository session and begin provisioning. |
| `GET /{id}/report` | Collected JSON report, retained after VM destruction. |
| `GET /{id}/output` | Bounded text output with common credential patterns redacted. |
| `POST /{id}/messages` | Send an interactive prompt, at most 64 KiB, to the guest OpenCode runner. |
| `GET /{id}/grants` | Current endpoint grants. |
| `POST /{id}/grants` | Grant a configured endpoint preset until the session deadline or an earlier expiry. |
| `DELETE /{id}/grants/{grant_id}` | Revoke a grant and terminate its active relay streams. |

An interactive request:

```json
{"kind":"interactive","duration_seconds":3600,"memory_mb":16384,"vcpus":6,"model_id":"studio"}
```

An audit request includes `repository`, its full 40-character `commit`, `ref_name`, `run_id` and a UTC RFC3339 `deadline`. The host injects `audit_profile`; callers cannot provide arbitrary host runtime commands or profile overrides. Audit admission is restricted to **01:00–06:00 America/Detroit**, including DST, and reserves 300 seconds for collection and cleanup. Delayed jobs cannot acquire another five hours after their scheduled window.

Repository sessions start in `awaiting_source`. The host rejects tar links, special files, absolute/traversing paths, `.git` contents, and archives exceeding 100 MiB transfer or expanded-file limits. This endpoint accepts data, never a path to a host directory. Interactive sessions without a repository start immediately.

Endpoint grant requests have the shape:

```json
{"preset_id":"research-mcp","expires_at":"2026-10-07T08:00:00Z"}
```

Grants work only while a session is running. New MCP configuration reaches interactive OpenCode on its next prompt; revocation takes effect immediately at the relay, including existing streams. Endpoint additions do not restart a currently executing audit.

## Lifecycle and failure behavior

Typical states are `awaiting_source → starting → running → collecting → cleaning → completed`. Cancellation ends in `cancelled`; workload failures or deadline-forced partial audits end in `failed`. A `cleanup_failed` record **retains the global admission gate** and retries containment. The gate is released only after runtime destruction succeeds and its terminal state is recorded durably. Issue publishing uses a separate per-repository lock.

The host monitors provisioning independently: a cancel or workload cutoff terminates the live runtime process. Its subprocesses use Linux parent-death signals, and cleanup quiesces a matching recorded provisioner through a pidfd before destroying VM/network resources. On management restart, active or partly recorded sessions are destroyed rather than resumed. The runtime additionally arms a host-owned cleanup deadline; guest root cannot extend it. No guest-produced success claim bypasses containment. Deadline-forced reports are marked partial rather than complete.

Repeated audit requests with the same repository, run ID, commit and ref return the existing record. Reusing a run ID for a different commit/ref is rejected. Source uploads occur only while `awaiting_source`.

Control metadata and collected reports remain under the host state root for retry, debugging and private review; `DELETE` cancels the run rather than erasing that history. Treat reports as sensitive host data. The UI's text redaction is defense in depth, not a promise to recognize every possible secret. Guest model/MCP capabilities expire and are revoked before VM deletion. The issue publisher applies its own report validation, sensitivity policy, deduplication and weekly issue limit.

`runtime_confirmed` means the configured runtime successfully completed provisioning/preflight checks. It is not a claim that KVM escape resistance, your TensorFold endpoint, or the exact OrcaSAQ conversion has been validated on this Mac. Run the Ubuntu acceptance harness before enabling scheduled audits.

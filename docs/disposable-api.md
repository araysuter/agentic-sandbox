# Local VM and audit API behavior

The dashboard uses the existing Rust management service. All routes below require
an explicit authenticated **administrator**; a guest capability never authorizes
management. Existing legacy persistent VM/container routes retain their separate
behavior. Runtime installation and acceptance are documented in the
[runtime guide](disposable-runtime.md).

## Workspaces: `/api/v2/disposable-sessions`

| Method and suffix | Behavior |
| --- | --- |
| `GET /` | Session records, active IDs and resource budget/usage. |
| `GET /presets` | Sanitized model/MCP presets, Small/Medium/Security resource choices and lifetime defaults. |
| `POST /` | Create a workspace or legacy external audit; `202`, or immediate `409` when capacity cannot fit it. |
| `GET /{id}` | State, lifetime/deadline, errors and policy status. |
| `DELETE /{id}` | Destructive workspace deletion or audit cancellation; repeated calls are safe. |
| `PUT /{id}/source` | Bounded plain-tar upload for an awaiting-source session. |
| `GET /{id}/terminal` | Authenticated SSE snapshots of the real guest terminal. |
| `POST /{id}/terminal` | Attach, input, resize, detach or restart the guest terminal process. |
| `GET /{id}/output` | Bounded legacy text output. |
| `POST /{id}/messages` | Legacy bounded interactive prompt path. |
| `GET /{id}/report` | Bounded collected audit JSON after VM teardown. |
| `GET /{id}/grants` | Session endpoint grants. |
| `POST /{id}/grants` | Grant a configured preset, optionally expiring earlier than the session. |
| `DELETE /{id}/grants/{grant_id}` | Revoke access and terminate its active relay streams. |

A default Small workspace request:

```json
{"kind":"interactive","name":"Build workspace","lifetime":"until_deleted","memory_mb":8192,"vcpus":2,"model_id":"studio"}
```

Medium accepts `12288` MiB / `4` vCPUs and Security accepts `16384` MiB / `6`
vCPUs; audits require Security. The global budget is `32768` MiB / `8` vCPUs.
Four Small workspaces or two Medium workspaces fit. A Small plus an audit fits;
a Medium plus an audit exceeds CPU capacity. Cleanup failures block admission.
These are shared vCPUs, not dedicated physical cores or a model-throughput claim.

`until_deleted` is interactive-only and has no deadline. `timed` requires a
bounded duration up to five hours. The UI confirms destructive deletion; the API
treats `DELETE` itself as authorization to destroy the workspace. After verified
containment, interactive disk/workspace/output/credential files are purged; the
base image and a bounded deletion receipt remain.

The optional creation field `github_token` enables the built-in GitHub MCP
preset. HTTP handling removes it before deserializing/persisting session
metadata, then saves the credential in a separate protected host file. Responses,
guest environment and OpenCode configuration never contain the PAT. Exa MCP is
a built-in default grant. Other grants select host-configured exact destinations,
methods and path scopes; `model_id` selects the preset, whose `model_name` is the
actual served Studio alias. Upstream credentials are injected on the host.

Endpoint configuration updates reach the guest, but require restarting the
OpenCode TUI to take effect. Revocation remains immediate at the host relay.

The terminal is a guest PTY, not a host shell. SSE uses authenticated fetch so
operator tokens stay out of URLs. One browser owns input at a time; detach
releases its lease while guest processes keep running. Reconnection returns the
bounded output tail and reports truncation when necessary. Restart starts a new
terminal process within the existing VM. Grant revocation stops new requests and
closes streams; it cannot retract a request already delivered upstream. An MCP
transport grant does not restrict what tools that server/token can perform.

## Repository calendar: `/api/v2/local-audits`

| Method and suffix | Behavior |
| --- | --- |
| `GET /` | Repository events, credential status, next starts, history and audit capacity status. |
| `POST /` | Save repository, host token and recurring weekly event. |
| `PUT /{id}` | Replace settings; omitted/blank token preserves its saved credential. |
| `DELETE /{id}` | Remove future schedule and credential; `409` while its run is active. |
| `POST /{id}/run` | Run now for the configured event duration, without queuing when busy. |
| `POST /runs/{id}/cancel` | Cancel a run and its VM. |
| `GET /runs/{id}/report` | Validated sanitized report, when available. |

Each repository record contains `repository` (`owner/name`), `model_id`,
`enabled`, `publish_issues`, a weekly `schedule`, and a bounded guest-only
`audit_profile`. Creation requires `github_token`; update may replace it.
`schedule` contains `weekday` (Monday=0 to Sunday=6), `start_time`/`end_time`
(`HH:MM`) and IANA `timezone`. Events are on one day, ten minutes to five hours;
defaults are 01:00–06:00 America/Detroit. Only GitHub's verified current default
branch is supported. Test commands are argv arrays run only in the guest.

Credentials are host files mode 0600 inside protected directories mode 0700. API
responses expose only `credential_configured`. Editing/deleting an active
repository is blocked; changing settings never silently alters a running VM.
Repository deletion removes its credential and future events while retaining
bounded run history. No repository workflow or GitHub Actions runner is involved.

The older external audit HTTP admission retains its separate host repository/ref
allowlist and overnight policy. The local scheduler uses a crate-private admission
path with the authenticated saved repository policy and absolute event end;
external callers cannot supply arbitrary profiles or bypass that policy.

## Lifecycle and retention

Workspace states include `awaiting_source → starting → running → cleaning`, then
`deleted`, `cancelled` or `failed`. Audits additionally collect reports and expose
local preparation/publication states. `cleanup_failed` retains containment and
resource ownership while retrying; successful guest output never releases it.

A running `until_deleted` workspace is recovered after management restart only
if runtime and saved gateway/capability state verify successfully. If recovery or
guest tools fail, its disk and capacity remain reserved in `unavailable` state
until explicit deletion. Timed sessions and interrupted audits are cleaned up, never resumed
or automatically replayed. A failed/cutoff audit may receive bounded offline
JSON validation after its deadline; that does not extend VM/model work or permit
GitHub writes after the deadline.

Metadata history is bounded to 200 terminal records, and collected reports are
bounded to 2 MiB. Interactive deletion purges its content; retained audit reports
remain sensitive protected host data until history retention removes them. Raw
source uploads reject links, special files, traversal, `.git` contents and archives
exceeding the 100 MiB transfer/expanded bounds. Source is data, never a path to a
host directory.

`runtime_confirmed` records runtime preflight/provisioning evidence, not proof of
KVM escape resistance or Studio model compatibility. Portable tests and Mac UI
previews use fixtures. Unused private SDK dependencies have been removed; the
full management native type-check passes. Linux compilation and actual
Ubuntu/Studio acceptance remain separate validation requirements.

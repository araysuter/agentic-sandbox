# Repository audits from the UI

Add a repository to the dashboard, save a fine-grained GitHub personal access
token on the Ubuntu host, and place a recurring audit event in the weekly
calendar. The default is **01:00–06:00 America/Detroit**; choose a separate night
for each repository. The event range is editable, from ten minutes to five hours. GitHub
Actions, a self-hosted Actions runner and a repository submodule are not part of
this flow.

## How the pieces work together

```mermaid
sequenceDiagram
    participant UI as Weekly calendar
    participant Host as Ubuntu management service
    participant GitHub
    participant VM as Fresh 16 GiB / 6 vCPU VM
    participant Studio as TensorFold model
    UI->>Host: Save repo, credential and repeating event
    Host->>Host: Event due: admit or record busy skip
    Host->>GitHub: Verify default branch; resolve commit; download archive
    Host->>VM: Pinned source + guest audit profile
    VM->>Studio: One OpenCode agent through scoped host relay
    VM->>VM: Scanners, tests and reproductions with guest Docker
    VM-->>Host: Bounded findings and coverage report
    Host->>Host: Revoke access; destroy VM; confirm cleanup
    Host->>Host: Validate and redact retained findings
    Host->>GitHub: Optionally create or update validated issues
    Host-->>UI: Run status, coverage and issue links
```

The service resolves the current default branch when the event runs. It pins
the resulting commit for source and report provenance. Source is downloaded and
repacked as bounded data on the host, without extracting it or running repository
code there. The VM gets a fresh disk, workspace and OpenCode home. TensorFold
and model weights stay on the Studio; the Ubuntu guest runs OpenCode, Semgrep
CE, Gitleaks, Trivy, tests and its own Docker daemon.

The local worker is `scripts/security-audit/local_audit_worker.py`. Rust owns
scheduling, admission, deadlines and lifecycle; the worker handles GitHub source
preparation and validated publication. It reuses the existing report validator
and publisher rather than treating OpenCode's terminal event stream as a
findings report.

## Calendar timing and overlap

Each repository has one weekly event, with a selected weekday, IANA timezone and
same-day start/end time, between ten minutes and five hours. The dashboard
defaults to America/Detroit 01:00–06:00 and suggests the first unused night when
adding a repository. You can change it; overlapping events are not queued.

The management service checks due events every 20 seconds. A start can be up to
60 seconds late; it is not an exact-time alarm. Later missed occurrences are not
backfilled or queued. The Ubuntu host and management service must remain running
for scheduled starts. Busy starts are recorded as skipped, without retrying later
that night. Audits use the shared 32 GiB / eight-vCPU budget. One Small
workspace (8 GiB / two vCPUs) can coexist with the audit. One Medium workspace
(12 GiB / four vCPUs) leaves too few CPUs; delete it before the scheduled start.
Four Small workspaces or two Medium workspaces fit. Overlapping audits are
still skipped. Cleanup failures block
admission until verified.

The event end is the absolute deadline. Delayed preparation reduces the usable
audit time instead of extending it. The controller reserves 300 seconds for
collection and cleanup, and the independent host watchdog enforces destruction.
The gate stays occupied if cleanup fails; successful guest output does not bypass
that condition.

A repeated daylight-saving wall time uses its first occurrence. Actual elapsed
time is capped at five hours, so the default fall-back 01:00–06:00 event ends at
05:00 local time that night. A nonexistent spring-forward start or end is
skipped. Persisted occurrence markers prevent a weekly event being replayed
after restart. Active interrupted audits are
cancelled and recorded as interrupted rather than resumed; inspect any partial
publication before running again. “Run now” starts at the current time for the
configured event duration, subject to the same busy rejection and containment.

## Tokens and repository settings

Use a fine-grained token limited to the selected repositories, with repository
contents read and issues write permissions when automatic issue publication is
enabled. Save it through the authenticated administrator UI. The credential
is stored on the Ubuntu host in an owner-only file (0600) inside protected
service storage (0700). API responses expose credential status, never the saved
token. The token is not copied into the guest, prompts, source archive, process
arguments or run output.

The host verifies GitHub's repository identity, default branch and visibility.
Only the verified default branch is supported in this local flow. Model and
remote MCP destinations remain host-defined endpoint presets; adding a GitHub
repository does not grant arbitrary guest internet access or access to the
Studio's other services.

Issue publication can be disabled for report-only audits. Pause an event to stop
future scheduled starts. Editing or deleting repository settings is blocked
while its run is active; cancel the run and wait for containment first. A running
VM uses its admitted configuration and absolute deadline. Cancellation cannot
retract an API request that GitHub has already received.

## Reports and issue publication

The host validates the versioned report against the pinned repository, commit
and source path manifest. Findings need location, impact, concrete evidence,
suggested fix and a validation flag. The flag is the investigator's assertion,
not independent human review. Scanner warnings without supporting evidence do
not become automatic issues. Completion is `complete`, `partial` or `failed`,
with skipped/failed coverage explicit. A partial report leaves the local run
marked failed. Validated findings from an otherwise completed VM can still be
published if enabled. A VM that fails or is cut off does not publish issues;
its available report is validated offline for private review, including after
the deadline. This bounded host-only step reads no credential, starts no VM,
and makes no network requests. Cancellation suppresses publication, and original bounded
reports can remain in protected controller storage even when no sanitized UI
report was produced.

With publication enabled, the publisher creates **zero to five new issues per
repository per ISO week**, using the run's America/Detroit start date. It updates
existing fingerprints, including previously closed issues, and retains further
findings in the report. Pagination, bounded rate-limit retries, per-repository
publication locks and reconciliation after ambiguous create responses prevent
blind duplicate POST retries. Partial publication preserves the issue links
already returned by GitHub.

Sensitive findings remain for private host review, even for private repos.
High/critical findings in public repositories default to private review. The
publisher rechecks visibility in case the repository became public during a run.
Common token/private-key patterns are redacted; sensitive titles, paths and
exploit details are withheld from UI-safe reports. Redaction cannot recognize
every possible secret representation, so keep unnecessary secrets out of the
guest and model context.

The staged source archive is removed after transfer or failure. Run files stay
in protected host storage: pinned source identity, bounded source
manifest, original report, sanitized report and publication result. No Actions
artifacts are uploaded. Audits do not fix source, push commits or open PRs in the
audited repository. The service retains the latest 200 run records and removes
local artifacts when older terminal records are pruned.

## Validation boundary

Portable scheduler, controller, worker and dashboard tests use fixture services
and publish no real issues. Actual KVM/network isolation, baseline tooling,
OpenCode interoperability and the Studio model need the separate
[Ubuntu acceptance run](disposable-runtime.md). Unused private SDK dependencies
have been removed and the full management native type-check passes. Linux
compilation remains an independent requirement. The opt-in installer is in
`deploy/local-ubuntu`; it does not create repository schedules automatically.

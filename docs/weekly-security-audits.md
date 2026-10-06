# Weekly repository audits

Each repository has its own small workflow; no submodule or central scheduling repo is needed. Copy `examples/weekly-security-audit.yml`, replace both SHA placeholders with the same reviewed commit of this fork, and choose a different local weekday for each repo. The reusable workflow checks out **only this pinned harness**, on the trusted Ubuntu host. Audited source is downloaded as data from GitHub at the exact commit and repacked without extracting it on the host. Builds, hooks, scanners, reproductions and Docker run only inside the disposable guest.

The path is:

```text
Repo schedule/manual dispatch → dedicated self-hosted runner
  → host Python adapter → Rust management admission (409 if busy)
  → fresh 16 GB / 6 vCPU KVM guest → one OpenCode audit agent
  → host-validated/redacted JSON → repository issues + Actions artifacts
  → revoke access / destroy guest / release host capacity
                          ↕ narrow inference gateway
                    Studio TensorFold API
```

## Scheduling and runner trust

The two UTC cron entries account for America/Detroit daylight saving time. The adapter compares the triggering cron with the UTC offset at the first local 1 AM of that date, skipping the alternate entry. A delayed correct entry remains eligible until the cutoff; the repeated fall-back 1 AM does not select both entries. Manual runs are allowed only from 1–6 AM. Both adapter and controller enforce the same 6 AM cutoff, with 300 seconds reserved for collection/cleanup; a late run never gets five extra hours. GitHub schedules are best effort, not an exact start guarantee.

Provision an explicitly trusted runner carrying `isolated-security-audit`. Restrict runner access and the controller repository allowlist to approved repositories/default branches. Require review of workflow changes and pin reusable workflow/action revisions. A runner label does not authenticate a job. Do not expose this runner to public fork PRs or untrusted workflows: GitHub executes caller workflow YAML on the host before the adapter can reject it. The reusable workflow rejects events other than schedule/manual dispatch and the adapter checks the default branch, but these are additional checks, not a substitute for runner/workflow authorization.

Host admission coordinates all repositories and dashboard sessions. A busy admission returns 409; the adapter does not retry it, preempt the active run or queue locally. GitHub itself may queue a job when every runner listener is busy. An additional idle trusted listener is needed to obtain prompt busy rejection while another listener is running the audit. Per-repo GitHub concurrency groups do not provide the global capacity lock.

## Host adapter and credentials

The Python 3.9+ stdlib adapter is `scripts/security-audit/audit_client.py`. It uses the per-job `GITHUB_TOKEN` with `contents: read` and `issues: write`, and a separate `HOST_AUDIT_TOKEN` for the locally bound controller. Neither token enters the guest, source tar, model context or report. `model_id` selects the operator-configured model/grant preset; no actual Studio address or credential is checked into the workflow. Controller URLs are restricted to loopback HTTP. Configure tokens only on the trusted host/Actions secret store; this PR does not provision runners or secrets.

Adapter contract:

1. `POST /api/v2/disposable-sessions` with audit identity, pinned commit, trusted default-branch ref, run ID, model preset, 16 GB / 6 vCPUs and absolute deadline; admission reserves capacity.
2. `PUT /{id}/source` with at most 100 MiB plain tar. The adapter removes GitHub's outer archive directory, rejects links, special files, traversal and duplicate paths, bounds compressed and decompressed bytes, and preserves only ordinary executable bits. It does not extract source locally. Safe guest extraction remains the controller/runtime's responsibility.
3. Poll `GET /{id}`. `cleanup_failed` is a failed run, never success. Obtain bounded findings from `GET /{id}/report` after completion.
4. Validate trusted repo/commit, schema, coverage, paths and field sizes; redact common token/private-key patterns. Publish and save selected outputs. Always request idempotent `DELETE /{id}`; the host watchdog remains responsible even if this process disappears.

## Evidence, publication and private review

`findings.schema.json` describes the version-1 report; the executable host validator additionally enforces total bytes, path safety, line ranges, unique fingerprints and trusted identity. OpenCode's event stream is not this report. Scanners and tests contribute evidence; unsupported warnings are not eligible for automatic issues. Completion remains `complete`, `partial` or `failed`, and skipped/failed coverage remains explicit. Partial runs may retain and publish validated findings while Actions records failure.

The publisher creates **zero to five new issues per repository per ISO week**, updates previously tracked fingerprints, and keeps additional findings in the report. It lists all issue pages including closed issues, uses exact repository-qualified fingerprint metadata headers, preserves an issue's original creation-week marker when updating, and reconciles ambiguous create responses before a retry can create another issue. API reads/updates use bounded rate-limit retries. A failed/uncertain creation exits for a later reconciliation rather than blindly repeating POST. A protected host-owned per-repository `flock` serializes publication across runner listeners and retries independently of VM teardown. Competing publication fails busy instead of queueing; the lock directory must be mode 0700 and owned by the runner (`AUDIT_PUBLISHER_STATE_DIR` can select it). Incremental publication checkpoints preserve issue URLs even if a later operation fails.

A finding must include path/lines, impact, concrete evidence, suggested fix and `validated: true`; this schema flag is the guest's assertion, not proof of independent human review. High/critical findings in public repositories default to private review even if the agent omitted the sensitive flag. Sensitive findings are held for operator review on the host rather than published as issues, even for private repos. Token-like content is redacted and automatically classified sensitive. Sensitive titles, paths and exploit details are also withheld from uploaded artifacts; the original bounded report remains in protected controller storage for review. Automated redaction is a defense against accidental copies, not a guarantee that every possible secret representation can be recognized. Configure the audit prompt and grant scopes to keep unnecessary secrets out of model/tool output.

The workflow uploads only `report.redacted.json`, `publication.json`, and `summary.md`, with 14-day retention. No raw scanner archives, terminal traces or arbitrary guest paths are uploaded. It never fixes source, pushes commits or opens PRs in an audited repository.

## Review checks

```sh
python3 -m unittest discover -s scripts/security-audit -v
```

Portable tests exercise source traversal/link/decompression limits, report identity/path/size rejection, redaction/private review, pagination and closed-issue deduplication, interrupted creation reconciliation, bounded rate-limit retries, the weekly five-issue cap, and DST/cutoff behavior. They use fake GitHub data and create no real issues. Actual KVM/network/Docker isolation and the Studio model require the separate Ubuntu acceptance harness; passing these portable tests does not establish either.

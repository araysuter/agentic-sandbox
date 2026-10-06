#!/usr/bin/env python3
"""Trusted host adapter. Repository code and all scanner/test commands stay in KVM."""
import argparse
from contextlib import contextmanager
import fcntl
import datetime as dt
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import re
import tarfile
import time
import urllib.error
import urllib.parse
import urllib.request
from zoneinfo import ZoneInfo

MAX_REPORT = 2 * 1024 * 1024
MAX_SOURCE = 100 * 1024 * 1024
REPO = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+\Z")
COMMIT = re.compile(r"[a-f0-9]{40}\Z")
FINGERPRINT = re.compile(r"[a-f0-9]{64}\Z")
TERMINAL = {"completed", "complete", "failed", "cancelled", "expired"}


class AuditError(Exception):
    pass


def checked_path(value):
    if not isinstance(value, str) or not value or len(value) > 1024:
        raise AuditError("Invalid report/source path")
    parts = value.split("/")
    if value.startswith("/") or "\\" in value or any(p in ("", ".", "..") for p in parts) or any(ord(c) < 32 for c in value):
        raise AuditError("Unsafe report/source path")
    return value


def redact(value):
    # Never intentionally transport real scanner secrets; also scrub common accidental copies.
    value = re.sub(r"(?i)(bearer\s+)[A-Za-z0-9._~+/=-]+", r"\1[REDACTED]", value)
    value = re.sub(r"\b(?:gh[pousr]_[A-Za-z0-9]{12,}|github_pat_[A-Za-z0-9_]+|AKIA[A-Z0-9]{16}|sk-[A-Za-z0-9_-]{16,})\b", "[REDACTED]", value)
    value = re.sub(r"(?is)-----BEGIN [^-]*PRIVATE KEY-----.*?-----END [^-]*PRIVATE KEY-----", "[REDACTED PRIVATE KEY]", value)
    value = re.sub(r"(?i)(password|secret|api[_-]?key|access[_-]?token)(\s*[:=]\s*)([\"']?)[^\s\"',;]+", r"\1\2[REDACTED]", value)
    return value


def clean_text(value, limit=16384):
    if not isinstance(value, str) or len(value.encode()) > limit:
        raise AuditError("Missing or oversized report text")
    if any(ord(c) < 32 and c not in "\n\t\r" for c in value):
        raise AuditError("Control character in report")
    return redact(value)


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise AuditError("Duplicate JSON object key")
        result[key] = value
    return result


def validate_report(raw, repository, commit, allowed_paths=None):
    if len(raw) > MAX_REPORT:
        raise AuditError("Report exceeds 2 MiB")
    try:
        data = json.loads(raw, object_pairs_hook=unique_object)
    except (ValueError, UnicodeError) as exc:
        raise AuditError("Invalid findings JSON") from exc
    if not isinstance(data, dict) or type(data.get("version")) is not int or data.get("version") != 1 or data.get("repository") != repository or data.get("commit") != commit:
        raise AuditError("Report identity/version mismatch")
    if set(data) != {"version", "repository", "commit", "completion", "coverage", "findings"}:
        raise AuditError("Unexpected report fields")
    if data.get("completion") not in ("complete", "partial", "failed"):
        raise AuditError("Missing audit completion status")
    findings = data.get("findings")
    if not isinstance(findings, list) or len(findings) > 200:
        raise AuditError("Invalid findings list")
    coverage = data.get("coverage")
    if not isinstance(coverage, dict) or set(coverage) != {"scanned_paths", "scanners", "tests", "skipped"}:
        raise AuditError("Missing coverage")
    paths = coverage.get("scanned_paths")
    if not isinstance(paths, list) or len(paths) > 2000:
        raise AuditError("Invalid coverage paths")
    clean = {"version": 1, "repository": repository, "commit": commit,
             "completion": data["completion"], "coverage": {"scanned_paths": [checked_path(p) for p in paths]}, "findings": []}
    for key in ("scanners", "tests"):
        items = coverage.get(key)
        if not isinstance(items, list) or len(items) > 200:
            raise AuditError("Invalid coverage tool list")
        clean["coverage"][key] = []
        for item in items:
            if not isinstance(item, dict) or set(item) != {"name", "status", "detail"} or item.get("status") not in ("passed", "failed", "skipped"):
                raise AuditError("Invalid coverage status")
            clean["coverage"][key].append({"name": clean_text(item.get("name"), 256), "status": item["status"], "detail": clean_text(item.get("detail"), 4096)})
    skipped = coverage.get("skipped")
    if not isinstance(skipped, list) or len(skipped) > 200:
        raise AuditError("Invalid skipped coverage")
    clean["coverage"]["skipped"] = [clean_text(item, 4096) for item in skipped]
    seen = set()
    for item in findings:
        if not isinstance(item, dict) or set(item) != {"fingerprint", "title", "path", "line_start", "line_end", "category", "severity", "impact", "evidence", "suggested_fix", "validated", "sensitive"} or not isinstance(item.get("fingerprint"), str) or not FINGERPRINT.fullmatch(item["fingerprint"]):
            raise AuditError("Invalid fingerprint")
        if item["fingerprint"] in seen:
            raise AuditError("Duplicate finding fingerprint")
        seen.add(item["fingerprint"])
        checked_path(item.get("path"))
        if allowed_paths is not None and item["path"] not in allowed_paths:
            raise AuditError("Finding path is absent from the staged commit")
        start, end = item.get("line_start"), item.get("line_end")
        if type(start) is not int or type(end) is not int or not 1 <= start <= end <= 10000000:
            raise AuditError("Invalid finding line range")
        if item.get("severity") not in ("critical", "high", "medium", "low") or type(item.get("validated")) is not bool or type(item.get("sensitive")) is not bool:
            raise AuditError("Invalid finding classification")
        finding = {k: item[k] for k in ("fingerprint", "path", "line_start", "line_end", "severity", "validated", "sensitive")}
        for key in ("title", "category", "impact", "evidence", "suggested_fix"):
            finding[key] = clean_text(item.get(key), 256 if key in ("title", "category") else 16384)
            if not finding[key].strip() or "<!-- agentic-sandbox" in finding[key]:
                raise AuditError("Empty finding evidence/description")
        # Never send a possible secret/leak to issues, including on private repos.
        if any(finding[k] != item[k] for k in ("title", "category", "impact", "evidence", "suggested_fix")):
            finding["sensitive"] = True
        clean["findings"].append(finding)
    return clean


class BoundedReader:
    def __init__(self, stream, limit):
        self.stream, self.remaining = stream, limit

    def read(self, size=-1):
        size = min(size if size >= 0 else self.remaining + 1, self.remaining + 1)
        data = self.stream.read(size)
        self.remaining -= len(data)
        if self.remaining < 0:
            raise AuditError("Expanded source stream exceeds limit")
        return data


def public_review_policy(report, private):
    # Public high-impact findings default to host review even if the agent omitted sensitivity.
    if not private:
        for finding in report["findings"]:
            if finding["severity"] in ("critical", "high"):
                finding["sensitive"] = True
    return report


def artifact_report(report):
    """Sensitive detail remains only in host-owned controller storage for private review."""
    safe = json.loads(json.dumps(report))
    for finding in safe["findings"]:
        if finding["sensitive"]:
            for key in ("title", "impact", "evidence", "suggested_fix", "category", "path"):
                finding[key] = "Withheld for private review"
    return safe


def stage_source(raw, include_paths=False):
    """Repack tarball into bounded regular files. No host extraction or hooks."""
    if len(raw) > MAX_SOURCE:
        raise AuditError("Compressed source too large")
    target = io.BytesIO()
    total, count, root, seen = 0, 0, None, set()
    try:
        with gzip.GzipFile(fileobj=io.BytesIO(raw)) as inflated, tarfile.open(fileobj=BoundedReader(inflated, MAX_SOURCE), mode="r|") as source, tarfile.open(fileobj=target, mode="w") as out:
            for member in source:
                parts = member.name.split("/")
                # GitHub archives contain one opaque top-level directory.
                if root is None:
                    root = parts[0]
                    checked_path(root)
                if parts[0] != root:
                    raise AuditError("Source archive has multiple roots")
                relative = "/".join(parts[1:]).rstrip("/")
                if not relative:
                    if not member.isdir():
                        raise AuditError("Invalid source root")
                    continue
                checked_path(relative)
                if member.isdir():
                    continue
                if not member.isfile() or member.issym() or member.islnk():
                    raise AuditError("Source links/special files are not supported")
                if relative in seen:
                    raise AuditError("Duplicate source path")
                seen.add(relative)
                total += member.size
                count += 1
                if total > MAX_SOURCE - 2 * 1024 * 1024 or count > 50000 or member.size < 0:
                    raise AuditError("Expanded source exceeds limit")
                item = tarfile.TarInfo(relative)
                item.size, item.mode, item.mtime = member.size, (0o755 if member.mode & 0o111 else 0o644), 0
                stream = source.extractfile(member)
                out.addfile(item, stream)
                if target.tell() > MAX_SOURCE:
                    raise AuditError("Staged source exceeds limit")
    except (tarfile.TarError, EOFError, OSError) as exc:
        raise AuditError("Invalid source archive") from exc
    if not count or target.tell() > MAX_SOURCE:
        raise AuditError("Empty/oversized source")
    return (target.getvalue(), seen) if include_paths else target.getvalue()


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class Http:
    def __init__(self, base, token, opener=None):
        self.base, self.token = base.rstrip("/"), token
        self.opener = opener or urllib.request.build_opener(NoRedirect())

    def request(self, method, path, body=None, raw=False, limit=MAX_REPORT):
        if not path.startswith("/") or path.startswith("//"):
            raise AuditError("Unsafe API path")
        payload = body if isinstance(body, bytes) else (json.dumps(body).encode() if body is not None else None)
        headers = {"Authorization": "Bearer " + self.token, "Accept": "application/vnd.github+json", "User-Agent": "agentic-sandbox-audit/1", "Content-Type": "application/octet-stream" if isinstance(body, bytes) else "application/json"}
        req = urllib.request.Request(self.base + path, data=payload, headers=headers, method=method)
        with self.opener.open(req, timeout=60) as response:
            data = response.read(limit + 1)
            if len(data) > limit:
                raise AuditError("API response exceeds bound")
            return data if raw else (json.loads(data) if data else None)


def read_retry(api, method, path, body=None, raw=False, limit=MAX_REPORT):
    for attempt in range(4):
        try:
            return api.request(method, path, body, raw, limit)
        except urllib.error.HTTPError as exc:
            if exc.code not in (429, 500, 502, 503, 504) and not (exc.code == 403 and exc.headers.get("Retry-After")):
                raise
            if attempt == 3:
                raise AuditError("API retry budget exhausted") from exc
            delay = exc.headers.get("Retry-After", str(2 ** attempt))
            exc.close()
            time.sleep(min(60, max(1, int(delay) if delay.isdigit() else 2 ** attempt)))
        except (urllib.error.URLError, TimeoutError):
            if attempt == 3:
                raise AuditError("API unavailable after bounded retries")
            time.sleep(2 ** attempt)


def all_issues(api, repository):
    result = []
    for page in range(1, 1001):
        items = read_retry(api, "GET", f"/repos/{repository}/issues?state=all&per_page=100&page={page}")
        if not isinstance(items, list):
            raise AuditError("Invalid GitHub issues response")
        result.extend(item for item in items if "pull_request" not in item)
        if len(items) < 100:
            return result
    raise AuditError("Issue pagination exceeds safety bound")


@contextmanager
def publication_lock(repository, state_root=None):
    """Serialize host publication independently of VM/model admission cleanup."""
    root = Path(state_root or os.environ.get("AUDIT_PUBLISHER_STATE_DIR", str(Path.home() / ".local/state/agentic-sandbox/audit-publication")))
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    stat = root.lstat()
    if root.is_symlink() or stat.st_uid != os.getuid() or stat.st_mode & 0o077:
        raise AuditError("Publisher state directory must be owned by the runner with mode 0700")
    path = root / (hashlib.sha256(repository.encode()).hexdigest() + ".lock")
    fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        stat = os.fstat(fd)
        if stat.st_uid != os.getuid() or stat.st_mode & 0o077 or stat.st_nlink != 1:
            raise AuditError("Unsafe publisher lock file")
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise AuditError("Repository publication is busy; active publication was not interrupted") from exc
        yield
    finally:
        os.close(fd)


def tracked_issue(issue, marker):
    return (issue.get("body") or "").split("\n", 1)[0] == marker


def issue_marker(repository, fingerprint):
    return f"<!-- agentic-sandbox:v1:{repository}:{fingerprint} -->"


def publish(api, report, private, week, checkpoint=None):
    repository = report["repository"]
    # Sensitivity overrides private visibility; raw secrets are never auto-published.
    eligible = [f for f in report["findings"] if f["validated"] and not f["sensitive"]]
    weekly_marker = f"<!-- agentic-sandbox-week:{week} -->"
    issues = all_issues(api, repository)
    by_marker = {issue_marker(repository, f["fingerprint"]): next((i for i in issues if tracked_issue(i, issue_marker(repository, f["fingerprint"]))), None) for f in eligible}
    created = sum((i.get("body") or "").startswith("<!-- agentic-sandbox:v1:" + repository + ":") and len((i.get("body") or "").split("\n")) > 1 and (i.get("body") or "").split("\n")[1] == weekly_marker for i in issues)
    published, deferred = [], []
    ranks = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    for finding in sorted(eligible, key=lambda f: (ranks[f["severity"]], f["fingerprint"])):
        marker = issue_marker(repository, finding["fingerprint"])
        previous = by_marker[marker]
        if not previous and created >= 5:
            deferred.append(finding["fingerprint"])
            continue
        path = urllib.parse.quote(finding["path"], safe="/")
        body = f"{marker}\n{weekly_marker}\n\nAudited commit: `{report['commit']}`; audit status: {report['completion']}.\n\nLocation: https://github.com/{repository}/blob/{report['commit']}/{path}#L{finding['line_start']}\n\nSeverity: **{finding['severity']}**; category: {finding['category']}.\n\nImpact: {finding['impact']}\n\nEvidence / reproduction:\n\n{finding['evidence']}\n\nSuggested fix:\n\n{finding['suggested_fix']}\n"
        payload = {"title": f"[Security audit] {finding['title']}", "body": body}
        if previous:
            # Keep creation's original weekly marker; updates must not consume this week's new-issue budget.
            original_weeks = re.findall(r"^<!-- agentic-sandbox-week:[^>]+ -->$", (previous.get("body") or "").split("\n")[1] if len((previous.get("body") or "").split("\n")) > 1 else "")
            if original_weeks:
                payload["body"] = body.replace(weekly_marker, original_weeks[0])
            issue = read_retry(api, "PATCH", f"/repos/{repository}/issues/{previous['number']}", payload)
        else:
            # Never blindly retry issue creation after an ambiguous response.
            try:
                issue = api.request("POST", f"/repos/{repository}/issues", payload)
            except (urllib.error.URLError, TimeoutError, urllib.error.HTTPError) as exc:
                matches = [i for i in all_issues(api, repository) if tracked_issue(i, marker)]
                if not matches:
                    raise AuditError("Issue creation uncertain; rerun to reconcile before creating again") from exc
                issue = matches[0]
            created += 1
        published.append({"fingerprint": finding["fingerprint"], "url": issue["html_url"], "number": issue["number"],
                          "action": "updated" if previous else "created", "title": payload["title"]})
        if checkpoint:
            checkpoint({"published": published, "deferred": deferred, "private_review": [f["fingerprint"] for f in report["findings"] if f["sensitive"]], "repository_private": private})
    return {"published": published, "deferred": deferred, "private_review": [f["fingerprint"] for f in report["findings"] if f["sensitive"]], "repository_private": private}


def audit_deadline(now, scheduled=False, schedule_expression=None):
    local = now.astimezone(ZoneInfo("America/Detroit"))
    if not 1 <= local.hour < 6:
        if scheduled:
            return None
        raise AuditError("Manual audits must arrive within 1–6 AM America/Detroit")
    # Pick the UTC cron corresponding to the first local 1 AM of this calendar day.
    # This also avoids double admission on the repeated fall-back 1 AM hour.
    if scheduled:
        expression = re.fullmatch(r"0 ([56]) \* \* ([0-6])", schedule_expression or "")
        if not expression:
            raise AuditError("Scheduled audits require the documented 5/6 UTC weekday cron")
        canonical_start = local.replace(hour=1, minute=0, second=0, microsecond=0, fold=0)
        if int(expression[1]) != canonical_start.astimezone(dt.timezone.utc).hour or int(expression[2]) != local.isoweekday() % 7:
            return None
    deadline = local.replace(hour=6, minute=0, second=0, microsecond=0).astimezone(dt.timezone.utc)
    if (deadline - now).total_seconds() <= 300:
        raise AuditError("Insufficient time for collection and cleanup")
    return deadline


def repository_archive(api, repository, commit):
    # Resolve GitHub's redirect without ever forwarding a credential to a new host.
    try:
        return api.request("GET", f"/repos/{repository}/tarball/{commit}", raw=True, limit=MAX_SOURCE)
    except urllib.error.HTTPError as exc:
        if exc.code not in (301, 302, 307):
            raise
        target = exc.headers.get("Location", "")
        parsed = urllib.parse.urlsplit(target)
        if parsed.scheme != "https" or parsed.hostname != "codeload.github.com" or parsed.port not in (None, 443) or parsed.username or parsed.password:
            raise AuditError("Unexpected GitHub archive redirect") from exc
        # Private archive signed URL is transient and never logged or persisted.
        request = urllib.request.Request(target, headers={"User-Agent": "agentic-sandbox-audit/1"})
        with urllib.request.build_opener(NoRedirect()).open(request, timeout=60) as response:
            data = response.read(MAX_SOURCE + 1)
            if len(data) > MAX_SOURCE:
                raise AuditError("Archive exceeds bound")
            return data


def run(args):
    if not REPO.fullmatch(args.repository) or not COMMIT.fullmatch(args.commit):
        raise AuditError("Invalid trusted repository/commit")
    endpoint = urllib.parse.urlsplit(args.controller)
    if endpoint.scheme != "http" or endpoint.hostname not in ("127.0.0.1", "localhost", "::1") or endpoint.username or endpoint.password or endpoint.path not in ("", "/"):
        raise AuditError("Controller must be a loopback HTTP endpoint")
    deadline = audit_deadline(dt.datetime.now(dt.timezone.utc), args.scheduled, args.schedule_expression)
    if deadline is None:
        print("Skipping alternate DST cron or out-of-window scheduled arrival")
        return
    github = Http("https://api.github.com", os.environ["GITHUB_TOKEN"])
    controller = Http(args.controller, os.environ["HOST_AUDIT_TOKEN"])
    metadata = read_retry(github, "GET", f"/repos/{args.repository}")
    if args.ref != metadata["default_branch"]:
        raise AuditError("Only the default branch may use the trusted runner")
    now = dt.datetime.now(dt.timezone.utc)
    request = {"kind": "audit", "repository": args.repository, "commit": args.commit, "run_id": args.run_id, "ref_name": "refs/heads/" + args.ref, "deadline": deadline.isoformat(), "duration_seconds": min(18000, int((deadline - now).total_seconds())), "memory_mb": 16384, "vcpus": 6, "model_id": args.model_id}
    # Admission is immediate. In particular do not retry HTTP 409 or queue locally.
    session = controller.request("POST", "/api/v2/disposable-sessions", request)
    identifier = session["id"]
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", identifier):
        raise AuditError("Unsafe session ID")
    base = "/api/v2/disposable-sessions/" + identifier
    output = Path(args.output)
    output.mkdir(parents=True, exist_ok=True, mode=0o700)
    try:
        source, source_paths = stage_source(repository_archive(github, args.repository, args.commit), include_paths=True)
        if session.get("state") == "awaiting_source":
            controller.request("PUT", base + "/source", source)
        while True:
            status = read_retry(controller, "GET", base)
            if status["state"] in TERMINAL:
                break
            if status["state"] == "cleanup_failed":
                raise AuditError("Host cleanup failed; admission remains blocked")
            if dt.datetime.now(dt.timezone.utc) >= deadline:
                controller.request("DELETE", base)
                raise AuditError("Host cutoff reached; session cancellation requested")
            time.sleep(10)
        raw = controller.request("GET", base + "/report", raw=True)
        report = public_review_policy(validate_report(raw, args.repository, args.commit, source_paths), bool(metadata["private"]))
        (output / "report.redacted.json").write_text(json.dumps(artifact_report(report), indent=2) + "\n")
        week = dt.datetime.now(ZoneInfo("America/Detroit")).strftime("%G-W%V")
        with publication_lock(args.repository):
            def save_publication(value):
                (output / "publication.json").write_text(json.dumps(value, indent=2) + "\n")
            publication = publish(github, report, bool(metadata["private"]), week, save_publication)
        (output / "publication.json").write_text(json.dumps(publication, indent=2) + "\n")
        summary = f"Security audit `{args.repository}` at `{args.commit}`: **{report['completion']}**. {len(publication['published'])} issues created/updated; {len(publication['deferred'])} additional validated findings retained; {len(publication['private_review'])} findings held for private review.\n"
        (output / "summary.md").write_text(summary)
        if os.environ.get("GITHUB_STEP_SUMMARY"):
            with open(os.environ["GITHUB_STEP_SUMMARY"], "a") as stream:
                stream.write(summary)
        if report["completion"] != "complete" or status["state"] not in ("completed", "complete"):
            raise AuditError("Audit is partial/failed; retained validated report and publication")
    finally:
        # Idempotent cancellation/reconciliation is host-owned; never release capacity here.
        controller.request("DELETE", base)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--controller", default="http://127.0.0.1:8122")
    parser.add_argument("--repository", required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--ref", required=True)
    parser.add_argument("--model-id", default="studio")
    parser.add_argument("--output", default="audit-output")
    parser.add_argument("--scheduled", action="store_true")
    parser.add_argument("--schedule-expression", default="")
    try:
        run(parser.parse_args())
    except (AuditError, urllib.error.URLError, KeyError, ValueError) as exc:
        # Do not echo server messages, URL query strings or credential-bearing request data.
        print("Security audit adapter failed: " + (str(exc) if isinstance(exc, AuditError) else type(exc).__name__))
        raise SystemExit(1)


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Local management helper: bounded GitHub data in, sanitized audit results out.

Only the host invokes this file. Credentials are read from an owner-only token
file and never included in arguments, source bundles, results, or errors. The
management service owns scheduling, VM admission, deadlines, and cancellation.
"""
import argparse
import datetime as dt
import json
import os
from pathlib import Path
import re
import stat
import sys
import tempfile
import urllib.parse
from zoneinfo import ZoneInfo

import audit_client as audit

MAX_JOB = 32768
MAX_TOKEN = 8192


def secure_read(path, limit, protected=False):
    if not isinstance(path, str) or not Path(path).is_absolute():
        raise audit.AuditError("Expected absolute host file path")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_nlink != 1:
            raise audit.AuditError("Unsafe host file")
        if protected and info.st_mode & 0o077:
            raise audit.AuditError("Credential/job file must be owner-only")
        with os.fdopen(fd, "rb", closefd=False) as stream:
            raw = stream.read(limit + 1)
        if len(raw) > limit:
            raise audit.AuditError("Host file exceeds bound")
        return raw
    finally:
        os.close(fd)


def output_root(value):
    if not isinstance(value, str) or not Path(value).is_absolute():
        raise audit.AuditError("Expected absolute run directory")
    root = Path(value)
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    info = root.lstat()
    if not stat.S_ISDIR(info.st_mode) or root.is_symlink() or info.st_uid != os.getuid() or info.st_mode & 0o077:
        raise audit.AuditError("Run directory must be owned by the service with mode 0700")
    return root


def write_file(path, raw):
    # Atomic replacement keeps checkpoints intact across a host/process crash.
    path = Path(path)
    if path.exists() or path.is_symlink():
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_nlink != 1 or info.st_mode & 0o077:
            raise audit.AuditError("Unsafe output file")
    fd, temporary = tempfile.mkstemp(prefix=".audit-write-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb", closefd=False) as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(fd)
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        os.close(fd)
        if os.path.exists(temporary):
            os.unlink(temporary)


def write_json(path, value):
    write_file(path, (json.dumps(value, indent=2) + "\n").encode())


def load_json(raw):
    try:
        value = json.loads(raw, object_pairs_hook=audit.unique_object)
    except (ValueError, UnicodeError) as exc:
        raise audit.AuditError("Invalid host job JSON") from exc
    if not isinstance(value, dict):
        raise audit.AuditError("Expected host JSON object")
    return value


def github_client(job):
    repository = job.get("repository")
    if not isinstance(repository, str) or not audit.REPO.fullmatch(repository):
        raise audit.AuditError("Invalid repository")
    token = secure_read(job.get("token_file"), MAX_TOKEN, protected=True).decode().strip()
    if not token or any(ord(c) <= 32 or ord(c) >= 127 for c in token):
        raise audit.AuditError("Invalid host credential")
    deadline = job.get("deadline")
    if deadline is not None:
        deadline = parse_time(deadline)
    return DeadlineHttp("https://api.github.com", token, deadline=deadline)


def parse_time(value):
    if not isinstance(value, str):
        raise audit.AuditError("Missing audit timestamp")
    try:
        value = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise audit.AuditError("Invalid audit timestamp") from exc
    if value.tzinfo is None:
        raise audit.AuditError("Audit timestamp requires a timezone")
    return value


class DeadlineHttp(audit.Http):
    def __init__(self, *args, deadline=None, **kwargs):
        super().__init__(*args, **kwargs)
        self.deadline = deadline

    def request(self, method, path, body=None, raw=False, limit=audit.MAX_REPORT):
        # Every retry comes through here, including an ambiguous POST reconcile.
        # A request already delivered to GitHub cannot be retracted by cancel.
        if self.deadline and dt.datetime.now(dt.timezone.utc) >= self.deadline:
            raise audit.AuditError("Audit deadline reached")
        return super().request(method, path, body, raw, limit)


def metadata(api, repository):
    value = audit.read_retry(api, "GET", f"/repos/{repository}")
    if not isinstance(value, dict) or str(value.get("full_name", "")).lower() != repository.lower() or type(value.get("private")) is not bool:
        raise audit.AuditError("GitHub repository identity mismatch")
    branch = value.get("default_branch")
    if not isinstance(branch, str) or not branch or len(branch) > 1024 or any(ord(c) < 32 for c in branch):
        raise audit.AuditError("Invalid default branch metadata")
    if value.get("archived") or value.get("disabled"):
        raise audit.AuditError("Repository is archived or disabled")
    return value


def prepare(job):
    root = output_root(job.get("output_dir"))
    api = github_client(job)
    repository = job["repository"]
    meta = metadata(api, repository)
    default = meta["default_branch"]
    requested = job.get("ref_name") or "refs/heads/" + default
    if requested not in (default, "refs/heads/" + default):
        raise audit.AuditError("Only the verified default branch is supported")
    commit_data = audit.read_retry(api, "GET", f"/repos/{repository}/commits/{urllib.parse.quote(default, safe='')}")
    commit = commit_data.get("sha") if isinstance(commit_data, dict) else None
    if not isinstance(commit, str) or not audit.COMMIT.fullmatch(commit):
        raise audit.AuditError("Invalid GitHub commit metadata")
    source, paths = audit.stage_source(audit.repository_archive(api, repository, commit), include_paths=True)
    if len((json.dumps(sorted(paths), indent=2) + "\n").encode()) > audit.MAX_REPORT:
        raise audit.AuditError("Prepared source manifest exceeds bound")
    source_path, paths_path = root / "source.tar", root / "source.paths.json"
    write_file(source_path, source)
    write_json(paths_path, sorted(paths))
    started_at = job.get("started_at") or dt.datetime.now(dt.timezone.utc).isoformat()
    identity = {"repository": repository, "commit": commit, "ref_name": "refs/heads/" + default,
                "private": meta["private"], "default_branch": default, "started_at": started_at}
    # This provenance never enters the guest. Publish must match this pinned run.
    write_json(root / "source.identity.json", identity)
    return dict(identity, source_path=str(source_path), paths_path=str(paths_path))


def publication_week(started_at):
    value = parse_time(started_at)
    return value.astimezone(ZoneInfo("America/Detroit")).strftime("%G-W%V")


def publish(job, offline=False):
    root = output_root(job.get("output_dir"))
    api = None if offline else github_client(job)
    identity = load_json(secure_read(str(root / "source.identity.json"), MAX_JOB, protected=True))
    repository, commit = job.get("repository"), job.get("commit", identity.get("commit"))
    if not isinstance(repository, str) or not audit.REPO.fullmatch(repository):
        raise audit.AuditError("Invalid repository")
    if identity.get("repository") != repository or identity.get("commit") != commit or not isinstance(commit, str) or not audit.COMMIT.fullmatch(commit):
        raise audit.AuditError("Publication does not match prepared source")
    run_id = job.get("run_id")
    if not isinstance(run_id, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", run_id):
        raise audit.AuditError("Invalid local run ID")
    paths_path = job.get("paths_path") or str(root / "source.paths.json")
    # Do not allow substitution of a path manifest from another prepared run.
    if Path(paths_path) != root / "source.paths.json":
        raise audit.AuditError("Publication requires this run's prepared manifest")
    paths = json.loads(secure_read(paths_path, audit.MAX_REPORT, protected=True))
    if not isinstance(paths, list) or len(paths) > 50000 or any(not isinstance(p, str) for p in paths):
        raise audit.AuditError("Invalid source manifest")
    paths = {audit.checked_path(path) for path in paths}
    raw = secure_read(job.get("report_path") or str(root / "report.json"), audit.MAX_REPORT)
    # Repo visibility can become public between preparation and publication.
    # Reverify it rather than trusting a guest or caller boolean.
    # Offline validation deliberately performs no credential read or network IO.
    # Visibility may have changed: unknown visibility uses the public policy.
    private = None if offline else metadata(api, repository)["private"]
    report = audit.public_review_policy(audit.validate_report(raw, repository, commit, paths), private)
    week = publication_week(identity["started_at"])
    if job.get("started_at") and publication_week(job["started_at"]) != week:
        raise audit.AuditError("Publication start time does not match prepared run")
    write_json(root / "report.redacted.json", audit.artifact_report(report))
    write_json(root / "report.safe.json", audit.artifact_report(report))
    publication = job.get("publication", {})
    if not isinstance(publication, dict) or type(publication.get("enabled", False)) is not bool:
        raise audit.AuditError("Invalid publication choice")
    enabled = False if offline else publication.get("enabled", job.get("publish_issues", False))
    if type(enabled) is not bool:
        raise audit.AuditError("Invalid publication choice")

    def result(value):
        issues = []
        for item in value["published"]:
            number = item.get("number")
            if type(number) is not int or number < 1:
                raise audit.AuditError("Invalid GitHub issue identity")
            issues.append({"number": number, "url": f"https://github.com/{repository}/issues/{number}",
                           "title": item["title"], "action": item["action"]})
        return {"run_id": run_id, "repository": repository, "commit": commit, "completion": report["completion"],
                "created": sum(i["action"] == "created" for i in issues), "updated": sum(i["action"] == "updated" for i in issues),
                "withheld": len(value["private_review"]), "deferred": len(value["deferred"]), "issues": issues,
                "publication_enabled": enabled, "repository_private": private, "visibility_verified": not offline,
                "result_path": str(root / "result.json")}

    if enabled:
        with audit.publication_lock(repository, root.parent / "publication-locks"):
            value = audit.publish(api, report, private, week, lambda value: write_json(root / "result.json", result(value)))
    else:
        value = {"published": [], "private_review": [f["fingerprint"] for f in report["findings"] if f["sensitive"]],
                 "deferred": [f["fingerprint"] for f in report["findings"] if f["validated"] and not f["sensitive"]]}
    final = result(value)
    write_json(root / "result.json", final)
    return final


def validate(job):
    """Retain a safe partial report after cutoff, with no credentials or network."""
    return publish(job, offline=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("prepare", "publish", "validate"))
    parser.add_argument("--job-file")
    args = parser.parse_args()
    try:
        raw = secure_read(args.job_file, MAX_JOB, protected=True) if args.job_file else sys.stdin.buffer.read(MAX_JOB + 1)
        if len(raw) > MAX_JOB:
            raise audit.AuditError("Job exceeds bound")
        result = {"prepare": prepare, "publish": publish, "validate": validate}[args.command](load_json(raw))
        print(json.dumps(result))
    except Exception:
        # Includes network URLs, HTTP response bodies, filesystem paths and tokens.
        # None of those belongs in management logs/UI or a process traceback.
        print(json.dumps({"error": {"prepare": "Local GitHub audit preparation failed",
                                    "publish": "Local GitHub audit publication failed",
                                    "validate": "Local audit report validation failed"}[args.command]}))
        raise SystemExit(1)


if __name__ == "__main__":
    main()

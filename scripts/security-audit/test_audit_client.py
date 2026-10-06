import datetime as dt
import gzip
import io
import json
import tarfile
import tempfile
import os
from pathlib import Path
from types import SimpleNamespace
import unittest
import urllib.error
from unittest.mock import patch

import audit_client as audit

REPO = "fixture/security"
SHA = "a" * 40


def finding(index=1, **updates):
    data = {"fingerprint": f"{index:064x}", "title": "Unsafe path", "path": "src/file.py", "line_start": 1,
            "line_end": 2, "category": "CWE-22", "severity": "high", "impact": "Reads an unintended file",
            "evidence": "Fixture reproduction confirms attacker path is used", "suggested_fix": "Restrict the path",
            "validated": True, "sensitive": False}
    data.update(updates)
    return data


def report(*findings):
    return {"version": 1, "repository": REPO, "commit": SHA, "completion": "partial",
            "coverage": {"scanned_paths": ["src/file.py"], "scanners": [{"name": "semgrep", "status": "passed", "detail": "fixture"}], "tests": [], "skipped": ["GPU tests unavailable"]}, "findings": list(findings)}


class GithubFixture:
    def __init__(self, issues=(), ambiguous=False):
        self.issues = list(issues)
        self.ambiguous = ambiguous
        self.posts = 0
        self.patches = 0
        self.pages = []

    def request(self, method, path, body=None, raw=False, limit=None):
        if method == "GET":
            page = int(path.split("page=")[-1])
            self.pages.append(page)
            return self.issues[(page-1)*100:page*100]
        if method == "PATCH":
            self.patches += 1
            issue = next(i for i in self.issues if str(i["number"]) == path.split("/")[-1])
            issue.update(body)
            return issue
        if method == "POST":
            self.posts += 1
            issue = dict(body, number=len(self.issues)+1, html_url=f"https://github.com/{REPO}/issues/{len(self.issues)+1}")
            self.issues.append(issue)
            if self.ambiguous:
                self.ambiguous = False
                raise urllib.error.URLError("lost response")
            return issue
        raise AssertionError(method)


def archive(name="fixture/src/file.py", link=False, size=2):
    data = io.BytesIO()
    with tarfile.open(fileobj=data, mode="w:gz") as stream:
        root = tarfile.TarInfo("fixture")
        root.type = tarfile.DIRTYPE
        stream.addfile(root)
        member = tarfile.TarInfo(name)
        if link:
            member.type, member.linkname = tarfile.SYMTYPE, "/etc/shadow"
            stream.addfile(member)
        else:
            member.size, member.mode = size, 0o4755
            stream.addfile(member, io.BytesIO(b"x" * size))
    return data.getvalue()


class ValidationTests(unittest.TestCase):
    def test_identity_mismatch(self):
        with self.assertRaises(audit.AuditError):
            audit.validate_report(json.dumps(report(finding())).encode(), "attacker/repo", SHA)

    def test_rejects_paths_bool_lines_duplicates_oversized(self):
        for item in (finding(path="../secret"), finding(line_start=True), finding(line_end=0), finding(evidence="x"*16385), finding(evidence="<!-- agentic-sandbox:v1:fake -->")):
            with self.subTest(item=item), self.assertRaises(audit.AuditError):
                audit.validate_report(json.dumps(report(item)).encode(), REPO, SHA)
        with self.assertRaises(audit.AuditError):
            audit.validate_report(json.dumps(report(finding(), finding())).encode(), REPO, SHA)

    def test_secret_redacted_and_private_review_detail_withheld(self):
        clean = audit.validate_report(json.dumps(report(finding(evidence="Authorization: Bearer fixture-secret-123456"))).encode(), REPO, SHA)
        self.assertIn("[REDACTED]", clean["findings"][0]["evidence"])
        self.assertTrue(clean["findings"][0]["sensitive"])
        artifact = audit.artifact_report(clean)
        self.assertNotIn("fixture-secret", json.dumps(artifact))
        self.assertEqual(artifact["findings"][0]["evidence"], "Withheld for private review")

    def test_archive_repack_does_not_extract_or_keep_suid(self):
        data = audit.stage_source(archive())
        with tarfile.open(fileobj=io.BytesIO(data)) as stream:
            member = stream.getmembers()[0]
            self.assertEqual(member.name, "src/file.py")
            self.assertEqual(member.mode, 0o755)
            self.assertEqual(stream.extractfile(member).read(), b"xx")

    def test_archive_links_and_traversal_rejected(self):
        for data in (archive(link=True), archive(name="fixture/../host")):
            with self.assertRaises(audit.AuditError):
                audit.stage_source(data)

    def test_bounded_decompression(self):
        reader = audit.BoundedReader(gzip.GzipFile(fileobj=io.BytesIO(gzip.compress(b"x"*1000))), 10)
        with self.assertRaises(audit.AuditError):
            reader.read(100)


class PublisherTests(unittest.TestCase):
    def test_zero_to_five_then_retry_deduplicates(self):
        fixture = GithubFixture()
        data = report(*(finding(i) for i in range(1, 9)))
        publication = audit.publish(fixture, data, False, "2026-W41")
        self.assertEqual((fixture.posts, len(publication["deferred"])), (5, 3))
        audit.publish(fixture, data, False, "2026-W41")
        self.assertEqual((fixture.posts, fixture.patches), (5, 5))

    def test_weekly_budget_includes_previous_manual_run(self):
        fixture = GithubFixture()
        audit.publish(fixture, report(*(finding(i) for i in range(1, 6))), False, "2026-W41")
        later = audit.publish(fixture, report(finding(99)), False, "2026-W41")
        self.assertEqual(fixture.posts, 5)
        self.assertEqual(len(later["deferred"]), 1)

    def test_update_does_not_count_as_new_issue_current_week(self):
        fixture = GithubFixture()
        audit.publish(fixture, report(finding()), False, "2026-W40")
        audit.publish(fixture, report(*(finding(i) for i in range(1, 7))), False, "2026-W41")
        self.assertEqual(fixture.posts, 6)
        self.assertIn("2026-W40", fixture.issues[0]["body"])

    def test_ambiguous_create_is_reconciled_without_duplicate(self):
        fixture = GithubFixture(ambiguous=True)
        audit.publish(fixture, report(finding()), False, "2026-W41")
        self.assertEqual((fixture.posts, len(fixture.issues)), (1, 1))

    def test_sensitive_and_unvalidated_never_published(self):
        for private in (False, True):
            fixture = GithubFixture()
            result = audit.publish(fixture, report(finding(sensitive=True), finding(2, validated=False)), private, "2026-W41")
            self.assertEqual(fixture.posts, 0)
            self.assertEqual(len(result["private_review"]), 1)

    def test_pagination_closed_issue_dedup(self):
        issues = [{"number": i, "html_url": str(i), "body": "", "state": "closed"} for i in range(1, 102)]
        issues[-1]["body"] = audit.issue_marker(REPO, finding()["fingerprint"])
        fixture = GithubFixture(issues)
        audit.publish(fixture, report(finding()), False, "2026-W41")
        self.assertEqual(fixture.pages, [1, 2])
        self.assertEqual((fixture.posts, fixture.patches), (0, 1))

    def test_rate_limit_read_has_bounded_retry(self):
        class Limited:
            calls = 0
            def request(self, *args):
                self.calls += 1
                if self.calls < 3:
                    raise urllib.error.HTTPError("fixture", 429, "limited", {"Retry-After": "1"}, io.BytesIO())
                return []
        api = Limited()
        with patch("audit_client.time.sleep") as sleep:
            self.assertEqual(audit.read_retry(api, "GET", "/fixture"), [])
        self.assertEqual((api.calls, sleep.call_count), (3, 2))


class LockAndAdapterTests(unittest.TestCase):
    def test_publication_lock_fails_busy_and_rejects_symlink(self):
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory) / "state"
            with audit.publication_lock(REPO, state):
                with self.assertRaises(audit.AuditError):
                    with audit.publication_lock(REPO, state):
                        self.fail("second publisher admitted")
            with audit.publication_lock(REPO, state):
                pass
            alias = Path(directory) / "alias"
            alias.symlink_to(state, target_is_directory=True)
            with self.assertRaises(audit.AuditError):
                with audit.publication_lock(REPO, alias):
                    self.fail("symlink accepted")

    def test_staged_path_required_and_duplicate_keys_rejected(self):
        raw = json.dumps(report(finding())).encode()
        with self.assertRaises(audit.AuditError):
            audit.validate_report(raw, REPO, SHA, {"other.py"})
        with self.assertRaises(audit.AuditError):
            audit.validate_report(b'{"version":1,"version":1}', REPO, SHA)

    def test_public_severe_defaults_to_private_review(self):
        data = audit.public_review_policy(report(finding()), False)
        fixture = GithubFixture()
        self.assertTrue(data["findings"][0]["sensitive"])
        self.assertEqual(len(audit.publish(fixture, data, False, "2026-W41")["private_review"]), 1)
        self.assertEqual(fixture.posts, 0)

    def test_full_adapter_fixture_and_idempotent_existing_session(self):
        data = report(finding(severity="medium"))
        data["completion"] = "complete"
        for state in ("awaiting_source", "completed"):
            with self.subTest(state=state), tempfile.TemporaryDirectory() as directory:
                calls = []
                github = GithubFixture()
                original = github.request
                def github_request(method, path, *args, **kwargs):
                    if path == "/repos/" + REPO:
                        return {"default_branch": "main", "private": False}
                    return original(method, path, *args, **kwargs)
                github.request = github_request
                class Controller:
                    def request(self, method, path, body=None, raw=False, limit=None):
                        calls.append((method, path, body))
                        if method == "POST":
                            return {"id": "fixture-run", "state": state}
                        if path.endswith("/report"):
                            return json.dumps(data).encode()
                        if method == "GET":
                            return {"state": "completed"}
                        return {}
                args = SimpleNamespace(repository=REPO, commit=SHA, ref="main", run_id="123", model_id="studio", output=str(Path(directory)/"output"), controller="http://127.0.0.1:8122", scheduled=False, schedule_expression="")
                future = dt.datetime.now(dt.timezone.utc) + dt.timedelta(minutes=30)
                env = {"GITHUB_TOKEN": "fake-token", "HOST_AUDIT_TOKEN": "fake-host-token", "AUDIT_PUBLISHER_STATE_DIR": str(Path(directory)/"state")}
                with patch.dict(os.environ, env), patch("audit_client.Http", side_effect=[github, Controller()]), patch("audit_client.audit_deadline", return_value=future), patch("audit_client.repository_archive", return_value=archive()):
                    audit.run(args)
                self.assertEqual(github.posts, 1)
                self.assertEqual(sum(c[0] == "PUT" for c in calls), int(state == "awaiting_source"))
                self.assertEqual(calls[-1][0], "DELETE")
                request = calls[0][2]
                self.assertEqual(request["ref_name"], "refs/heads/main")
                self.assertNotIn("fake-token", json.dumps(request))
                self.assertTrue((Path(args.output)/"publication.json").exists())


class WindowTests(unittest.TestCase):
    def test_dst_duplicate_guard(self):
        winter = dt.datetime(2026, 12, 1, 6, tzinfo=dt.timezone.utc)
        summer = dt.datetime(2026, 7, 7, 5, tzinfo=dt.timezone.utc)
        self.assertEqual(audit.audit_deadline(winter, True, "0 6 * * 2").hour, 11)
        self.assertEqual(audit.audit_deadline(summer, True, "0 5 * * 2").hour, 10)
        self.assertIsNone(audit.audit_deadline(summer + dt.timedelta(hours=1), True, "0 6 * * 2"))
        self.assertIsNone(audit.audit_deadline(winter - dt.timedelta(hours=1), True, "0 5 * * 2"))

    def test_delayed_correct_cron_and_fallback_hour(self):
        late = dt.datetime(2026, 7, 7, 8, tzinfo=dt.timezone.utc)
        self.assertEqual(audit.audit_deadline(late, True, "0 5 * * 2").hour, 10)
        fallback = dt.datetime(2026, 11, 1, 6, tzinfo=dt.timezone.utc)
        self.assertIsNone(audit.audit_deadline(fallback, True, "0 6 * * 0"))
        self.assertEqual(audit.audit_deadline(fallback, True, "0 5 * * 0").hour, 11)

    def test_late_cutoff_and_outside_rejected(self):
        for moment in (dt.datetime(2026, 7, 7, 10, tzinfo=dt.timezone.utc), dt.datetime(2026, 7, 7, 9, 58, tzinfo=dt.timezone.utc)):
            with self.assertRaises(audit.AuditError):
                audit.audit_deadline(moment)


if __name__ == "__main__":
    unittest.main()

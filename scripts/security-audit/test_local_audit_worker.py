import datetime as dt
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
import urllib.error
from unittest.mock import patch

import audit_client as audit
import local_audit_worker as worker
from test_audit_client import GithubFixture, REPO, SHA, archive, finding, report


class LocalGithubFixture(GithubFixture):
    def __init__(self, private=True):
        super().__init__()
        self.private = private
        self.archive_commits = []

    def request(self, method, path, body=None, raw=False, limit=None):
        if method == "GET" and path == f"/repos/{REPO}":
            return {"full_name": REPO, "private": self.private, "default_branch": "main"}
        if method == "GET" and path == f"/repos/{REPO}/commits/main":
            return {"sha": SHA}
        if method == "GET" and path.startswith(f"/repos/{REPO}/tarball/"):
            self.archive_commits.append(path.rsplit("/", 1)[-1])
            return archive()
        return super().request(method, path, body, raw, limit)


class LocalWorkerTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.run = self.root / "runs" / "run-fixture"
        self.run.mkdir(mode=0o700, parents=True)
        self.token = self.root / "credential.key"
        worker.write_file(self.token, b"github_pat_fixture123456789")
        self.fixture = LocalGithubFixture()
        self.job = {"repository": REPO, "ref_name": "", "token_file": str(self.token),
                    "output_dir": str(self.run), "run_id": "local-fixture", "started_at": "2026-10-05T05:00:00Z",
                    "publication": {"enabled": False}}
        self.client_patch = patch.object(worker, "DeadlineHttp", return_value=self.fixture)
        self.client_patch.start()

    def tearDown(self):
        self.client_patch.stop()
        self.temporary.cleanup()

    def prepare_report(self, *findings):
        prepared = worker.prepare(self.job)
        worker.write_json(self.run / "report.json", report(*findings))
        return dict(self.job, commit=prepared["commit"], paths_path=prepared["paths_path"],
                    report_path=str(self.run / "report.json"))

    def test_prepare_pins_live_default_branch_and_outputs_only_host_data(self):
        result = worker.prepare(self.job)
        self.assertEqual(result["ref_name"], "refs/heads/main")
        self.assertEqual(result["commit"], SHA)
        self.assertEqual(self.fixture.archive_commits, [SHA])
        self.assertEqual(json.loads((self.run / "source.paths.json").read_text()), ["src/file.py"])
        self.assertNotIn(self.token.read_text(), json.dumps(result))
        for path in self.run.iterdir():
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)

    def test_arbitrary_branch_and_repo_metadata_mismatch_rejected(self):
        with self.assertRaises(audit.AuditError):
            worker.prepare(dict(self.job, ref_name="refs/heads/untrusted"))
        with patch.object(self.fixture, "request", return_value={"full_name": "other/repo", "private": True, "default_branch": "main"}):
            with self.assertRaises(audit.AuditError):
                worker.prepare(self.job)

    def test_token_owner_only_and_no_symlinks(self):
        self.token.chmod(0o644)
        with self.assertRaises(audit.AuditError):
            worker.github_client(self.job)
        self.token.chmod(0o600)
        alias = self.root / "alias.key"
        alias.symlink_to(self.token)
        with self.assertRaises(OSError):
            worker.github_client(dict(self.job, token_file=str(alias)))

    def test_local_report_without_publication_never_writes_github(self):
        job = self.prepare_report(finding(severity="medium"))
        result = worker.publish(job)
        self.assertEqual((result["created"], result["updated"], result["deferred"]), (0, 0, 1))
        self.assertEqual((self.fixture.posts, self.fixture.patches), (0, 0))
        self.assertTrue((self.run / "report.safe.json").exists())
        self.assertEqual(json.loads((self.run / "result.json").read_text()), result)

    def test_offline_validation_after_cutoff_needs_no_credential_or_network(self):
        job = self.prepare_report(finding(), finding(2, severity="medium"))
        job["deadline"] = "2020-10-05T10:00:00Z"
        job["publication"] = {"enabled": True}
        self.token.unlink()
        with patch.object(worker, "github_client", side_effect=AssertionError("credential accessed")), patch.object(self.fixture, "request", side_effect=AssertionError("network accessed")):
            result = worker.validate(job)
        self.assertEqual((result["created"], result["updated"], result["withheld"], result["deferred"]), (0, 0, 1, 1))
        self.assertEqual(result["completion"], "partial")
        self.assertFalse(result["publication_enabled"])
        self.assertFalse(result["visibility_verified"])
        self.assertIsNone(result["repository_private"])
        safe = json.loads((self.run / "report.safe.json").read_text())
        self.assertEqual(safe["findings"][0]["evidence"], "Withheld for private review")
        self.assertEqual(safe["findings"][1]["title"], "Unsafe path")
        self.assertEqual(json.loads((self.run / "result.json").read_text()), result)

    def test_offline_validation_retains_failed_report_and_rejects_unpinned_data(self):
        job = self.prepare_report(finding(severity="medium"))
        failed = report(finding(severity="medium"))
        failed["completion"] = "failed"
        worker.write_json(self.run / "report.json", failed)
        self.assertEqual(worker.validate(job)["completion"], "failed")
        with self.assertRaises(audit.AuditError):
            worker.validate(dict(job, commit="b" * 40))

    def test_publish_zero_to_five_retry_updates_and_same_week_limit(self):
        job = self.prepare_report(*(finding(i, severity="medium") for i in range(1, 9)))
        job["publication"] = {"enabled": True}
        first = worker.publish(job)
        second = worker.publish(job)
        self.assertEqual((first["created"], first["deferred"]), (5, 3))
        self.assertEqual((second["created"], second["updated"], second["deferred"]), (0, 5, 3))
        self.assertEqual(self.fixture.posts, 5)
        self.assertTrue(all(issue["url"].startswith(f"https://github.com/{REPO}/issues/") for issue in first["issues"]))
        self.assertIn("agentic-sandbox-week:2026-W41", self.fixture.issues[0]["body"])

    def test_live_visibility_switch_withholds_high_and_sensitive_details(self):
        job = self.prepare_report(finding(), finding(2, severity="low", evidence="github_pat_accidental_secret1234"))
        job["publication"] = {"enabled": True}
        self.fixture.private = False
        result = worker.publish(job)
        self.assertEqual((result["created"], result["withheld"]), (0, 2))
        safe = (self.run / "report.safe.json").read_text()
        self.assertNotIn("accidental_secret", safe)
        self.assertNotIn("Reads an unintended file", safe)

    def test_pinned_identity_path_manifest_and_week_reject_substitution(self):
        job = self.prepare_report(finding())
        for changed in (dict(job, commit="b" * 40), dict(job, paths_path=str(self.root / "other.json")),
                        dict(job, started_at="2026-10-12T05:00:00Z")):
            with self.subTest(changed=changed), self.assertRaises(audit.AuditError):
                worker.publish(changed)
        worker.write_json(self.run / "report.json", report(finding(path="host/secrets")))
        with self.assertRaises(audit.AuditError):
            worker.publish(job)
        self.assertEqual(self.fixture.posts, 0)

    def test_output_is_atomic_and_does_not_follow_links(self):
        result = self.run / "result.json"
        worker.write_json(result, {"value": 1})
        worker.write_json(result, {"value": 2})
        self.assertEqual(json.loads(result.read_text()), {"value": 2})
        self.assertEqual(list(self.run.glob(".audit-write-*")), [])
        result.unlink()
        result.symlink_to(self.token)
        with self.assertRaises(audit.AuditError):
            worker.write_json(result, {})
        self.assertEqual(self.token.read_text(), "github_pat_fixture123456789")

    def test_cli_error_does_not_echo_token_paths_or_traceback(self):
        bad = dict(self.job, token_file=str(self.root / "missing-secret-file"))
        path = self.run / "job.json"
        worker.write_json(path, bad)
        env = {key: value for key, value in os.environ.items() if not key.startswith("GITHUB_")}
        result = subprocess.run([sys.executable, worker.__file__, "prepare", "--job-file", str(path)],
                                capture_output=True, text=True, env=env, timeout=10)
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stderr, "")
        self.assertEqual(json.loads(result.stdout), {"error": "Local GitHub audit preparation failed"})
        self.assertNotIn(str(self.root), result.stdout)


class DeadlineTests(unittest.TestCase):
    def test_each_retry_rechecks_deadline_before_publication_request(self):
        start = dt.datetime(2026, 10, 5, 5, tzinfo=dt.timezone.utc)
        client = worker.DeadlineHttp("https://api.github.com", "fixture", deadline=start + dt.timedelta(seconds=1))
        error = urllib.error.HTTPError("https://api.github.com/fixture", 503, "unavailable", {}, io.BytesIO(b"fixture unavailable"))
        with patch.object(worker.dt, "datetime") as clock, patch.object(audit.Http, "request", side_effect=error) as call, patch.object(audit.time, "sleep"):
            clock.now.side_effect = [start, start + dt.timedelta(seconds=2)]
            with self.assertRaises(audit.AuditError):
                audit.read_retry(client, "PATCH", "/repos/fixture/security/issues/1", {})
        self.assertEqual(call.call_count, 1)


if __name__ == "__main__":
    unittest.main()

import importlib.util
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch


SCRIPT = Path(__file__).resolve().parents[1] / "auto-release.py"
spec = importlib.util.spec_from_file_location("auto_release", SCRIPT)
auto_release = importlib.util.module_from_spec(spec)
spec.loader.exec_module(auto_release)


class ReleasePolicyTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.remote = self.root / "remote.git"
        self.repo = self.root / "repo"
        subprocess.run(["git", "init", "--bare", "--initial-branch=main", str(self.remote)], check=True, capture_output=True)
        self.repo.mkdir()
        self.previous = Path.cwd()
        os.chdir(self.repo)
        self.addCleanup(os.chdir, self.previous)
        self.git("init", "--initial-branch=main")
        self.git("config", "user.name", "Release Policy Test")
        self.git("config", "user.email", "release-test@example.invalid")
        self.git("remote", "add", "origin", str(self.remote))
        self.write_version("0.10.3")
        self.git("add", ".")
        self.git("commit", "-m", "version")
        self.git("push", "-u", "origin", "main")
        self.sha = self.git("rev-parse", "HEAD")

    def git(self, *args):
        return subprocess.check_output(["git", *args], text=True, stderr=subprocess.DEVNULL).strip()

    def write_version(self, version, locked=None):
        Path("Cargo.toml").write_text(f'[package]\nname = "maestro"\nversion = "{version}"\n')
        Path("Cargo.lock").write_text(f'[[package]]\nname = "maestro"\nversion = "{locked or version}"\n')

    def test_new_stable_version_and_semantic_ordering(self):
        self.git("tag", "v0.9.99")
        self.git("tag", "v0.10.2")
        self.assertEqual(auto_release.plan(self.sha), "v0.10.3")

    def test_existing_tag_is_unchanged_even_on_a_different_commit(self):
        self.git("tag", "-a", "v0.10.3", "-m", "existing")
        original = self.git("rev-parse", "refs/tags/v0.10.3")
        Path("extra").write_text("later main change without a version bump")
        self.git("add", ".")
        self.git("commit", "-m", "later")
        self.git("push", "origin", "main")
        self.assertIsNone(auto_release.plan(self.git("rev-parse", "HEAD")))
        self.assertEqual(self.git("rev-parse", "refs/tags/v0.10.3"), original)

    def test_invalid_versions_mismatched_lock_and_wrong_sha_are_rejected(self):
        with self.assertRaises(ValueError):
            auto_release.plan("0" * 40)
        self.write_version("0.10.3", "0.10.2")
        with self.assertRaises(ValueError):
            auto_release.plan(self.sha)
        for version in ["0.10.4-rc.1", "0.10.4+build", "01.2.3"]:
            self.write_version(version)
            self.assertIsNone(auto_release.plan(self.sha))

    def test_version_below_existing_stable_release_is_rejected(self):
        self.git("tag", "v0.11.0")
        with self.assertRaises(ValueError):
            auto_release.plan(self.sha)

    def test_stale_main_run_does_not_tag(self):
        self.git("update-ref", "refs/remotes/origin/main", "0" * 40)
        # A different real commit represents main advancing while CI runs.
        Path("extra").write_text("next")
        self.git("add", ".")
        self.git("commit", "-m", "next")
        next_sha = self.git("rev-parse", "HEAD")
        self.git("update-ref", "refs/remotes/origin/main", next_sha)
        self.git("checkout", "--detach", self.sha)
        self.assertIsNone(auto_release.plan(self.sha))

    def test_tag_command_pushes_annotated_exact_commit_and_rerun_is_idempotent(self):
        env = {**os.environ, "EXPECTED_SHA": self.sha}
        subprocess.run(["python3", str(SCRIPT), "tag"], env=env, check=True, capture_output=True)
        self.assertEqual(self.git("cat-file", "-t", "refs/tags/v0.10.3"), "tag")
        self.assertEqual(self.git("rev-parse", "v0.10.3^{}"), self.sha)
        first = self.git("rev-parse", "refs/tags/v0.10.3")
        self.assertIn(first, self.git("ls-remote", "origin", "refs/tags/v0.10.3"))
        subprocess.run(["python3", str(SCRIPT), "tag"], env=env, check=True, capture_output=True)
        self.assertEqual(self.git("rev-parse", "refs/tags/v0.10.3"), first)

    def test_plan_reports_action_output_without_pushing(self):
        output = self.root / "output"
        with patch.dict(os.environ, {"EXPECTED_SHA": self.sha, "GITHUB_OUTPUT": str(output)}):
            with patch("sys.argv", [str(SCRIPT), "plan"]):
                auto_release.main()
        self.assertEqual(output.read_text(), "needed=true\n")
        self.assertEqual(self.git("tag", "--list"), "")


if __name__ == "__main__":
    unittest.main()

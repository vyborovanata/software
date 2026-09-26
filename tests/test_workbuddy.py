import io
import os
from pathlib import Path
import stat
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from unittest.mock import patch

import codecraft
import workbuddy


class WorkbuddyStatusTests(unittest.TestCase):
    def test_offline_restricted_status_does_not_print_secrets(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "workbuddy.json"
            codecraft.save_account(path, {"provider": "google", "status": "restricted", "email": "private@example.test"})
            codecraft.save_account(workbuddy.session_path(path), {
                "cookies": [{"domain": ".workbuddy.ai", "value": "private-cookie"}],
                "origins": [{"origin": "https://www.workbuddy.ai", "localStorage": [{"value": "private-data"}]}],
                "sessionStorage": {"https://www.workbuddy.ai": {"token": "private-session"}},
            })
            output = io.StringIO()
            with patch.dict(os.environ, {"WORKBUDDY_CREDENTIALS_FILE": str(path)}), redirect_stdout(output):
                self.assertEqual(workbuddy.main(["status"]), 0)
            self.assertIn("Workbuddy status: restricted", output.getvalue())
            self.assertIn("First-party session snapshot saved", output.getvalue())
            for secret in ("private@example.test", "private-cookie", "private-data", "private-session"):
                self.assertNotIn(secret, output.getvalue())
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            self.assertEqual(stat.S_IMODE(workbuddy.session_path(path).stat().st_mode), 0o600)

    def test_unrecognized_status_and_non_workbuddy_cookies_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "workbuddy.json"
            codecraft.save_account(path, {"provider": "google", "status": "active"})
            with self.assertRaises(codecraft.PipelineError):
                workbuddy.status(path)
            codecraft.save_account(path, {"provider": "google", "status": "restricted"})
            state = {"cookies": [{"domain": ".google.com", "value": "hidden"}],
                     "origins": [], "sessionStorage": {}}
            codecraft.save_account(workbuddy.session_path(path), state)
            with self.assertRaises(codecraft.PipelineError):
                workbuddy.status(path)
            state["cookies"][0]["domain"] = "workbuddy.ai.attacker.test"
            codecraft.save_account(workbuddy.session_path(path), state)
            with self.assertRaises(codecraft.PipelineError):
                workbuddy.status(path)
            state["cookies"] = []
            state["origins"] = [{"origin": "http://www.workbuddy.ai"}]
            codecraft.save_account(workbuddy.session_path(path), state)
            with self.assertRaises(codecraft.PipelineError):
                workbuddy.status(path)

    def test_no_account_status_requires_no_network_or_proxy(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "workbuddy.json"
            output = io.StringIO()
            with patch.dict(os.environ, {"WORKBUDDY_CREDENTIALS_FILE": str(path), "NEWPROXY": ""}), \
                    redirect_stdout(output):
                self.assertEqual(workbuddy.main(["status"]), 0)
            self.assertIn("Workbuddy status: not attempted", output.getvalue())
            self.assertIn("No first-party session saved", output.getvalue())
            self.assertFalse(path.exists())

    def test_insecure_file_permissions_and_symlinks_fail_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "workbuddy.json"
            codecraft.save_account(path, {"provider": "google", "status": "restricted"})
            path.chmod(0o644)
            with self.assertRaises(codecraft.PipelineError):
                workbuddy.status(path)
            path.chmod(0o600)
            alias = Path(directory) / "alias.json"
            alias.symlink_to(path)
            with patch.dict(os.environ, {"WORKBUDDY_CREDENTIALS_FILE": str(alias)}), \
                    self.assertRaises(codecraft.PipelineError):
                workbuddy.account_path()
            folder = Path(directory) / "insecure"
            folder.mkdir(mode=0o755)
            other = folder / "account.json"
            codecraft.save_account(other, {"provider": "google", "status": "restricted"})
            with self.assertRaises(codecraft.PipelineError):
                workbuddy.status(other)

    def test_cli_provides_no_automated_login_or_agent_request(self):
        output = io.StringIO()
        for command in ("login", "chat", "run"):
            with self.subTest(command=command), redirect_stderr(output), self.assertRaises(SystemExit) as raised:
                workbuddy.main([command])
            self.assertEqual(raised.exception.code, 2)


if __name__ == "__main__":
    unittest.main()

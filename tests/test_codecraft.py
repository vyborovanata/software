import email.message
import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest
from unittest.mock import patch

import codecraft


class PipelineTests(unittest.TestCase):
    def test_form_extracts_csrf_and_never_uses_unrelated_inputs(self):
        page = '<form action="/register" method="POST"><input type="hidden" name="_token" value="csrf"><input name="email"><input name="password"><input name="name"><input name="password_confirmation"></form>'
        form = codecraft.form_for(page, "/register", ("email", "name"))
        self.assertEqual(codecraft.form_data(form, {"email": "user@example.com"}), {"_token": "csrf", "email": "user@example.com"})
        with self.assertRaises(codecraft.PipelineError):
            codecraft.form_for(page.replace('value="csrf"', 'value=""'), "/register")

    def test_origin_rejects_external_redirect_and_insecure_url(self):
        for url in ("http://codecraftapi.com/login", "https://codecraftapi.com.evil.test/login", "https://codecraftapi.com:8443/login"):
            with self.subTest(url=url), self.assertRaises(codecraft.PipelineError):
                codecraft.site_url(url)
        with self.assertRaises(codecraft.PipelineError):
            codecraft.SameOriginRedirect().redirect_request(None, None, 302, "", {}, "https://other.test/")

    def test_credentials_saved_atomically_private_and_loaded(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "secret.json"
            account = {"email": "user@example.com", "password": "random", "api_key": "cc_" + "x" * 48}
            codecraft.save_account(path, account)
            self.assertEqual(codecraft.read_account(path), account)
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            path.chmod(0o644)
            with self.assertRaises(codecraft.PipelineError):
                codecraft.read_account(path)

    def test_verification_proof_accepts_only_recent_site_mail(self):
        now = codecraft.datetime.now(codecraft.timezone.utc)
        msg = email.message.EmailMessage()
        msg["From"] = "CodeCraft <verify@codecraftapi.com>"
        msg["Date"] = email.utils.format_datetime(now)
        msg.set_content('Verify: https://codecraftapi.com/email/verify/123/hash?expires=5&signature=abc')
        self.assertEqual(codecraft.verification_proof(msg.as_bytes(), now), "https://codecraftapi.com/email/verify/123/hash?expires=5&signature=abc")
        msg.replace_header("From", "Other <verify@evil.test>")
        self.assertIsNone(codecraft.verification_proof(msg.as_bytes(), now))

    def test_six_digit_email_code_and_resume_verification(self):
        now = codecraft.datetime.now(codecraft.timezone.utc)
        msg = email.message.EmailMessage()
        msg["From"] = "CodeCraft <verify@codecraftapi.com>"
        msg["Subject"] = "Verify your CodeCraft account"
        msg["Date"] = email.utils.format_datetime(now)
        msg.set_content("Your verification code is 314159. It expires in 10 minutes.")
        self.assertEqual(codecraft.verification_proof(msg.as_bytes(), now), "314159")
        msg.replace_header("Date", email.utils.format_datetime(now - codecraft.timedelta(hours=1)))
        self.assertIsNone(codecraft.verification_proof(msg.as_bytes(), now))
        del msg["Date"]
        self.assertIsNone(codecraft.verification_proof(msg.as_bytes(), now))

        class Site:
            def __init__(self):
                self.submitted = None

            def dashboard(self):
                return ("/verify-email", "<form action='/verify-email/resend' method='POST'><input name='_token' value='csrf'></form>") if self.submitted is None else ("/dashboard", "dashboard")

            def request(self, route, data=None):
                self.assert_route = route
                return "/verify-email", "<form action='/verify-email' method='POST'><input name='_token' value='csrf'><input name='code'></form>"

            def submit(self, page, path, values, fields):
                self.submitted = values
                return "/dashboard", ""

        with tempfile.TemporaryDirectory() as folder, patch.object(codecraft, "wait_for_verification", return_value="314159"):
            site = Site()
            self.assertEqual(codecraft.verify_dashboard(site, now, {}, Path(folder) / "creds.json", timeout_seconds=0), "dashboard")
            self.assertEqual(site.submitted, {"code": "314159"})

        old = email.message.EmailMessage()
        old["From"] = "CodeCraft <verify@codecraftapi.com>"
        old["Subject"] = "Your verification code"
        old["Date"] = email.utils.format_datetime(now - codecraft.timedelta(hours=2))
        old.set_content("Your verification code is 314159")
        self.assertEqual(codecraft.verification_proof(old.as_bytes(), now, received_at=now), "314159")

    def test_late_email_uses_imap_arrival_time_and_does_not_retry_used_code(self):
        now = codecraft.datetime.now(codecraft.timezone.utc)
        msg = email.message.EmailMessage()
        msg["From"] = "CodeCraft <verify@codecraftapi.com>"
        msg["Subject"] = "Your verification code"
        msg["Date"] = email.utils.format_datetime(now - codecraft.timedelta(hours=2))
        msg.set_content("Your verification code is 314159")
        internal = now.strftime("%d-%b-%Y %H:%M:%S %z").encode()

        class Mailbox:
            def __enter__(self):
                return self

            def __exit__(self, *args):
                pass

            def login(self, *args):
                pass

            def list(self):
                return "OK", []

            def select(self, *args, **kwargs):
                return "OK", [b"1"]

            def search(self, *args):
                return "OK", [b"1"]

            def fetch(self, *args):
                return "OK", [(b'1 (BODY[] INTERNALDATE "' + internal + b'")', msg.as_bytes())]

        env = {"GMAILLOG": "user@example.com", "APPASS": "app-secret", "PROXY": "http://proxy.example:1234"}
        with patch.dict(os.environ, env), patch.object(codecraft, "ProxiedIMAP", return_value=Mailbox()):
            self.assertEqual(codecraft.wait_for_verification(now, seconds=0), "314159")
            self.assertIsNone(codecraft.wait_for_verification(now, seconds=0, ignored={"314159"}))

    def test_site_form_posts_refer_to_the_page_with_csrf_token(self):
        class Response:
            def __enter__(self):
                return self

            def __exit__(self, *args):
                pass

            def geturl(self):
                return "https://codecraftapi.com/verify-email"

            def read(self):
                return b"OK"

        with patch.dict(os.environ, {"PROXY": "http://proxy.example:1234"}):
            site = codecraft.Site()
            with patch.object(site.opener, "open", return_value=Response()) as opened:
                site.submit('<form method="POST" action="/verify-email"><input type="hidden" name="_token" value="csrf"><input name="code"></form>', "/verify-email", {"code": "123456"}, ("code",))
            request = opened.call_args.args[0]
            self.assertEqual(request.get_header("Referer"), "https://codecraftapi.com/verify-email")
            self.assertEqual(request.get_header("Origin"), "https://codecraftapi.com")
            self.assertEqual(request.get_method(), "POST")

    def test_existing_key_skips_network_and_mismatched_account_is_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "account.json"
            codecraft.save_account(path, {"email": "user@example.com", "password": "test", "api_key": "cc_" + "x" * 48})
            with patch.dict(os.environ, {"GMAILLOG": "user@example.com", "PROXY": "http://proxy.example:1234"}), patch.object(codecraft, "Site") as site:
                self.assertEqual(codecraft.ensure(path, None), "API key already saved")
                site.assert_not_called()
            with patch.dict(os.environ, {"GMAILLOG": "other@example.com", "PROXY": "http://proxy.example:1234"}):
                with self.assertRaises(codecraft.PipelineError):
                    codecraft.ensure(path, None)

    def test_registration_saves_password_before_post_and_does_not_duplicate(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "account.json"

            class Site:
                def request(self, route, data=None):
                    self.requested_registration = route == "/register"
                    return "/register", '<form method="POST" action="/register"><input name="_token" value="csrf"><input name="name"><input name="email"><input name="password"><input name="password_confirmation"></form>'

                def submit(self, page, route, values, fields):
                    saved = codecraft.read_account(path)
                    self.saved_before_post = saved["password"] == values["password"] and len(saved["password"]) >= 40
                    self.passwords_match = values["password"] == values["password_confirmation"]
                    return "/dashboard", ""

            site = Site()

            def save_key(*args):
                saved = codecraft.read_account(path)
                saved["api_key"] = "cc_" + "k" * 48
                codecraft.save_account(path, saved)

            with patch.dict(os.environ, {"GMAILLOG": "user@example.com", "PROXY": "http://proxy.example:1234"}), patch.object(codecraft, "Site", return_value=site) as factory, patch.object(codecraft, "verify_dashboard", return_value="dashboard"), patch.object(codecraft, "create_key", side_effect=save_key):
                self.assertEqual(codecraft.ensure(path, "Test User"), "CodeCraft account and API key saved")
                self.assertTrue(site.requested_registration and site.saved_before_post and site.passwords_match)
                self.assertEqual(codecraft.ensure(path, None), "API key already saved")
                factory.assert_called_once()

    def test_one_time_key_is_saved_and_missing_response_is_not_retried(self):
        key = "cc_" + "k" * 48
        dashboard = '<a href="/dashboard/api-keys">API Keys</a>'
        key_page = '<form method="POST" action="/dashboard/api-keys"><input type="hidden" name="_token" value="csrf"><input name="name"></form>'

        class Site:
            def __init__(self, result):
                self.calls = []
                self.result = result

            def request(self, route, data=None, source=None):
                self.calls.append((route, data))
                return ("/dashboard/api-keys", key_page if data is None else self.result)

        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "account.json"
            account = {"email": "user@example.com", "password": "password", "registered": True, "key_name": "hoplite-agent"}
            codecraft.save_account(path, account)
            site = Site("New key: " + key)
            codecraft.create_key(site, account, path, dashboard)
            self.assertEqual(codecraft.read_account(path)["api_key"], key)
            self.assertNotIn("key_attempted", codecraft.read_account(path))
            self.assertEqual(len(site.calls), 2)
            self.assertEqual(site.calls[1][1], {"_token": "csrf", "name": "hoplite-agent"})

            account.pop("api_key")
            site = Site("No key in response")
            with self.assertRaises(codecraft.PipelineError):
                codecraft.create_key(site, account, path, dashboard)
            self.assertTrue(codecraft.read_account(path)["key_attempted"])

    def test_proxy_is_mandatory_and_direct_https_is_refused(self):
        from urllib.request import Request
        with patch.dict(os.environ, {"PROXY": ""}):
            with self.assertRaises(codecraft.PipelineError):
                codecraft.Site()
        with self.assertRaises(codecraft.PipelineError):
            codecraft.TunnelOnlyHTTPS().https_open(Request("https://codecraftapi.com/login"))

    def test_pending_email_does_not_try_to_create_key(self):
        now = codecraft.datetime.now(codecraft.timezone.utc)

        class Site:
            def dashboard(self):
                return "/verify-email", "Verification pending"

        with tempfile.TemporaryDirectory() as folder, patch.object(codecraft, "wait_for_verification", return_value=None), patch.object(codecraft, "create_key") as create:
            account = {"last_resend_at": now.isoformat()}
            with self.assertRaisesRegex(codecraft.PipelineError, "No CodeCraft verification email"):
                codecraft.verify_dashboard(Site(), now, account, Path(folder) / "creds.json", timeout_seconds=0)
            create.assert_not_called()

    def test_verification_resend_is_recorded_before_post(self):
        now = codecraft.datetime.now(codecraft.timezone.utc)
        verify_page = '<form method="POST" action="/verify-email/resend"><input type="hidden" name="_token" value="csrf"></form>'

        class Site:
            def __init__(self, file):
                self.file = file
                self.resends = 0

            def dashboard(self):
                return "/verify-email", verify_page

            def request(self, route, data=None, source=None):
                if data is not None:
                    self.resends += 1
                    self.source = source
                    self.recorded_before_post = bool(codecraft.read_account(self.file).get("last_resend_at"))
                return "/verify-email", verify_page

        with tempfile.TemporaryDirectory() as folder, patch.object(codecraft, "wait_for_verification", return_value=None) as poll:
            path = Path(folder) / "account.json"
            account = {"email": "user@example.com", "key_name": "hoplite-agent"}
            codecraft.save_account(path, account)
            site = Site(path)
            with self.assertRaisesRegex(codecraft.PipelineError, "No CodeCraft verification email"):
                codecraft.verify_dashboard(site, now, account, path, timeout_seconds=0)
            self.assertEqual(site.resends, 1)
            self.assertEqual(site.source, "/verify-email")
            self.assertTrue(site.recorded_before_post)
            self.assertEqual(poll.call_count, 2)

    def test_expired_code_is_ignored_until_fresh_code_arrives(self):
        now = codecraft.datetime.now(codecraft.timezone.utc)

        class Site:
            def __init__(self):
                self.submissions = []

            def dashboard(self):
                return ("/dashboard", "dashboard") if len(self.submissions) == 2 else ("/verify-email", "verification page")

            def request(self, route, data=None):
                return "/verify-email", "form page"

            def submit(self, page, path, values, fields):
                self.submissions.append(values["code"])
                return "/verify-email" if len(self.submissions) == 1 else "/dashboard", ""

        with tempfile.TemporaryDirectory() as folder, patch.object(codecraft, "wait_for_verification", side_effect=["111111", "222222"]) as poll:
            account = {"last_resend_at": now.isoformat()}
            site = Site()
            self.assertEqual(codecraft.verify_dashboard(site, now, account, Path(folder) / "creds.json", timeout_seconds=5), "dashboard")
            self.assertEqual(site.submissions, ["111111", "222222"])
            self.assertIn("111111", poll.call_args_list[1].kwargs["ignored"])

    def test_transient_imap_connect_failure_does_not_abort_wait(self):
        now = codecraft.datetime.now(codecraft.timezone.utc)

        class Site:
            def __init__(self):
                self.verified = False

            def dashboard(self):
                return ("/dashboard", "dashboard") if self.verified else ("/verify-email", "verification page")

            def request(self, route, data=None):
                return "/verify-email", "verification form"

            def submit(self, page, path, values, fields):
                self.verified = values["code"] == "314159"
                return "/dashboard", ""

        with tempfile.TemporaryDirectory() as folder, patch.object(codecraft, "wait_for_verification", side_effect=[OSError("temporary proxy failure"), "314159"]) as poll:
            account = {"last_resend_at": now.isoformat()}
            self.assertEqual(codecraft.verify_dashboard(Site(), now, account, Path(folder) / "creds.json", timeout_seconds=5), "dashboard")
            self.assertEqual(poll.call_count, 2)

    def test_verification_wait_default_is_three_hours_and_configurable(self):
        with patch.dict(os.environ, {}, clear=True):
            self.assertEqual(codecraft.verification_timeout(), 10800)
        with patch.dict(os.environ, {"CODECRAFT_VERIFY_TIMEOUT": "14400"}):
            self.assertEqual(codecraft.verification_timeout(), 14400)
        for value in ("long", "-1", "86401"):
            with patch.dict(os.environ, {"CODECRAFT_VERIFY_TIMEOUT": value}), self.assertRaises(codecraft.PipelineError):
                codecraft.verification_timeout()

    def test_agent_launcher_does_not_inherit_mail_or_captcha_credentials(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "account.json"
            codecraft.save_account(path, {"email": "user@example.com", "password": "site-password", "api_key": "cc_" + "x" * 48})
            env = {"PROXY": "http://proxy.example:1234", "GMAILLOG": "user@example.com", "APPASS": "mail-secret", "RUCAPTCHA": "captcha-secret", "CODECRAFT_CREDENTIALS_FILE": str(path),
                   "CODECRAFT_GOOGLE_EMAIL": "other@example.com", "CODECRAFT_GOOGLE_PASSWORD": "google-secret", "NEWPROXY": "http://new.example:1234"}

            class AgentStarted(Exception):
                pass

            with patch.dict(os.environ, env), patch.object(sys, "argv", ["codecraft.py", "run", "--", "agent"]), patch.object(codecraft.os, "execvpe", side_effect=AgentStarted) as exec_command:
                with self.assertRaises(AgentStarted):
                    codecraft.main()
            command, args, agent_env = exec_command.call_args.args
            self.assertEqual((command, args), ("agent", ["agent"]))
            self.assertEqual(agent_env["OPENAI_API_KEY"], "cc_" + "x" * 48)
            self.assertEqual(agent_env["HTTPS_PROXY"], env["PROXY"])
            for name in ("APPASS", "GMAILLOG", "RUCAPTCHA", "CODECRAFT_CREDENTIALS_FILE",
                         "CODECRAFT_GOOGLE_EMAIL", "CODECRAFT_GOOGLE_PASSWORD", "NEWPROXY"):
                self.assertNotIn(name, agent_env)


if __name__ == "__main__":
    unittest.main()

import json
import os
from pathlib import Path
import stat
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import MagicMock, patch

import codecraft
import onemin


class OneMinTests(unittest.TestCase):
    def test_proxy_config_requires_proxy_and_parses_authenticated_proxy(self):
        with patch.dict(os.environ, {"PROXY": ""}), self.assertRaises(codecraft.PipelineError):
            onemin.proxy_config()
        with patch.dict(os.environ, {"PROXY": "user:pass@proxy.test:8080"}):
            config = onemin.proxy_config()
            self.assertEqual(config, {"server": "http://proxy.test:8080", "username": "user", "password": "pass", "bypass": ""})

    def test_firefox_uses_own_home_only_when_inherited_home_has_different_owner(self):
        with patch.dict(os.environ, {"HOME": "/home/other"}), \
                patch.object(onemin.os, "stat", return_value=SimpleNamespace(st_uid=1000)), \
                patch.object(onemin.os, "geteuid", return_value=0), \
                patch.object(onemin.pwd, "getpwuid", return_value=SimpleNamespace(pw_dir="/root")) as owner:
            self.assertEqual(onemin.firefox_launch_env()["HOME"], "/root")
            owner.assert_called_once_with(0)
        with patch.dict(os.environ, {"HOME": "/home/current"}), \
                patch.object(onemin.os, "stat", return_value=SimpleNamespace(st_uid=1000)), \
                patch.object(onemin.os, "geteuid", return_value=1000), \
                patch.object(onemin.pwd, "getpwuid") as owner:
            self.assertIsNone(onemin.firefox_launch_env())
            owner.assert_not_called()

    def test_first_party_session_keeps_no_google_cookies_or_storage(self):
        session = {"cookies": [{"name": "app", "domain": ".1min.ai"}, {"name": "google", "domain": ".google.com"}],
                   "origins": [{"origin": "https://app.1min.ai", "indexedDB": {"databases": []}},
                               {"origin": "https://accounts.google.com", "localStorage": [{"name": "token", "value": "other"}]}]}
        result = onemin.filter_session(session, {"auth": "first-party-only"})
        self.assertEqual([cookie["name"] for cookie in result["cookies"]], ["app"])
        self.assertEqual([origin["origin"] for origin in result["origins"]], ["https://app.1min.ai"])
        self.assertEqual(result["sessionStorage"], {"auth": "first-party-only"})
        self.assertFalse(onemin.first_party("1min.ai.attacker.test"))

    def test_google_login_requires_only_basic_scopes_from_google_authorization(self):
        url = "https://accounts.google.com/o/oauth2/v2/auth?scope=email+openid+profile"
        self.assertEqual(onemin.google_scope_request(url), ["email openid profile"])
        self.assertEqual(onemin.google_scope_request(url.replace("/o/oauth2/v2/auth", "/o/oauth2/auth")), ["email openid profile"])
        onemin.require_basic_google_scopes([onemin.google_scope_request(url)])
        self.assertIsNone(onemin.google_scope_request(url.replace("accounts.google.com", "accounts.google.com.attacker.test")))
        self.assertIsNone(onemin.google_scope_request(url.replace("https://", "http://")))
        self.assertIsNone(onemin.google_scope_request(url.replace("accounts.google.com", "accounts.google.com:8443")))
        bad_requests = ([], [[]], [["email profile"]], [["email openid profile openid"]],
                        [["email openid profile https://www.googleapis.com/auth/drive"]],
                        [["email openid profile", "email openid profile"]],
                        [["email openid profile"], ["email openid profile https://www.googleapis.com/auth/gmail.readonly"]])
        for requests in bad_requests:
            with self.subTest(requests=requests), self.assertRaises(codecraft.PipelineError):
                onemin.require_basic_google_scopes(requests)

    def test_google_login_rejects_unknown_scopes_before_entering_credentials(self):
        for scopes in (None, "openid email profile https://www.googleapis.com/auth/drive"):
            with self.subTest(scopes=scopes), patch.dict(os.environ, {"ONEMIN_EMAIL": "user@example.test", "ONEMIN_PASSWORD": "private"}):
                context, page, popup = MagicMock(), MagicMock(), MagicMock()
                page.locator.return_value.count.return_value = 0
                popup.url = "https://accounts.google.com/v3/signin/identifier"
                context.expect_page.return_value.__enter__.return_value.value = popup
                if scopes:
                    context.on.side_effect = lambda event, callback: callback(SimpleNamespace(
                        url="https://accounts.google.com/o/oauth2/v2/auth?scope=" + scopes.replace(" ", "+")))

                with self.assertRaises(codecraft.PipelineError):
                    onemin.google_login(context, page)
                popup.locator.return_value.fill.assert_not_called()
                popup.locator.return_value.first.fill.assert_not_called()

    def test_google_login_rejects_added_scopes_before_consent(self):
        with patch.dict(os.environ, {"ONEMIN_EMAIL": "user@example.test", "ONEMIN_PASSWORD": "private"}):
            context, page, popup = MagicMock(), MagicMock(), MagicMock()
            page.locator.return_value.count.return_value = 0
            popup.url = "https://accounts.google.com/v3/signin/identifier"
            popup.is_closed.return_value = False
            context.expect_page.return_value.__enter__.return_value.value = popup
            elements = {}
            popup.locator.side_effect = lambda selector: elements.setdefault(selector, MagicMock())
            popup.locator("body").inner_text.return_value = "Google will allow 1min.AI to sign in"
            callbacks = []

            def observe(event, callback):
                callbacks.append(callback)
                callback(SimpleNamespace(url="https://accounts.google.com/o/oauth2/v2/auth?scope=email+openid+profile"))

            context.on.side_effect = observe

            def after_password(**kwargs):
                popup.url = "https://accounts.google.com/signin/oauth/id"
                callbacks[0](SimpleNamespace(url="https://accounts.google.com/o/oauth2/v2/auth?scope=openid+email+profile+https%3A%2F%2Fwww.googleapis.com%2Fauth%2Fdrive"))

            popup.locator("#passwordNext").click.side_effect = after_password
            with self.assertRaises(codecraft.PipelineError):
                onemin.google_login(context, page)
            popup.locator('input[type="password"]:visible').first.fill.assert_called_once_with("private")
            popup.get_by_role.return_value.click.assert_not_called()

    def test_only_one_valid_active_key_is_selected(self):
        row = {"key": "k" * 40, "teamId": "own-team", "status": "ACTIVE", "createdAt": "today"}
        revoked = {**row, "key": "r" * 40, "status": "REVOKED"}
        self.assertEqual(onemin.unique_key([row], "own-team")["api_key"], "k" * 40)
        self.assertEqual(onemin.unique_key([revoked, row], "own-team")["api_key"], "k" * 40)
        self.assertIsNone(onemin.unique_key([], "own-team"))
        for rows, team in (([row, row], "own-team"), ([row], "other-team"), ([revoked], "own-team"),
                           ([row, {**revoked, "teamId": "other-team"}], "own-team"),
                           ([{**row, "key": "*" * 40}], "own-team")):
            with self.subTest(rows=rows, team=team), self.assertRaises(codecraft.PipelineError):
                onemin.unique_key(rows, team)

    def test_existing_key_does_not_require_browser_or_repeat_creation(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "account.json"
            codecraft.save_account(path, {"api_key": "k" * 40, "team_id": "own-team"})
            with patch.dict(os.environ, {"PROXY": "http://proxy.test:8080"}), patch.object(onemin, "app_session") as session:
                self.assertEqual(onemin.ensure(path), "1min.ai API key already saved")
                session.assert_not_called()
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)

    def test_stale_key_attempt_never_submits_another(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "account.json"
            codecraft.save_account(path, {"key_attempted": True, "team_id": "own-team"})

            from contextlib import contextmanager

            @contextmanager
            def session(*args):
                yield object(), "own-team", []

            with patch.dict(os.environ, {"PROXY": "http://proxy.test:8080"}), patch.object(onemin, "app_session", side_effect=session), self.assertRaises(codecraft.PipelineError):
                onemin.ensure(path)

    def test_documented_chat_api_sends_only_key_and_payload_via_https(self):
        class Response:
            def __enter__(self):
                return self

            def __exit__(self, *args):
                pass

            def read(self, limit):
                return b'{"aiRecord":{"status":"DONE"}}'

        with patch.dict(os.environ, {"PROXY": "http://proxy.test:8080", "NO_PROXY": "api.1min.ai", "no_proxy": "api.1min.ai"}), patch.object(onemin, "build_opener") as open_client:
            open_client.return_value.open.return_value = Response()
            result = onemin.chat_request("k" * 40, onemin.OPUS_5, "Hi")
            handlers = open_client.call_args.args
            self.assertIsInstance(handlers[0], onemin.ProxyHandler)
            self.assertEqual(handlers[0].proxies, {"https": "http://proxy.test:8080"})
            self.assertIsInstance(handlers[1], onemin.NoRedirect)
            self.assertIsInstance(handlers[2], codecraft.TunnelOnlyHTTPS)
            self.assertEqual((os.environ["NO_PROXY"], os.environ["no_proxy"]), ("", ""))
            request = open_client.return_value.open.call_args.args[0]
            self.assertEqual(result["aiRecord"]["status"], "DONE")
            self.assertEqual(request.full_url, "https://api.1min.ai/api/chat-with-ai")
            self.assertEqual(request.get_method(), "POST")
            self.assertEqual(request.get_header("Api-key"), "k" * 40)
            self.assertEqual(json.loads(request.data), {"type": "UNIFY_CHAT_WITH_AI", "model": onemin.OPUS_5, "promptObject": {"prompt": "Hi"}})

    def test_redirect_never_forwards_api_key(self):
        with self.assertRaises(codecraft.PipelineError):
            onemin.NoRedirect().redirect_request(None, None, 302, "", {}, "https://other.test/")

    def test_agent_receives_key_and_proxy_but_not_google_credentials(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "account.json"
            codecraft.save_account(path, {"api_key": "k" * 40})
            settings = {"ONEMIN_CREDENTIALS_FILE": str(path), "PROXY": "http://proxy.test:8080",
                        "ONEMIN_EMAIL": "user@example.test", "ONEMIN_PASSWORD": "private",
                        "GMAILLOG": "gmail@example.test", "APPASS": "app-password", "PASSWORD": "google-secret",
                        "CODECRAFT_GOOGLE_EMAIL": "other@example.test", "CODECRAFT_GOOGLE_PASSWORD": "different-secret",
                        "CODECRAFT_GOOGLE_CREDENTIALS_FILE": "/tmp/private.json", "NEWPROXY": "http://new.test:8181"}

            class Started(Exception):
                pass

            with patch.dict(os.environ, settings), patch.object(sys, "argv", ["onemin.py", "run", "--", "agent"]), patch.object(onemin.os, "execvpe", side_effect=Started) as run:
                with self.assertRaises(Started):
                    onemin.main()
            command, args, env = run.call_args.args
            self.assertEqual((command, args), ("agent", ["agent"]))
            self.assertEqual(env["ONEMIN_API_KEY"], "k" * 40)
            self.assertEqual(env["HTTPS_PROXY"], settings["PROXY"])
            for name in ("ONEMIN_EMAIL", "ONEMIN_PASSWORD", "APPASS", "GMAILLOG", "PASSWORD", "ONEMIN_CREDENTIALS_FILE",
                         "CODECRAFT_GOOGLE_EMAIL", "CODECRAFT_GOOGLE_PASSWORD", "CODECRAFT_GOOGLE_CREDENTIALS_FILE", "NEWPROXY"):
                self.assertNotIn(name, env)


if __name__ == "__main__":
    unittest.main()

import io
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
from types import ModuleType, SimpleNamespace
import unittest
from unittest.mock import MagicMock, patch

import codecraft
import codecraft_google as oauth
from onemin import NoRedirect


class GoogleCodeCraftTests(unittest.TestCase):
    def test_legacy_credential_file_cannot_be_reused_for_google(self):
        with tempfile.TemporaryDirectory() as directory:
            legacy = Path(directory) / "legacy.json"
            alias = Path(directory) / "alias.json"
            alias.symlink_to(legacy)
            for new_path, legacy_override in (
                (str(codecraft.CREDS), str(legacy)),
                (str(legacy), str(legacy)),
                (str(alias), str(legacy)),
            ):
                with self.subTest(new_path=new_path), patch.dict(os.environ, {
                    "CODECRAFT_CREDENTIALS_FILE": legacy_override, "CODECRAFT_GOOGLE_CREDENTIALS_FILE": new_path,
                }), self.assertRaises(codecraft.PipelineError):
                    oauth.account_path()

    def test_only_canonical_https_hosts_are_accepted(self):
        self.assertTrue(oauth.codecraft_url(codecraft.BASE + "/dashboard", "/dashboard"))
        self.assertTrue(oauth.codecraft_url("https://codecraftapi.com:443/dashboard", "/dashboard"))
        for url in ("http://codecraftapi.com/dashboard", "https://codecraftapi.com:8443/dashboard",
                    "https://codecraftapi.com.attacker.test/dashboard", "https://name:secret@codecraftapi.com/dashboard"):
            with self.subTest(url=url):
                self.assertFalse(oauth.codecraft_url(url, "/dashboard"))
        self.assertFalse(oauth.secure_host("https://accounts.google.com:8443/", "accounts.google.com"))

    def test_new_proxy_is_required_even_if_old_proxy_exists(self):
        with patch.dict(os.environ, {"NEWPROXY": "", "PROXY": "http://old.test:8080"}), self.assertRaises(codecraft.PipelineError):
            codecraft.proxy_url("NEWPROXY")
        with patch.dict(os.environ, {"NEWPROXY": "user:pass@new.test:9090", "PROXY": "http://old.test:8080"}):
            proxy = codecraft.proxy_url("NEWPROXY")
            self.assertEqual(oauth.proxy_config(proxy), {
                "server": "http://new.test:9090", "username": "user", "password": "pass", "bypass": "",
            })

    def test_google_browser_uses_owner_home_without_changing_proxy(self):
        module = ModuleType("playwright.sync_api")
        module.sync_playwright = MagicMock()
        browser = module.sync_playwright.return_value.__enter__.return_value.firefox.launch.return_value
        browser.new_context.side_effect = RuntimeError("stopped before browsing")
        with tempfile.TemporaryDirectory() as directory, \
                patch.dict(sys.modules, {"playwright": ModuleType("playwright"), "playwright.sync_api": module}), \
                patch.dict(os.environ, {"NEWPROXY": "http://new.test:9090"}), \
                patch.object(oauth, "firefox_launch_env", return_value={"HOME": "/root"}), \
                self.assertRaisesRegex(RuntimeError, "stopped before browsing"):
            with oauth.app_session(Path(directory) / "account.json"):
                pass
        module.sync_playwright.return_value.__enter__.return_value.firefox.launch.assert_called_once_with(
            headless=True, proxy={"server": "http://new.test:9090", "username": "", "password": "", "bypass": ""},
            env={"HOME": "/root"})

    def test_session_saves_codecraft_data_not_google_cookies(self):
        original = {
            "cookies": [{"domain": ".codecraftapi.com"}, {"domain": ".google.com"},
                        {"domain": "codecraftapi.com.attacker.test"}],
            "origins": [{"origin": "https://codecraftapi.com"}, {"origin": "https://accounts.google.com"},
                        {"origin": "http://codecraftapi.com"}],
        }
        session = oauth.filter_session(original)
        self.assertEqual([c["domain"] for c in session["cookies"]], [".codecraftapi.com"])
        self.assertEqual([o["origin"] for o in session["origins"]], [codecraft.BASE])

    def test_unknown_scopes_stop_before_google_credentials(self):
        with patch.dict(os.environ, {"CODECRAFT_GOOGLE_EMAIL": "user@example.test", "CODECRAFT_GOOGLE_PASSWORD": "private"}):
            context, page = MagicMock(), MagicMock()
            page.url = "https://accounts.google.com/v3/signin/identifier"
            for scopes in (None, "openid+email+profile+https%3A%2F%2Fwww.googleapis.com%2Fauth%2Fdrive"):
                with self.subTest(scopes=scopes):
                    context.reset_mock()
                    page.reset_mock()
                    if scopes:
                        context.on.side_effect = lambda event, handler: handler(SimpleNamespace(
                            url="https://accounts.google.com/o/oauth2/auth?scope=" + scopes))
                    else:
                        context.on.side_effect = None
                    with self.assertRaises(codecraft.PipelineError):
                        oauth.google_login(context, page)
                    page.locator.return_value.fill.assert_not_called()
                    context.remove_listener.assert_called_once()

    def test_saved_key_and_interrupted_creation_never_submit_again(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "account.json"
            with patch.dict(os.environ, {"NEWPROXY": "http://new.test:8080"}), patch.object(oauth, "app_session") as session:
                codecraft.save_account(path, {"email": "user@example.test", "api_key": "cc_" + "k" * 48})
                before = path.stat().st_mtime_ns
                self.assertEqual(oauth.ensure(path), "CodeCraft Google API key already saved")
                self.assertEqual(path.stat().st_mtime_ns, before)
                codecraft.save_account(path, {"email": "user@example.test", "key_attempted": True})
                with self.assertRaises(codecraft.PipelineError):
                    oauth.ensure(path)
                session.assert_not_called()
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)

    def test_existing_key_row_blocks_new_creation(self):
        page = MagicMock()
        page.url = codecraft.BASE + "/dashboard/api-keys"
        page.goto.return_value.status = 200
        page.locator.return_value.count.return_value = 1
        page.locator.return_value.first.inner_text.return_value = "Previously created key"
        with patch.object(oauth, "save_account") as save, self.assertRaises(codecraft.PipelineError):
            oauth.create_key(page, {"key_name": oauth.KEY_NAME}, Path("unused.json"))
        save.assert_not_called()
        page.get_by_role.assert_not_called()

    def test_key_page_redirect_to_another_origin_is_rejected(self):
        page = MagicMock()
        page.goto.return_value.status = 200
        for url in ("http://codecraftapi.com/dashboard/api-keys", "https://codecraftapi.com:8443/dashboard/api-keys"):
            with self.subTest(url=url):
                page.url = url
                with patch.object(oauth, "save_account") as save, self.assertRaises(codecraft.PipelineError):
                    oauth.create_key(page, {"key_name": oauth.KEY_NAME}, Path("unused.json"))
                save.assert_not_called()
                page.get_by_role.assert_not_called()

    def test_new_key_is_saved_once_with_private_permissions(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "account.json"
            page = MagicMock()
            page.url = codecraft.BASE + "/dashboard/api-keys"
            page.goto.return_value.status = 200
            rows, options, name_input = MagicMock(), MagicMock(), MagicMock()
            rows.count.return_value = 1
            rows.first.inner_text.return_value = oauth.EMPTY_KEYS
            scope_fields = []
            for scope in sorted(oauth.SCOPES):
                field = MagicMock()
                field.get_attribute.return_value = scope
                field.is_checked.return_value = True
                scope_fields.append(field)
            options.all.return_value = scope_fields
            page.locator.side_effect = lambda selector: {
                "table tbody tr": rows, 'input[name="scopes[]"]': options, 'input[name="name"]': name_input,
            }[selector]
            page.content.side_effect = [
                '<form method="POST" action="/dashboard/api-keys"><input type="hidden" name="_token" value="csrf">'
                '<input name="name"></form>',
                '<div><code>cc_' + "k" * 48 + '</code></div>',
            ]
            opener = page.get_by_role.return_value
            opener.count.return_value = 1
            opener.get_attribute.return_value = "showCreateModal = true"
            name_input.count.return_value = 1
            submit = name_input.locator.return_value.get_by_role.return_value
            submit.count.return_value = 1
            submit.get_attribute.return_value = "submit"
            page.expect_response.return_value.__enter__.return_value.value.status = 302
            account = {"email": "user@example.test", "key_name": oauth.KEY_NAME}
            oauth.create_key(page, account, path)
            self.assertEqual(codecraft.read_account(path)["api_key"], "cc_" + "k" * 48)
            self.assertNotIn("key_attempted", codecraft.read_account(path))
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            name_input.fill.assert_called_once_with(oauth.KEY_NAME)
            opener.click.assert_called_once()
            submit.click.assert_called_once()
            page.remove_listener.assert_called_once()

    def test_one_time_key_from_redirect_response_is_saved_without_dom(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "account.json"
            page = MagicMock()
            page.url = codecraft.BASE + "/dashboard/api-keys"
            page.goto.return_value.status = 200
            rows, options = MagicMock(), MagicMock()
            rows.count.return_value = 1
            rows.first.inner_text.return_value = oauth.EMPTY_KEYS
            options.all.return_value = [MagicMock() for _ in oauth.SCOPES]
            for option, scope in zip(options.all.return_value, sorted(oauth.SCOPES)):
                option.get_attribute.return_value = scope
                option.is_checked.return_value = True
            name_input = MagicMock()
            name_input.count.return_value = 1
            submit = name_input.locator.return_value.get_by_role.return_value
            submit.count.return_value = 1
            submit.get_attribute.return_value = "submit"
            page.locator.side_effect = lambda selector: {
                "table tbody tr": rows, 'input[name="scopes[]"]': options, 'input[name="name"]': name_input,
            }[selector]
            page.content.return_value = '<form method="POST" action="/dashboard/api-keys">' \
                '<input type="hidden" name="_token" value="csrf"><input name="name"></form>'
            page.get_by_role.return_value.count.return_value = 1
            page.get_by_role.return_value.get_attribute.return_value = "showCreateModal = true"
            page.expect_response.return_value.__enter__.return_value.value.status = 302

            def on_response(event, handler):
                handler(SimpleNamespace(url=codecraft.BASE + "/dashboard/api-keys", status=200,
                                        request=SimpleNamespace(method="GET"),
                                        text=lambda: '<code>cc_' + "k" * 48 + '</code>'))

            page.on.side_effect = on_response
            oauth.create_key(page, {"key_name": oauth.KEY_NAME}, path)
            self.assertEqual(codecraft.read_account(path)["api_key"], "cc_" + "k" * 48)
            submit.click.assert_called_once()

    def test_key_dialog_must_open_before_one_time_submission(self):
        page = MagicMock()
        page.url = codecraft.BASE + "/dashboard/api-keys"
        page.goto.return_value.status = 200
        rows = page.locator.return_value
        rows.count.return_value = 1
        rows.first.inner_text.return_value = oauth.EMPTY_KEYS
        form = '<form method="POST" action="/dashboard/api-keys">' \
            '<input type="hidden" name="_token" value="csrf"><input name="name"></form>'
        page.content.return_value = form
        scope_fields = [MagicMock() for _ in oauth.SCOPES]
        for field, scope in zip(scope_fields, sorted(oauth.SCOPES)):
            field.get_attribute.return_value = scope
            field.is_checked.return_value = True
        scopes = MagicMock()
        scopes.all.return_value = scope_fields
        name_input = MagicMock()
        name_input.count.return_value = 1
        name_input.wait_for.side_effect = TimeoutError("dialog did not open")
        page.locator.side_effect = lambda selector: {
            "table tbody tr": rows, 'input[name="scopes[]"]': scopes, 'input[name="name"]': name_input,
        }[selector]
        opener = page.get_by_role.return_value
        opener.count.return_value = 1
        opener.get_attribute.return_value = "showCreateModal = true"
        with patch.object(oauth, "save_account") as save, self.assertRaises(TimeoutError):
            oauth.create_key(page, {"key_name": oauth.KEY_NAME}, Path("unused.json"))
        opener.click.assert_called_once()
        save.assert_not_called()
        page.expect_response.assert_not_called()

    def test_model_check_uses_only_new_proxy_and_no_redirect(self):
        class Response:
            def __enter__(self):
                return self

            def __exit__(self, *args):
                pass

            def read(self, limit):
                return b'{"object":"list","data":[{"id":"safe-model"}]}'

        with patch.dict(os.environ, {"NEWPROXY": "http://new.test:8080", "NO_PROXY": "codecraftapi.com", "no_proxy": "codecraftapi.com"}), patch.object(oauth, "build_opener") as builder:
            builder.return_value.open.return_value = Response()
            self.assertEqual(oauth.verify_key("cc_" + "k" * 48), 1)
            handlers = builder.call_args.args
            self.assertIsInstance(handlers[0], oauth.ProxyHandler)
            self.assertEqual(handlers[0].proxies, {"https": "http://new.test:8080"})
            self.assertIsInstance(handlers[1], NoRedirect)
            self.assertIsInstance(handlers[2], codecraft.TunnelOnlyHTTPS)
            self.assertEqual((os.environ["NO_PROXY"], os.environ["no_proxy"]), ("", ""))
            request = builder.return_value.open.call_args.args[0]
            self.assertEqual(request.full_url, codecraft.BASE + "/v1/models")
            self.assertEqual(request.get_header("Authorization"), "Bearer cc_" + "k" * 48)
            self.assertEqual(request.get_header("User-agent"), "Mozilla/5.0")

    def test_agent_inherits_new_key_and_proxy_but_no_google_secrets(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "account.json"
            codecraft.save_account(path, {"email": "user@example.test", "api_key": "cc_" + "k" * 48})
            env = {
                "CODECRAFT_GOOGLE_CREDENTIALS_FILE": str(path), "NEWPROXY": "http://new.test:8080",
                "PROXY": "http://old.test:8080", "CODECRAFT_GOOGLE_EMAIL": "user@example.test",
                "CODECRAFT_GOOGLE_PASSWORD": "private", "GMAILLOG": "other@example.test", "APPASS": "secret",
            }
            with patch.dict(os.environ, env), patch.object(sys, "argv", ["codecraft_google.py", "run", "--", "agent"]), patch.object(oauth.os, "execvpe", side_effect=RuntimeError("started")) as run, patch.object(sys, "stderr", new_callable=io.StringIO):
                self.assertEqual(oauth.main(), 1)
            command, arguments, exported = run.call_args.args
            self.assertEqual((command, arguments), ("agent", ["agent"]))
            self.assertEqual(exported["OPENAI_API_KEY"], "cc_" + "k" * 48)
            self.assertEqual(exported["HTTPS_PROXY"], env["NEWPROXY"])
            self.assertEqual(exported["PROXY"], env["NEWPROXY"])
            for key in ("CODECRAFT_GOOGLE_EMAIL", "CODECRAFT_GOOGLE_PASSWORD", "GMAILLOG", "APPASS", "NEWPROXY",
                        "CODECRAFT_GOOGLE_CREDENTIALS_FILE"):
                self.assertNotIn(key, exported)


if __name__ == "__main__":
    unittest.main()

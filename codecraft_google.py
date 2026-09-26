#!/usr/bin/env python3
"""Sign in to a separate CodeCraft account through Google and retain one API key."""

import argparse
from contextlib import contextmanager
import fcntl
import html
import json
import os
from pathlib import Path
import stat
import sys
import time
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import ProxyHandler, Request, build_opener

from codecraft import BASE, CREDS, KEY_PATTERN, PipelineError, TunnelOnlyHTTPS, account_path as legacy_account_path, form_for, proxy_url, read_account, save_account
from onemin import NoRedirect, firefox_launch_env, google_scope_request, proxy_config, require_basic_google_scopes


DEFAULT_FILE = Path(__file__).resolve().parent / ".secrets" / "codecraft-google.json"
KEY_NAME = "hoplite-google-agent"
SCOPES = {"inference", "models:read", "embeddings"}
EMPTY_KEYS = 'No API keys yet. Click "Create API Key" above to generate one.'


def account_path():
    path = Path(os.environ.get("CODECRAFT_GOOGLE_CREDENTIALS_FILE", DEFAULT_FILE)).expanduser().resolve()
    if path in (CREDS.resolve(), legacy_account_path()):
        raise PipelineError("CodeCraft Google credentials must not reuse the legacy account file")
    return path


def session_path(path):
    return path.with_name(path.stem + "-session.json")


@contextmanager
def locked_account(path):
    path.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
    if path.parent.stat().st_mode & 0o077:
        raise PipelineError("CodeCraft Google credentials directory must be private (chmod 700)")
    fd = os.open(path.parent / ".codecraft-google.lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        mode = os.fstat(fd).st_mode
        if not stat.S_ISREG(mode) or stat.S_IMODE(mode) != 0o600:
            raise PipelineError("CodeCraft Google account lock must be private (chmod 600)")
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        os.close(fd)


def filter_session(state):
    return {
        "cookies": [cookie for cookie in state.get("cookies", []) if cookie.get("domain", "").lstrip(".") == "codecraftapi.com"],
        "origins": [origin for origin in state.get("origins", []) if origin.get("origin") == BASE],
    }


def secure_host(value, host):
    url = urlsplit(value)
    try:
        return (url.scheme == "https" and url.hostname == host and url.port in (None, 443)
                and url.username is None and url.password is None)
    except ValueError:
        return False


def codecraft_url(value, path=None):
    return secure_host(value, "codecraftapi.com") and (path is None or urlsplit(value).path == path)


def google_login(context, page, accept_workspace_notice=False):
    email = os.environ.get("CODECRAFT_GOOGLE_EMAIL", "")
    password = os.environ.get("CODECRAFT_GOOGLE_PASSWORD", "")
    if not email or "@" not in email or not password:
        raise PipelineError("Set CODECRAFT_GOOGLE_EMAIL and CODECRAFT_GOOGLE_PASSWORD to renew Google OAuth")
    scopes_seen = []

    def capture(request):
        scopes = google_scope_request(request.url)
        if scopes is not None:
            scopes_seen.append(scopes)

    context.on("request", capture)
    try:
        page.goto(BASE + "/auth/google/redirect", wait_until="domcontentloaded", timeout=55000)
        page.locator("#identifierId").wait_for(state="visible", timeout=30000)
        if not secure_host(page.url, "accounts.google.com"):
            raise PipelineError("Google OAuth navigated to an unexpected host")
        require_basic_google_scopes(scopes_seen)
        page.locator("#identifierId").fill(email)
        page.locator("#identifierNext").click(timeout=20000)
        page.locator('input[type="password"]:visible').wait_for(state="visible", timeout=30000)
        if not secure_host(page.url, "accounts.google.com"):
            raise PipelineError("Refusing to send Google password to an unexpected host")
        require_basic_google_scopes(scopes_seen)
        page.locator('input[type="password"]:visible').first.fill(password)
        page.locator("#passwordNext").click(timeout=20000)

        deadline = time.monotonic() + 180
        notice_accepted = False
        consented = False
        while time.monotonic() < deadline:
            url = urlsplit(page.url)
            if codecraft_url(page.url):
                break
            # Google synchronizes sign-in cookies through country domains before consent.
            if url.path == "/accounts/SetSID" and any(secure_host(page.url, host) for host in ("accounts.google.de", "accounts.google.at")):
                page.wait_for_timeout(500)
                continue
            if not any(secure_host(page.url, host) for host in ("accounts.google.com", "accounts.google.at")):
                raise PipelineError("Google OAuth moved to an unexpected host")
            if url.path.endswith("/rejected"):
                raise PipelineError("Google rejected this OAuth sign-in")
            if url.path == "/v3/signin/speedbump/workspacetermsofservice" and not notice_accepted:
                if not accept_workspace_notice:
                    raise PipelineError("Google Workspace notice requires --accept-workspace-notice")
                button = page.get_by_role("button", name="I understand")
                button.wait_for(state="visible", timeout=16000)
                if "Your school manages this account" not in page.locator("body").inner_text(timeout=8000):
                    raise PipelineError("Unexpected Google Workspace notice")
                button.click(no_wait_after=True, timeout=16000)
                notice_accepted = True
            elif url.path == "/signin/oauth/id" and not consented:
                button = page.get_by_role("button", name="Continue")
                button.wait_for(state="visible", timeout=16000)
                if "codecraft" not in page.locator("body").inner_text(timeout=8000).casefold():
                    raise PipelineError("Unexpected Google consent application")
                require_basic_google_scopes(scopes_seen)
                button.click(no_wait_after=True, timeout=16000)
                consented = True
            elif page.locator('input[name="totpPin"]:visible, input[type="tel"]:visible, iframe[src*="recaptcha"]:visible').count():
                raise PipelineError("Google requires additional account verification")
            page.wait_for_timeout(1200)
        else:
            raise PipelineError("Google OAuth did not return to CodeCraft")
        require_basic_google_scopes(scopes_seen)
    finally:
        context.remove_listener("request", capture)


@contextmanager
def app_session(path, expected_email=None, accept_workspace_notice=False, force=False):
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        raise PipelineError("Install requirements-oauth.txt and Playwright Firefox to sign in to CodeCraft") from None
    session_file = session_path(path)
    saved = read_account(session_file) if session_file.exists() and not force else None
    with sync_playwright() as playwright:
        options = {"headless": True, "proxy": proxy_config(proxy_url("NEWPROXY"))}
        launch_env = firefox_launch_env()
        if launch_env is not None:
            options["env"] = launch_env
        browser = playwright.firefox.launch(**options)
        try:
            context = browser.new_context(storage_state=filter_session(saved) if saved else None,
                                          service_workers="block", accept_downloads=False)
            try:
                page = context.new_page()
                page.goto(BASE + "/dashboard", wait_until="domcontentloaded", timeout=50000)
                if codecraft_url(page.url, "/login"):
                    google_login(context, page, accept_workspace_notice)
                    page.goto(BASE + "/dashboard", wait_until="domcontentloaded", timeout=50000)
                if not codecraft_url(page.url, "/dashboard"):
                    raise PipelineError("CodeCraft did not open the dashboard after Google OAuth")
                page.goto(BASE + "/dashboard/settings", wait_until="domcontentloaded", timeout=50000)
                if not codecraft_url(page.url, "/dashboard/settings"):
                    raise PipelineError("CodeCraft account settings are unavailable")
                fields = page.locator('input[name="email"]')
                if fields.count() != 1:
                    raise PipelineError("Cannot verify the signed-in CodeCraft account")
                email = fields.input_value().strip()
                if not email or "@" not in email:
                    raise PipelineError("CodeCraft did not provide the signed-in account email")
                if expected_email and email.casefold() != expected_email.casefold():
                    raise PipelineError("CodeCraft Google account does not match the requested account")
                save_account(session_file, filter_session(context.storage_state(indexed_db=True)))
                yield page, email
            finally:
                context.close()
        finally:
            browser.close()


def create_key(page, account, path):
    response = page.goto(BASE + "/dashboard/api-keys", wait_until="domcontentloaded", timeout=50000)
    if not response or response.status != 200 or not codecraft_url(page.url, "/dashboard/api-keys"):
        raise PipelineError("CodeCraft API Keys page is unavailable")
    rows = page.locator("table tbody tr")
    if rows.count() != 1 or rows.first.inner_text().strip() != EMPTY_KEYS:
        raise PipelineError("Existing or unknown API key entries; refusing to create another")
    form_for(page.content(), path="/dashboard/api-keys", fields=("name",))
    scopes = page.locator('input[name="scopes[]"]')
    options = scopes.all()
    if len(options) != 3 or {option.get_attribute("value") for option in options} != SCOPES or not all(option.is_checked() for option in options):
        raise PipelineError("CodeCraft API key scopes changed or are incomplete")
    opener = page.get_by_role("button", name="Create API Key", exact=True)
    if opener.count() != 1 or opener.get_attribute("@click") != "showCreateModal = true":
        raise PipelineError("CodeCraft key creation dialog has changed")
    opener.click(timeout=10000)
    name_field = page.locator('input[name="name"]')
    if name_field.count() != 1:
        raise PipelineError("CodeCraft key name field is unavailable")
    name_field.wait_for(state="visible", timeout=7000)
    submit = name_field.locator("xpath=ancestor::form").get_by_role("button", name="Create Key", exact=True)
    if submit.count() != 1 or submit.get_attribute("type") != "submit":
        raise PipelineError("CodeCraft key submission button has changed")
    name_field.fill(account["key_name"])
    account["key_attempted"] = True
    save_account(path, account)

    def retain(raw):
        keys = set(KEY_PATTERN.findall(html.unescape(raw)))
        if len(keys) > 1:
            raise PipelineError("Multiple one-time keys returned; inspect the account before retrying")
        if keys:
            account["api_key"] = keys.pop()
            del account["key_attempted"]
            save_account(path, account)
            return True
        return False

    replies = []

    def capture(result):
        if codecraft_url(result.url, "/dashboard/api-keys"):
            if result.request.method in ("POST", "GET"):
                replies.append(result)

    page.on("response", capture)
    try:
        with page.expect_response(
            lambda result: codecraft_url(result.url, "/dashboard/api-keys") and result.request.method == "POST",
            timeout=30000,
        ) as created:
            submit.click(no_wait_after=True, timeout=15000)
        result = created.value
        if result.status not in (200, 201, 302, 303):
            raise PipelineError(f"CodeCraft key creation returned HTTP {result.status}; inspect the account before retrying")
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            while replies:
                reply = replies.pop(0)
                if reply.status == 200 and retain(reply.text()):
                    return
            if not codecraft_url(page.url):
                raise PipelineError("CodeCraft key creation redirected to an unexpected host")
            try:
                if retain(page.content()):
                    return
            except PipelineError:
                raise
            except Exception:
                pass  # A redirect may temporarily destroy the old page context.
            page.wait_for_timeout(250)
    finally:
        page.remove_listener("response", capture)
    raise PipelineError("One-time API key was not displayed; inspect the account before retrying")


def ensure(path, accept_workspace_notice=False):
    proxy_url("NEWPROXY")
    with locked_account(path):
        account = read_account(path) if path.exists() else None
        requested_email = os.environ.get("CODECRAFT_GOOGLE_EMAIL")
        if account and requested_email and account["email"].casefold() != requested_email.casefold():
            raise PipelineError("CODECRAFT_GOOGLE_EMAIL does not match the saved account")
        if account and account.get("api_key"):
            return "CodeCraft Google API key already saved"
        if account and account.get("key_attempted"):
            raise PipelineError("Previous key creation may have succeeded; inspect the dashboard before retrying")
        with app_session(path, expected_email=requested_email or (account or {}).get("email"),
                         accept_workspace_notice=accept_workspace_notice) as (page, email):
            account = account or {"email": email, "key_name": KEY_NAME, "provider": "google"}
            save_account(path, account)
            create_key(page, account, path)
            return "CodeCraft Google account and API key saved"


def login(path, accept_workspace_notice=False, force=False):
    proxy_url("NEWPROXY")
    with locked_account(path):
        account = read_account(path) if path.exists() else None
        expected = os.environ.get("CODECRAFT_GOOGLE_EMAIL") or (account or {}).get("email")
        with app_session(path, expected_email=expected, accept_workspace_notice=accept_workspace_notice, force=force) as (_, email):
            if not account:
                save_account(path, {"email": email, "key_name": KEY_NAME, "provider": "google"})
            return "CodeCraft Google sign-in verified through NEWPROXY"


def verify_key(key):
    proxy = proxy_url("NEWPROXY")
    os.environ["NO_PROXY"] = os.environ["no_proxy"] = ""
    opener = build_opener(ProxyHandler({"https": proxy}), NoRedirect(), TunnelOnlyHTTPS())
    request = Request(BASE + "/v1/models", headers={
        "Authorization": "Bearer " + key, "Accept": "application/json", "User-Agent": "Mozilla/5.0",
    })
    try:
        with opener.open(request, timeout=45) as response:
            data = json.loads(response.read(2_000_000))
    except HTTPError as exc:
        raise PipelineError(f"CodeCraft model API returned HTTP {exc.code}") from None
    except (URLError, TimeoutError):
        raise PipelineError("Cannot reach CodeCraft model API through NEWPROXY") from None
    if not isinstance(data, dict) or data.get("object") != "list" or not isinstance(data.get("data"), list):
        raise PipelineError("Unexpected CodeCraft model API response")
    return len(data["data"])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    actions = parser.add_subparsers(dest="action", required=True)
    auth = actions.add_parser("login", help="Verify or renew the separate Google OAuth account")
    auth.add_argument("--force", action="store_true")
    auth.add_argument("--accept-workspace-notice", action="store_true")
    create = actions.add_parser("ensure", help="Create at most one Google-account API key")
    create.add_argument("--accept-workspace-notice", action="store_true")
    actions.add_parser("status", help="Inspect the Google-account key without network access")
    actions.add_parser("verify", help="Check the API key with GET /v1/models through NEWPROXY")
    run = actions.add_parser("run", help="Launch an agent with this account's key and NEWPROXY")
    run.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    try:
        path = account_path()
        if args.action == "status":
            account = read_account(path) if path.exists() else None
            print("API key saved" if account and account.get("api_key") else "API key not saved")
            return 0
        if args.action == "login":
            print(login(path, args.accept_workspace_notice, args.force))
            return 0
        if args.action == "ensure":
            print(ensure(path, args.accept_workspace_notice))
            return 0
        if args.action == "verify":
            account = read_account(path)
            if not account or not account.get("api_key"):
                raise PipelineError("Run ensure before checking the API key")
            print(f"CodeCraft API key accepted; {verify_key(account['api_key'])} models available")
            return 0
        command = args.command[1:] if args.command[:1] == ["--"] else args.command
        if not command:
            raise PipelineError("Pass an agent command after --")
        ensure(path)
        account = read_account(path)
        proxy = proxy_url("NEWPROXY")
        env = os.environ.copy()
        for secret in ("CODECRAFT_GOOGLE_EMAIL", "CODECRAFT_GOOGLE_PASSWORD", "CODECRAFT_GOOGLE_CREDENTIALS_FILE",
                       "NEWPROXY", "ONEMIN_EMAIL", "ONEMIN_PASSWORD", "ONEMIN_API_KEY", "ONEMIN_CREDENTIALS_FILE",
                       "GMAILLOG", "APPASS", "PASSWORD", "AUTHENTICATION", "RUCAPTCHA", "RUCAPTCHA_KEY",
                       "RUCAPTCHA_API_KEY", "CODECRAFT_CREDENTIALS_FILE"):
            env.pop(secret, None)
        env.update({
            "CODECRAFT_API_KEY": account["api_key"], "CODECRAFT_BASE_URL": BASE + "/v1",
            "OPENAI_API_KEY": account["api_key"], "OPENAI_BASE_URL": BASE + "/v1",
            "PROXY": proxy, "HTTPS_PROXY": proxy, "HTTP_PROXY": proxy, "ALL_PROXY": proxy,
            "https_proxy": proxy, "http_proxy": proxy, "all_proxy": proxy,
            "NO_PROXY": "", "no_proxy": "",
        })
        os.execvpe(command[0], command, env)
    except Exception as exc:
        print(f"Error: {exc if isinstance(exc, PipelineError) else type(exc).__name__}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())

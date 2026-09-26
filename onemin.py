#!/usr/bin/env python3
"""Manage a 1min.ai Google session and API key, then call its documented chat API."""

import argparse
from contextlib import contextmanager
import fcntl
import json
import os
from pathlib import Path
import pwd
import re
import stat
import sys
import time
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qs, unquote, urlsplit
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener

from codecraft import PipelineError, TunnelOnlyHTTPS, proxy_url, read_account, save_account


APP = "https://app.1min.ai"
API = "https://api.1min.ai"
OPUS_5 = "us.anthropic.claude-opus-5"
KEY_ROUTE = re.compile(r"^/api/teams/([^/]+)/keys$")
DEFAULT_FILE = Path(__file__).resolve().parent / ".secrets" / "onemin.json"


class SessionExpired(PipelineError):
    pass


def account_path():
    return Path(os.environ.get("ONEMIN_CREDENTIALS_FILE", DEFAULT_FILE)).expanduser().resolve()


def session_path(path):
    return path.with_name("onemin-session.json")


@contextmanager
def locked_account(path):
    path.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
    if path.parent.stat().st_mode & 0o077:
        raise PipelineError("1min.ai credentials directory must be private (chmod 700)")
    fd = os.open(path.parent / ".onemin.lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        if stat.S_IMODE(os.fstat(fd).st_mode) != 0o600:
            raise PipelineError("1min.ai account lock must be private (chmod 600)")
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        os.close(fd)


def proxy_config(proxy=None):
    parts = urlsplit(proxy or proxy_url())
    return {
        "server": f"http://{parts.hostname}:{parts.port}",
        "username": unquote(parts.username or ""),
        "password": unquote(parts.password or ""),
        "bypass": "",
    }


def firefox_launch_env():
    home = os.environ.get("HOME")
    if home and os.stat(home).st_uid != os.geteuid():
        # Firefox refuses to start when HOME belongs to another user.
        return {**os.environ, "HOME": pwd.getpwuid(os.geteuid()).pw_dir}
    return None


def first_party(host):
    return host == "1min.ai" or bool(host and host.endswith(".1min.ai"))


def filter_session(state, session_storage=None):
    return {
        "cookies": [cookie for cookie in state.get("cookies", []) if first_party(cookie.get("domain", "").lstrip("."))],
        "origins": [origin for origin in state.get("origins", []) if first_party(urlsplit(origin.get("origin", "")).hostname)],
        "sessionStorage": session_storage or {},
    }


def restore_session(context, session):
    storage = session.get("sessionStorage", {})
    if storage:
        context.add_init_script(
            script='if (location.hostname === "app.1min.ai") { for (const [key, value] of Object.entries('
            + json.dumps(storage) + ")) sessionStorage.setItem(key, value); }"
        )


def save_session(context, page, path):
    storage = page.evaluate("Object.fromEntries(Object.keys(sessionStorage).map(key => [key, sessionStorage.getItem(key)]))")
    save_account(path, filter_session(context.storage_state(indexed_db=True), storage))


def load_key_list(page):
    responses = []

    def capture(response):
        url = urlsplit(response.url)
        if url.hostname == "api.1min.ai" and KEY_ROUTE.fullmatch(url.path) and response.request.method == "GET":
            responses.append(response)

    page.on("response", capture)
    try:
        page.goto(APP + "/api", wait_until="domcontentloaded", timeout=40000)
        deadline = time.monotonic() + 22
        while not responses and time.monotonic() < deadline:
            page.wait_for_timeout(500)
    finally:
        page.remove_listener("response", capture)
    if not responses:
        if page.get_by_role("button", name="Log In").count():
            raise SessionExpired("1min.ai OAuth session expired")
        raise PipelineError("1min.ai did not return an API key list")
    response = responses[-1]
    if response.status in (401, 403):
        raise SessionExpired("1min.ai OAuth session expired")
    if response.status != 200:
        raise PipelineError(f"1min.ai API key list returned HTTP {response.status}")
    route = KEY_ROUTE.fullmatch(urlsplit(response.url).path)
    data = response.json()
    if not isinstance(data, dict) or not isinstance(data.get("apiKeyList"), list):
        raise PipelineError("Unexpected 1min.ai API key list format")
    return route.group(1), data["apiKeyList"]


def google_scope_request(request_url):
    url = urlsplit(request_url)
    try:
        trusted = url.scheme == "https" and url.hostname == "accounts.google.com" and url.port in (None, 443) and url.username is None and url.password is None
    except ValueError:
        trusted = False
    if not trusted or url.path not in ("/o/oauth2/auth", "/o/oauth2/v2/auth"):
        return None
    return parse_qs(url.query, keep_blank_values=True).get("scope", [])


def require_basic_google_scopes(requests):
    basic = {"openid", "email", "profile"}
    if not requests or any(len(scopes) != 1 or len(scopes[0].split()) != 3 or set(scopes[0].split()) != basic for scopes in requests):
        raise PipelineError("Google OAuth scopes are missing or exceed basic sign-in")


def google_login(context, page, accept_workspace_notice=False):
    email = os.environ.get("ONEMIN_EMAIL", "")
    password = os.environ.get("ONEMIN_PASSWORD", "")
    if not email or "@" not in email or not password:
        raise PipelineError("Set ONEMIN_EMAIL and ONEMIN_PASSWORD to re-enter Google OAuth")
    # The consent copy can change; enforce the scopes in Google's authorization request.
    scopes_seen = []

    def capture_auth(request):
        scopes = google_scope_request(request.url)
        if scopes is not None:
            scopes_seen.append(scopes)

    context.on("request", capture_auth)
    page.goto(APP + "/", wait_until="domcontentloaded", timeout=40000)
    page.wait_for_timeout(1500)
    tour = page.locator(".ant-tour-close")
    if tour.count():
        tour.first.click(timeout=10000)
    page.get_by_role("button", name="Log In").first.click(timeout=15000)
    with context.expect_page(timeout=25000) as opened:
        page.get_by_role("dialog").get_by_role("button", name=re.compile("Google", re.I)).click(no_wait_after=True, timeout=15000)
    popup = opened.value
    popup.locator("#identifierId").wait_for(state="visible", timeout=30000)
    if urlsplit(popup.url).hostname != "accounts.google.com":
        raise PipelineError("Google OAuth navigated to an unexpected host")
    require_basic_google_scopes(scopes_seen)
    popup.locator("#identifierId").fill(email)
    popup.locator("#identifierNext").click(timeout=20000)
    popup.locator('input[type="password"]:visible').wait_for(timeout=25000)
    if urlsplit(popup.url).hostname != "accounts.google.com":
        raise PipelineError("Refusing to send Google password to a different host")
    popup.locator('input[type="password"]:visible').first.fill(password)
    popup.locator("#passwordNext").click(timeout=20000)

    deadline = time.monotonic() + 180
    notice_accepted = False
    consented = False
    while time.monotonic() < deadline:
        if popup.is_closed():
            break
        url = urlsplit(popup.url)
        if url.hostname == "app.1min.ai":
            break
        if url.hostname not in ("accounts.google.com", "accounts.google.at"):
            raise PipelineError("Google OAuth moved to an unexpected host")
        if url.path == "/v3/signin/speedbump/workspacetermsofservice":
            if not accept_workspace_notice:
                raise PipelineError("Google Workspace notice requires --accept-workspace-notice")
            if not notice_accepted:
                text = popup.locator("body").inner_text(timeout=8000)
                if "Your school manages this account" not in text:
                    raise PipelineError("Unexpected Google Workspace notice")
                popup.get_by_role("button", name="I understand").click(no_wait_after=True, timeout=16000)
                notice_accepted = True
        elif url.path.endswith("/rejected"):
            raise PipelineError("Google rejected this OAuth sign-in")
        elif url.path == "/signin/oauth/id" and not consented:
            text = popup.locator("body").inner_text(timeout=8000)
            if "1min.AI" not in text or "Google will allow 1min.AI" not in text:
                raise PipelineError("Unexpected Google consent request")
            require_basic_google_scopes(scopes_seen)
            popup.get_by_role("button", name="Continue").click(no_wait_after=True, timeout=16000)
            consented = True
        elif popup.locator('input[name="totpPin"]:visible, input[type="tel"]:visible, iframe[src*="recaptcha"]:visible').count():
            raise PipelineError("Google requires additional account verification")
        page.wait_for_timeout(1500)
    else:
        raise PipelineError("Google OAuth did not return to 1min.ai")

    deadline = time.monotonic() + 35
    while page.get_by_role("button", name="Log In").count() and time.monotonic() < deadline:
        page.wait_for_timeout(500)
    if page.get_by_role("button", name="Log In").count():
        raise PipelineError("1min.ai did not accept the Google OAuth callback")
    require_basic_google_scopes(scopes_seen)
    context.remove_listener("request", capture_auth)


@contextmanager
def app_session(path, accept_workspace_notice=False, force=False):
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        raise PipelineError("Install requirements-oauth.txt and Playwright Firefox to sign in to 1min.ai") from None
    saved_path = session_path(path)
    saved = read_account(saved_path) if saved_path.exists() and not force else None
    with sync_playwright() as playwright:
        options = {"headless": True, "proxy": proxy_config()}
        launch_env = firefox_launch_env()
        if launch_env is not None:
            options["env"] = launch_env
        browser = playwright.firefox.launch(**options)
        try:
            context = browser.new_context(
                storage_state={"cookies": filter_session(saved)["cookies"], "origins": filter_session(saved)["origins"]} if saved else None,
                service_workers="block", accept_downloads=False,
            )
            if saved:
                restore_session(context, saved)
            page = context.new_page()
            try:
                if saved:
                    try:
                        team, keys = load_key_list(page)
                    except SessionExpired:
                        google_login(context, page, accept_workspace_notice)
                        save_session(context, page, saved_path)
                        team, keys = load_key_list(page)
                else:
                    google_login(context, page, accept_workspace_notice)
                    save_session(context, page, saved_path)
                    team, keys = load_key_list(page)
                yield page, team, keys
            finally:
                context.close()
        finally:
            browser.close()


def unique_key(rows, team):
    if not rows:
        return None
    if any(not isinstance(row, dict) or row.get("teamId") != team for row in rows):
        raise PipelineError("1min.ai returned API keys for an unexpected team")
    active = [row for row in rows if row.get("status") == "ACTIVE"]
    if len(active) != 1:
        raise PipelineError("Expected exactly one active API key; refusing to select or create another automatically")
    row = active[0]
    key = row.get("key")
    if (row.get("teamId") != team or row.get("status") != "ACTIVE" or not isinstance(key, str)
            or not 16 <= len(key) <= 512 or any(char.isspace() for char in key) or "*" in key):
        raise PipelineError("1min.ai returned an unusable or masked API key")
    return {"api_key": key, "team_id": team, "status": "ACTIVE", "created_at": row.get("createdAt")}


def ensure(path, accept_workspace_notice=False):
    proxy_url()
    with locked_account(path):
        account = read_account(path) if path.exists() else None
        if account and account.get("api_key"):
            return "1min.ai API key already saved"
        with app_session(path, accept_workspace_notice) as (page, team, rows):
            result = unique_key(rows, team)
            if result:
                save_account(path, result)
                return "Existing 1min.ai API key saved"
            if account and account.get("key_attempted"):
                raise PipelineError("Previous key request may have succeeded; inspect the dashboard before retrying")
            tour = page.locator(".ant-tour-close")
            if tour.count():
                tour.first.click(timeout=10000)
            button = page.get_by_role("button", name="New API Key")
            if button.count() != 1:
                raise PipelineError("1min.ai New API Key button not found")
            save_account(path, {"key_attempted": True, "team_id": team})
            with page.expect_response(
                lambda response: urlsplit(response.url).hostname == "api.1min.ai"
                and urlsplit(response.url).path == f"/api/teams/{team}/keys"
                and response.request.method == "POST", timeout=25000,
            ) as request:
                button.click(timeout=14000, no_wait_after=True)
            if request.value.status not in (200, 201):
                raise PipelineError(f"1min.ai API key creation returned HTTP {request.value.status}")
            team_after, rows_after = load_key_list(page)
            if team != team_after or not (result := unique_key(rows_after, team)):
                raise PipelineError("API key creation may have succeeded; inspect the dashboard before retrying")
            save_account(path, result)
            return "1min.ai API key created and saved"


def login(path, accept_workspace_notice=False, force=False):
    proxy_url()
    with locked_account(path):
        with app_session(path, accept_workspace_notice, force=force) as (_, __, ___):
            return "1min.ai sign-in verified through PROXY"


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, request, response, code, message, headers, newurl):
        raise PipelineError("Refusing to forward an API key through a redirect")


def chat_request(key, model, prompt):
    proxy = proxy_url()
    os.environ["NO_PROXY"] = os.environ["no_proxy"] = ""
    client = build_opener(ProxyHandler({"https": proxy}), NoRedirect(), TunnelOnlyHTTPS())
    body = json.dumps({"type": "UNIFY_CHAT_WITH_AI", "model": model, "promptObject": {"prompt": prompt}}).encode()
    request = Request(
        API + "/api/chat-with-ai", data=body, method="POST",
        headers={"API-KEY": key, "Content-Type": "application/json", "Accept": "application/json"},
    )
    try:
        with client.open(request, timeout=180) as response:
            return json.loads(response.read(3_000_000))
    except HTTPError as exc:
        raise PipelineError(f"1min.ai chat API returned HTTP {exc.code}") from None
    except (URLError, TimeoutError):
        raise PipelineError("Cannot reach 1min.ai chat API through PROXY") from None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    actions = parser.add_subparsers(dest="action", required=True)
    auth = actions.add_parser("login", help="Verify or renew the first-party 1min.ai Google session")
    auth.add_argument("--force", action="store_true", help="Require a fresh Google OAuth login")
    auth.add_argument("--accept-workspace-notice", action="store_true", help="Acknowledge an education-managed account notice, if shown")
    create = actions.add_parser("ensure", help="Recover or create exactly one API key")
    create.add_argument("--accept-workspace-notice", action="store_true")
    actions.add_parser("status", help="Inspect local account and key state without network access")
    chat = actions.add_parser("chat", help="Send stdin as a prompt to the documented 1min.ai chat API")
    chat.add_argument("--model", default=OPUS_5)
    run = actions.add_parser("run", help="Launch an agent with the 1min.ai key and proxy in its environment")
    run.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    path = account_path()
    try:
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
        if args.action == "chat":
            account = read_account(path)
            if not account or not account.get("api_key"):
                raise PipelineError("Run ensure before sending a chat request")
            prompt = sys.stdin.read(12001).strip()
            if not prompt or len(prompt) > 12000:
                raise PipelineError("Pass a nonempty prompt of at most 12000 characters on stdin")
            print(json.dumps(chat_request(account["api_key"], args.model, prompt), ensure_ascii=False))
            return 0
        command = args.command[1:] if args.command[:1] == ["--"] else args.command
        if not command:
            raise PipelineError("Pass an agent command after --")
        ensure(path)
        account = read_account(path)
        proxy = proxy_url()
        env = os.environ.copy()
        for secret in (
            "ONEMIN_EMAIL", "ONEMIN_PASSWORD", "ONEMIN_CREDENTIALS_FILE", "GMAILLOG", "APPASS",
            "PASSWORD", "AUTHENTICATION", "RUCAPTCHA", "RUCAPTCHA_KEY", "RUCAPTCHA_API_KEY",
            "CODECRAFT_CREDENTIALS_FILE", "CODECRAFT_API_KEY", "CODECRAFT_GOOGLE_EMAIL",
            "CODECRAFT_GOOGLE_PASSWORD", "CODECRAFT_GOOGLE_CREDENTIALS_FILE", "NEWPROXY",
        ):
            env.pop(secret, None)
        env.update({
            "ONEMIN_API_KEY": account["api_key"], "ONEMIN_API_BASE_URL": API,
            "HTTP_PROXY": proxy, "HTTPS_PROXY": proxy, "ALL_PROXY": proxy,
            "http_proxy": proxy, "https_proxy": proxy, "all_proxy": proxy,
            "NO_PROXY": "", "no_proxy": "",
        })
        os.execvpe(command[0], command, env)
    except (PipelineError, OSError, ValueError, KeyError, json.JSONDecodeError) as exc:
        print(f"Error: {exc if isinstance(exc, PipelineError) else type(exc).__name__}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())

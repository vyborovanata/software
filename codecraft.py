#!/usr/bin/env python3
"""Create and retain a CodeCraft account and API key over the configured proxy."""

import argparse
import base64
import email
import email.policy
import email.utils
import fcntl
import html
from html.parser import HTMLParser
import imaplib
import json
import os
from pathlib import Path
import re
import secrets
import socket
import ssl
import stat
import sys
import tempfile
import time
from datetime import datetime, timedelta, timezone
from http.cookiejar import CookieJar
from urllib.error import HTTPError, URLError
from urllib.parse import unquote, urlencode, urljoin, urlsplit
from urllib.request import (
    HTTPCookieProcessor, HTTPRedirectHandler, HTTPSHandler, ProxyHandler,
    Request, build_opener,
)


BASE = "https://codecraftapi.com"
CREDS = Path(__file__).resolve().parent / ".secrets" / "codecraft.json"
KEY_PATTERN = re.compile(r"(?<![\w])cc_[A-Za-z0-9_-]{48}(?![\w-])")
VERIFY_PATH = re.compile(r"^/(?:email/verify|verify-email)(?:/|$)")


class PipelineError(Exception):
    pass


def site_url(value):
    url = urljoin(BASE + "/", value)
    parts = urlsplit(url)
    if parts.scheme != "https" or parts.hostname != "codecraftapi.com" or parts.port not in (None, 443) or parts.username:
        raise PipelineError("Refusing to send account data outside codecraftapi.com over HTTPS")
    return url


def proxy_url(variable="PROXY"):
    proxy = os.environ.get(variable)
    if not proxy:
        raise PipelineError(f"{variable} is required; direct connections are forbidden")
    parts = urlsplit(proxy if "://" in proxy else "http://" + proxy)
    if parts.scheme != "http" or not parts.hostname or not parts.port:
        raise PipelineError(f"{variable} must be an HTTP proxy with a port")
    return proxy if "://" in proxy else "http://" + proxy


class SameOriginRedirect(HTTPRedirectHandler):
    def redirect_request(self, request, response, code, message, headers, newurl):
        site_url(newurl)
        return super().redirect_request(request, response, code, message, headers, newurl)


class TunnelOnlyHTTPS(HTTPSHandler):
    def https_open(self, request):
        if not request._tunnel_host:
            raise PipelineError("Refusing a direct HTTPS connection")
        return super().https_open(request)


class Page(HTMLParser):
    def __init__(self, body):
        super().__init__()
        self.forms = []
        self.links = []
        self._form = None
        self._link = None
        self.feed(body)

    def handle_starttag(self, tag, attrs):
        attr = dict(attrs)
        if tag == "form":
            self._form = {"action": attr.get("action", ""), "method": attr.get("method", "GET").upper(), "inputs": []}
            self.forms.append(self._form)
        elif tag == "input" and self._form is not None:
            self._form["inputs"].append({"name": attr.get("name"), "type": attr.get("type", "text"), "value": attr.get("value", "")})
        elif tag == "a":
            self._link = {"href": attr.get("href", ""), "text": ""}
            self.links.append(self._link)

    def handle_data(self, data):
        if self._link is not None:
            self._link["text"] += data

    def handle_endtag(self, tag):
        if tag == "a":
            self._link = None
        elif tag == "form":
            self._form = None


def form_for(body, path=None, fields=()):
    for form in Page(body).forms:
        names = {field["name"] for field in form["inputs"]}
        if form["method"] != "POST" or not set(fields) <= names:
            continue
        if path is None or urlsplit(site_url(form["action"])).path == path:
            if not any(field["name"] == "_token" and field["value"] for field in form["inputs"]):
                raise PipelineError("CSRF token missing from form")
            return form
    raise PipelineError("Expected POST form not found on CodeCraft")


def form_data(form, values):
    data = {field["name"]: field["value"] for field in form["inputs"] if field["name"] and field["type"] == "hidden"}
    data.update(values)
    return data


class Site:
    def __init__(self):
        proxy = proxy_url()
        # urllib honours NO_PROXY even for explicit proxies. Never let it bypass ours.
        os.environ["NO_PROXY"] = os.environ["no_proxy"] = ""
        self.opener = build_opener(
            ProxyHandler({"https": proxy}), SameOriginRedirect(),
            HTTPCookieProcessor(CookieJar()), TunnelOnlyHTTPS(),
        )

    def request(self, url, data=None, source=None):
        url = site_url(url)
        headers = {"User-Agent": "Mozilla/5.0 (compatible; CodeCraftAccountClient/1.0)", "Accept": "text/html,application/json"}
        if data is not None:
            headers.update({"Content-Type": "application/x-www-form-urlencoded", "Origin": BASE, "Referer": site_url(source or "/")})
        request = Request(url, data=urlencode(data).encode() if data is not None else None, headers=headers)
        try:
            with self.opener.open(request, timeout=30) as result:
                return urlsplit(result.geturl()).path, result.read().decode("utf-8", "replace")
        except HTTPError as exc:
            body = exc.read().decode("utf-8", "replace")
            if "cf-chl" in body or "Just a moment" in body:
                raise PipelineError("Cloudflare challenge encountered; registration needs review") from None
            raise PipelineError(f"CodeCraft returned HTTP {exc.code} on {urlsplit(url).path}") from None
        except (URLError, TimeoutError) as exc:
            raise PipelineError(f"Cannot reach CodeCraft through PROXY ({type(exc).__name__})") from None

    def submit(self, page, path, values, fields):
        form = form_for(page, path=path, fields=fields)
        return self.request(form["action"], form_data(form, values), source=path)

    def login(self, account):
        _, page = self.request("/login")
        path, _ = self.submit(page, "/login", {"email": account["email"], "password": account["password"]}, ("email", "password"))
        if path == "/login":
            raise PipelineError("CodeCraft rejected saved login credentials")

    def dashboard(self):
        path, page = self.request("/dashboard")
        if path == "/login":
            raise PipelineError("Not signed in to CodeCraft")
        return path, page


def verification_proof(raw, started, received_at=None):
    message = email.message_from_bytes(raw, policy=email.policy.default)
    sender = email.utils.parseaddr(message.get("From", ""))[1].rsplit("@", 1)[-1].lower()
    if sender != "codecraftapi.com" and not sender.endswith(".codecraftapi.com"):
        return None
    try:
        sent = email.utils.parsedate_to_datetime(message.get("Date", "")) if message.get("Date") else None
    except (TypeError, ValueError):
        return None
    if not sent or (sent.astimezone(timezone.utc) < started - timedelta(minutes=2)
                    and (received_at is None or received_at < started - timedelta(minutes=2))):
        return None
    for part in message.walk():
        if part.get_content_type() not in ("text/plain", "text/html"):
            continue
        text = html.unescape(part.get_content())
        for candidate in re.findall(r'https://codecraftapi\.com/[^\s<>"\']+', text):
            candidate = candidate.rstrip(".,;)")
            if VERIFY_PATH.match(urlsplit(candidate).path):
                return site_url(candidate)
        text = re.sub(r"<[^>]+>", " ", text)
        code = re.search(r"(?:verification|verify|code)[^\d]{0,80}(\d{6})(?!\d)", text, re.I)
        if code:
            return code.group(1)
        if re.search(r"verif|code", str(message.get("Subject", "")), re.I):
            codes = re.findall(r"(?<!\d)\d{6}(?!\d)", text)
            if len(codes) == 1:
                return codes[0]
    return None


class ProxiedIMAP(imaplib.IMAP4_SSL):
    def _create_socket(self, timeout):
        proxy = urlsplit(proxy_url())
        sock = socket.create_connection((proxy.hostname, proxy.port), timeout=timeout)
        sock.settimeout(timeout)
        try:
            authority = f"{self.host}:{self.port}"
            lines = [f"CONNECT {authority} HTTP/1.1", f"Host: {authority}"]
            if proxy.username is not None:
                auth = (unquote(proxy.username) + ":" + unquote(proxy.password or "")).encode()
                lines.append("Proxy-Authorization: Basic " + base64.b64encode(auth).decode("ascii"))
            sock.sendall(("\r\n".join(lines) + "\r\n\r\n").encode("ascii"))
            reader = sock.makefile("rb")
            response = reader.readline(4096).split()
            if len(response) < 2 or response[1] != b"200":
                raise PipelineError("PROXY refused Gmail IMAP tunnel")
            for _ in range(40):
                if reader.readline(4096) in (b"\r\n", b"\n", b""):
                    break
            else:
                raise PipelineError("Invalid PROXY response to IMAP tunnel")
            return self.ssl_context.wrap_socket(sock, server_hostname=self.host)
        except Exception:
            sock.close()
            raise


def wait_for_verification(started, seconds=300, ignored=()):
    if not os.environ.get("GMAILLOG") or not os.environ.get("APPASS"):
        raise PipelineError("GMAILLOG and APPASS are needed for email verification")
    deadline = time.monotonic() + seconds
    with ProxiedIMAP("imap.gmail.com", 993, timeout=25) as mailbox:
        mailbox.login(os.environ["GMAILLOG"], os.environ["APPASS"])
        folders = ["INBOX"]
        _, listed = mailbox.list()
        for item in listed or []:
            if any(flag in item for flag in (b"\\All", b"\\Junk", b"\\Trash")):
                match = re.match(rb'\([^)]*\)\s+"[^"]+"\s+(.+)$', item)
                if match:
                    folders.append(match.group(1).decode("utf-8", "replace"))
        while True:
            for folder in folders:
                status, _ = mailbox.select(folder, readonly=True)
                if status != "OK":
                    continue
                _, found = mailbox.search(None, "SINCE", started.strftime("%d-%b-%Y"), "OR", "FROM", '"codecraftapi.com"', "SUBJECT", '"CodeCraft"')
                for identifier in reversed(found[0].split()[-50:]):
                    _, items = mailbox.fetch(identifier, "(BODY.PEEK[] INTERNALDATE)")
                    for item in items:
                        if not isinstance(item, tuple):
                            continue
                        match = re.search(rb'INTERNALDATE "([^"]+)"', item[0])
                        received_at = datetime.strptime(match.group(1).decode("ascii"), "%d-%b-%Y %H:%M:%S %z") if match else None
                        if received_at and received_at < started - timedelta(minutes=2):
                            continue
                        proof = verification_proof(item[1], started, received_at)
                        if proof and proof not in ignored:
                            return proof
            if time.monotonic() >= deadline:
                return None
            time.sleep(min(30, max(0, deadline - time.monotonic())))


def account_path():
    return Path(os.environ.get("CODECRAFT_CREDENTIALS_FILE", CREDS)).expanduser().resolve()


def save_account(path, account):
    fd, temp = tempfile.mkstemp(prefix=".codecraft-", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(account, stream, indent=2)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp, path)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if os.path.exists(temp):
            os.unlink(temp)


def read_account(path):
    if not path.exists():
        return None
    mode = path.lstat().st_mode
    if not stat.S_ISREG(mode) or mode & 0o077:
        raise PipelineError("Credentials must be a regular file accessible only to its owner (chmod 600)")
    with path.open(encoding="utf-8") as stream:
        return json.load(stream)


def verification_timeout():
    try:
        seconds = int(os.environ.get("CODECRAFT_VERIFY_TIMEOUT", "10800"))
    except ValueError:
        raise PipelineError("CODECRAFT_VERIFY_TIMEOUT must be a number of seconds") from None
    if not 0 <= seconds <= 86400:
        raise PipelineError("CODECRAFT_VERIFY_TIMEOUT must be between 0 and 86400 seconds")
    return seconds


def verify_dashboard(site, started, account, account_file, timeout_seconds=None):
    if timeout_seconds is None:
        timeout_seconds = verification_timeout()
    deadline = time.monotonic() + timeout_seconds
    ignored = set()
    first_check = True
    while True:
        path, page = site.dashboard()
        if path == "/dashboard":
            return page
        if not VERIFY_PATH.match(path):
            raise PipelineError("CodeCraft requires an unexpected account confirmation step")
        earliest = max(started, datetime.now(timezone.utc) - timedelta(hours=3))
        try:
            proof = wait_for_verification(earliest, seconds=0, ignored=ignored) if first_check else None
        except (imaplib.IMAP4.abort, OSError):
            proof = None
        first_check = False
        last_resend = account.get("last_resend_at")
        recent_resend = last_resend and datetime.now(timezone.utc) - datetime.fromisoformat(last_resend) < timedelta(hours=1)
        if not proof and not recent_resend:
            form = form_for(page, "/verify-email/resend")
            account["last_resend_at"] = datetime.now(timezone.utc).isoformat()
            save_account(account_file, account)
            site.request(form["action"], form_data(form, {}), source="/verify-email")
        if not proof:
            try:
                proof = wait_for_verification(earliest, seconds=min(300, max(0, deadline - time.monotonic())), ignored=ignored)
            except (imaplib.IMAP4.abort, OSError):
                if time.monotonic() >= deadline:
                    raise PipelineError("Gmail IMAP disconnected while waiting for CodeCraft email") from None
                time.sleep(min(10, max(0, deadline - time.monotonic())))
                continue
        if not proof:
            if time.monotonic() >= deadline:
                raise PipelineError("No CodeCraft verification email received within the configured wait; rerun ensure later")
            continue
        ignored.add(proof)
        if proof.isdecimal() and len(proof) == 6:
            _, verify_page = site.request("/verify-email")
            site.submit(verify_page, "/verify-email", {"code": proof}, ("code",))
        else:
            site.request(proof)
        if time.monotonic() >= deadline and site.dashboard()[0] != "/dashboard":
            raise PipelineError("CodeCraft did not confirm the emailed code before the wait expired")


def create_key(site, account, path, dashboard):
    links = Page(dashboard).links
    matches = [link["href"] for link in links if "api keys" in link["text"].lower() or "api-keys" in link["href"]]
    if not matches:
        raise PipelineError("API Keys link not found in CodeCraft dashboard")
    destination = site_url(matches[0])
    _, page = site.request(destination)
    if account["key_name"] in page:
        raise PipelineError("Existing agent key cannot be recovered; revoke it in the dashboard before retrying")
    form = form_for(page, fields=("name",))
    account["key_attempted"] = True
    save_account(path, account)
    _, result = site.request(form["action"], form_data(form, {"name": account["key_name"]}), source=destination)
    match = KEY_PATTERN.search(html.unescape(result))
    if not match:
        raise PipelineError("Key submission completed but one-time key was not shown; inspect dashboard before retrying")
    account["api_key"] = match.group()
    del account["key_attempted"]
    save_account(path, account)


def ensure(path, name):
    proxy_url()
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if path.parent.stat().st_mode & 0o077:
        raise PipelineError("Credentials directory must be private (chmod 700)")
    lock_fd = os.open(path.parent / ".lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(lock_fd, fcntl.LOCK_EX)
        account = read_account(path)
        if account and os.environ.get("GMAILLOG") and account["email"].lower() != os.environ["GMAILLOG"].lower():
            raise PipelineError("GMAILLOG does not match the saved CodeCraft account")
        if account and account.get("api_key"):
            return "API key already saved"
        if account and account.get("key_attempted"):
            raise PipelineError("Previous key creation may have succeeded; inspect dashboard before retrying")
        existing = bool(account)
        if not existing:
            if not os.environ.get("GMAILLOG") or not name:
                raise PipelineError("GMAILLOG and --name are required to register a new account")
            account = {"email": os.environ["GMAILLOG"], "name": name, "password": secrets.token_urlsafe(32), "registered": False, "key_name": "hoplite-agent", "registered_at": datetime.now(timezone.utc).isoformat()}
            save_account(path, account)
        if not account.get("registered_at"):
            account["registered_at"] = datetime.fromtimestamp(path.stat().st_mtime, timezone.utc).isoformat()
            save_account(path, account)
        site = Site()
        started = datetime.fromisoformat(account["registered_at"])
        if existing:
            try:
                site.login(account)
            except PipelineError as exc:
                if account["registered"] or "rejected saved login" not in str(exc):
                    raise
                existing = False
        if not existing:
            _, page = site.request("/register")
            path_after, _ = site.submit(page, "/register", {
                "name": account["name"], "email": account["email"],
                "password": account["password"], "password_confirmation": account["password"],
            }, ("name", "email", "password", "password_confirmation"))
            if path_after == "/register":
                raise PipelineError("CodeCraft rejected registration; check if the email is already in use")
            account["registered"] = True
            save_account(path, account)
        dashboard = verify_dashboard(site, started, account, path)
        create_key(site, account, path, dashboard)
        return "CodeCraft account and API key saved"
    finally:
        os.close(lock_fd)


def login(path):
    account = read_account(path)
    if not account:
        raise PipelineError("No saved credentials; run ensure first")
    site = Site()
    site.login(account)
    destination, _ = site.dashboard()
    return "Logged in; email verification pending" if VERIFY_PATH.match(destination) else "Logged in using saved credentials"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    actions = parser.add_subparsers(dest="action", required=True)
    ensure_parser = actions.add_parser("ensure", help="Register if needed and save a one-time API key")
    ensure_parser.add_argument("--name", default=os.environ.get("CODECRAFT_NAME"), help="Account holder's name for the required registration field")
    actions.add_parser("login", help="Verify a fresh login through PROXY")
    actions.add_parser("status", help="Show whether credentials and a key are saved (offline)")
    run_parser = actions.add_parser("run", help="Launch an agent with the API key, base URL, and proxy in its environment")
    run_parser.add_argument("--name", default=os.environ.get("CODECRAFT_NAME"))
    run_parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    path = account_path()
    try:
        if args.action == "status":
            account = read_account(path)
            print("API key saved" if account and account.get("api_key") else "API key not saved")
        elif args.action == "login":
            print(login(path))
        elif args.action == "ensure":
            print(ensure(path, args.name))
        else:
            command = args.command[1:] if args.command[:1] == ["--"] else args.command
            if not command:
                raise PipelineError("Pass an agent command after --")
            ensure(path, args.name)
            account = read_account(path)
            proxy = proxy_url()
            env = os.environ.copy()
            for secret in (
                "APPASS", "GMAILLOG", "RUCAPTCHA", "RUCAPTCHA_KEY", "RUCAPTCHA_API_KEY", "CODECRAFT_CREDENTIALS_FILE",
                "CODECRAFT_GOOGLE_EMAIL", "CODECRAFT_GOOGLE_PASSWORD", "CODECRAFT_GOOGLE_CREDENTIALS_FILE",
                "ONEMIN_EMAIL", "ONEMIN_PASSWORD", "ONEMIN_CREDENTIALS_FILE", "ONEMIN_API_KEY",
                "NEWPROXY", "PASSWORD", "AUTHENTICATION",
            ):
                env.pop(secret, None)
            env.update({
                "CODECRAFT_API_KEY": account["api_key"], "CODECRAFT_BASE_URL": BASE + "/v1",
                "OPENAI_API_KEY": account["api_key"], "OPENAI_BASE_URL": BASE + "/v1",
                "HTTPS_PROXY": proxy, "HTTP_PROXY": proxy, "ALL_PROXY": proxy,
                "https_proxy": proxy, "http_proxy": proxy, "all_proxy": proxy,
                "NO_PROXY": "", "no_proxy": "",
            })
            os.execvpe(command[0], command, env)
    except (PipelineError, OSError, imaplib.IMAP4.error, ValueError, json.JSONDecodeError) as exc:
        print(f"Error: {exc if isinstance(exc, PipelineError) else type(exc).__name__}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())

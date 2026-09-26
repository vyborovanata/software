#!/usr/bin/env python3
"""Inspect saved Workbuddy status offline; do not access the service."""

import argparse
import json
import os
from pathlib import Path
import stat
import sys
from urllib.parse import urlsplit

from codecraft import PipelineError, read_account


DEFAULT_FILE = Path(__file__).resolve().parent / ".secrets" / "workbuddy.json"


def account_path():
    path = Path(os.environ.get("WORKBUDDY_CREDENTIALS_FILE", DEFAULT_FILE)).expanduser()
    if path.is_symlink():
        raise PipelineError("Workbuddy account path must not be a symlink")
    return path.resolve()


def session_path(path):
    return path.with_name(path.stem + "-session.json")


def private_read(path):
    if path.parent.exists() and path.parent.stat().st_mode & 0o077:
        raise PipelineError("Workbuddy credentials directory must be private (chmod 700)")
    return read_account(path)


def workbuddy_host(host):
    return host == "workbuddy.ai" or bool(host and host.endswith(".workbuddy.ai"))


def workbuddy_url(value):
    url = urlsplit(value)
    try:
        return (url.scheme == "https" and workbuddy_host(url.hostname) and url.port in (None, 443)
                and url.username is None and url.password is None)
    except ValueError:
        return False


def check_session(session):
    if not isinstance(session, dict):
        raise PipelineError("Invalid Workbuddy session snapshot")
    try:
        own_cookies = all(workbuddy_host(cookie["domain"].lstrip(".")) for cookie in session["cookies"])
        own_origins = all(workbuddy_url(origin["origin"]) for origin in session["origins"])
        own_storage = all(workbuddy_url(origin) for origin in session["sessionStorage"])
    except (KeyError, TypeError, AttributeError, ValueError):
        raise PipelineError("Invalid Workbuddy session snapshot") from None
    if not own_cookies or not own_origins or not own_storage:
        raise PipelineError("Workbuddy snapshot contains non-first-party data")


def status(path):
    account = private_read(path)
    if account is not None and (not isinstance(account, dict)
                                or account.get("provider") != "google"
                                or account.get("status") not in ("pending", "restricted")):
        raise PipelineError("Unrecognized Workbuddy account metadata")
    session = private_read(session_path(path))
    if session is not None:
        check_session(session)
    return account["status"] if account else "not attempted", session is not None


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="action", required=True)
    commands.add_parser("status", help="Read private Workbuddy files without network access")
    args = parser.parse_args(argv)
    try:
        current, has_session = status(account_path())
    except PipelineError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    except (OSError, ValueError, json.JSONDecodeError):
        print("Error: invalid private Workbuddy files", file=sys.stderr)
        return 1
    print("Workbuddy status: " + current)
    print("First-party session snapshot saved" if has_session else "No first-party session saved")
    return 0


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""Visit 1min.ai daily and submit its AI Agent survey at most once."""

import argparse
from datetime import datetime, time as clock_time, timedelta, timezone
import json
import os
from pathlib import Path
import re
import stat
import sys
import time
from urllib.parse import urlsplit

from codecraft import PipelineError, read_account, save_account
from onemin import APP, account_path, app_session, locked_account, proxy_url, save_session, session_path


PST = timezone(timedelta(hours=-8))
VISIT_ROUTE = "/free-credits"
SURVEY_ROUTE = "/ai-agent-demo"
SURVEY_FIELDS = ("role", "industry", "organization", "aiUseCase", "usageFrequency")
TASK = (
    "I would like an AI Agent to help with software development in ZCode, using Claude through "
    "the 1min.ai API. It should turn an issue into an actionable plan, inspect relevant repository "
    "files, propose a small reviewable change, run focused tests, and summarize what worked and "
    "what remains uncertain. For a first task, I would ask it to diagnose a failing test, make a "
    "minimal fix, verify the result, and explain the diff. It should keep credentials private, "
    "ask before destructive operations, and never claim a check passed without evidence."
)


def state_path(path):
    target = path.with_name("onemin-rewards.json")
    if target in (path, session_path(path)):
        raise PipelineError("1min.ai reward status must be separate from account and session files")
    return target


def utc_now():
    return datetime.now(timezone.utc)


def reward_day(now):
    return now.astimezone(PST).date().isoformat()


def next_visit(now):
    today = now.astimezone(PST).date()
    boundary = datetime.combine(today, clock_time(0, 15), PST).astimezone(timezone.utc)
    return boundary if now < boundary else boundary + timedelta(days=1)


def visit_ready(now):
    today = now.astimezone(PST).date()
    return now >= datetime.combine(today, clock_time(0, 15), PST).astimezone(timezone.utc)


def require_app_page(page, route, response):
    url = urlsplit(page.url)
    try:
        safe = (url.scheme == "https" and url.hostname == "app.1min.ai" and url.port in (None, 443)
                and url.username is None and url.password is None and url.path == route)
    except ValueError:
        safe = False
    if not safe or response is None or response.status != 200:
        raise PipelineError("1min.ai did not open the expected authenticated web page")


def account_team(path):
    account = read_account(path)
    if not isinstance(account, dict) or not isinstance(account.get("team_id"), str) or not account["team_id"]:
        raise PipelineError("Run onemin.py ensure before claiming 1min.ai rewards")
    return account["team_id"]


def load_state(path, team):
    state = read_account(state_path(path)) or {"team_id": team}
    if not isinstance(state, dict) or state.get("team_id") != team or any(
            field in state and not isinstance(state[field], dict) for field in ("daily", "survey")):
        raise PipelineError("1min.ai reward status does not match this team")
    return state


def own_response(response, team, endpoint, method):
    url = urlsplit(response.url)
    try:
        return (url.scheme == "https" and url.hostname == "api.1min.ai" and url.port in (None, 443)
                and url.username is None and url.password is None and url.path == f"/teams/{team}/{endpoint}"
                and response.request.method == method)
    except ValueError:
        return False


def wait_response(page, responses, seconds=15):
    deadline = time.monotonic() + seconds
    while not responses and time.monotonic() < deadline:
        page.wait_for_timeout(350)
    if not responses:
        raise PipelineError("1min.ai did not confirm the requested page's account state")
    return responses[-1]


def visit(path, accept_workspace_notice=False):
    with locked_account(path):
        team = account_team(path)
        state = load_state(path, team)
        today = reward_day(utc_now())
        daily = state.get("daily", {})
        if daily.get("date") == today:
            if daily.get("status") == "visited":
                return f"Already visited 1min.ai for {today} (fixed PST); no duplicate visit"
            raise PipelineError("Today's visit may already have occurred; check the account before retrying")
        proxy_url()
        with app_session(path, accept_workspace_notice) as (page, logged_team, _keys):
            if logged_team != team:
                raise PipelineError("The saved 1min.ai account and web session belong to different teams")
            state["daily"] = {"date": today, "status": "attempted", "started_at": utc_now().isoformat()}
            save_account(state_path(path), state)
            responses = []

            def capture(response):
                if own_response(response, team, "credits", "GET"):
                    responses.append(response)

            page.on("response", capture)
            try:
                result = page.goto(APP + VISIT_ROUTE, wait_until="domcontentloaded", timeout=55000)
                require_app_page(page, VISIT_ROUTE, result)
                reply = wait_response(page, responses)
                if reply.status != 200:
                    raise PipelineError(f"1min.ai did not return the credits page (HTTP {reply.status})")
                credits = reply.json()
                if not isinstance(credits, dict) or not isinstance(credits.get("credit"), int) or credits["credit"] < 0:
                    raise PipelineError("1min.ai credits summary is unavailable")
                page.get_by_role("heading", name=re.compile("Daily Visit", re.I)).wait_for(state="visible", timeout=12000)
                if "Unlock 15,000 FREE credits EVERY DAY" not in page.locator("body").inner_text(timeout=12000):
                    raise PipelineError("1min.ai changed the daily visit offer")
                if page.get_by_role("button", name="Log In").count():
                    raise PipelineError("1min.ai web session has expired")
                if reward_day(utc_now()) != today:
                    raise PipelineError("The 1min.ai daily reset passed during this visit; inspect before retrying")
                save_session(page.context, page, session_path(path))
            finally:
                page.remove_listener("response", capture)
            state["daily"] = {"date": today, "status": "visited", "visited_at": utc_now().isoformat()}
            save_account(state_path(path), state)
            return (f"Authenticated 1min.ai visit confirmed for {today} (fixed PST). "
                    "The 15,000-credit award for this day cannot be independently confirmed")


def survey_status(reply):
    if reply.status != 200:
        raise PipelineError(f"1min.ai survey status returned HTTP {reply.status}")
    value = reply.json()
    if not isinstance(value, dict) or type(value.get("submitted")) is not bool or type(value.get("teamRewarded")) is not bool:
        raise PipelineError("Unexpected 1min.ai survey status format")
    return value


def select_choice(page, identifier, choice):
    if identifier not in SURVEY_FIELDS or not isinstance(choice, str) or not choice.strip() or len(choice) > 120:
        raise PipelineError("Incomplete 1min.ai survey answer")
    control = page.locator("#" + identifier)
    if control.count() != 1:
        raise PipelineError("1min.ai survey fields changed")
    parent = control.locator('xpath=ancestor::*[contains(concat(" ",normalize-space(@class)," ")," ant-select ")][1]')
    parent.click(timeout=10000)
    if control.get_attribute("readonly") is None:
        control.fill(choice)
    dropdown = page.locator(".ant-select-dropdown:visible").filter(has=page.locator("#" + identifier + "_list"))
    option = dropdown.locator(".ant-select-item-option-content").filter(has_text=re.compile("^" + re.escape(choice) + "$"))
    option.wait_for(state="visible", timeout=9000)
    if option.count() != 1 or option.inner_text().strip() != choice:
        raise PipelineError("1min.ai survey does not offer the selected answer")
    option.click(timeout=9000)
    if parent.locator(".ant-select-selection-item").inner_text().strip() != choice:
        raise PipelineError("1min.ai survey did not record a selected answer")


def read_task(path):
    if path is None:
        return TASK
    file = Path(path).expanduser()
    mode = file.lstat().st_mode
    if not stat.S_ISREG(mode) or mode & 0o077 or file.parent.stat().st_mode & 0o077:
        raise PipelineError("Survey task file and directory must be private (chmod 600/700)")
    text = file.read_text(encoding="utf-8").strip()
    if not 40 <= len(text) <= 4000:
        raise PipelineError("Survey task description must contain 40–4000 characters")
    return text


def submit_survey(path, answers, task_text, accept_workspace_notice=False):
    if not isinstance(task_text, str) or not 40 <= len(task_text.strip()) <= 4000:
        raise PipelineError("Survey task description must contain 40–4000 characters")
    if set(answers) != set(SURVEY_FIELDS) or any(not isinstance(value, str) or not value.strip() for value in answers.values()):
        raise PipelineError("All 1min.ai survey questions must have truthful answers")
    with locked_account(path):
        team = account_team(path)
        state = load_state(path, team)
        if state.get("survey", {}).get("status"):
            raise PipelineError("Survey already submitted or attempted; never send a duplicate automatically")
        proxy_url()
        with app_session(path, accept_workspace_notice) as (page, logged_team, _keys):
            if logged_team != team:
                raise PipelineError("The saved 1min.ai account and web session belong to different teams")
            responses = []

            def capture(response):
                if own_response(response, team, "ai-agent-survey", "GET"):
                    responses.append(response)

            page.on("response", capture)
            try:
                opened = page.goto(APP + SURVEY_ROUTE, wait_until="domcontentloaded", timeout=55000)
                require_app_page(page, SURVEY_ROUTE, opened)
                before = survey_status(wait_response(page, responses))
                if before["submitted"] or before["teamRewarded"]:
                    state["survey"] = {"status": "already_submitted", "team_rewarded": before["teamRewarded"]}
                    save_account(state_path(path), state)
                    return "1min.ai already has a survey submission; no duplicate sent"
                form = page.locator("form").filter(has=page.locator("#agentTask"))
                if form.count() != 1 or "Submissions require admin approval" not in form.inner_text(timeout=9000):
                    raise PipelineError("1min.ai survey form or reward rules changed")
                tour = page.locator(".ant-tour-close")
                if tour.count():
                    tour.first.click(timeout=8000)
                for identifier in SURVEY_FIELDS:
                    select_choice(page, identifier, answers[identifier])
                description = form.locator("#agentTask")
                if description.count() != 1:
                    raise PipelineError("1min.ai survey task field changed")
                description.fill(task_text)
                if description.input_value().strip() != task_text.strip():
                    raise PipelineError("1min.ai did not accept the survey description")
                button = form.get_by_role("button", name="Get Early Access")
                if button.count() != 1 or not button.is_enabled():
                    raise PipelineError("1min.ai survey submit button is unavailable")
                state["survey"] = {"status": "attempted", "started_at": utc_now().isoformat(),
                                   "answers": answers, "task": task_text}
                save_account(state_path(path), state)
                with page.expect_response(lambda reply: own_response(reply, team, "ai-agent-survey", "POST"),
                                          timeout=30000) as sent:
                    button.click(no_wait_after=True, timeout=15000)
                if sent.value.status not in (200, 201):
                    raise PipelineError(f"1min.ai survey submission returned HTTP {sent.value.status}; check manually")
                responses.clear()
                refreshed = page.goto(APP + SURVEY_ROUTE, wait_until="domcontentloaded", timeout=55000)
                require_app_page(page, SURVEY_ROUTE, refreshed)
                after = survey_status(wait_response(page, responses))
                if not after["submitted"]:
                    raise PipelineError("1min.ai did not confirm survey submission; do not retry automatically")
                save_session(page.context, page, session_path(path))
                state["survey"].update({"status": "submitted", "submitted_at": utc_now().isoformat(),
                                        "team_rewarded": after["teamRewarded"]})
                save_account(state_path(path), state)
                if after["teamRewarded"]:
                    return "Survey submitted once; 1min.ai reports this team rewarded (check the credit balance)"
                return "Survey submitted once for admin review; 1min.ai has not reported a team reward yet"
            finally:
                page.remove_listener("response", capture)


def watch(path, accept_workspace_notice=False):
    tried_day = None
    while True:
        now = utc_now()
        today = reward_day(now)
        if visit_ready(now) and tried_day != today:
            tried_day = today
            try:
                print(visit(path, accept_workspace_notice), flush=True)
            except PipelineError as exc:
                print(f"1min.ai daily visit stopped: {exc}", file=sys.stderr, flush=True)
            except Exception as exc:
                print(f"1min.ai daily visit stopped ({type(exc).__name__}); inspect manually", file=sys.stderr, flush=True)
        time.sleep(min(max((next_visit(utc_now()) - utc_now()).total_seconds(), 1), 3600))


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("status", help="Read local daily/survey status without network")
    visit_command = commands.add_parser("daily", help="Visit the authenticated web app once per PST day")
    visit_command.add_argument("--accept-workspace-notice", action="store_true")
    watch_command = commands.add_parser("watch", help="Run the daily command after 08:15 UTC while this process stays alive")
    watch_command.add_argument("--accept-workspace-notice", action="store_true")
    survey = commands.add_parser("survey", help="Submit the AI Agent survey at most once")
    for flag in ("role", "industry", "organization", "use-case", "frequency"):
        survey.add_argument("--" + flag, required=True)
    survey.add_argument("--task-file", help="Private 0600 UTF-8 file in a 0700 directory; otherwise use the draft")
    survey.add_argument("--submit", action="store_true", help="Actually submit the one-time survey")
    survey.add_argument("--accept-workspace-notice", action="store_true")
    args = parser.parse_args(argv)
    try:
        path = account_path()
        if args.command == "status":
            team = account_team(path)
            state = load_state(path, team)
            print("Daily visit: " + str(state.get("daily", {}).get("status", "not attempted")) +
                  " (" + str(state.get("daily", {}).get("date", "no date")) + " PST)")
            print("AI Agent survey: " + str(state.get("survey", {}).get("status", "not submitted")))
        elif args.command == "daily":
            print(visit(path, args.accept_workspace_notice))
        elif args.command == "watch":
            watch(path, args.accept_workspace_notice)
        else:
            answers = {"role": args.role, "industry": args.industry, "organization": args.organization,
                       "aiUseCase": args.use_case, "usageFrequency": args.frequency}
            task = read_task(args.task_file)
            if not args.submit:
                print("Draft answers (no survey submitted):")
                for field in SURVEY_FIELDS:
                    print(f"  {field}: {answers[field]}")
                print("Draft task:\n" + task)
                print("Pass --submit after confirming all answers and the task")
            else:
                print(submit_survey(path, answers, task, args.accept_workspace_notice))
    except PipelineError as exc:
        print("Error: " + str(exc), file=sys.stderr)
        return 1
    except Exception as exc:
        print("Error: 1min.ai rewards operation failed (" + type(exc).__name__ + ")", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())

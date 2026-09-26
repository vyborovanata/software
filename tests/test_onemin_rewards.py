from contextlib import contextmanager, redirect_stderr, redirect_stdout
from datetime import datetime, timezone
import io
import json
import os
from pathlib import Path
import stat
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import MagicMock, patch

import codecraft
import onemin_rewards as rewards


NOW = datetime(2026, 9, 26, 21, 30, tzinfo=timezone.utc)
TEAM = "owned-team"


def mock_response(endpoint, method="GET", status=200, data=None, host="api.1min.ai"):
    return SimpleNamespace(url=f"https://{host}/teams/{TEAM}/{endpoint}", status=status,
                           request=SimpleNamespace(method=method), json=lambda: data)


class RewardsTests(unittest.TestCase):
    def account(self, directory, team=TEAM):
        path = Path(directory) / "onemin.json"
        codecraft.save_account(path, {"team_id": team, "api_key": "private-upstream-key", "status": "ACTIVE"})
        return path

    def page(self, route, responses):
        page = MagicMock()
        page.url = rewards.APP + route
        page.goto.return_value.status = 200
        handlers = []

        def listen(_event, callback):
            handlers.append(callback)

        def visit(*_args, **_kwargs):
            for callback in handlers:
                for reply in responses:
                    callback(reply)
            return SimpleNamespace(status=200)

        page.on.side_effect = listen
        page.goto.side_effect = visit
        page.get_by_role.return_value.count.return_value = 0
        page.locator.return_value.inner_text.return_value = "Unlock 15,000 FREE credits EVERY DAY"
        return page

    @contextmanager
    def authenticated(self, page, team=TEAM):
        yield page, team, []

    def test_fixed_pst_daily_boundary_even_during_daylight_saving(self):
        before = datetime(2026, 9, 26, 7, 59, tzinfo=timezone.utc)
        early = datetime(2026, 9, 26, 8, 2, tzinfo=timezone.utc)
        after = datetime(2026, 9, 26, 8, 15, tzinfo=timezone.utc)
        self.assertEqual(rewards.reward_day(before), "2026-09-25")
        self.assertEqual(rewards.reward_day(after), "2026-09-26")
        self.assertFalse(rewards.visit_ready(early))
        self.assertTrue(rewards.visit_ready(after))
        self.assertEqual(rewards.next_visit(before), after)
        self.assertEqual(rewards.next_visit(after), datetime(2026, 9, 27, 8, 15, tzinfo=timezone.utc))

    def test_watcher_visits_once_per_day_after_boundary_even_on_error(self):
        class StopWatching(Exception):
            pass

        for failed in (False, True):
            with self.subTest(failed=failed):
                current = [datetime(2026, 9, 26, 8, 14, tzinfo=timezone.utc)]
                later = iter((datetime(2026, 9, 26, 8, 15, tzinfo=timezone.utc),
                              datetime(2026, 9, 26, 9, 0, tzinfo=timezone.utc),
                              datetime(2026, 9, 27, 8, 15, tzinfo=timezone.utc)))

                def advance(_seconds):
                    try:
                        current[0] = next(later)
                    except StopIteration:
                        raise StopWatching from None

                path = Path("mock-account.json")
                error = codecraft.PipelineError("pre-visit failure") if failed else None
                with patch.object(rewards, "utc_now", side_effect=lambda: current[0]), \
                        patch.object(rewards, "visit", return_value="visited", side_effect=error) as visit, \
                        patch.object(rewards.time, "sleep", side_effect=advance) as sleep, \
                        redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                    with self.assertRaises(StopWatching):
                        rewards.watch(path)
                self.assertEqual([entry.args for entry in visit.call_args_list], [(path, False), (path, False)])
                self.assertEqual(sleep.call_count, 4)

    def test_daily_visit_is_recorded_once_after_first_party_credit_summary(self):
        with tempfile.TemporaryDirectory() as directory:
            path = self.account(directory)
            page = self.page(rewards.VISIT_ROUTE, [mock_response("credits", data={"credit": 15000})])
            with patch.object(rewards, "utc_now", return_value=NOW), \
                    patch.object(rewards, "proxy_url", return_value="http://proxy.test:8080") as proxy, \
                    patch.object(rewards, "app_session", return_value=self.authenticated(page)) as login, \
                    patch.object(rewards, "save_session") as save:
                self.assertIn("not be independently confirmed", rewards.visit(path))
                status = codecraft.read_account(rewards.state_path(path))
                self.assertEqual(status["team_id"], TEAM)
                self.assertEqual(status["daily"]["date"], "2026-09-26")
                self.assertEqual(status["daily"]["status"], "visited")
                self.assertEqual(stat.S_IMODE(rewards.state_path(path).stat().st_mode), 0o600)
                self.assertIn("no duplicate visit", rewards.visit(path))
            proxy.assert_called_once()
            login.assert_called_once()
            save.assert_called_once_with(page.context, page, rewards.session_path(path))
            self.assertNotIn("private-upstream-key", rewards.state_path(path).read_text())

    def test_failed_or_ambiguous_visit_cannot_retry_same_day(self):
        with tempfile.TemporaryDirectory() as directory:
            path = self.account(directory)
            page = self.page(rewards.VISIT_ROUTE, [mock_response("credits", status=401)])
            with patch.object(rewards, "utc_now", return_value=NOW), \
                    patch.object(rewards, "proxy_url", return_value="http://proxy.test:8080"), \
                    patch.object(rewards, "app_session", return_value=self.authenticated(page)) as login, \
                    patch.object(rewards, "save_session") as save:
                with self.assertRaises(codecraft.PipelineError):
                    rewards.visit(path)
                self.assertEqual(codecraft.read_account(rewards.state_path(path))["daily"]["status"], "attempted")
                with self.assertRaisesRegex(codecraft.PipelineError, "may already have occurred"):
                    rewards.visit(path)
            login.assert_called_once()
            save.assert_not_called()

    def test_team_mismatch_stops_before_touching_any_reward_state(self):
        with tempfile.TemporaryDirectory() as directory:
            path = self.account(directory)
            page = self.page(rewards.VISIT_ROUTE, [])
            with patch.object(rewards, "utc_now", return_value=NOW), \
                    patch.object(rewards, "proxy_url", return_value="http://proxy.test:8080"), \
                    patch.object(rewards, "app_session", return_value=self.authenticated(page, "different-team")):
                with self.assertRaisesRegex(codecraft.PipelineError, "different teams"):
                    rewards.visit(path)
            self.assertFalse(rewards.state_path(path).exists())
            page.goto.assert_not_called()

    def test_only_exact_https_first_party_api_state_is_accepted(self):
        self.assertTrue(rewards.own_response(mock_response("ai-agent-survey"), TEAM, "ai-agent-survey", "GET"))
        for host in ("api.1min.ai.attacker.test", "app.1min.ai", "accounts.google.com"):
            self.assertFalse(rewards.own_response(mock_response("ai-agent-survey", host=host), TEAM,
                                                   "ai-agent-survey", "GET"))
        self.assertFalse(rewards.own_response(mock_response("ai-agent-survey", method="POST"), TEAM,
                                               "ai-agent-survey", "GET"))
        self.assertFalse(rewards.own_response(mock_response("ai-agent-survey"), "other-team",
                                               "ai-agent-survey", "GET"))

    def test_survey_status_requires_both_boolean_fields(self):
        self.assertEqual(rewards.survey_status(mock_response("ai-agent-survey", data={
            "submitted": True, "teamRewarded": False})), {"submitted": True, "teamRewarded": False})
        for data in ({"submitted": "true", "teamRewarded": False}, {"submitted": False}, None):
            with self.subTest(data=data), self.assertRaises(codecraft.PipelineError):
                rewards.survey_status(mock_response("ai-agent-survey", data=data))

    def test_server_submitted_state_prevents_duplicate_survey_post(self):
        with tempfile.TemporaryDirectory() as directory:
            path = self.account(directory)
            page = self.page(rewards.SURVEY_ROUTE, [mock_response("ai-agent-survey", data={
                "submitted": True, "teamRewarded": False})])
            answers = dict.fromkeys(rewards.SURVEY_FIELDS, "Other")
            with patch.object(rewards, "proxy_url", return_value="http://proxy.test:8080"), \
                    patch.object(rewards, "app_session", return_value=self.authenticated(page)) as login:
                self.assertIn("already has a survey submission", rewards.submit_survey(path, answers, rewards.TASK))
                self.assertEqual(codecraft.read_account(rewards.state_path(path))["survey"]["status"], "already_submitted")
                with self.assertRaisesRegex(codecraft.PipelineError, "never send a duplicate"):
                    rewards.submit_survey(path, answers, rewards.TASK)
            login.assert_called_once()
            page.expect_response.assert_not_called()

    def test_survey_submission_marked_attempted_before_click_and_then_confirmed(self):
        for rewarded in (False, True):
            with self.subTest(rewarded=rewarded), tempfile.TemporaryDirectory() as directory:
                path = self.account(directory)
                data = iter(({"submitted": False, "teamRewarded": False},
                             {"submitted": True, "teamRewarded": rewarded}))
                page = self.page(rewards.SURVEY_ROUTE, [])
                handlers = []
                page.on.side_effect = lambda _event, callback: handlers.append(callback)

                def visit(*_args, **_kwargs):
                    reply = mock_response("ai-agent-survey", data=next(data))
                    for callback in handlers:
                        callback(reply)
                    return SimpleNamespace(status=200)

                page.goto.side_effect = visit
                form = page.locator.return_value.filter.return_value
                form.count.return_value = 1
                form.inner_text.return_value = "Submissions require admin approval"
                form.locator.return_value.count.return_value = 1
                form.locator.return_value.input_value.return_value = rewards.TASK
                button = form.get_by_role.return_value
                button.count.return_value = 1
                button.is_enabled.return_value = True
                sent = SimpleNamespace(status=201)
                page.expect_response.return_value.__enter__.return_value.value = sent

                def click(*_args, **_kwargs):
                    state = codecraft.read_account(rewards.state_path(path))
                    self.assertEqual(state["survey"]["status"], "attempted")

                button.click.side_effect = click
                answers = {"role": "Software Engineer / Developer", "industry": "Other", "organization": "Other",
                           "aiUseCase": "Software Development & Coding", "usageFrequency": "Daily"}
                with patch.object(rewards, "proxy_url", return_value="http://proxy.test:8080"), \
                        patch.object(rewards, "app_session", return_value=self.authenticated(page)), \
                        patch.object(rewards, "select_choice") as select, \
                        patch.object(rewards, "save_session") as save:
                    result = rewards.submit_survey(path, answers, rewards.TASK)
                self.assertIn("reports this team rewarded" if rewarded else "admin review", result)
                self.assertEqual(select.call_count, 5)
                state = codecraft.read_account(rewards.state_path(path))
                self.assertEqual(state["survey"]["status"], "submitted")
                self.assertIs(state["survey"]["team_rewarded"], rewarded)
                self.assertEqual(stat.S_IMODE(rewards.state_path(path).stat().st_mode), 0o600)
                button.click.assert_called_once()
                save.assert_called_once_with(page.context, page, rewards.session_path(path))

    def test_unconfirmed_survey_post_never_auto_retries(self):
        with tempfile.TemporaryDirectory() as directory:
            path = self.account(directory)
            codecraft.save_account(rewards.state_path(path), {"team_id": TEAM,
                                  "survey": {"status": "attempted", "started_at": "today"}})
            with patch.object(rewards, "app_session") as login, self.assertRaises(codecraft.PipelineError):
                rewards.submit_survey(path, dict.fromkeys(rewards.SURVEY_FIELDS, "Other"), rewards.TASK)
            login.assert_not_called()

    def test_ambiguous_survey_submission_remains_blocked(self):
        for failure in ("http_error", "timeout", "unconfirmed"):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as directory:
                path = self.account(directory)
                page = self.page(rewards.SURVEY_ROUTE, [])
                handlers = []
                page.on.side_effect = lambda _event, callback: handlers.append(callback)

                def visit(*_args, **_kwargs):
                    reply = mock_response("ai-agent-survey", data={"submitted": False, "teamRewarded": False})
                    for callback in handlers:
                        callback(reply)
                    return SimpleNamespace(status=200)

                page.goto.side_effect = visit
                form = page.locator.return_value.filter.return_value
                form.count.return_value = 1
                form.inner_text.return_value = "Submissions require admin approval"
                form.locator.return_value.count.return_value = 1
                form.locator.return_value.input_value.return_value = rewards.TASK
                button = form.get_by_role.return_value
                button.count.return_value = 1
                button.is_enabled.return_value = True
                page.expect_response.return_value.__enter__.return_value.value = SimpleNamespace(
                    status=503 if failure == "http_error" else 201)
                if failure == "timeout":
                    page.expect_response.return_value.__exit__.side_effect = TimeoutError("Response timed out")

                answers = dict.fromkeys(rewards.SURVEY_FIELDS, "Other")
                with patch.object(rewards, "proxy_url", return_value="http://proxy.test:8080"), \
                        patch.object(rewards, "app_session", return_value=self.authenticated(page)) as login, \
                        patch.object(rewards, "select_choice"), \
                        patch.object(rewards, "save_session") as save:
                    with self.assertRaises(TimeoutError if failure == "timeout" else codecraft.PipelineError):
                        rewards.submit_survey(path, answers, rewards.TASK)
                    self.assertEqual(codecraft.read_account(rewards.state_path(path))["survey"]["status"],
                                     "attempted")
                    with self.assertRaisesRegex(codecraft.PipelineError, "never send a duplicate"):
                        rewards.submit_survey(path, answers, rewards.TASK)
                login.assert_called_once()
                button.click.assert_called_once()
                save.assert_not_called()

    def test_draft_is_offline_and_task_file_requires_private_permissions(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "onemin.json"
            settings = {"ONEMIN_CREDENTIALS_FILE": str(path), "PROXY": ""}
            args = ["survey", "--role", "Other", "--industry", "Other", "--organization", "Other",
                    "--use-case", "Software Development & Coding", "--frequency", "Daily"]
            output = io.StringIO()
            with patch.dict(os.environ, settings), redirect_stdout(output):
                self.assertEqual(rewards.main(args), 0)
            self.assertIn("Draft task", output.getvalue())
            for field, value in (("role", "Other"), ("industry", "Other"), ("organization", "Other"),
                                 ("aiUseCase", "Software Development & Coding"), ("usageFrequency", "Daily")):
                self.assertIn(f"{field}: {value}", output.getvalue())
            self.assertFalse(rewards.state_path(path).exists())
            taskfile = Path(directory) / "task.txt"
            taskfile.write_text("Document a small code change, then run checks and report the result.\n")
            taskfile.chmod(0o600)
            self.assertIn("Document", rewards.read_task(taskfile))
            taskfile.chmod(0o644)
            with self.assertRaises(codecraft.PipelineError):
                rewards.read_task(taskfile)
            public = Path(directory) / "public"
            public.mkdir()
            public.chmod(0o755)
            taskfile = public / "task.txt"
            taskfile.write_text("Document a small code change, then run checks and report the result.\n")
            taskfile.chmod(0o600)
            with self.assertRaisesRegex(codecraft.PipelineError, "file and directory must be private"):
                rewards.read_task(taskfile)


if __name__ == "__main__":
    unittest.main()

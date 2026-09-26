from contextlib import contextmanager, redirect_stderr, redirect_stdout
from http.client import HTTPConnection
import io
import json
import os
from pathlib import Path
import stat
import tempfile
import threading
import unittest
from unittest.mock import patch

import codecraft
import onemin
import onemin_adapter as adapter


def result(text, status="SUCCESS"):
    return {"aiRecord": {"status": status, "aiRecordDetail": {"resultObject": [text]}}}


class Upstream:
    def __init__(self, payload):
        if isinstance(payload, dict):
            payload = json.dumps(payload).encode("utf-8")
        self.source = io.BytesIO(payload)

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        pass

    def read(self, limit):
        return self.source.read(limit)

    def readline(self, limit):
        return self.source.readline(limit)


class AdapterTests(unittest.TestCase):
    @contextmanager
    def server(self):
        server = adapter.Bridge(("127.0.0.1", 0), "private-upstream", "local-only-token", "http://proxy.test:8080")
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            yield server.server_address[1]
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)
            self.assertFalse(thread.is_alive())

    def call(self, port, method, path, body=None, token="local-only-token", content_type="application/json"):
        client = HTTPConnection("127.0.0.1", port, timeout=8)
        headers = {"Content-Type": content_type}
        if token is not None:
            headers["Authorization"] = "Bearer " + token
        client.request(method, path, body=json.dumps(body).encode() if body is not None else None, headers=headers)
        response = client.getresponse()
        payload, headers = response.read(), dict(response.getheaders())
        status = response.status
        client.close()
        return status, payload, headers

    def test_models_and_authentication_are_local_only(self):
        with self.server() as port, patch.object(adapter, "upstream_request") as upstream:
            status, payload, headers = self.call(port, "GET", "/v1/models", token=None)
            self.assertEqual(status, 401)
            self.assertNotIn("Access-Control-Allow-Origin", headers)
            self.assertNotIn(b"private-upstream", payload)
            status, payload, _ = self.call(port, "GET", "/v1/models", token="wrong")
            self.assertEqual(status, 401)
            status, payload, _ = self.call(port, "GET", "/v1/models", token="café")
            self.assertEqual(status, 401)
            status, payload, _ = self.call(port, "GET", "/v1/models")
            self.assertEqual(status, 200)
            self.assertEqual(json.loads(payload)["data"][0]["id"], adapter.MODEL)
            status, payload, _ = self.call(port, "POST", "/v1/chat/completions",
                                           {"model": adapter.MODEL, "messages": [{"role": "user", "content": "x"}]}, token=None)
            self.assertEqual(status, 401)
            self.assertNotIn(b"private-upstream", payload)
            upstream.assert_not_called()
        with self.assertRaises(ValueError):
            adapter.Bridge(("0.0.0.0", 0), "key", "token", "http://proxy.test:8080")

    def test_simple_completion_translates_to_one_upstream_call(self):
        with self.server() as port, patch.object(adapter, "upstream_request", return_value=Upstream(result("Hello from Claude"))) as upstream:
            status, payload, headers = self.call(port, "POST", "/v1/chat/completions",
                                                 {"model": adapter.MODEL, "messages": [{"role": "user", "content": "Hello"}]})
        self.assertEqual(status, 200)
        response = json.loads(payload)
        self.assertEqual(response["object"], "chat.completion")
        self.assertEqual(response["choices"][0]["message"], {"role": "assistant", "content": "Hello from Claude"})
        self.assertEqual(response["choices"][0]["finish_reason"], "stop")
        self.assertEqual(upstream.call_args.args, ("private-upstream", "http://proxy.test:8080", "Hello", False))
        self.assertEqual(headers["Cache-Control"], "no-store")

    def test_multi_turn_history_system_and_tool_results_are_preserved(self):
        messages = [
            {"role": "system", "content": "Answer truthfully"},
            {"role": "user", "content": "Read docs"},
            {"role": "assistant", "content": None, "tool_calls": [{"id": "call_a", "type": "function",
                "function": {"name": "read_file", "arguments": '{"path":"README.md"}'}}]},
            {"role": "tool", "tool_call_id": "call_a", "content": "Documentation text"},
        ]
        prompt, definitions, choice, forced = adapter.prepare_request({"model": adapter.MODEL, "messages": messages})
        self.assertIn("Answer truthfully", prompt)
        self.assertIn("Documentation text", prompt)
        self.assertIn("call_a", prompt)
        self.assertIn("tool_calls", prompt)
        self.assertFalse(definitions)

    def test_stream_converts_actual_1min_sse_to_openai_chunks(self):
        sse = (b'event: content\ndata: {"content":"Hello"}\n\n'
               b'event: content\ndata: {"content":" world"}\n\n'
               b'event: result\ndata: ' + json.dumps(result("Hello world")).encode() + b'\n\n'
               b'event: done\ndata: {"message":"Stream completed"}\n\n')
        with self.server() as port, patch.object(adapter, "upstream_request", return_value=Upstream(sse)) as upstream:
            status, payload, headers = self.call(port, "POST", "/v1/chat/completions",
                {"model": adapter.MODEL, "messages": [{"role": "user", "content": "Hello"}], "stream": True})
        self.assertEqual(status, 200)
        self.assertIn("text/event-stream", headers["Content-Type"])
        chunks = [line[6:] for line in payload.decode().splitlines() if line.startswith("data: ")]
        self.assertEqual(chunks[-1], "[DONE]")
        events = [json.loads(chunk) for chunk in chunks[:-1]]
        self.assertEqual(events[0]["choices"][0]["delta"], {"role": "assistant"})
        self.assertEqual("".join(e["choices"][0]["delta"].get("content", "") for e in events), "Hello world")
        self.assertEqual(events[-1]["choices"][0]["finish_reason"], "stop")
        self.assertEqual(upstream.call_args.args[-1], True)

    def test_stream_fails_closed_on_upstream_error_event(self):
        sse = b'event: error\ndata: {"error":"private account details"}\n\n'
        with self.server() as port, patch.object(adapter, "upstream_request", return_value=Upstream(sse)):
            status, payload, _ = self.call(port, "POST", "/v1/chat/completions",
                {"model": adapter.MODEL, "messages": [{"role": "user", "content": "hello"}], "stream": True})
        self.assertEqual(status, 200)
        self.assertIn(b'"error"', payload)
        self.assertNotIn(b"private account details", payload)
        self.assertIn(b"data: [DONE]", payload)
        self.assertNotIn(b'"finish_reason": "stop"', payload)

    def test_sse_line_read_is_bounded_before_allocating_untrusted_data(self):
        upstream = Upstream(b'event: content\ndata: ' + b'a' * 200)
        with patch.object(adapter, "MAX_REPLY", 100), self.assertRaises(adapter.AdapterError):
            list(adapter.sse_events(upstream))
        self.assertLessEqual(upstream.source.tell(), 101)

    def test_tool_call_round_trip_nonstream_and_stream(self):
        tools = [{"type": "function", "function": {"name": "read_file", "description": "Reads file",
                                                      "parameters": {"type": "object", "properties": {"path": {"type": "string"}},
                                                                     "required": ["path"]}}}]
        body = {"model": adapter.MODEL, "messages": [{"role": "user", "content": "Read README.md"}], "tools": tools}
        first = result('{"tool_calls":[{"name":"read_file","arguments":{"path":"README.md"}}]}')
        with self.server() as port, patch.object(adapter, "upstream_request", return_value=Upstream(first)) as upstream:
            status, payload, _ = self.call(port, "POST", "/v1/chat/completions", body)
            self.assertEqual(status, 200)
            message = json.loads(payload)["choices"][0]["message"]
            self.assertIsNone(message["content"])
            tool = message["tool_calls"][0]
            self.assertEqual(tool["function"]["name"], "read_file")
            self.assertEqual(json.loads(tool["function"]["arguments"]), {"path": "README.md"})
            self.assertEqual(json.loads(payload)["choices"][0]["finish_reason"], "tool_calls")
            prompt = upstream.call_args.args[2]
            self.assertIn("read_file", prompt)
            self.assertIn("README.md", prompt)
            self.assertFalse(upstream.call_args.args[-1])
            body["messages"].append({"role": "assistant", "content": None, "tool_calls": [tool]})
            body["messages"].append({"role": "tool", "tool_call_id": tool["id"], "content": "It explains how to run the CLI."})
            upstream.return_value = Upstream(result('{"final":"The README explains the CLI."}'))
            status, payload, _ = self.call(port, "POST", "/v1/chat/completions", body)
            self.assertEqual(status, 200)
            self.assertEqual(json.loads(payload)["choices"][0]["message"]["content"], "The README explains the CLI.")
            self.assertIn("It explains how to run the CLI.", upstream.call_args.args[2])
            upstream.return_value = Upstream(first)
            body["messages"] = [{"role": "user", "content": "Read README.md"}]
            body["stream"] = True
            status, payload, _ = self.call(port, "POST", "/v1/chat/completions", body)
            self.assertEqual(status, 200)
            deltas = [json.loads(line[6:])["choices"][0] for line in payload.decode().splitlines() if line.startswith("data: {")]
            self.assertEqual(deltas[-1]["finish_reason"], "tool_calls")
            self.assertEqual(deltas[1]["delta"]["tool_calls"][0]["index"], 0)
            self.assertFalse(upstream.call_args.args[-1])

    def test_unsupported_inputs_do_not_charge_upstream(self):
        valid = {"model": adapter.MODEL, "messages": [{"role": "user", "content": "Hi"}]}
        bad = [
            ({**valid, "model": "unknown-model"}, 400),
            ({**valid, "messages": [{"role": "user", "content": [{"type": "image_url", "image_url": {"url": "x"}}]}]}, 400),
            ({**valid, "messages": [{"role": "user", "content": "hi", "attachments": [{"file_id": "secret"}]}]}, 400),
            ({**valid, "attachments": [{"file_id": "secret"}]}, 400),
            ({**valid, "modalities": ["audio"]}, 400),
            ({**valid, "tool_choice": "required"}, 400),
            ({**valid, "response_format": {"type": "json_object"}}, 400),
            ({**valid, "messages": [{"role": "user", "content": "x" * (adapter.MAX_PROMPT + 1)}]}, 413),
        ]
        with self.server() as port, patch.object(adapter, "upstream_request") as upstream:
            for body, expected in bad:
                with self.subTest(expected=expected, keys=list(body)):
                    status, payload, _ = self.call(port, "POST", "/v1/chat/completions", body)
                    self.assertEqual(status, expected)
                    self.assertIn(b'"error"', payload)
            upstream.assert_not_called()
            status, _, _ = self.call(port, "POST", "/v1/chat/completions", valid, content_type="text/plain")
            self.assertEqual(status, 415)
            status, _, _ = self.call(port, "GET", "/v1/secret")
            self.assertEqual(status, 404)

    def test_invalid_tool_output_and_upstream_failure_do_not_leak_details(self):
        tools = [{"type": "function", "function": {"name": "read_file", "parameters": {"type": "object"}}}]
        body = {"model": adapter.MODEL, "messages": [{"role": "user", "content": "read"}], "tools": tools}
        with self.server() as port, patch.object(adapter, "upstream_request", return_value=Upstream(
                result('{"tool_calls":[{"name":"dangerous_undeclared_tool","arguments":{}}]}'))) as upstream:
            status, payload, _ = self.call(port, "POST", "/v1/chat/completions", body)
            self.assertEqual(status, 502)
            self.assertNotIn(b"dangerous_undeclared_tool", payload)
            upstream.return_value = Upstream(result("secret internal error", "FAILED"))
            status, payload, _ = self.call(port, "POST", "/v1/chat/completions", body)
            self.assertEqual(status, 502)
            self.assertNotIn(b"secret internal error", payload)

    def test_parallel_calls_can_use_same_function_but_opt_out_blocks_them(self):
        definitions = {"read_file": {"name": "read_file", "parameters": {"type": "object"}}}
        text = json.dumps({"tool_calls": [
            {"name": "read_file", "arguments": {"path": "one"}},
            {"name": "read_file", "arguments": {"path": "two"}},
        ]})
        content, calls = adapter.parse_tool_response(text, definitions, "auto", None)
        self.assertIsNone(content)
        self.assertEqual(len(calls), 2)
        self.assertEqual([json.loads(call["function"]["arguments"])["path"] for call in calls], ["one", "two"])
        with self.assertRaises(adapter.AdapterError):
            adapter.parse_tool_response(text, definitions, "auto", None, parallel=False)

    def test_upstream_request_sends_key_only_via_proxy_to_fixed_endpoint(self):
        with patch.object(adapter, "build_opener") as builder:
            builder.return_value.open.return_value = Upstream(result("ok"))
            with adapter.upstream_request("secret-api-key", "http://proxy.test:8080", "prompt", streaming=True):
                pass
            handlers = builder.call_args.args
            self.assertEqual(handlers[0].proxies, {"https": "http://proxy.test:8080"})
            self.assertIsInstance(handlers[1], onemin.NoRedirect)
            self.assertIsInstance(handlers[2], codecraft.TunnelOnlyHTTPS)
            request, timeout = builder.return_value.open.call_args.args[0], builder.return_value.open.call_args.kwargs["timeout"]
            self.assertEqual(request.full_url, "https://api.1min.ai/api/chat-with-ai?isStreaming=true")
            self.assertEqual(request.get_method(), "POST")
            self.assertEqual(request.get_header("Api-key"), "secret-api-key")
            self.assertEqual(json.loads(request.data)["promptObject"], {"prompt": "prompt"})
            self.assertEqual(timeout, 180)

    def test_local_token_private_reused_and_separate_from_upstream_key(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "onemin.json"
            codecraft.save_account(path, {"api_key": "private-upstream"})
            with patch.dict(os.environ, {"ONEMIN_CREDENTIALS_FILE": str(path)}):
                self.assertEqual(adapter.account_key(), "private-upstream")
                token = adapter.local_token(adapter.token_path())
                self.assertNotEqual(token, "private-upstream")
                self.assertEqual(adapter.local_token(adapter.token_path()), token)
                self.assertEqual(stat.S_IMODE(adapter.token_path().stat().st_mode), 0o600)
                output = io.StringIO()
                with redirect_stdout(output):
                    self.assertEqual(adapter.main(["token"]), 0)
                self.assertEqual(output.getvalue().strip(), token)
                adapter.token_path().chmod(0o644)
                with self.assertRaises(codecraft.PipelineError):
                    adapter.local_token(adapter.token_path())
                adapter.token_path().unlink()
                adapter.token_path().symlink_to(path)
                with self.assertRaises(codecraft.PipelineError):
                    adapter.local_token(adapter.token_path())

    def test_token_command_refuses_to_print_real_upstream_key_as_local_token(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "onemin.json"
            private = "k" * 43
            codecraft.save_account(path, {"api_key": private})
            token_file = Path(directory) / adapter.TOKEN_NAME
            token_file.write_text(private + "\n", encoding="ascii")
            token_file.chmod(0o600)
            output, errors = io.StringIO(), io.StringIO()
            with patch.dict(os.environ, {"ONEMIN_CREDENTIALS_FILE": str(path)}), \
                    redirect_stdout(output), redirect_stderr(errors):
                self.assertEqual(adapter.main(["token"]), 1)
            self.assertNotIn(private, output.getvalue() + errors.getvalue())

    def test_serve_requires_proxy_and_clears_no_proxy_before_listening(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "onemin.json"
            codecraft.save_account(path, {"api_key": "private-upstream"})
            with patch.dict(os.environ, {"ONEMIN_CREDENTIALS_FILE": str(path), "PROXY": "",
                                         "NO_PROXY": "api.1min.ai"}), patch.object(adapter, "Bridge") as bridge, \
                    redirect_stderr(io.StringIO()):
                self.assertEqual(adapter.main(["serve"]), 1)
                bridge.assert_not_called()
                self.assertFalse((Path(directory) / adapter.TOKEN_NAME).exists())
            with patch.dict(os.environ, {"ONEMIN_CREDENTIALS_FILE": str(path), "PROXY": "http://proxy.test:8080",
                                         "NO_PROXY": "api.1min.ai"}), patch.object(adapter, "Bridge") as bridge, \
                    redirect_stdout(io.StringIO()):
                self.assertEqual(adapter.main(["serve", "--port", "8765"]), 0)
                bridge.assert_called_once()
                self.assertEqual(bridge.call_args.args[:2], (("127.0.0.1", 8765), "private-upstream"))
                self.assertEqual(os.environ["NO_PROXY"], "")
                self.assertEqual(os.environ["no_proxy"], "")


if __name__ == "__main__":
    unittest.main()

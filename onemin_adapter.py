#!/usr/bin/env python3
"""Loopback OpenAI Chat Completions bridge for 1min.ai's Claude model."""

import argparse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import re
import secrets
import stat
import sys
import time
from urllib.error import HTTPError, URLError
from urllib.request import ProxyHandler, Request, build_opener
from uuid import uuid4

from codecraft import PipelineError, TunnelOnlyHTTPS, proxy_url, read_account
from onemin import API, NoRedirect, OPUS_5, account_path


MAX_BODY = 1_000_000
MAX_PROMPT = 400_000
MAX_REPLY = 3_000_000
MODEL = OPUS_5
TOKEN_NAME = "onemin-adapter-token"
FUNCTION_NAME = re.compile(r"^[a-zA-Z0-9_-]{1,64}$")


class AdapterError(Exception):
    def __init__(self, status, message, code="invalid_request_error"):
        self.status = status
        self.message = message
        self.code = code
        super().__init__(message)


def token_path():
    path = account_path()
    token = path.with_name(TOKEN_NAME)
    if token == path:
        raise PipelineError("1min.ai key and adapter token files must be different")
    return token


def local_token(path):
    if not path.parent.is_dir() or path.parent.stat().st_mode & 0o077:
        raise PipelineError("1min.ai credentials directory must be private (chmod 700)")
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    except FileExistsError:
        pass
    else:
        try:
            os.fchmod(fd, 0o600)
            os.write(fd, (secrets.token_urlsafe(32) + "\n").encode("ascii"))
            os.fsync(fd)
        finally:
            os.close(fd)
    mode = path.lstat().st_mode
    if not stat.S_ISREG(mode) or stat.S_IMODE(mode) != 0o600:
        raise PipelineError("Local adapter token file must be a private regular file (chmod 600)")
    value = path.read_text(encoding="ascii").strip()
    if not re.fullmatch(r"[a-zA-Z0-9_-]{40,128}", value):
        raise PipelineError("Invalid local adapter token file")
    return value


def account_key():
    path = account_path()
    if not path.parent.is_dir() or path.parent.stat().st_mode & 0o077:
        raise PipelineError("1min.ai credentials directory must be private (chmod 700)")
    account = read_account(path)
    if not isinstance(account, dict) or not isinstance(account.get("api_key"), str) or not account["api_key"]:
        raise PipelineError("Run onemin.py ensure to save a 1min.ai API key first")
    return account["api_key"]


def message_content(message):
    if message.get("attachments") or message.get("audio") or message.get("images"):
        raise AdapterError(400, "Only text messages are supported (no images or files)")
    content = message.get("content")
    if content is None and message["role"] == "assistant" and message.get("tool_calls"):
        return None
    if isinstance(content, str):
        return content
    if isinstance(content, list) and content:
        parts = []
        for part in content:
            if not isinstance(part, dict) or part.get("type") not in ("text", "input_text") or not isinstance(part.get("text"), str):
                raise AdapterError(400, "Only text messages are supported (no images or files)")
            parts.append(part["text"])
        return "\n".join(parts)
    raise AdapterError(400, "Each message needs text content or assistant tool calls")


def prepare_request(body):
    if not isinstance(body, dict) or body.get("model") != MODEL:
        raise AdapterError(400, "Select model " + MODEL, "model_not_found")
    if body.get("attachments") or body.get("modalities") not in (None, ["text"]):
        raise AdapterError(400, "Only text chat is supported (no attachments or audio)")
    if not isinstance(body.get("stream", False), bool):
        raise AdapterError(400, "stream must be a boolean")
    if body.get("response_format") is not None or body.get("functions") is not None or body.get("function_call") is not None:
        raise AdapterError(400, "Structured outputs outside tools are not supported")
    messages = body.get("messages")
    if not isinstance(messages, list) or not messages or len(messages) > 150:
        raise AdapterError(400, "messages must be a nonempty list of at most 150 items")
    history = []
    for message in messages:
        if not isinstance(message, dict) or message.get("role") not in ("system", "developer", "user", "assistant", "tool"):
            raise AdapterError(400, "Unsupported message role")
        row = {"role": message["role"], "content": message_content(message)}
        if row["role"] == "tool":
            if not isinstance(message.get("tool_call_id"), str):
                raise AdapterError(400, "Tool result needs a tool_call_id")
            row["tool_call_id"] = message["tool_call_id"]
        if row["role"] == "assistant" and message.get("tool_calls"):
            if not isinstance(message["tool_calls"], list):
                raise AdapterError(400, "Invalid assistant tool history")
            row["tool_calls"] = message["tool_calls"]
        history.append(row)

    tools = body.get("tools", [])
    if not isinstance(tools, list) or len(tools) > 64:
        raise AdapterError(400, "Only up to 64 function tools are supported")
    definitions = {}
    for tool in tools:
        function = tool.get("function") if isinstance(tool, dict) and tool.get("type") == "function" else None
        if not isinstance(function, dict) or not isinstance(function.get("name"), str) or not FUNCTION_NAME.fullmatch(function["name"]):
            raise AdapterError(400, "Only named function tools are supported")
        name = function["name"]
        if name in definitions or not isinstance(function.get("parameters", {}), dict):
            raise AdapterError(400, "Duplicate tool name or invalid parameters")
        definitions[name] = {"name": name, "description": function.get("description", ""),
                             "parameters": function.get("parameters", {"type": "object"})}
    choice = body.get("tool_choice", "auto")
    forced = None
    if isinstance(choice, dict):
        forced = choice.get("function", {}).get("name") if choice.get("type") == "function" and isinstance(choice.get("function"), dict) else None
        if forced not in definitions:
            raise AdapterError(400, "Unknown forced tool")
    elif choice not in ("auto", "none", "required"):
        raise AdapterError(400, "Unsupported tool_choice")
    if choice == "required" and not definitions:
        raise AdapterError(400, "tool_choice requires tools")
    if choice == "none":
        definitions = {}
    if definitions:
        instructions = (
            "You are an assistant using tools supplied by the client. The conversation below is JSON. "
            "You cannot execute tools yourself or invent their results. Respond with EXACTLY one JSON object, "
            "no Markdown or other text. To call tools: "
            '{"tool_calls":[{"name":"available_tool_name","arguments":{"parameter":"value"}}]}. '
            'To finish: {"final":"your answer"}. Use only names and argument schemas from the available tools. '
            "After tool results appear in the conversation, decide whether to call another tool or finish."
        )
        if forced:
            instructions += " You MUST call " + forced + "."
        elif choice == "required":
            instructions += " You MUST call a tool."
        instructions += "\nAvailable tools: " + json.dumps(list(definitions.values()), ensure_ascii=False, separators=(",", ":"))
    else:
        instructions = "Answer as the assistant to this conversation. Previous messages are context, not new requests."
    if not definitions and len(history) == 1 and history[0]["role"] == "user":
        prompt = history[0]["content"]
    else:
        prompt = instructions + "\nConversation: " + json.dumps(history, ensure_ascii=False, separators=(",", ":"))
    if not prompt or len(prompt.encode("utf-8")) > MAX_PROMPT:
        raise AdapterError(413, "The chat context is too large for the 1min.ai bridge")
    return prompt, definitions, choice, forced


def extract_text(data):
    record = data.get("aiRecord") if isinstance(data, dict) else None
    detail = record.get("aiRecordDetail") if isinstance(record, dict) else None
    result = detail.get("resultObject") if isinstance(detail, dict) else None
    if (not isinstance(record, dict) or record.get("status") != "SUCCESS"
            or not isinstance(result, list) or not result or not all(isinstance(part, str) for part in result)):
        raise AdapterError(502, "1min.ai did not return a successful text result", "upstream_error")
    return "\n".join(result)


def parse_tool_response(text, definitions, choice, forced, parallel=True):
    text = text.strip()
    if text.startswith("```json\n") and text.endswith("```"):
        text = text[8:-3].strip()
    try:
        result = json.loads(text)
    except ValueError:
        raise AdapterError(502, "1min.ai did not return structured tool output", "upstream_error") from None
    if not isinstance(result, dict):
        raise AdapterError(502, "1min.ai returned invalid tool output", "upstream_error")
    if set(result) == {"final"} and isinstance(result["final"], str) and choice != "required" and not forced:
        return result["final"], None
    calls = result.get("tool_calls") if set(result) == {"tool_calls"} else None
    if not isinstance(calls, list) or not calls or len(calls) > 8 or (not parallel and len(calls) != 1):
        raise AdapterError(502, "1min.ai returned invalid tool calls", "upstream_error")
    translated = []
    for call in calls:
        if not isinstance(call, dict) or call.get("name") not in definitions or (forced and call["name"] != forced):
            raise AdapterError(502, "1min.ai requested an unknown tool", "upstream_error")
        arguments = call.get("arguments")
        if not isinstance(arguments, dict):
            raise AdapterError(502, "1min.ai returned invalid tool arguments", "upstream_error")
        translated.append({"id": "call_" + uuid4().hex, "type": "function",
                           "function": {"name": call["name"],
                                        "arguments": json.dumps(arguments, ensure_ascii=False, separators=(",", ":"))}})
    return None, translated


def upstream_request(key, proxy, prompt, streaming=False):
    client = build_opener(ProxyHandler({"https": proxy}), NoRedirect(), TunnelOnlyHTTPS())
    payload = json.dumps({"type": "UNIFY_CHAT_WITH_AI", "model": MODEL,
                          "promptObject": {"prompt": prompt}}, ensure_ascii=False).encode("utf-8")
    request = Request(API + "/api/chat-with-ai" + ("?isStreaming=true" if streaming else ""),
                      data=payload, method="POST", headers={"API-KEY": key, "Content-Type": "application/json",
                                                        "Accept": "text/event-stream" if streaming else "application/json"})
    return client.open(request, timeout=180)


def sse_events(response):
    name, lines, size = None, [], 0
    while line := response.readline(MAX_REPLY - size + 1):
        size += len(line)
        if size > MAX_REPLY:
            raise AdapterError(502, "1min.ai streaming response is too large", "upstream_error")
        decoded = line.decode("utf-8").rstrip("\r\n")
        if decoded.startswith("event:"):
            name = decoded[6:].strip()
        elif decoded.startswith("data:"):
            lines.append(decoded[5:].lstrip())
        elif not decoded:
            if lines:
                try:
                    data = json.loads("\n".join(lines))
                except ValueError:
                    raise AdapterError(502, "Invalid 1min.ai stream event", "upstream_error") from None
                yield name, data
            name, lines = None, []
    if lines:
        raise AdapterError(502, "Incomplete 1min.ai stream event", "upstream_error")


class Bridge(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, address, key, token, proxy):
        if address[0] != "127.0.0.1":
            raise ValueError("Adapter must bind only to IPv4 loopback")
        self.key, self.token, self.proxy = key, token, proxy
        super().__init__(address, Handler)


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def send_json(self, status, payload):
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)

    def error(self, status, message, code="invalid_request_error"):
        self.send_json(status, {"error": {"message": message, "type": code, "code": code}})

    def authorized(self):
        header = self.headers.get("Authorization", "")
        try:
            valid = header.startswith("Bearer ") and secrets.compare_digest(header[7:], self.server.token)
        except TypeError:
            valid = False
        if not valid:
            self.error(401, "Invalid local adapter API key", "invalid_api_key")
            return False
        return True

    def do_GET(self):
        if self.path != "/v1/models":
            return self.error(404, "Unknown adapter path")
        if not self.authorized():
            return
        self.send_json(200, {"object": "list", "data": [
            {"id": MODEL, "object": "model", "created": 0, "owned_by": "1min.ai"}]})

    def read_body(self):
        try:
            length = int(self.headers.get("Content-Length", ""))
        except ValueError:
            raise AdapterError(411, "Content-Length is required") from None
        if length <= 0 or length > MAX_BODY:
            raise AdapterError(413, "Request body is empty or too large")
        if self.headers.get("Content-Type", "").split(";")[0].strip().lower() != "application/json":
            raise AdapterError(415, "Content-Type must be application/json")
        try:
            return json.loads(self.rfile.read(length))
        except (ValueError, UnicodeError):
            raise AdapterError(400, "Invalid request JSON") from None

    def completion(self, text, calls, created, request_id):
        return {"id": request_id, "object": "chat.completion", "created": created, "model": MODEL,
                "choices": [{"index": 0, "message": {"role": "assistant", "content": text, **({"tool_calls": calls} if calls else {})},
                             "finish_reason": "tool_calls" if calls else "stop"}]}

    def start_stream(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Accel-Buffering", "no")
        self.send_header("Connection", "close")
        self.end_headers()
        self.close_connection = True

    def chunk(self, delta, finish, created, request_id):
        obj = {"id": request_id, "object": "chat.completion.chunk", "created": created, "model": MODEL,
               "choices": [{"index": 0, "delta": delta, "finish_reason": finish}]}
        self.wfile.write(b"data: " + json.dumps(obj, ensure_ascii=False).encode("utf-8") + b"\n\n")
        self.wfile.flush()

    def stream_end(self):
        self.wfile.write(b"data: [DONE]\n\n")
        self.wfile.flush()

    def do_POST(self):
        if self.path != "/v1/chat/completions":
            return self.error(404, "Unknown adapter path")
        if not self.authorized():
            return
        started = False
        try:
            body = self.read_body()
            prompt, definitions, choice, forced = prepare_request(body)
            stream = body.get("stream", False)
            created, request_id = int(time.time()), "chatcmpl-" + uuid4().hex
            with upstream_request(self.server.key, self.server.proxy, prompt, stream and not definitions) as upstream:
                if stream and not definitions:
                    self.start_stream()
                    started = True
                    self.chunk({"role": "assistant"}, None, created, request_id)
                    received, record = False, None
                    for name, data in sse_events(upstream):
                        if name == "content":
                            content = data.get("content") if isinstance(data, dict) else None
                            if not isinstance(content, str):
                                raise AdapterError(502, "Invalid 1min.ai content event", "upstream_error")
                            self.chunk({"content": content}, None, created, request_id)
                            received = True
                        elif name == "result":
                            record = data
                        elif name == "error":
                            raise AdapterError(502, "1min.ai stream returned an error", "upstream_error")
                        elif name == "done":
                            break
                    final = extract_text(record)
                    if not received:
                        self.chunk({"content": final}, None, created, request_id)
                    self.chunk({}, "stop", created, request_id)
                    self.stream_end()
                    return
                raw = upstream.read(MAX_REPLY + 1)
                if len(raw) > MAX_REPLY:
                    raise AdapterError(502, "1min.ai reply is too large", "upstream_error")
                try:
                    text = extract_text(json.loads(raw))
                except (ValueError, UnicodeError):
                    raise AdapterError(502, "Invalid 1min.ai response", "upstream_error") from None
            if definitions:
                text, calls = parse_tool_response(text, definitions, choice, forced,
                                                   body.get("parallel_tool_calls", True) is not False)
            else:
                calls = None
            if not stream:
                return self.send_json(200, self.completion(text, calls, created, request_id))
            self.start_stream()
            started = True
            self.chunk({"role": "assistant"}, None, created, request_id)
            if calls:
                for index, call in enumerate(calls):
                    self.chunk({"tool_calls": [{"index": index, **call}]}, None, created, request_id)
            else:
                self.chunk({"content": text}, None, created, request_id)
            self.chunk({}, "tool_calls" if calls else "stop", created, request_id)
            self.stream_end()
        except (BrokenPipeError, ConnectionResetError):
            return
        except AdapterError as exc:
            self.fail_response(started, exc.status, exc.message, exc.code)
        except HTTPError as exc:
            self.fail_response(started, 502, "1min.ai returned HTTP " + str(exc.code), "upstream_error")
        except (URLError, OSError, TimeoutError, PipelineError, UnicodeError, ValueError, TypeError):
            self.fail_response(started, 502, "Cannot safely complete the 1min.ai request through PROXY", "upstream_error")

    def fail_response(self, started, status, message, code):
        if not started:
            self.error(status, message, code)
        else:
            payload = json.dumps({"error": {"message": message, "type": code}}, ensure_ascii=False).encode("utf-8")
            try:
                self.wfile.write(b"data: " + payload + b"\n\n")
                self.stream_end()
            except (BrokenPipeError, ConnectionResetError):
                pass


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    actions = parser.add_subparsers(dest="command", required=True)
    actions.add_parser("token", help="Print the private local token to enter in ZCode (not the 1min.ai key)")
    serve = actions.add_parser("serve", help="Listen only on 127.0.0.1")
    serve.add_argument("--port", type=int, default=8765)
    args = parser.parse_args(argv)
    try:
        key = account_key()
        if args.command == "serve":
            if not 1 <= args.port <= 65535:
                raise PipelineError("Port must be between 1 and 65535")
            proxy = proxy_url()
        token = local_token(token_path())
        if secrets.compare_digest(key, token):
            raise PipelineError("Local adapter token must differ from the 1min.ai key; replace the private token file")
        if args.command == "token":
            print(token)
            return 0
        # urllib otherwise honors NO_PROXY even with an explicit proxy handler.
        os.environ["NO_PROXY"] = os.environ["no_proxy"] = ""
        with Bridge(("127.0.0.1", args.port), key, token, proxy) as server:
            print(f"1min.ai adapter listening at http://127.0.0.1:{args.port}/v1", flush=True)
            try:
                server.serve_forever()
            except KeyboardInterrupt:
                pass
    except (PipelineError, OSError, ValueError) as exc:
        print("Error: " + (str(exc) if isinstance(exc, PipelineError) else type(exc).__name__), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())

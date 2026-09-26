# CodeCraft API account pipeline

Register once, retain the generated site password and one-time API key, and start an OpenAI-compatible agent. Python 3.10+; no third-party dependencies.

```sh
export GMAILLOG='your-email@gmail.com'    # Gmail address
export APPASS='...'                        # Gmail app password, used only if verification is requested
export PROXY='http://user:password@host:port'
python3 codecraft.py ensure --name 'Your name'
python3 codecraft.py status
python3 codecraft.py login                # fresh session using saved credentials
python3 codecraft.py run -- your-agent-command
```

Use your own environment or secrets manager for these variables; do not commit them. `PROXY` is mandatory for all website requests and Gmail IMAP (HTTP CONNECT). `run` passes the proxy to the agent as `HTTP_PROXY`/`HTTPS_PROXY`/`ALL_PROXY`, along with `OPENAI_API_KEY`, `OPENAI_BASE_URL=https://codecraftapi.com/v1`, `CODECRAFT_API_KEY`, and `CODECRAFT_BASE_URL`, but does not forward the Gmail app password or CAPTCHA key. **The agent must honor proxy environment variables** for its own network traffic; arbitrary subprocess traffic cannot be forced through the proxy by environment variables alone. Use `CODECRAFT_NAME` instead of `--name` if preferred.

The generated password is written **before registration** and the API key **immediately when issued** to `.secrets/codecraft.json` (directory mode 0700, file mode 0600). This path is ignored by Git; override it with `CODECRAFT_CREDENTIALS_FILE` pointing to a private directory. The key is never printed by the CLI. An interrupted registration can be resumed with `ensure`; a possibly successful key creation is never repeated automatically. If email confirmation is required, the CLI checks Gmail for a six-digit code or signed link (Inbox, All Mail, Spam, Trash) every 30 seconds, waits up to **3 hours**, requests a resend if necessary (at most once per hour), and resumes when mail arrives. Configure the wait with `CODECRAFT_VERIFY_TIMEOUT` in seconds (0–86400, e.g. `14400` for 4 hours). If a CAPTCHA or other new confirmation step appears, the CLI stops rather than sending credentials elsewhere or bypassing the proxy.

Run the offline tests with `python3 -m unittest discover -s tests -v`.

## CodeCraft through Google OAuth (separate account)

If the email-confirmation route above cannot finish, use CodeCraft's **Sign up with Google** with a separate Google Workspace account and `NEWPROXY`. The original `.secrets/codecraft.json` account is untouched. Set credentials in a secret manager or environment; do not pass them as CLI arguments or commit them:

```sh
export NEWPROXY='http://user:********@host:port'
export CODECRAFT_GOOGLE_EMAIL='your-google-account@example.com'
export CODECRAFT_GOOGLE_PASSWORD='...'
python3 -m pip install -r requirements-oauth.txt
python3 -m playwright install firefox
python3 codecraft_google.py login               # --accept-workspace-notice only if authorized
python3 codecraft_google.py ensure              # create at most one key
python3 codecraft_google.py verify              # GET /v1/models using the new key
python3 codecraft_google.py status
python3 codecraft_google.py run -- your-agent-command
```

The browser sends Google credentials only to `accounts.google.com` after verifying CodeCraft's OAuth request contains **only** `openid`, `email`, and `profile`. It stores only CodeCraft cookies and storage in `.secrets/codecraft-google-session.json`; the account email and one-time key live in `.secrets/codecraft-google.json` (private permissions). Google cookies and the password are not saved. `CODECRAFT_GOOGLE_CREDENTIALS_FILE` overrides the **key file path**, with the session beside it. If a key already exists or creation might have succeeded but its one-time value was not captured, `ensure` stops instead of making another. This key uses CodeCraft's default `inference`, `models:read`, and `embeddings` scopes. `run` supplies the OpenAI-compatible `/v1` URL and key plus standard proxy variables, not Google/Gmail secrets; the agent must honor those variables itself. The `verify` client sends a browser-like User-Agent because this API returned HTTP 403 to Python urllib's default User-Agent.

## 1min.ai: Google login and external chat API

The app accepts Google OAuth and also offers email/password. **Do not put Google credentials in source code or CLI arguments.** To sign in or renew an expired session:

```sh
export PROXY='http://user:password@host:port'  # same proxy as CodeCraft
export ONEMIN_EMAIL='your-google-account@example.com'
export ONEMIN_PASSWORD='...'                 # Google password, only for OAuth
test -x .venv/bin/python || uv venv --python python3 .venv  # managed workspace setup already creates it
uv pip install --python .venv/bin/python -r requirements-oauth.txt
.venv/bin/python -m playwright install firefox
.venv/bin/python onemin.py login --accept-workspace-notice  # only if authorized to acknowledge a managed account notice
.venv/bin/python onemin.py ensure         # recovers the existing key or creates one
python3 onemin.py status
printf 'Reply exactly OK.\n' | python3 onemin.py chat --model us.anthropic.claude-opus-5
python3 onemin.py run -- your-agent-command
```

OAuth needs a browser only for sign-in/key creation; `chat`, `status`, and `run` with an existing key use the Python standard library. The client always uses `PROXY` for OAuth and API calls; `run` gives the agent `ONEMIN_API_KEY`, `ONEMIN_API_BASE_URL=https://api.1min.ai`, and proxy variables, **not** Google/Gmail passwords. The agent must honor proxy variables itself. The API is **not OpenAI-compatible**: send `POST https://api.1min.ai/api/chat-with-ai` with `API-KEY: <key>` and JSON `{"type":"UNIFY_CHAT_WITH_AI","model":"us.anthropic.claude-opus-5","promptObject":{"prompt":"..."}}`. Requests use account credits; `chat` prints the JSON response to stdout. The first-party OAuth session (including local storage/IndexedDB) and key are saved under `.secrets/onemin-session.json` and `.secrets/onemin.json` with private permissions; Google cookies and the Google password are **not** saved. A potentially successful key creation is never repeated automatically.

`ONEMIN_CREDENTIALS_FILE` overrides the **key file path**; the session file is saved beside it. Google OAuth proceeds only when its authorization request asks for exactly `openid`, `email`, and `profile`; it stops before entering credentials if it cannot verify those scopes.

Verified via this account: Google OAuth login, one API key created and recovered, and one remote Claude Opus 5 request returned HTTP 200 with an `aiRecord`. The app's chat client points at `POST /teams/{teamId}/features/v2/unified-chat?isStreaming=true` using its own bearer session; use the [documented external Chat API](https://docs.1min.ai/docs/api/chat-with-ai-api) with your key instead. The model identifier appeared as active in the app's model catalog, although the official API docs do not list Claude models. Key creation is described in the [official guide](https://docs.1min.ai/docs/api/create-api-key).

### 1min.ai AI Agent survey and daily visit

The [AI Agent early-access form](https://app.1min.ai/ai-agent-demo) offers **1,000,000 credits for a free-plan team**, not one million model tokens. Requests require admin approval: submitting does **not** instantly award credits. The site allows one survey submission per user and one reward per team; rejected submissions can be corrected on the site. Answer all five questions honestly. The CLI previews every answer and its built-in English task description without submitting anything; review them and, if needed, pass `--task-file` with a `0600` UTF-8 file inside a private `0700` directory.

```sh
export PROXY='http://user:********@host:port'
# On a new machine, install the Python dependencies and browser as shown above first.
.venv/bin/python onemin_rewards.py survey --role 'Software Engineer / Developer' \
  --industry 'Other' --organization 'Other' \
  --use-case 'Software Development & Coding' --frequency 'Daily'  # preview only; choose truthful categories
# Review all five answers and the task, then repeat the command with --submit to send it once.
.venv/bin/python onemin_rewards.py status   # offline; no password, key, or task body displayed
```

To register an authenticated visit under the [daily 15,000-credit offer](https://app.1min.ai/free-credits), run `.venv/bin/python onemin_rewards.py daily` once per day. The command reuses your existing first-party browser session and existing Google login pipeline if a fresh sign-in is necessary; it does not create keys or save Google credentials. It records a private idempotency marker at `.secrets/onemin-rewards.json` (mode `0600`), and does not retry an ambiguous visit or survey submission automatically. It verifies that the web app and authenticated credits summary loaded, **not** that today's 15,000 credits have already posted. Check the site's balance if you need proof of the award.

For automatic daily visits on an always-running machine, launch `.venv/bin/python onemin_rewards.py watch` under your process supervisor alongside the ZCode adapter. It tries once after **08:15 UTC**, i.e. 00:15 fixed PST or 01:15 during Pacific daylight time; this is safely after the site's stated 12 AM PST reset. The watcher must stay running, with `PROXY` configured in its **private** environment. After an error it does not retry that day: inspect the balance and local `status` before deciding what to do. This thread's sandbox has no persistent cron or user systemd scheduler, so no unattended visits are installed here. If the OAuth session expires, refresh it interactively with `.venv/bin/python onemin.py login` or provide approved credentials via your own secret manager; never place a Google password in ZCode, cron arguments, source files, or agent prompts. Login and survey activity remain subject to [1min.ai's terms](https://1min.ai/terms).

### ZCode: local OpenAI-compatible adapter

On the **same machine as ZCode**, with this repository and your private `.secrets/onemin.json` present, run:

```sh
export PROXY='http://user:password@proxy-host:port'  # your existing 1min.ai proxy
python3 onemin_adapter.py serve                        # stays running; binds only to 127.0.0.1
```

In ZCode, go to **Manage Models → Model Settings → Add Provider**, select **OpenAI protocol** (not Anthropic) and enter:

| ZCode setting | Value |
| --- | --- |
| OpenAI Base URL | `http://127.0.0.1:8765/v1` |
| API Key | Output of `python3 onemin_adapter.py token`, run **locally** on the same machine (do not paste it in chat) |
| Add Model / Model ID | `us.anthropic.claude-opus-5` |

Enable the provider and select the model. ZCode must reach loopback directly; if ZCode has its own HTTP proxy configured, exclude `127.0.0.1` or disable its proxy for this connection. The adapter itself **requires `PROXY`** for every outbound 1min.ai request. Never expose its loopback port to the internet or put the real 1min.ai key into ZCode: the adapter uses a separate local-only token saved at `.secrets/onemin-adapter-token` with mode `0600`. No OAuth cookies or Google password are shared with ZCode. `GET /v1/models` and `POST /v1/chat/completions` support text, multiple turns via serialized prompt context, and SSE streaming. Unrecognized models, attachments, and image/file inputs fail explicitly instead of being silently discarded. Requests use your 1min.ai credits. This repository uses POSIX `fcntl`: on Windows run the adapter in WSL and confirm that ZCode can reach its loopback port.

**Agent limitation:** [1min.ai documents no native function/tool calling](https://docs.1min.ai/docs/api/chat-with-ai-api). For ZCode tool calls, the adapter asks Claude for structured JSON and translates it into OpenAI-format tool calls; this is **best effort**, not equivalent to native tools. It never executes tools itself. Complex coding tasks, large contexts, strict schemas, and ZCode's full agent loop may fail; test with a non-critical project first. Streaming tool calls are buffered until the upstream response is complete. The local adapter has been verified with HTTP tests, but the desktop ZCode application itself has not been tested in this workspace. If the app runs on another machine, `127.0.0.1` in ZCode does **not** point to this workspace; run the bridge and keep its secret files on the IDE machine instead.

## Workbuddy: account restricted; offline status only

The account holder authorized acknowledgment of Workbuddy's [service](https://www.workbuddy.ai/document/term), [data-processing](https://www.workbuddy.ai/document/dpsa), [privacy](https://www.workbuddy.ai/document/privacy-policy), and [acceptable-use](https://www.workbuddy.ai/document/acceptable-use-policy) documents. During the Google signup through `NEWPROXY`, the Google authorization request contained only `openid`, `email`, and `profile`. On return, Workbuddy displayed **Account Access Restricted** at `/auth/realms/copilot/login-actions/first-broker-login`: the account is temporarily unavailable due to security policy restrictions. The authenticated workspace did not open, so **no agent prompt was sent and no Workbuddy API key was available to save**.

Workbuddy's [Acceptable Use Policy §3.5](https://www.workbuddy.ai/document/acceptable-use-policy) disallows automated bots, scrapers, or crawlers accessing the service unless expressly authorized by its API terms. Accordingly, this repository does **not** automate further Workbuddy login, agent requests, or undocumented API access. Contact Workbuddy support about the account restriction and obtain express API authorization before attempting an integration. The public [FAQ](https://www.workbuddy.ai/docs/workbuddy/From-Beginner-to-Expert-Guide/FAQ) mentions API keys for third-party skills, not a confirmed external Workbuddy agent API.

The first-party Workbuddy cookie/storage snapshot is saved in `.secrets/workbuddy-session.json`, and the restricted account status in `.secrets/workbuddy.json`, both mode `0600` and ignored by Git. Google cookies and password were not saved. `python3 workbuddy.py status` checks the locally saved state and file permissions **without connecting to Workbuddy**. `WORKBUDDY_CREDENTIALS_FILE` can override the offline metadata path; the session file is beside it.

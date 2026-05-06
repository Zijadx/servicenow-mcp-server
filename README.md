# Automatiki — ServiceNow MCP Connector

A production-ready **Model Context Protocol (MCP) server** for ServiceNow, plus a sleek **chat UI** that lets you talk to your instance in natural language. Built in Python — no Node.js, no build step, no JavaScript framework required.

The repo ships three components:

| Component | File | Purpose |
|---|---|---|
| MCP Server | `server.py` | Exposes ServiceNow as MCP tools (incidents, users, records, queries) over stdio or streamable HTTP |
| Chat UI | `ui_server.py` | FastAPI web app with a dark chat interface and ServiceNow-validated login |
| Security Analyst Agent | `security_analyst.py` | Optional Claude-powered Tier-2 SOC investigator (see `RELEASE_NOTES.md`) |

---

## Quick start

### 1. Install

```bash
git clone https://github.com/Zijadx/servicenow-mcp-server.git
cd servicenow-mcp-server
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
```

### 2. Configure

```bash
cp .env.example .env
# then edit .env and fill in:
#   SN_INSTANCE, SN_USER, SN_PASS  (the service-account creds the server uses)
#   MCP_AUTH_TOKEN                 (any random token — generate below)
#   SESSION_SECRET                 (any random secret — generate below)
python -c "import secrets; print(secrets.token_urlsafe(32))"
```

### 3. Run

**MCP Server** (for Claude Desktop, IDEs, or any MCP client):
```bash
# stdio transport (default — for local MCP clients)
python server.py

# streamable HTTP transport (for remote clients)
MCP_TRANSPORT=streamable-http python server.py
```

**Chat UI** (browser):
```bash
python ui_server.py
# then open http://localhost:3000
```

---

## Chat UI

The chat UI lets a human talk to ServiceNow in natural language. It's a single-page app served by a FastAPI backend — vanilla HTML/CSS/JS on the frontend, no build step.

### Features

- **Dark, modern chat interface** (Claude.ai / ChatGPT styling)
- **Sticky input bar**, message bubbles (user right / assistant left), typing indicator
- **Mobile-responsive**
- **Deterministic intent routing** — keyword/pattern-matched, no LLM required for routing reliability
- **Markdown-style rendering** (bold, lists, code) in assistant messages
- **Status indicator** in the header (green when authenticated)
- **Logout button** in the header

### Supported intents

| Try saying… | Calls |
|---|---|
| "show me open P1 incidents", "active incidents" | `list_incidents` (filtered) |
| "who is john.doe", "look up user alice@example.com" | `get_user` |
| "what fields does the incident table have", "schema for cmdb_ci_server" | `get_table_schema` |
| "health check", "ping", "are we connected?" | `health_check` |
| "update INC0010001 add work note ..." | `update_incident` |

If no intent matches, the assistant returns a help message listing what it can do.

---

## Authentication model

There are **two independent auth layers**:

### 1. ServiceNow service account (server-side, in `.env`)
`SN_USER` / `SN_PASS` are the credentials the *server* uses to talk to ServiceNow. Every API call the chat UI makes on a user's behalf goes through this account. These are stored only in `.env` and are never exposed to the browser.

### 2. Per-user login (chat UI session)
When a user opens the chat UI they're redirected to `/login`. They enter their *own* ServiceNow username and password. The UI server makes a **Basic Auth probe** to `GET /api/now/table/sys_user?sysparm_limit=1` against your instance:

- **HTTP 200** → credentials are valid → server-side session created (`express-session`-equivalent via Starlette `SessionMiddleware`); user is redirected to the chat
- **HTTP 401/403** → invalid credentials → inline error on login page
- **Network/DNS error** → "Cannot reach ServiceNow instance" error

The user's password is **never persisted** — it's used once to verify access, then discarded. Only `session.authenticated = true` and `session.sn_user = <username>` are stored in the signed session cookie.

### Session config
- 4-hour session lifetime (demo-friendly)
- HTTP-only cookie
- `secure=True` automatically when `UI_BEHIND_HTTPS=1` is set in `.env`

---

## MCP Server tools

`server.py` exposes the following tools to MCP clients:

**Incidents**: `get_incident`, `list_incidents`, `create_incident`, `update_incident`, `get_similar_incidents`
**Records (any table)**: `get_record`, `list_records`, `create_record`, `update_record`, `delete_record`
**Users**: `get_user`, `list_users`
**Utilities**: `health_check`, `run_query`, `get_table_schema`

See `TECHNICAL_SPECS.md` for full parameter details.

The streamable-HTTP transport requires `MCP_AUTH_TOKEN` to be set — clients must send `Authorization: Bearer <token>` on every request.

---

## Security

All credentials must be supplied via `.env` and are **never committed**. The repo enforces this at multiple layers:

- `.gitignore` excludes `.env`, `.env.*`, `*.env`
- `.env.example` ships with empty values — copy it to `.env` and fill in your own
- All `os.environ` references in code have a corresponding `.env.example` entry
- The Chat UI never echoes session credentials in responses or logs
- Bearer-token middleware (`_BearerAuth` in `server.py`) guards the streamable-HTTP transport
- Session cookies are signed (`SESSION_SECRET`) and HTTP-only

If you're forking this repo, **rotate every secret** before pointing it at production.

---

## Project layout

```
servicenow-mcp-server/
├── server.py              # MCP server (stdio / streamable-HTTP)
├── ui_server.py           # FastAPI Chat UI + login + session auth
├── security_analyst.py    # Claude-powered SOC investigator (v3.0.0)
├── ui/
│   ├── static/            # CSS + JS (vanilla, no build)
│   └── templates/         # Jinja2 HTML (login, chat)
├── requirements.txt
├── .env.example
├── README.md              ← you are here
├── FEATURES.md            # Detailed feature changelog
├── RELEASE_NOTES.md
└── TECHNICAL_SPECS.md
```

---

## Documentation

- **`README.md`** — this file (setup, quick start, auth model)
- **`FEATURES.md`** — complete catalog of every feature added on top of the MCP server, with rationale and how to use each
- **`RELEASE_NOTES.md`** — version history
- **`TECHNICAL_SPECS.md`** — MCP tool reference

---

## License

Internal — Automatiki LLC.

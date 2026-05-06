# Features added in this branch

This document catalogs every change introduced by the **public-repo + chat UI** initiative on branch `claude/review-code-instructions-LxVyB`. Pair this with `RELEASE_NOTES.md` (high-level versions) for a complete history.

---

## 1. Repo security hardening

### 1.1 Hardened `.gitignore`
- Added `.env.*`, `*.env`, `*.log`, `.DS_Store`, `Thumbs.db`, editor folders (`.vscode/`, `.idea/`), and Python cache dirs (`*.egg-info/`, `.pytest_cache/`)
- Existing entries (`.env`, `__pycache__/`, `*.pyc`, etc.) preserved

### 1.2 Audited & extended `.env.example`
- Added `SESSION_SECRET` (signs the chat-UI session cookie — required)
- Added `UI_PORT` (chat UI listen port — default 3000)
- Added `UI_BEHIND_HTTPS` (toggles `Secure` cookie flag for production)
- Added `MCP_TRANSPORT` (was used in code but not documented)
- Cleaned the `ANTHROPIC_API_KEY` placeholder to an empty string for consistency
- Cross-checked that **every** `os.environ` / `_require_env` reference in code now has a corresponding `.env.example` entry

### 1.3 Repo audit results
A full audit was run against:
- Hardcoded passwords/tokens/API keys → **none found** (all values come from `os.environ`)
- URLs containing embedded credentials (`https://user:pass@…`) → **none**
- AWS / Anthropic / GitHub / Slack / private-key patterns → **none**
- Tracked `.env` files → **none** (only `.env.example`, which is intentional)
- Git-history leaks → **none** (verified with `git log --all -p`)

---

## 2. Chat UI (`ui_server.py`)

A new FastAPI web app that serves a dark-mode chat interface for natural-language ServiceNow queries.

### 2.1 Stack
- **FastAPI** (chosen because `uvicorn` was already a dependency)
- **Starlette `SessionMiddleware`** for signed-cookie sessions
- **Jinja2** templates for `login.html` and `chat.html`
- **Vanilla HTML / CSS / JS** on the frontend — no build step, no React, no bundler
- **No new runtime services** — single Python process, runs alongside the existing MCP server

### 2.2 New dependencies (in `requirements.txt`)
```
fastapi>=0.110.0,<1.0.0
jinja2>=3.1.0,<4.0.0
itsdangerous>=2.1.0,<3.0.0      # required by SessionMiddleware
python-multipart>=0.0.9,<1.0.0  # required for form-data login POST
```

### 2.3 Routes
| Method | Path | Purpose |
|---|---|---|
| GET  | `/`                  | Chat page (auth-gated; redirects to `/login` if not signed in) |
| GET  | `/login`             | Login page |
| POST | `/api/auth/login`    | Validate SN credentials → set session |
| POST | `/api/auth/logout`   | Destroy session |
| POST | `/api/chat`          | Auth-gated chat endpoint (returns `{intent, reply}`) |
| GET  | `/static/*`          | CSS + JS assets |

### 2.4 Visual design (Claude.ai / ChatGPT-inspired)
- Deep navy / near-black background (`#0d0f14`) with subtle radial highlights on auth screen
- Electric blue accent (`#3b82f6`) for primary actions, focus rings, and user message bubbles
- Inter / system-ui font stack
- Sticky composer at the bottom; auto-growing textarea (max 160px)
- Subtle 180ms fade-in for new messages
- 3-dot pulsing typing indicator while waiting for a response
- Top header bar: brand mark, "Automatiki — ServiceNow Connector" title, green status dot, signed-in user pill, sign-out button
- Mobile breakpoint at 600px (hides the user pill, widens bubbles, tightens padding)

### 2.5 Frontend behavior
- **Submit on Enter**, newline on Shift+Enter
- **Auto-grow textarea**
- **Minimal markdown renderer** (vanilla JS, no library): `**bold**`, `*italic*`, `` `code` ``, ` ```fenced``` ` blocks, `- ` bullet lists, line breaks
- **HTML escaping** before any markdown is applied (XSS-safe)
- **Session expiry handling**: if `/api/chat` returns 401, the UI shows a notice and redirects to `/login` after 1.2s

### 2.6 Backend chat behavior — deterministic intent routing
Per the design brief, the routing layer is keyword/pattern-based, not LLM-driven, so demos behave identically every run.

| User says… | Routes to | ServiceNow tool used |
|---|---|---|
| "health", "ping", "status", "connected" | `_intent_health` | `GET /sys_user?sysparm_limit=1` |
| "incidents", "P1", "P2", "active", "open ticket" (with optional `unassigned`) | `_intent_list_incidents` | `GET /incident` with built-up `sysparm_query` |
| "who is …", "find user …", "look up user …" | `_intent_get_user` | `GET /sys_user` filtered by `user_name` or `email` |
| "schema", "fields", "structure" | `_intent_table_schema` | `GET /sys_dictionary?name={table}` |
| Mentions `INC……` + "update / change / set / work note" | `_intent_update_incident` | Lookup `sys_id`, then `PATCH /incident/{sys_id}` |
| Anything else | `unknown` | Returns help text listing supported intents |

All ServiceNow API calls go through the **service-account** credentials in `.env` (`SN_USER` / `SN_PASS`) — never the per-user session credentials.

### 2.7 Reply formatting
The `_format_reply()` helper turns the structured intent result into a markdown-ish string the frontend renders:
- **Health**: green-checkmark-style success or error detail
- **Incidents**: bulleted list of `**INC#####** · P{n} · {state} · {assignee}` plus short description
- **User**: name + username, email, department, manager, active status
- **Schema**: table name + first 25 fields with type and `*required*` flag, plus "…and N more" overflow
- **Update**: confirmation with the changed fields shown as `key`=`value`
- **Help / unknown**: lists every supported intent with examples

---

## 3. ServiceNow-validated login (Phase 3)

### 3.1 Login flow
1. User opens any auth-gated page → redirected to `/login`
2. Form submits to `POST /api/auth/login` with `username` + `password` form-encoded
3. Server makes an **isolated** `httpx.AsyncClient` Basic Auth probe to:
   ```
   GET {SN_INSTANCE}/api/now/table/sys_user?sysparm_limit=1
   ```
   — using a **fresh client** (not the shared service-account one) so the user's password lives only inside that single request scope
4. Response handling:
   - `200` → session created (`session.authenticated = True`, `session.sn_user = username`, fresh CSRF token), 200 JSON `{success:true}`, frontend redirects to `/`
   - `401 / 403` → 401 JSON `{success:false, error:"Invalid ServiceNow credentials"}`, inline error on login form
   - Network/DNS error → 502 JSON `{success:false, error:"Cannot reach ServiceNow instance"}`
   - Other → 502 JSON with the upstream status code

### 3.2 Session config (Starlette `SessionMiddleware`)
```python
SessionMiddleware(
    secret_key=SESSION_SECRET,        # required from .env
    max_age=60 * 60 * 4,              # 4 hours (demo-friendly)
    same_site="lax",
    https_only=UI_BEHIND_HTTPS,       # auto-flips Secure flag for production
)
```
- Cookie is signed (HMAC) and HTTP-only by default in Starlette
- `https_only` is wired to `UI_BEHIND_HTTPS` so production deployments behind TLS get the `Secure` flag without code changes

### 3.3 Logout
- Sign-out button in chat header → `POST /api/auth/logout` → `request.session.clear()` → frontend redirects to `/login`

### 3.4 What's never stored
- The user's password (only used in the one-time probe, then discarded)
- Any session-bound SN authentication tokens (the server uses its own service account for downstream calls)

---

## 4. Documentation

### 4.1 New `README.md`
Comprehensive top-of-repo doc with:
- Component overview table (MCP server / Chat UI / Security Analyst Agent)
- Quick-start (install, configure, run)
- Chat UI feature list and supported intents
- **Authentication model** section explicitly explaining the service-account vs. per-user-login split
- MCP server tool catalog
- **Security** section noting that all credentials must be in `.env` and explaining each defense layer
- Project layout
- Pointer to all other docs (FEATURES.md, RELEASE_NOTES.md, TECHNICAL_SPECS.md)

### 4.2 This file (`FEATURES.md`)
Detailed catalog of everything added on this branch, with rationale per feature.

---

## 5. What's verified to work (smoke tests)

Automated smoke tests exercised against a running `ui_server.py`:

- [x] `GET /` unauthenticated → `303 → /login`
- [x] `GET /login` → `200`, renders `loginForm`
- [x] `GET /static/styles.css` → `200`, ~8KB CSS
- [x] `POST /api/chat` unauthenticated → `401 {"error":"Unauthorized"}`
- [x] `POST /api/auth/login` against unreachable host → `502 {"error":"Cannot reach ServiceNow instance"}`
- [x] `_route()` correctly classifies all 10 representative intent samples
- [x] `_format_reply()` produces clean output for health, incidents (empty), user, schema, update
- [x] Server starts cleanly with no deprecation warnings (lifespan context manager pattern)

What still requires a live ServiceNow instance to verify end-to-end:
- [ ] Login with real SN credentials → redirect into chat
- [ ] Login with bad SN creds → inline 401 error
- [ ] At least 3 chat intents executed against a live instance (the design contract from Phase 4 of the brief)

These are listed as a manual checklist in `README.md` "Quick start" — they can't be exercised in CI without an instance.

---

## 6. Files changed / added

```
A  README.md                       (new — top-of-repo docs)
A  FEATURES.md                     (new — this file)
A  ui_server.py                    (new — FastAPI chat + auth)
A  ui/templates/login.html         (new)
A  ui/templates/chat.html          (new)
A  ui/static/styles.css            (new)
A  ui/static/login.js              (new)
A  ui/static/chat.js               (new)
M  .gitignore                      (added .env.* / *.env / logs / OS / editor)
M  .env.example                    (added SESSION_SECRET, UI_PORT, UI_BEHIND_HTTPS, MCP_TRANSPORT; cleaned ANTHROPIC_API_KEY placeholder)
M  requirements.txt                (added fastapi, jinja2, itsdangerous, python-multipart)
```

No existing Python source (`server.py`, `security_analyst.py`) was modified — the new chat UI layer is fully additive.

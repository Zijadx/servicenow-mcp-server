"""
Automatiki ServiceNow Chat UI — FastAPI app
============================================
Single-process web server that:
  1. Serves a dark-mode chat UI (vanilla HTML/CSS/JS) at GET /
  2. Gates the chat behind a per-user ServiceNow login at /login
  3. Routes natural-language queries to ServiceNow via the same client
     code patterns used by the MCP server (server.py)

Auth model — see README.md "Authentication model":
  - SN_USER / SN_PASS (in .env)        → service-account creds the server uses
                                          to call ServiceNow on the user's behalf
  - User's SN username + password      → used only at /login to validate access,
                                          never stored after the probe

Run:
    python ui_server.py
    open http://localhost:3000
"""
from __future__ import annotations

import logging
import os
import re
import secrets
from typing import Any

import httpx
from contextlib import asynccontextmanager
from dotenv import load_dotenv
from fastapi import FastAPI, Form, Request, status
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware

load_dotenv()

# ─── Logging ──────────────────────────────────────────────────────────────────

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)
logger = logging.getLogger("servicenow-ui")

# ─── Config ───────────────────────────────────────────────────────────────────

def _require_env(key: str) -> str:
    val = os.environ.get(key)
    if not val:
        raise RuntimeError(f"Required environment variable {key!r} is not set. Check your .env file.")
    return val

SN_BASE         = _require_env("SN_INSTANCE").rstrip("/")
SN_USER         = _require_env("SN_USER")
SN_PASS         = _require_env("SN_PASS")
SESSION_SECRET  = _require_env("SESSION_SECRET")
UI_PORT         = int(os.environ.get("UI_PORT", "3000"))
UI_BEHIND_HTTPS = os.environ.get("UI_BEHIND_HTTPS", "0") == "1"

SESSION_MAX_AGE = 60 * 60 * 4   # 4 hours

# ─── Shared HTTP client (service-account creds) ───────────────────────────────

_client: httpx.AsyncClient | None = None


@asynccontextmanager
async def _lifespan(app: FastAPI):
    global _client
    logger.info("Starting Chat UI — instance: %s, port: %d", SN_BASE, UI_PORT)
    _client = httpx.AsyncClient(
        auth=(SN_USER, SN_PASS),
        headers={"Accept": "application/json", "Content-Type": "application/json"},
        timeout=30.0,
    )
    try:
        yield
    finally:
        await _client.aclose()


# ─── App + middleware ─────────────────────────────────────────────────────────

app = FastAPI(title="Automatiki ServiceNow Chat UI", lifespan=_lifespan)

app.add_middleware(
    SessionMiddleware,
    secret_key=SESSION_SECRET,
    max_age=SESSION_MAX_AGE,
    same_site="lax",
    https_only=UI_BEHIND_HTTPS,
)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
app.mount("/static", StaticFiles(directory=os.path.join(BASE_DIR, "ui", "static")), name="static")
templates = Jinja2Templates(directory=os.path.join(BASE_DIR, "ui", "templates"))

# ─── Auth helpers ─────────────────────────────────────────────────────────────

def _is_authed(request: Request) -> bool:
    return bool(request.session.get("authenticated"))

# ─── Login routes ─────────────────────────────────────────────────────────────

@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    if _is_authed(request):
        return RedirectResponse("/", status_code=status.HTTP_303_SEE_OTHER)
    return templates.TemplateResponse(request=request, name="login.html", context={"error": None})


@app.post("/api/auth/login")
async def login_submit(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
):
    """
    Validate the supplied SN credentials against the live instance with a
    Basic Auth probe. Never persist the password — only the success flag.
    """
    if not username or not password:
        return JSONResponse({"success": False, "error": "Username and password required"}, status_code=400)

    probe_url = f"{SN_BASE}/api/now/table/sys_user"
    try:
        async with httpx.AsyncClient(timeout=15.0) as probe:
            r = await probe.get(
                probe_url,
                params={"sysparm_limit": 1},
                auth=(username, password),
                headers={"Accept": "application/json"},
            )
    except httpx.RequestError as e:
        logger.warning("Login probe network error: %s", e)
        return JSONResponse(
            {"success": False, "error": "Cannot reach ServiceNow instance"},
            status_code=502,
        )

    if r.status_code == 200:
        request.session.clear()
        request.session["authenticated"] = True
        request.session["sn_user"] = username
        request.session["csrf"] = secrets.token_urlsafe(16)
        logger.info("Login success: user=%s", username)
        return JSONResponse({"success": True})

    if r.status_code in (401, 403):
        logger.info("Login rejected by SN: user=%s status=%d", username, r.status_code)
        return JSONResponse(
            {"success": False, "error": "Invalid ServiceNow credentials"},
            status_code=401,
        )

    logger.warning("Login probe unexpected status %d", r.status_code)
    return JSONResponse(
        {"success": False, "error": f"Unexpected response from ServiceNow ({r.status_code})"},
        status_code=502,
    )


@app.post("/api/auth/logout")
async def logout(request: Request):
    request.session.clear()
    return JSONResponse({"success": True})

# ─── Chat page ────────────────────────────────────────────────────────────────

@app.get("/", response_class=HTMLResponse)
async def chat_page(request: Request):
    if not _is_authed(request):
        return RedirectResponse("/login", status_code=status.HTTP_303_SEE_OTHER)
    return templates.TemplateResponse(
        request=request,
        name="chat.html",
        context={"sn_user": request.session.get("sn_user", "")},
    )

# ─── ServiceNow client wrappers (service-account credentials) ─────────────────

def _table(table: str) -> str:
    return f"/api/now/table/{table}"

async def _sn_get(path: str, params: dict | None = None) -> dict:
    try:
        r = await _client.get(f"{SN_BASE}{path}", params=params)
        r.raise_for_status()
        return r.json()
    except httpx.HTTPStatusError as e:
        return {"error": f"HTTP {e.response.status_code}: {e.response.text[:300]}"}
    except Exception as e:
        return {"error": str(e)}

async def _sn_patch(path: str, body: dict) -> dict:
    try:
        r = await _client.patch(f"{SN_BASE}{path}", json=body)
        r.raise_for_status()
        return r.json()
    except httpx.HTTPStatusError as e:
        return {"error": f"HTTP {e.response.status_code}: {e.response.text[:300]}"}
    except Exception as e:
        return {"error": str(e)}

# ─── Intent routing ───────────────────────────────────────────────────────────
#
# Deterministic keyword/pattern matching — no LLM in the routing layer so the
# demo behaves the same every time.

_INC_NUMBER_RE = re.compile(r"\b(INC\d{6,})\b", re.IGNORECASE)
_TABLE_NAME_RE = re.compile(r"\b([a-z][a-z0-9_]{2,40})\b")

def _priority_filter(message: str) -> str | None:
    m = re.search(r"\bp([1-4])\b", message, re.IGNORECASE)
    if m:
        return m.group(1)
    if "critical" in message:
        return "1"
    if "high priority" in message:
        return "2"
    return None


async def _intent_health(_: str) -> dict:
    data = await _sn_get(_table("sys_user"), {"sysparm_limit": 1})
    if "error" in data:
        return {"kind": "health", "ok": False, "instance": SN_BASE, "detail": data["error"]}
    return {"kind": "health", "ok": True, "instance": SN_BASE}


async def _intent_list_incidents(message: str) -> dict:
    parts = ["active=true"]
    pri = _priority_filter(message)
    if pri:
        parts.append(f"priority={pri}")
    if "unassigned" in message:
        parts.append("assigned_to=NULL")
    query = "^".join(parts)
    data = await _sn_get(_table("incident"), {
        "sysparm_query":         query,
        "sysparm_fields":        "number,short_description,state,priority,assigned_to,opened_at",
        "sysparm_limit":         10,
        "sysparm_display_value": "true",
    })
    return {"kind": "incidents", "query": query, "data": data}


async def _intent_get_user(message: str) -> dict:
    candidates = re.findall(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}", message)
    if not candidates:
        candidates = re.findall(r"\b([a-zA-Z][a-zA-Z0-9._\-]{2,})\b", message)
        stop = {"who", "is", "the", "user", "find", "look", "up", "show", "me", "what", "about"}
        candidates = [c for c in candidates if c.lower() not in stop]
    if not candidates:
        return {"kind": "help", "reason": "Could not extract a username or email from your message."}
    target = candidates[-1]
    query = f"user_name={target}^ORemail={target}"
    data = await _sn_get(_table("sys_user"), {
        "sysparm_query":         query,
        "sysparm_fields":        "user_name,name,email,department,manager,active",
        "sysparm_display_value": "true",
        "sysparm_limit":         1,
    })
    return {"kind": "user", "target": target, "data": data}


async def _intent_table_schema(message: str) -> dict:
    after = re.search(r"(?:fields|schema|structure)\s+(?:for|of|on)\s+([a-z][a-z0-9_]*)", message, re.IGNORECASE)
    table = after.group(1) if after else None
    if not table:
        words = re.findall(r"\b([a-z][a-z0-9_]{2,40})\b", message)
        skip = {"what", "fields", "does", "the", "table", "have", "schema", "for", "structure",
                "show", "me", "of", "tell", "give", "list"}
        candidates = [w for w in words if w not in skip]
        table = candidates[-1] if candidates else None
    if not table or not re.match(r"^[a-z][a-z0-9_]*$", table):
        return {"kind": "help", "reason": "I couldn't tell which table you meant. Try: 'schema for incident'."}
    data = await _sn_get("/api/now/table/sys_dictionary", {
        "sysparm_query":  f"name={table}",
        "sysparm_fields": "element,internal_type,mandatory,default_value,max_length",
        "sysparm_limit":  100,
    })
    return {"kind": "schema", "table": table, "data": data}


async def _intent_update_incident(message: str) -> dict:
    m = _INC_NUMBER_RE.search(message)
    if not m:
        return {"kind": "help", "reason": "To update an incident, include its number (e.g. INC0010001) and what you want to change."}
    number = m.group(1).upper()
    look = await _sn_get(_table("incident"), {
        "sysparm_query":  f"number={number}",
        "sysparm_fields": "sys_id",
        "sysparm_limit":  1,
    })
    rec = (look.get("result") or [None])[0]
    if not rec:
        return {"kind": "update", "ok": False, "number": number, "detail": f"Incident {number} not found"}

    body: dict[str, Any] = {}
    note_match = re.search(r"work[\s_-]?note[s]?[:\s]+(.+)$", message, re.IGNORECASE)
    if note_match:
        body["work_notes"] = note_match.group(1).strip()
    state_match = re.search(r"\bstate[:\s=]+([1-7])\b", message, re.IGNORECASE)
    if state_match:
        body["state"] = state_match.group(1)
    pri_match = re.search(r"\bpriority[:\s=]+([1-4])\b", message, re.IGNORECASE)
    if pri_match:
        body["priority"] = pri_match.group(1)

    if not body:
        return {"kind": "help", "reason": f"Found {number}. Tell me what to change — e.g. 'work notes: Investigating now', 'state: 2', 'priority: 1'."}

    result = await _sn_patch(f"{_table('incident')}/{rec['sys_id']}", body)
    return {"kind": "update", "ok": "error" not in result, "number": number, "changes": body, "data": result}


def _route(message: str) -> str:
    """Return the intent name. Order matters — most specific first."""
    m = message.lower()
    if any(k in m for k in ("health", "ping", "status", "connected")):
        return "health"
    if _INC_NUMBER_RE.search(message) or any(k in m for k in ("update", "change", "set field", "set state", "work note")):
        if _INC_NUMBER_RE.search(message):
            return "update_incident"
    if any(k in m for k in ("schema", "fields", "structure")):
        return "schema"
    if any(k in m for k in ("incident", "p1", "p2", "p3", "p4", "active", "open ticket")):
        return "incidents"
    if any(k in m for k in ("who is", "find user", "look up user", "lookup user", "show user")):
        return "user"
    return "unknown"


_HELP_TEXT = (
    "I can help you with **ServiceNow** through these intents:\n\n"
    "- **health** — verify the connection (try: `ping` or `health check`)\n"
    "- **incidents** — list active incidents (try: `show me open P1 incidents`)\n"
    "- **users** — look someone up (try: `who is john.doe` or `look up user alice@example.com`)\n"
    "- **schema** — inspect a table (try: `what fields does the incident table have`)\n"
    "- **update** — change an incident (try: `update INC0010001 work notes: Investigating now`)\n"
)

# ─── Chat endpoint ────────────────────────────────────────────────────────────

@app.post("/api/chat")
async def chat(request: Request):
    if not _is_authed(request):
        return JSONResponse({"error": "Unauthorized"}, status_code=401)

    payload = await request.json()
    message = (payload.get("message") or "").strip()
    if not message:
        return JSONResponse({"error": "Empty message"}, status_code=400)

    intent = _route(message)
    logger.info("chat intent=%s user=%s", intent, request.session.get("sn_user"))

    if intent == "health":
        result = await _intent_health(message)
    elif intent == "incidents":
        result = await _intent_list_incidents(message)
    elif intent == "user":
        result = await _intent_get_user(message)
    elif intent == "schema":
        result = await _intent_table_schema(message)
    elif intent == "update_incident":
        result = await _intent_update_incident(message)
    else:
        return JSONResponse({"intent": "unknown", "reply": _HELP_TEXT})

    return JSONResponse({"intent": intent, "reply": _format_reply(result)})


# ─── Reply formatting (plain markdown-ish text the frontend renders) ──────────

def _format_reply(r: dict) -> str:
    kind = r.get("kind")

    if kind == "help":
        return r.get("reason", _HELP_TEXT) + "\n\n" + _HELP_TEXT

    if kind == "health":
        if r["ok"]:
            return f"**Connected.** Instance `{r['instance']}` is reachable and credentials are valid."
        return f"**Connection failed.** {r.get('detail', 'unknown error')}"

    if kind == "incidents":
        data = r["data"]
        if "error" in data:
            return f"**Query failed.** {data['error']}"
        rows = data.get("result", [])
        if not rows:
            return f"No incidents matched `{r['query']}`."
        lines = [f"Found **{len(rows)}** incident(s) for `{r['query']}`:\n"]
        for row in rows:
            number = row.get("number", "")
            short = row.get("short_description", "")
            pri = row.get("priority", "")
            state = row.get("state", "")
            assigned = (row.get("assigned_to") or {}).get("display_value", "—") if isinstance(row.get("assigned_to"), dict) else (row.get("assigned_to") or "—")
            lines.append(f"- **{number}** · P{pri} · {state} · {assigned}\n  {short}")
        return "\n".join(lines)

    if kind == "user":
        data = r["data"]
        if "error" in data:
            return f"**Lookup failed.** {data['error']}"
        rows = data.get("result", [])
        if not rows:
            return f"No user matching `{r['target']}`."
        u = rows[0]
        active = "active" if str(u.get("active", "")).lower() in ("true", "1") else "inactive"
        return (
            f"**{u.get('name', '')}** (`{u.get('user_name', '')}`)\n"
            f"- Email: {u.get('email', '—')}\n"
            f"- Department: {u.get('department', '—') if not isinstance(u.get('department'), dict) else u['department'].get('display_value', '—')}\n"
            f"- Manager: {u.get('manager', '—') if not isinstance(u.get('manager'), dict) else u['manager'].get('display_value', '—')}\n"
            f"- Status: {active}"
        )

    if kind == "schema":
        data = r["data"]
        if "error" in data:
            return f"**Schema fetch failed.** {data['error']}"
        rows = data.get("result", [])
        if not rows:
            return f"No fields found for table `{r['table']}` (does it exist?)."
        lines = [f"Schema for **`{r['table']}`** ({len(rows)} fields):\n"]
        for row in rows[:25]:
            mand = " *required*" if str(row.get("mandatory", "")).lower() in ("true", "1") else ""
            lines.append(f"- `{row.get('element', '')}` — {row.get('internal_type', '')}{mand}")
        if len(rows) > 25:
            lines.append(f"\n…and {len(rows) - 25} more.")
        return "\n".join(lines)

    if kind == "update":
        if not r["ok"]:
            return f"**Update failed.** {r.get('detail') or r.get('data', {}).get('error', 'unknown error')}"
        changes = ", ".join(f"`{k}`={v!r}" for k, v in r["changes"].items())
        return f"**Updated {r['number']}.** Changes: {changes}"

    return _HELP_TEXT


# ─── Entry point ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("ui_server:app", host="0.0.0.0", port=UI_PORT, reload=False)

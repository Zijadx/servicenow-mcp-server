"""
ServiceNow MCP Server — Production Ready
Automatiki / Eli — v2.1.0

Tools covered:
  Incidents  : get_incident, list_incidents, create_incident, update_incident,
               get_similar_incidents
  Records    : get_record, list_records, create_record, update_record, delete_record
  Users      : get_user, list_users
  Utilities  : health_check, run_query, get_table_schema
"""

import logging
import os
import re
from contextlib import asynccontextmanager
from typing import Any

import httpx
from dotenv import load_dotenv
from mcp.server.fastmcp import FastMCP
from mcp.server.transport_security import TransportSecuritySettings

load_dotenv()

# ─── Logging ──────────────────────────────────────────────────────────────────

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)
logger = logging.getLogger("servicenow-mcp")

# ─── Config ───────────────────────────────────────────────────────────────────

def _require_env(key: str) -> str:
    val = os.environ.get(key)
    if not val:
        raise RuntimeError(f"Required environment variable {key!r} is not set. Check your .env file.")
    return val

SN_BASE        = _require_env("SN_INSTANCE")
SN_USER        = _require_env("SN_USER")
SN_PASS        = _require_env("SN_PASS")
MCP_AUTH_TOKEN = os.environ.get("MCP_AUTH_TOKEN")  # Required in production — set this
PORT = int(os.environ.get("PORT", os.environ.get("MCP_PORT", "8000")))

if not MCP_AUTH_TOKEN:
    logger.warning("MCP_AUTH_TOKEN is not set — server is unauthenticated. Set this in production.")

HEADERS = {
    "Accept":       "application/json",
    "Content-Type": "application/json",
}

# ─── Input validation ─────────────────────────────────────────────────────────

_TABLE_RE  = re.compile(r"^[a-z][a-z0-9_]*$")
_SYS_ID_RE = re.compile(r"^[0-9a-f]{32}$")

def _validate_table(name: str) -> str:
    if not _TABLE_RE.match(name):
        raise ValueError(f"Invalid table name: {name!r} — must be lowercase alphanumeric with underscores")
    return name

def _validate_sys_id(sys_id: str) -> str:
    if not _SYS_ID_RE.match(sys_id):
        raise ValueError(f"Invalid sys_id: {sys_id!r} — must be a 32-character lowercase hex string")
    return sys_id

# ─── Shared HTTP client (connection pooling via lifespan) ─────────────────────

_client: httpx.AsyncClient | None = None

@asynccontextmanager
async def lifespan(app):
    global _client
    logger.info("Starting ServiceNow MCP server — instance: %s", SN_BASE)
    _client = httpx.AsyncClient(
        auth=(SN_USER, SN_PASS),
        headers=HEADERS,
        timeout=30.0,
    )
    yield
    await _client.aclose()
    logger.info("ServiceNow MCP server stopped")

# ─── Server init ─────────────────────────────────────────────────────────────

# DNS-rebinding protection in FastMCP defaults to allowing only localhost. When
# deployed behind a proxy (Railway, etc.) the Host header is the public domain
# and gets rejected with HTTP 421 "Invalid Host header". Honor an optional
# MCP_ALLOWED_HOSTS env var ("host1,host2") and otherwise disable the check.
_allowed_hosts = [h.strip() for h in os.environ.get("MCP_ALLOWED_HOSTS", "").split(",") if h.strip()]
_transport_security = TransportSecuritySettings(
    enable_dns_rebinding_protection=bool(_allowed_hosts),
    allowed_hosts=_allowed_hosts or ["*"],
    allowed_origins=["*"],
)

mcp = FastMCP("servicenow", lifespan=lifespan, transport_security=_transport_security)

# ─── Health check endpoint (unauthenticated) ──────────────────────────────────
from starlette.routing import Route
from starlette.responses import JSONResponse, PlainTextResponse

async def health(request):
    return JSONResponse({"status": "ok"})

async def root(request):
    return PlainTextResponse("ServiceNow MCP server. POST /mcp for MCP traffic.")

# Paths exempted from Bearer auth (probes, health checks, root landing)
_AUTH_EXEMPT_PATHS = {"/health", "/healthz", "/"}

# ─── ASGI Bearer-token auth middleware ────────────────────────────────────────

class _BearerAuth:
    """Pure-ASGI middleware — validates Authorization: Bearer <token> on every request."""

    def __init__(self, app):
        self._app = app

    async def __call__(self, scope, receive, send):
        if (
            MCP_AUTH_TOKEN
            and scope["type"] in ("http", "websocket")
            and scope.get("path") not in _AUTH_EXEMPT_PATHS
        ):
            headers = {k.lower(): v for k, v in scope.get("headers", [])}
            auth_header = headers.get(b"authorization", b"").decode()
            if auth_header != f"Bearer {MCP_AUTH_TOKEN}":
                logger.warning(
                    "Unauthorized request — invalid or missing Bearer token "
                    "(client: %s)", scope.get("client")
                )
                if scope["type"] == "http":
                    await send({
                        "type": "http.response.start",
                        "status": 401,
                        "headers": [(b"content-type", b"text/plain; charset=utf-8")],
                    })
                    await send({
                        "type": "http.response.body",
                        "body": b"Unauthorized",
                        "more_body": False,
                    })
                return
        await self._app(scope, receive, send)

# ─── HTTP helpers ─────────────────────────────────────────────────────────────

async def _get(path: str, params: dict | None = None) -> dict | None:
    logger.info("GET %s params=%s", path, params)
    try:
        r = await _client.get(f"{SN_BASE}{path}", params=params)
        r.raise_for_status()
        return r.json()
    except httpx.HTTPStatusError as e:
        logger.error("HTTP %s on GET %s: %s", e.response.status_code, path, e.response.text[:300])
        return {"error": f"HTTP {e.response.status_code}: {e.response.text}"}
    except Exception as e:
        logger.error("Error on GET %s: %s", path, e)
        return {"error": str(e)}

async def _post(path: str, body: dict) -> dict | None:
    logger.info("POST %s", path)
    try:
        r = await _client.post(f"{SN_BASE}{path}", json=body)
        r.raise_for_status()
        return r.json()
    except httpx.HTTPStatusError as e:
        logger.error("HTTP %s on POST %s: %s", e.response.status_code, path, e.response.text[:300])
        return {"error": f"HTTP {e.response.status_code}: {e.response.text}"}
    except Exception as e:
        logger.error("Error on POST %s: %s", path, e)
        return {"error": str(e)}

async def _patch(path: str, body: dict) -> dict | None:
    logger.info("PATCH %s", path)
    try:
        r = await _client.patch(f"{SN_BASE}{path}", json=body)
        r.raise_for_status()
        return r.json()
    except httpx.HTTPStatusError as e:
        logger.error("HTTP %s on PATCH %s: %s", e.response.status_code, path, e.response.text[:300])
        return {"error": f"HTTP {e.response.status_code}: {e.response.text}"}
    except Exception as e:
        logger.error("Error on PATCH %s: %s", path, e)
        return {"error": str(e)}

async def _delete(path: str) -> dict:
    logger.info("DELETE %s", path)
    try:
        r = await _client.delete(f"{SN_BASE}{path}")
        r.raise_for_status()
        return {"success": True, "status": r.status_code}
    except httpx.HTTPStatusError as e:
        logger.error("HTTP %s on DELETE %s: %s", e.response.status_code, path, e.response.text[:300])
        return {"error": f"HTTP {e.response.status_code}: {e.response.text}"}
    except Exception as e:
        logger.error("Error on DELETE %s: %s", path, e)
        return {"error": str(e)}

def _table(table: str) -> str:
    return f"/api/now/table/{table}"

# ─── Utility ──────────────────────────────────────────────────────────────────

@mcp.tool()
async def health_check() -> dict:
    """
    Verify the MCP server is running and can reach the ServiceNow instance.
    Call this first to confirm connectivity before running other tools.
    Returns instance URL, auth status, and a sample API response.
    """
    data = await _get("/api/now/table/sys_user", params={"sysparm_limit": 1})
    if data and "error" not in data:
        return {"status": "ok", "instance": SN_BASE, "auth": "valid"}
    return {"status": "error", "instance": SN_BASE, "detail": data}


@mcp.tool()
async def get_table_schema(table_name: str) -> dict:
    """
    Get the field schema for any ServiceNow table.
    Use this before create/update calls to discover available fields and their types.

    Args:
        table_name: ServiceNow table name (e.g. 'incident', 'change_request', 'cmdb_ci_server')
    """
    _validate_table(table_name)
    data = await _get("/api/now/table/sys_dictionary", params={
        "sysparm_query":  f"name={table_name}",
        "sysparm_fields": "element,internal_type,mandatory,default_value,max_length",
        "sysparm_limit":  100,
    })
    return data or {"error": "Could not fetch schema"}


@mcp.tool()
async def run_query(
    table_name: str,
    query: str,
    fields: str = "",
    limit: int = 10,
    offset: int = 0,
) -> dict:
    """
    Run an encoded query against any ServiceNow table using the Table API.
    Useful for ad-hoc lookups and complex filtered searches.

    Args:
        table_name : ServiceNow table name (e.g. 'incident', 'change_request')
        query      : Encoded query string (e.g. 'active=true^priority=1^assigned_to=javascript:gs.getUserID()')
        fields     : Comma-separated field list. Leave blank for all fields.
        limit      : Max records to return (default 10, max 100)
        offset     : Pagination offset (default 0)
    """
    _validate_table(table_name)
    params: dict[str, Any] = {
        "sysparm_query":          query,
        "sysparm_limit":          max(1, min(limit, 100)),
        "sysparm_offset":         max(0, offset),
        "sysparm_display_value":  "true",
    }
    if fields:
        params["sysparm_fields"] = fields
    return await _get(_table(table_name), params=params) or {"error": "Query failed"}


# ─── Generic record CRUD ──────────────────────────────────────────────────────

@mcp.tool()
async def get_record(table_name: str, sys_id: str, fields: str = "") -> dict:
    """
    Get a single ServiceNow record by sys_id from any table.

    Args:
        table_name : Table name (e.g. 'incident', 'problem', 'change_request')
        sys_id     : The record's sys_id (32-char hex GUID)
        fields     : Optional comma-separated field list. Blank = all fields.
    """
    _validate_table(table_name)
    _validate_sys_id(sys_id)
    params: dict[str, Any] = {"sysparm_display_value": "true"}
    if fields:
        params["sysparm_fields"] = fields
    return await _get(f"{_table(table_name)}/{sys_id}", params=params) or {"error": "Not found"}


@mcp.tool()
async def list_records(
    table_name: str,
    query: str = "",
    fields: str = "",
    limit: int = 10,
    offset: int = 0,
) -> dict:
    """
    List records from any ServiceNow table with optional filtering.

    Args:
        table_name : Table name (e.g. 'incident', 'sc_request')
        query      : Encoded query (e.g. 'active=true^priority=1'). Blank = no filter.
        fields     : Comma-separated fields. Blank = all fields.
        limit      : Records to return (default 10, max 100)
        offset     : Pagination offset
    """
    _validate_table(table_name)
    params: dict[str, Any] = {
        "sysparm_limit":          max(1, min(limit, 100)),
        "sysparm_offset":         max(0, offset),
        "sysparm_display_value":  "true",
    }
    if query:
        params["sysparm_query"] = query
    if fields:
        params["sysparm_fields"] = fields
    return await _get(_table(table_name), params=params) or {"error": "List failed"}


@mcp.tool()
async def create_record(table_name: str, fields: dict) -> dict:
    """
    Create a new record in any ServiceNow table.
    Call get_table_schema first if unsure of required fields.

    Args:
        table_name : Table name (e.g. 'incident', 'change_request')
        fields     : Dict of field_name -> value to set on the new record.
                     Example: {"short_description": "VPN down", "priority": "1", "caller_id": "admin"}
    """
    _validate_table(table_name)
    return await _post(_table(table_name), fields) or {"error": "Create failed"}


@mcp.tool()
async def update_record(table_name: str, sys_id: str, fields: dict) -> dict:
    """
    Update an existing ServiceNow record by sys_id.

    For kb_knowledge records, automatically transitions through draft → update → published
    to satisfy ServiceNow's workflow ACL on published articles.

    Args:
        table_name : Table name (e.g. 'incident', 'kb_knowledge')
        sys_id     : The record's sys_id (32-char hex GUID)
        fields     : Dict of field_name -> new value. Only include fields to change.
                     Example: {"state": "2", "work_notes": "Investigating now"}
    """
    _validate_table(table_name)
    _validate_sys_id(sys_id)

    if table_name == "kb_knowledge":
        path = f"{_table(table_name)}/{sys_id}"
        draft = await _patch(path, {"workflow_state": "draft"})
        if draft and "error" in draft:
            return {"error": f"Could not set article to draft: {draft['error']}"}
        result = await _patch(path, fields)
        if result and "error" in result:
            return {"error": f"Could not update article: {result['error']}"}
        published = await _patch(path, {"workflow_state": "published"})
        if published and "error" in published:
            return {"error": f"Update applied but could not re-publish: {published['error']}"}
        return published or {"error": "Update failed"}

    return await _patch(f"{_table(table_name)}/{sys_id}", fields) or {"error": "Update failed"}


@mcp.tool()
async def delete_record(table_name: str, sys_id: str, confirm: bool = False) -> dict:
    """
    Delete a ServiceNow record by sys_id. This is permanent and cannot be undone.
    You MUST pass confirm=true to execute the deletion.

    Args:
        table_name : Table name
        sys_id     : The record's sys_id (32-char hex GUID)
        confirm    : Must be true to execute. Defaults to false as a safety guard.
    """
    if not confirm:
        return {
            "error": "Deletion not executed. Pass confirm=true to permanently delete this record."
        }
    _validate_table(table_name)
    _validate_sys_id(sys_id)
    return await _delete(f"{_table(table_name)}/{sys_id}")


# ─── Incidents ────────────────────────────────────────────────────────────────

@mcp.tool()
async def get_incident(number: str) -> dict:
    """
    Get a single incident by incident number (e.g. INC0010001).
    Returns full incident details including caller, assignment group, state, priority, and work notes.

    Args:
        number: Incident number (e.g. 'INC0010001')
    """
    data = await _get(_table("incident"), params={
        "sysparm_query":         f"number={number}",
        "sysparm_display_value": "true",
        "sysparm_limit":         1,
    })
    records = (data or {}).get("result", [])
    return records[0] if records else {"error": f"Incident {number} not found"}


@mcp.tool()
async def list_incidents(
    query: str = "active=true",
    fields: str = "number,short_description,state,priority,assigned_to,assignment_group,opened_at",
    limit: int = 10,
    offset: int = 0,
) -> dict:
    """
    List incidents with filtering. Defaults to active incidents.
    Common query patterns:
      - All P1s open:            priority=1^active=true
      - Assigned to me:          assigned_to=javascript:gs.getUserID()
      - Unassigned in group:     assignment_group.name=Service Desk^assigned_to=NULL
      - Opened today:            opened_atONToday@javascript:gs.beginningOfToday()@javascript:gs.endOfToday()

    Args:
        query  : Encoded query string (default: active=true)
        fields : Comma-separated field names
        limit  : Max records (default 10, max 100)
        offset : Pagination offset
    """
    params: dict[str, Any] = {
        "sysparm_query":         query,
        "sysparm_fields":        fields,
        "sysparm_limit":         max(1, min(limit, 100)),
        "sysparm_offset":        max(0, offset),
        "sysparm_display_value": "true",
    }
    return await _get(_table("incident"), params=params) or {"error": "Query failed"}


@mcp.tool()
async def create_incident(
    short_description: str,
    caller_id: str,
    category: str = "inquiry",
    subcategory: str = "",
    priority: str = "3",
    assignment_group: str = "",
    description: str = "",
    impact: str = "3",
    urgency: str = "3",
) -> dict:
    """
    Create a new ServiceNow incident.

    Args:
        short_description : One-line summary (required)
        caller_id         : Username or sys_id of the affected user (required)
        category          : Category (e.g. 'network', 'hardware', 'software', 'inquiry')
        subcategory       : Subcategory value
        priority          : 1=Critical, 2=High, 3=Moderate, 4=Low (default: 3)
        assignment_group  : Group name or sys_id to assign to
        description       : Full description / steps to reproduce
        impact            : 1=High, 2=Medium, 3=Low (default: 3)
        urgency           : 1=High, 2=Medium, 3=Low (default: 3)
    """
    body: dict[str, Any] = {
        "short_description": short_description,
        "caller_id":         caller_id,
        "category":          category,
        "priority":          priority,
        "impact":            impact,
        "urgency":           urgency,
    }
    if subcategory:       body["subcategory"]       = subcategory
    if assignment_group:  body["assignment_group"]  = assignment_group
    if description:       body["description"]       = description
    return await _post(_table("incident"), body) or {"error": "Create failed"}


@mcp.tool()
async def update_incident(
    number: str,
    state: str = "",
    work_notes: str = "",
    close_notes: str = "",
    close_code: str = "",
    assigned_to: str = "",
    assignment_group: str = "",
    priority: str = "",
    additional_fields: dict | None = None,
) -> dict:
    """
    Update an existing incident by number (e.g. INC0010001).
    Only provide fields you want to change.

    State values: 1=New, 2=In Progress, 3=On Hold, 6=Resolved, 7=Closed
    Close codes: Solved (Permanently), Solved (Work Around), Not Solved (Not Reproducible),
                 Not Solved (Too Costly), Closed/Resolved by Caller

    Args:
        number           : Incident number (e.g. INC0010001)
        state            : New state value
        work_notes       : Internal work note to add
        close_notes      : Resolution notes (required when resolving)
        close_code       : Close code (required when resolving)
        assigned_to      : Username or sys_id to assign to
        assignment_group : Group name or sys_id
        priority         : New priority (1-4)
        additional_fields: Any other fields as a dict
    """
    data = await _get(_table("incident"), params={
        "sysparm_query":  f"number={number}",
        "sysparm_fields": "sys_id",
        "sysparm_limit":  1,
    })
    records = (data or {}).get("result", [])
    if not records:
        return {"error": f"Incident {number} not found"}
    sys_id = records[0]["sys_id"]

    body: dict[str, Any] = {}
    if state:             body["state"]            = state
    if work_notes:        body["work_notes"]       = work_notes
    if close_notes:       body["close_notes"]      = close_notes
    if close_code:        body["close_code"]       = close_code
    if assigned_to:       body["assigned_to"]      = assigned_to
    if assignment_group:  body["assignment_group"] = assignment_group
    if priority:          body["priority"]         = priority
    if additional_fields:
        body.update(additional_fields)

    return await _patch(f"{_table('incident')}/{sys_id}", body) or {"error": "Update failed"}


@mcp.tool()
async def get_similar_incidents(
    input_text: str,
    limit: int = 5,
    state_filter: str = "",
) -> dict:
    """
    Find incidents with similar short descriptions to the input text.
    Useful for duplicate detection and RCA. Searches each significant word.

    Args:
        input_text   : Text to search for (e.g. 'VPN not connecting after password change')
        limit        : Max results per keyword match (default 5, max 20)
        state_filter : Optional state filter (e.g. '6' for Resolved only)
    """
    stop_words = {"the", "a", "an", "is", "in", "on", "at", "to", "for",
                  "of", "and", "or", "not", "with", "after", "before"}
    keywords = [
        w.strip().lower()
        for w in input_text.split()
        if w.strip().lower() not in stop_words and len(w.strip()) > 2
    ]

    all_results: list = []
    seen: set = set()
    capped_limit = max(1, min(limit, 20))

    for keyword in keywords[:5]:
        base_query = f"short_descriptionCONTAINS{keyword}"
        if state_filter:
            base_query += f"^state={state_filter}"
        data = await _get(_table("incident"), params={
            "sysparm_query":         base_query,
            "sysparm_fields":        "number,short_description,state,priority,resolved_at,close_notes",
            "sysparm_limit":         capped_limit,
            "sysparm_display_value": "true",
        })
        for rec in (data or {}).get("result", []):
            if rec.get("number") not in seen:
                seen.add(rec["number"])
                all_results.append(rec)

    return {"result": all_results, "total": len(all_results), "keywords_used": keywords}


# ─── Discovery: Incidents ─────────────────────────────────────────────────────
# Paste this block into server.py before the # ─── Users ─── section

@mcp.tool()
async def discover_incidents(
days_back: int = 90,
limit: int = 1000,
) -> dict:
    """
    Recon tool — queries the incident table to surface automation opportunities.

    Analyzes incident patterns over a rolling window and returns ranked insights:
    - Volume by category and subcategory
    - Mean time to resolve (MTTR) per category
    - Repeat/recurring incident patterns
    - High-volume + low-complexity candidates for automation or Virtual Agent deflection
    - Resolution code distribution (how-to, self-service, known error, etc.)

    Args:
        days_back : Rolling lookback window in days (default 90)
        limit     : Max incidents to analyze (default 1000, max 2000)
    """
    import json
    from collections import defaultdict
    from datetime import datetime, timedelta, timezone

    capped_limit = max(1, min(limit, 2000))
    cutoff = (datetime.now(timezone.utc) - timedelta(days=days_back)).strftime(
        "%Y-%m-%d %H:%M:%S"
    )

    # ── 1. Pull incidents ──────────────────────────────────────────────────────
    data = await _get(
        _table("incident"),
        params={
            "sysparm_query": f"sys_created_on>={cutoff}^state!=6",  # exclude cancelled
            "sysparm_fields": (
                "number,category,subcategory,priority,state,"
                "assignment_group,close_code,short_description,"
                "sys_created_on,resolved_at,closed_at,caller_id"
            ),
            "sysparm_limit": capped_limit,
            "sysparm_display_value": "true",
        },
    )

    records = (data or {}).get("result", [])
    if not records:
        return {"error": "No incidents found for the given window.", "days_back": days_back}

    total = len(records)

    # ── 2. Aggregate ───────────────────────────────────────────────────────────
    cat_volume: dict[str, int] = defaultdict(int)
    subcat_volume: dict[str, int] = defaultdict(int)
    cat_mttr_minutes: dict[str, list[float]] = defaultdict(list)
    close_code_volume: dict[str, int] = defaultdict(int)
    group_volume: dict[str, int] = defaultdict(int)
    priority_volume: dict[str, int] = defaultdict(int)
    desc_map: dict[str, int] = defaultdict(int)          # short_desc dedup → recurrence
    caller_map: dict[str, int] = defaultdict(int)        # repeat callers

    for inc in records:
        cat   = inc.get("category") or "uncategorized"
        subcat = inc.get("subcategory") or "none"
        group  = inc.get("assignment_group") or "unassigned"
        prio   = inc.get("priority") or "unknown"
        code   = inc.get("close_code") or "not closed"
        desc   = (inc.get("short_description") or "").strip().lower()[:80]
        caller = inc.get("caller_id") or "unknown"

        cat_volume[cat] += 1
        subcat_volume[f"{cat} / {subcat}"] += 1
        group_volume[group] += 1
        priority_volume[prio] += 1
        close_code_volume[code] += 1
        if desc:
            desc_map[desc] += 1
        caller_map[caller] += 1

        # MTTR — use resolved_at, fallback to closed_at
        created_raw   = inc.get("sys_created_on", "")
        resolved_raw  = inc.get("resolved_at") or inc.get("closed_at", "")
        if created_raw and resolved_raw:
            try:
                fmt = "%Y-%m-%d %H:%M:%S"
                created_dt  = datetime.strptime(created_raw, fmt)
                resolved_dt = datetime.strptime(resolved_raw, fmt)
                minutes = (resolved_dt - created_dt).total_seconds() / 60
                if minutes > 0:
                    cat_mttr_minutes[cat].append(minutes)
            except Exception:
                pass

    # ── 3. Build ranked category table ────────────────────────────────────────
    def avg(lst: list[float]) -> float:
        return round(sum(lst) / len(lst), 1) if lst else 0.0

    ranked_categories = sorted(
        [
            {
                "category": cat,
                "incident_count": vol,
                "pct_of_total": round(vol / total * 100, 1),
                "avg_mttr_minutes": avg(cat_mttr_minutes.get(cat, [])),
                "mttr_sample_size": len(cat_mttr_minutes.get(cat, [])),
            }
            for cat, vol in cat_volume.items()
        ],
        key=lambda x: x["incident_count"],
        reverse=True,
    )

    ranked_subcats = sorted(
        [{"subcategory": k, "count": v} for k, v in subcat_volume.items()],
        key=lambda x: x["count"],
        reverse=True,
    )[:15]

    # ── 4. Automation candidates ───────────────────────────────────────────────
    # High volume + low MTTR = strong automation signal
    # Close codes associated with self-service / how-to = deflection signal
    deflection_codes = {
        "solved (permanently)", "solved (work around)", "solved remotely",
        "not solved (not reproducible)", "closed/resolved by caller",
        "how to", "self-service", "known error",
    }

    deflection_volume = sum(
        v for code, v in close_code_volume.items()
        if any(d in code.lower() for d in deflection_codes)
    )

    automation_candidates = []
    for cat_data in ranked_categories:
        cat  = cat_data["category"]
        vol  = cat_data["incident_count"]
        mttr = cat_data["avg_mttr_minutes"]
        pct  = cat_data["pct_of_total"]
        score = 0
        reasons = []

        if vol >= total * 0.08:       # 8%+ of all incidents
            score += 3
            reasons.append(f"high volume ({pct}% of total)")
        elif vol >= total * 0.04:
            score += 1
            reasons.append(f"moderate volume ({pct}% of total)")

        if 0 < mttr <= 30:
            score += 3
            reasons.append(f"fast resolution (avg {mttr} min)")
        elif 0 < mttr <= 90:
            score += 1
            reasons.append(f"moderate resolution time (avg {mttr} min)")

        if score >= 3:
            priority = "🔥 High"
        elif score == 2:
            priority = "⚡ Medium"
        elif score >= 1:
            priority = "👀 Low"
        else:
            continue

        automation_candidates.append({
            "category": cat,
            "automation_priority": priority,
            "incident_count": vol,
            "avg_mttr_minutes": mttr,
            "reasons": reasons,
            "suggested_approach": (
                "Virtual Agent deflection + Flow Designer auto-resolve"
                if score >= 4
                else "Virtual Agent deflection"
                if score >= 2
                else "Knowledge article + self-service catalog"
            ),
        })

    # ── 5. Recurring descriptions (repeat incident signal) ────────────────────
    recurring = sorted(
        [{"description": d, "occurrences": c} for d, c in desc_map.items() if c >= 3],
        key=lambda x: x["occurrences"],
        reverse=True,
    )[:10]

    # ── 6. Top repeat callers ─────────────────────────────────────────────────
    top_callers = sorted(
        [{"caller": c, "incidents": v} for c, v in caller_map.items() if v >= 3],
        key=lambda x: x["incidents"],
        reverse=True,
    )[:10]

    # ── 7. Summary ────────────────────────────────────────────────────────────
    summary = {
        "window_days": days_back,
        "total_incidents_analyzed": total,
        "unique_categories": len(cat_volume),
        "deflection_eligible_incidents": deflection_volume,
        "deflection_eligible_pct": round(deflection_volume / total * 100, 1) if total else 0,
        "top_category": ranked_categories[0]["category"] if ranked_categories else "n/a",
        "top_category_volume": ranked_categories[0]["incident_count"] if ranked_categories else 0,
    }

    return {
        "summary": summary,
        "automation_candidates": automation_candidates,
        "categories_ranked_by_volume": ranked_categories,
        "subcategories_ranked_by_volume": ranked_subcats,
        "close_code_distribution": dict(
            sorted(close_code_volume.items(), key=lambda x: x[1], reverse=True)
        ),
        "priority_distribution": dict(
            sorted(priority_volume.items(), key=lambda x: x[1], reverse=True)
        ),
        "assignment_group_volume": dict(
            sorted(group_volume.items(), key=lambda x: x[1], reverse=True)[:15]
        ),
        "recurring_descriptions": recurring,
        "top_repeat_callers": top_callers,
    }





# ─── Users ────────────────────────────────────────────────────────────────────

@mcp.tool()
async def get_user(username_or_email: str) -> dict:
    """
    Look up a ServiceNow user by username or email address.

    Args:
        username_or_email: Username (user_name field) or email address
    """
    query = f"user_name={username_or_email}^ORemail={username_or_email}"
    data = await _get(_table("sys_user"), params={
        "sysparm_query":         query,
        "sysparm_fields":        "user_name,name,email,department,manager,active,roles",
        "sysparm_display_value": "true",
        "sysparm_limit":         1,
    })
    records = (data or {}).get("result", [])
    return records[0] if records else {"error": f"User '{username_or_email}' not found"}


@mcp.tool()
async def list_users(
    query: str = "active=true",
    fields: str = "user_name,name,email,department,manager",
    limit: int = 10,
) -> dict:
    """
    List ServiceNow users.

    Args:
        query  : Encoded query (e.g. 'department.name=IT^active=true')
        fields : Fields to return
        limit  : Max records (max 100)
    """
    return await _get(_table("sys_user"), params={
        "sysparm_query":         query,
        "sysparm_fields":        fields,
        "sysparm_limit":         max(1, min(limit, 100)),
        "sysparm_display_value": "true",
    }) or {"error": "Query failed"}


# ─── Entry point ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    transport = os.environ.get("MCP_TRANSPORT", "stdio")

    if transport == "streamable-http":
        import uvicorn
        app = mcp.streamable_http_app()
        # Add unauthenticated health + root routes so probes (Railway, Claude
        # Desktop reachability checks, uptime monitors) don't get 404/401.
        app.router.routes.append(Route("/health", health, methods=["GET"]))
        app.router.routes.append(Route("/healthz", health, methods=["GET"]))
        app.router.routes.append(Route("/", root, methods=["GET"]))
        wrapped = _BearerAuth(app)
        logger.info("ServiceNow MCP server listening on 0.0.0.0:%d", PORT)
        uvicorn.run(wrapped, host="0.0.0.0", port=PORT)
    else:
        mcp.run(transport="stdio")

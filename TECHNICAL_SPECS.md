# ServiceNow MCP Server — Technical Specifications

**Version:** 2.0.0  
**Language:** Python 3.10+  
**Protocol:** Model Context Protocol (MCP) 2024-11-05  
**ServiceNow API:** Table API (`/api/now/table/`) + Service Catalog API (`/api/sn_sc/`)

---

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                     Claude (LLM)                        │
└────────────────────────┬────────────────────────────────┘
                         │ MCP Protocol
          ┌──────────────┴──────────────┐
          │                             │
   stdio transport              streamable-http transport
  (Claude Desktop)              (Anthropic API connector)
          │                             │
          └──────────────┬──────────────┘
                         │
┌────────────────────────▼────────────────────────────────┐
│              ServiceNow MCP Server (FastMCP)             │
│                                                          │
│  ┌─────────────┐  ┌──────────────┐  ┌────────────────┐  │
│  │ Auth Layer  │  │ Input Valid. │  │ Structured Log │  │
│  └──────┬──────┘  └──────┬───────┘  └───────┬────────┘  │
│         └────────────────┼───────────────────┘           │
│                          │                               │
│  ┌───────────────────────▼───────────────────────────┐   │
│  │         Tool Handlers (26 tools)                  │   │
│  └───────────────────────┬───────────────────────────┘   │
│                          │                               │
│  ┌───────────────────────▼───────────────────────────┐   │
│  │    Shared httpx.AsyncClient (connection pool)     │   │
│  └───────────────────────┬───────────────────────────┘   │
└──────────────────────────┼──────────────────────────────┘
                           │ HTTPS + Basic Auth
┌──────────────────────────▼──────────────────────────────┐
│                  ServiceNow Instance                     │
│            Table API / Service Catalog API               │
└─────────────────────────────────────────────────────────┘
```

---

## Transport

The server supports two transports, selected at startup via the `MCP_TRANSPORT` environment variable.

| Mode | Value | Use Case |
|---|---|---|
| stdio | `stdio` (default) | Claude Desktop — launched as a subprocess |
| HTTP | `streamable-http` | Anthropic API MCP connector, remote agents |

**stdio mode** — Claude Desktop manages the process lifecycle. No network port is opened.

**streamable-http mode** — The server binds `0.0.0.0:<MCP_PORT>` and serves the MCP Streamable HTTP protocol over uvicorn. All requests pass through the Bearer token middleware before reaching the MCP layer.

---

## Configuration

All configuration is via environment variables. The server reads from a `.env` file if present (via `python-dotenv`).

| Variable | Required | Default | Description |
|---|---|---|---|
| `SN_INSTANCE` | Yes | — | Full ServiceNow instance URL, no trailing slash (e.g. `https://dev123.service-now.com`) |
| `SN_USER` | Yes | — | ServiceNow username |
| `SN_PASS` | Yes | — | ServiceNow password |
| `MCP_AUTH_TOKEN` | Recommended | — | Bearer token required by HTTP clients. Unset = unauthenticated (logs a warning) |
| `MCP_TRANSPORT` | No | `stdio` | Transport mode: `stdio` or `streamable-http` |
| `MCP_PORT` | No | `8000` | TCP port for HTTP mode |

The server raises `RuntimeError` on startup if any required variable is missing.

---

## Authentication

### MCP Layer (HTTP transport only)

Incoming requests must include:

```
Authorization: Bearer <MCP_AUTH_TOKEN>
```

Implemented as a pure-ASGI middleware class (`_BearerAuth`) wrapping the FastMCP Starlette application. Invalid or missing tokens return `HTTP 401` before the MCP layer is reached. Token validation is constant-time string comparison.

### ServiceNow Layer

All outbound requests to ServiceNow use HTTP Basic Auth (`SN_USER:SN_PASS`) passed via `httpx`'s `auth=` parameter on the shared client.

---

## HTTP Client

A single `httpx.AsyncClient` instance is created at server startup via FastMCP's `lifespan` context manager and closed on shutdown. All tool handlers share this client.

```python
httpx.AsyncClient(
    auth=(SN_USER, SN_PASS),
    headers={"Accept": "application/json", "Content-Type": "application/json"},
    timeout=30.0,
)
```

Benefits: connection pooling, keep-alive reuse, consistent headers and auth across all requests.

---

## Input Validation

Two validators are applied before any user-supplied value is interpolated into a URL path:

**Table name** — must match `^[a-z][a-z0-9_]*$`  
Applied to: `get_record`, `list_records`, `create_record`, `update_record`, `delete_record`, `run_query`, `get_table_schema`, `get_ci`, `list_cis`, `get_ci_relationships`

**sys_id** — must match `^[0-9a-f]{32}$`  
Applied to: `get_record`, `update_record`, `delete_record`, `get_ci_relationships`, `submit_catalog_request`

Validation failures raise `ValueError`, which FastMCP surfaces as a tool error to Claude.

**Limit clamping** — all `limit` parameters are clamped to `[1, 100]` using `max(1, min(limit, 100))`.

---

## Tools Reference

### Utility

#### `health_check()`
Verifies connectivity to the ServiceNow instance. Fetches one record from `sys_user` and returns `{"status": "ok", "instance": ..., "auth": "valid"}` on success.

#### `get_table_schema(table_name)`
Queries `sys_dictionary` for field definitions of any table. Returns element name, type, mandatory flag, default value, and max length for up to 100 fields.

#### `run_query(table_name, query, fields, limit, offset)`
Executes an arbitrary encoded query against any table via the Table API. Supports pagination and field projection.

---

### Generic Record CRUD

#### `get_record(table_name, sys_id, fields)`
Fetches a single record by sys_id. Optionally projects specific fields.

#### `list_records(table_name, query, fields, limit, offset)`
Lists records with optional encoded query filter and field projection. Paginated.

#### `create_record(table_name, fields)`
Creates a new record by POSTing a field dictionary to the table endpoint.

#### `update_record(table_name, sys_id, fields)`
PATCHes specified fields on an existing record.

#### `delete_record(table_name, sys_id, confirm)`
Deletes a record permanently. **Requires `confirm=True`.** Returns an error message if called without confirmation.

---

### Incidents

#### `get_incident(number)`
Fetches a single incident by number (e.g. `INC0010001`) using a query on the `number` field. Returns the full incident record with display values.

#### `list_incidents(query, fields, limit, offset)`
Lists incidents with an encoded query. Default query: `active=true`. Default fields: number, description, state, priority, assignment group, opened date.

#### `create_incident(short_description, caller_id, category, subcategory, priority, assignment_group, description, impact, urgency)`
Creates an incident. Required: `short_description`, `caller_id`. Optional fields are omitted from the POST body if blank.

#### `update_incident(number, state, work_notes, close_notes, close_code, assigned_to, assignment_group, priority, additional_fields)`
Resolves the incident number to a sys_id with a preflight GET, then PATCHes only the fields provided. Supports arbitrary additional fields via `additional_fields` dict.

#### `get_similar_incidents(input_text, limit, state_filter)`
Tokenizes `input_text`, removes stop words, and runs a `short_descriptionCONTAINS` query for each significant keyword (capped at 5 keywords). Deduplicates results by incident number. Useful for duplicate detection.

---

### Change Requests

#### `get_change(number)`
Fetches a change request by number (e.g. `CHG0030001`).

#### `list_changes(query, fields, limit)`
Lists change requests. Default query: `active=true`.

#### `create_change(short_description, change_type, assignment_group, description, justification, risk, impact, start_date, end_date)`
Creates a change request. `change_type` accepts `normal`, `standard`, or `emergency`.

---

### Problems

#### `get_problem(number)`
Fetches a problem record by number (e.g. `PRB0040001`).

#### `list_problems(query, fields, limit)`
Lists problems. Default query: `active=true`.

---

### CMDB

#### `get_ci(name_or_sys_id, ci_class)`
Attempts a name lookup first; falls back to sys_id lookup if the input is a valid 32-char hex string. Default table: `cmdb_ci`.

#### `list_cis(query, ci_class, fields, limit)`
Lists CIs from any CMDB class table. Default query: `install_status=1` (installed).

#### `get_ci_relationships(ci_sys_id)`
Queries `cmdb_rel_ci` for all relationships where the CI is parent or child. Returns up to 50 relationships with parent/child names, class names, and relationship type.

---

### Users

#### `get_user(username_or_email)`
Queries `sys_user` with `user_name=X^ORemail=X`. Returns user details including department, manager, active status, and roles.

#### `list_users(query, fields, limit)`
Lists users. Default query: `active=true`.

---

### Service Catalog

#### `list_catalog_items(query, limit)`
Queries `sc_cat_item`. Default query: `active=true^sc_catalogs!=NULL`. Returns name, description, category, price, and delivery time.

#### `submit_catalog_request(catalog_item_sys_id, variables, requested_for)`
POSTs to `/api/sn_sc/servicecatalog/items/{sys_id}/order_now` with a variables dict and optional `requested_for` username.

---

## Error Handling

All HTTP helper functions (`_get`, `_post`, `_patch`, `_delete`) catch two exception types:

- `httpx.HTTPStatusError` — returns `{"error": "HTTP <status>: <body>"}` and logs at ERROR level with truncated response body (300 chars).
- `Exception` (catch-all) — returns `{"error": "<message>"}` and logs at ERROR level.

Tools that look up a record before operating (e.g. `update_incident`) return `{"error": "<entity> not found"}` if the preflight GET returns no results.

---

## Dependencies

| Package | Version Range | Purpose |
|---|---|---|
| `mcp[cli]` | `>=1.0.0,<2.0.0` | MCP server framework (FastMCP) |
| `httpx` | `>=0.27.0,<1.0.0` | Async HTTP client |
| `python-dotenv` | `>=1.0.0,<2.0.0` | `.env` file loading |
| `uvicorn` | `>=0.30.0,<1.0.0` | ASGI server for HTTP transport |

---

## Deployment

### Claude Desktop (stdio)

Add to `~/Library/Application Support/Claude/claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "servicenow": {
      "command": "python3",
      "args": ["/path/to/server.py"],
      "env": {
        "SN_INSTANCE": "https://your-instance.service-now.com",
        "SN_USER": "your_username",
        "SN_PASS": "your_password"
      }
    }
  }
}
```

### Anthropic API (streamable-http)

Start the server:

```bash
MCP_TRANSPORT=streamable-http python3 server.py
```

Reference in API calls:

```json
{
  "mcp_servers": [
    {
      "type": "url",
      "url": "http://your-host:8000/mcp",
      "name": "servicenow",
      "authorization_token": "<MCP_AUTH_TOKEN>"
    }
  ],
  "tools": [
    {
      "type": "mcp_toolset",
      "mcp_server_name": "servicenow"
    }
  ]
}
```

### Production Recommendations

- Terminate TLS at a reverse proxy (nginx, Caddy) — the server itself does not handle HTTPS.
- Run the server as a non-root system user with read-only access to the `.env` file.
- Rotate `MCP_AUTH_TOKEN` periodically and update the corresponding `authorization_token` in your API config.
- Use a ServiceNow service account with the minimum required roles (typically `itil` for incident/change/problem, `cmdb_read` for CMDB reads).

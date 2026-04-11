# ServiceNow MCP Server — Release Notes

## v2.0.0 — April 10, 2026

### Overview

ServiceNow MCP Server v2.0.0 is the first production-ready release of a Model Context Protocol (MCP) server that connects Claude directly to ServiceNow. It enables Claude to read, create, and update ServiceNow records in real time — across incidents, change requests, problems, the CMDB, users, and the service catalog — all through natural language.

---

### What's New in v2.0.0

#### Production Hardening
- **Dual transport support** — the server runs over `stdio` for Claude Desktop and over `streamable-http` for the Anthropic API MCP connector, selectable via a single environment variable. No code changes required to switch modes.
- **Bearer token authentication** — all HTTP endpoints are protected by an `Authorization: Bearer` token check. Unauthenticated requests are rejected with a `401` before any ServiceNow data is touched.
- **Fail-fast configuration** — the server refuses to start if required credentials (`SN_INSTANCE`, `SN_USER`, `SN_PASS`) are missing, preventing silent misconfigurations.
- **Connection pooling** — a shared `httpx` client is maintained across all tool calls, reducing TCP overhead and improving response times under load.

#### Safety & Security
- **Input validation** — all table names and `sys_id` values are validated before being used in API paths, preventing path traversal and malformed requests.
- **Deletion safeguard** — the `delete_record` tool requires an explicit `confirm=true` parameter. Calls without confirmation return a warning instead of executing.
- **No hardcoded credentials** — all secrets are loaded from environment variables only. There are no fallback values.

#### Observability
- **Structured logging** — every outbound ServiceNow API call is logged with method, path, and parameters. HTTP errors are logged with status code and truncated response body. All logs are timestamped and labeled.

#### Tooling
- Pinned dependency versions for reproducible installs.
- `.env.example` template included for safe onboarding.
- `.gitignore` pre-configured to exclude `.env` and credential files.

---

### Capabilities

26 tools across 8 categories are available in this release:

| Category | Tools |
|---|---|
| Incidents | Get, list, create, update, find similar |
| Change Requests | Get, list, create |
| Problems | Get, list |
| CMDB | Get CI, list CIs, get CI relationships |
| Users | Get, list |
| Service Catalog | List items, submit request |
| Generic Records | Get, list, create, update, delete |
| Utilities | Health check, run query, get table schema |

---

### Compatibility

| Component | Requirement |
|---|---|
| Python | 3.10+ |
| MCP Library | `mcp[cli]` 1.x |
| ServiceNow | Any instance supporting the Table API (Tokyo+) |
| Claude Desktop | All versions (stdio transport) |
| Anthropic API | MCP Connector beta (`mcp-client-2025-11-20`) |

---

### Upgrade Notes

v2.0.0 is the initial public release. There is no migration path from v1.0.0, which was an internal prototype with hardcoded credentials and no HTTP transport support.

If you were running v1.0.0 locally:
1. Copy your `SN_INSTANCE`, `SN_USER`, and `SN_PASS` values into a `.env` file.
2. Generate a new `MCP_AUTH_TOKEN` and add it to `.env`.
3. Run `pip install -r requirements.txt` to install the updated dependencies.
4. Restart the server.

---

### Known Limitations

- The server does not yet support OAuth token-based authentication to ServiceNow (only username/password via Basic Auth).
- Rate limiting is not implemented at the MCP layer. ServiceNow instance rate limits apply.
- HTTPS termination for the HTTP transport is not handled by the server itself — use a reverse proxy (nginx, Caddy) or a cloud load balancer in production.

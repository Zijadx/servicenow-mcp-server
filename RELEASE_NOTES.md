# ServiceNow MCP Server — Release Notes

## v3.0.0 — April 14, 2026

### Overview

v3.0.0 introduces the **Security Analyst Agent** — an AI-powered security incident investigator built on Claude Opus 4.6 with adaptive thinking. Given a security alert (from CrowdStrike, Sentinel, or any EDR/SIEM), the agent autonomously runs a full Tier-2 SOC investigation across 8 specialized tools, produces a NIST SP 800-61-aligned analysis report, and files a Priority 1 incident in ServiceNow — all in under 2 minutes.

This release also adds `anthropic` to the dependency stack and extends `.env` with Anthropic API key support.

---

### What's New in v3.0.0

#### Security Analyst Agent (`security_analyst.py`)

A single-agent agentic loop powered by Claude Opus 4.6 with adaptive thinking. The agent investigates security alerts end-to-end without human prompting, using a systematic toolkit that mirrors a Tier-2 SOC workflow.

**8 investigation tools:**

| Tool | Data Source | Type |
|---|---|---|
| `lookup_cve` | NIST NVD API | Real |
| `check_ip_reputation` | AbuseIPDB API | Real (simulated fallback if key not set) |
| `get_mitre_technique` | MITRE ATT&CK v14 | Real (cached) |
| `get_asset_context` | ServiceNow CMDB | Real |
| `query_siem_logs` | — | Simulated (replace with Splunk/QRadar/Sentinel) |
| `get_process_tree` | — | Simulated (replace with CrowdStrike/SentinelOne) |
| `check_file_hash` | — | Simulated (replace with VirusTotal/ThreatConnect) |
| `create_security_incident` | ServiceNow incident table | Real |

**Report output (NIST SP 800-61 aligned):**
- Executive summary for leadership
- Chronological attack timeline with kill chain phase labels
- Technical findings: CVE details, attacker infrastructure, process execution chain
- MITRE ATT&CK mapping with tactic and technique IDs
- Full IOC table (IPs, hashes, files, URLs, accounts)
- Prioritized remediation: Immediate / 24-hour / 30-day
- Confidence assessment per finding dimension
- Data source provenance (real vs. simulated clearly labeled)

**Three run modes:**
```bash
python3 security_analyst.py                        # built-in Log4Shell demo alert
python3 security_analyst.py --alert alert.json     # load custom alert JSON
python3 security_analyst.py --incident INC0010340  # investigate existing SN incident
```

**Tested against:** Log4Shell (CVE-2021-44228) demo alert. Agent completed in 6 iterations, filed INC0010344 as Priority 1 - Critical with full report in work notes.

#### Dependency update
- Added `anthropic>=0.50.0,<1.0.0` to `requirements.txt`

#### Environment update
- Added `ANTHROPIC_API_KEY` to `.env.example` (required for Security Analyst Agent)
- Added `ABUSEIPDB_API_KEY` to `.env.example` (optional — enables real IP reputation data)
- `load_dotenv(override=True)` ensures `.env` values take precedence over shell environment

---

## v2.1.0 — April 10, 2026

### Overview

v2.1.0 reduces the tool surface to a focused, production-appropriate scope. Ten tools covering Change Requests, Problems, CMDB, and the Service Catalog have been removed. The server now covers Incidents, generic record CRUD (suitable for Knowledge Base access), Users, and admin utilities — 15 tools total.

### What's New in v2.1.0

#### Scope Reduction
- **Removed:** Change Requests (`get_change`, `list_changes`, `create_change`)
- **Removed:** Problems (`get_problem`, `list_problems`)
- **Removed:** CMDB (`get_ci`, `list_cis`, `get_ci_relationships`)
- **Removed:** Service Catalog (`list_catalog_items`, `submit_catalog_request`)

A smaller tool surface means less attack surface, simpler auditing, and a more predictable model behavior. Knowledge Base articles and categories are accessible via the generic CRUD tools (`get_record`, `list_records`, `create_record`, `update_record`, `delete_record`) against the `kb_knowledge` and `kb_category` tables.

---

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

15 tools across 4 categories are available in this release:

| Category | Tools | Notes |
|---|---|---|
| Incidents | Get, list, create, update, find similar | Delete via generic `delete_record` |
| Generic Records | Get, list, create, update, delete | Covers KB articles/categories and any other table |
| Users | Get, list | |
| Utilities | Health check, run query, get table schema | |

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

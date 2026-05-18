# Changelog

All notable changes to servicenow-mcp-server are documented here.

---

## [2.2.0] — 2026-05-18

### Added

- **`discover_incidents`** — recon tool that analyzes the incident table over a rolling window and surfaces automation opportunities ranked by signal strength.

  **Parameters**
  - `days_back` (int, default 90) — rolling lookback window in days
  - `limit` (int, default 1000, max 2000) — max incidents to pull for analysis

  **Returns**
  - `summary` — total incidents analyzed, deflection-eligible count + %, top category by volume
  - `automation_candidates` — categories scored by volume + MTTR with suggested automation approach
  - `categories_ranked_by_volume` — per-category incident count, % of total, avg MTTR, MTTR sample size
  - `subcategories_ranked_by_volume` — top 15 subcategories by volume
  - `close_code_distribution` — resolution code breakdown, used as deflection signal
  - `recurring_descriptions` — short descriptions appearing 3+ times in the window
  - `top_repeat_callers` — callers with 3+ incidents in the window

  **Scoring logic**
  - Volume signal: 8%+ of total = +3, 4–8% = +1
  - MTTR signal: avg ≤ 30 min = +3, avg ≤ 90 min = +1
  - Score ≥ 4 → 🔥 High (Virtual Agent + Flow Designer auto-resolve)
  - Score 2–3 → ⚡ Medium (Virtual Agent deflection)
  - Score 1 → 👀 Low (Knowledge article + self-service catalog)
  - Score 0 → excluded from candidates

  Cancelled incidents (`state != 6`) are excluded from all analysis.

---

## [2.1.0] — prior

### Added

- Dual transport support: `stdio` and `streamable-http`
- Bearer token auth middleware (`_BearerAuth`) for HTTP mode
- Connection-pooled

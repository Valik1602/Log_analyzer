# GKE Log Analyzer

Local web app for analyzing Google Kubernetes Engine JSON logs and Datadog CSV exports — trace request chains, browse errors with context, filter by severity/service/time, and search by UUID, email, or free text.

## Quick start

**Windows:** double-click `start.bat` (or run it in a terminal).

The script creates a virtual environment, installs dependencies, and opens the browser automatically.

## Usage

1. Drop a `.json`, `.ndjson`, or Datadog CSV export onto the upload area (or click to browse).
2. Supports JSON array format `[{...}, {...}]`, newline-delimited JSON (one object per line), and Datadog's "Export to CSV" format (`Date,Host,Service,Content`, optionally with a `Status`/`Level` column).
3. After upload the dashboard shows total entries, error/warning counts, and time range. For CSV uploads, the "Container"/"Pod" labels switch to "Service"/"Host" to match Datadog's terminology.
4. Use the sidebar filters (severity, service/container) and the time/text filters to narrow entries.
5. Click any row to open the full detail panel.
6. Click **Trace Request Chain** to see all entries sharing the same correlation id — for CSV logs without a dedicated trace/request field, this reconstructs the dependency chain (e.g. list → fetch → parse) for the same entity/resource mentioned in the log text.
7. Switch to the **Errors** tab for all ERROR/CRITICAL entries with ±5 context entries, grouped by a normalized root-cause template (dynamic values like ids/numbers/GUIDs are stripped so recurring errors are grouped even without a structured exception field).
8. Use the **search bar** in the header to search by ExternalEventId, QueueMessageId, RequestId (UUID), email address, or free text — results appear in the **Search Results** tab grouped by event, with error summaries.

### CSV logs without a severity column

When a Datadog CSV export has no `Status`/`Level` column, severity is inferred from the message text (`error`/`exception`/`failed` → ERROR, `warn` → WARNING, `fatal`/`panic` → CRITICAL, `debug` → DEBUG, otherwise INFO). Correlation/dependency ids are pulled out of the free-text message: explicit `request_id=`/`trace_id=`/`correlation_id=`/`session_id=`/`job_id=`/`task_id=` fields or an inline UUID become the RequestId; an `iid=<entity>` + `date=<date>` pair (common in data-pipeline logs) becomes a coarser ExternalEventId grouping, and is carried forward to adjacent log lines from the same host/service that don't repeat the identifier.

## Requirements

- Python 3.12+

## API endpoints

| Method | Path | Description |
|--------|------|-------------|
| POST | `/upload` | Upload and parse a log file |
| GET | `/summary` | Counts by severity, top containers, time range |
| GET | `/entries` | Paginated entries with filters |
| GET | `/entry/{idx}` | Full detail for one entry |
| GET | `/chain/{request_id}` | All entries sharing a RequestId/ConnectionId |
| GET | `/errors` | ERROR/CRITICAL entries with surrounding context |
| GET | `/containers` | List of container names |
| GET | `/search?q=` | Search by UUID, email, or text — returns event groups, errors, error summary |
| GET | `/event/{id}` | All entries for a given ExternalEventId |

### Filter parameters for `/entries`

- `severity` — multi-value, e.g. `?severity=ERROR&severity=CRITICAL`
- `container` — exact container name
- `timeFrom` / `timeTo` — ISO 8601 datetime
- `search` — substring match on message
- `page` / `page_size` — pagination (default 1 / 50)

## Memory note

Parsed log entries are held in memory. A 30 MB file with ~200 k entries typically uses **300–600 MB RAM** depending on payload size. If that is a concern, the in-memory `_store` dict in `backend/main.py` can be swapped for a lightweight SQLite database without changing the API surface.

## File format support

- **JSON array**: `[{...}, {...}, ...]`
- **NDJSON / newline-delimited JSON**: one JSON object per line
- **Datadog CSV export**: `Date,Host,Service,Content` (column names are matched case-insensitively; `Message`/`Timestamp`/`Level`/`Tags` and similar variants are also recognized). Detected by a `.csv` filename or a non-JSON first byte; `/upload` and `/summary` report which format was detected via `"format": "gke_json" | "datadog_csv"`.

Malformed lines are silently skipped and counted in the `skipped` field returned by `/upload`.

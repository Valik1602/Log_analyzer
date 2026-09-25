#Log Analyzer

Local web app for analyzing logs from the formats L2/L3 support engineers actually run into day to day — GKE JSON, Datadog CSV, generic/arbitrary CSV, Windows Event Log (CSV or XML export), AWS CloudWatch Logs (JSON export), and plain-text application logs — trace request chains, browse errors with context, filter by severity/service/time, and search by UUID, email, or free text.

## Quick start

**Windows:** double-click `start.bat` (or run it in a terminal).

The script creates a virtual environment, installs dependencies, and opens the browser automatically.

## Usage

1. Drop a log file onto the upload area (or click to browse) — any of the formats below.
2. The upload format is auto-detected from the filename and content; see **File format support**.
3. After upload the dashboard shows total entries, error/warning counts, and time range. The "Container"/"Pod" labels switch per format (e.g. "Service"/"Host" for CSV, "Source"/"Computer" for Windows Event Log, "Log Group"/"Log Stream" for CloudWatch) to match that source's own terminology.
4. Use the sidebar filters (severity, service/container) and the time/text filters to narrow entries.
5. Click any row to open the full detail panel.
6. Click **Trace Request Chain** to see all entries sharing the same correlation id — for CSV logs without a dedicated trace/request field, this reconstructs the dependency chain (e.g. list → fetch → parse) for the same entity/resource mentioned in the log text.
7. Switch to the **Errors** tab for all ERROR/CRITICAL entries with ±5 context entries, grouped by a normalized root-cause template (dynamic values like ids/numbers/GUIDs are stripped so recurring errors are grouped even without a structured exception field).
8. Use the **search bar** in the header to search by ExternalEventId, QueueMessageId, RequestId (UUID), email address, or free text — results appear in the **Search Results** tab grouped by event, with error summaries.

### Severity and correlation ids when the format doesn't provide them

When a format has no explicit severity/status field (Datadog CSV without `Status`, plain-text logs, CloudWatch messages), severity is inferred from the message text (`error`/`exception`/`failed` → ERROR, `warn` → WARNING, `fatal`/`panic` → CRITICAL, `debug` → DEBUG, otherwise INFO).

Correlation/dependency ids are pulled out of the free-text message wherever the format doesn't carry a dedicated field: explicit `request_id=`/`trace_id=`/`correlation_id=`/`session_id=`/`job_id=`/`task_id=` fields or an inline UUID become the RequestId; an `iid=<entity>` + `date=<date>` pair (common in data-pipeline logs) becomes a coarser ExternalEventId grouping and is carried forward to adjacent log lines from the same host/service that don't repeat the identifier. Windows Event Log entries use their own EventID as the ExternalEventId instead, since that's how engineers already triage them ("show me every 4625").

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

Format is auto-detected from the filename extension and, where that's ambiguous, from the file's own shape (first byte, header row, etc.) — no need to pick a format manually. `/upload`, `/upload-compare` and `/summary` report which one was detected via a `"format"` field.

| Format | `format` value | Detected by |
|---|---|---|
| GKE JSON array: `[{...}, {...}, ...]` | `gke_json` | Starts with `[` |
| NDJSON — one JSON object per line | `gke_json` | Starts with `{` |
| AWS CloudWatch Logs JSON export — `filter-log-events` output (`{"events":[...]}`), a subscription/export dump (`{"logGroup":...,"logEvents":[...]}`), or a Logs Insights export (`[[{"field":...,"value":...}, ...], ...]`); a batch (list) of any of these is also accepted | `cloudwatch_json` | JSON whose shape matches one of the above (falls back to `gke_json` otherwise) |
| Windows Event Log XML export (single `<Event>`, `<Events>...</Events>`, or several `<Event>` blocks concatenated without a root) | `windows_event_xml` | Starts with `<` |
| Windows Event Log CSV export (`Get-WinEvent`/`Get-EventLog \| Export-Csv`, or Event Viewer's own CSV export) | `windows_event_csv` | `.csv` file whose header contains Windows Event Log-specific columns (`TimeCreated`, `EventID`, `ProviderName`, `EntryType`, …) |
| Datadog CSV export: `Date,Host,Service,Content`, or any other CSV with a timestamp + message-shaped column set (`Occurred`/`Machine`/`Component`/`Severity`/`Description`, etc.) | `csv` | `.csv` file, or any file whose first line is comma-separated and isn't itself a timestamped log line |
| Plain-text / unstructured `.log` or `.txt` — one entry per recognized leading timestamp (ISO 8601, bracketed, Apache/Nginx, syslog, or US `MM/DD/YYYY`); lines with no timestamp (e.g. a stack trace frame) attach to the previous entry instead of becoming entries of their own | `plaintext` | Anything that isn't JSON, XML, or CSV-shaped |

Column/field names are matched case-insensitively with a generous list of synonyms for each format, so a close-but-not-exact match (e.g. `Machine` instead of `Host`, `Description` instead of `Message`) is still picked up.

Malformed lines are silently skipped and counted in the `skipped` field returned by `/upload`.

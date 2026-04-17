# GKE Log Analyzer

Local web app for analyzing Google Kubernetes Engine JSON logs — trace request chains, browse errors with context, filter by severity/container/time, and search by UUID, email, or free text.

## Quick start

**Windows:** double-click `start.bat` (or run it in a terminal).

The script creates a virtual environment, installs dependencies, and opens the browser automatically.

## Usage

1. Drop a `.json` or `.ndjson` log file onto the upload area (or click to browse).
2. Supports both JSON array format `[{...}, {...}]` and newline-delimited JSON (one object per line).
3. After upload the dashboard shows total entries, error/warning counts, and time range.
4. Use the sidebar filters (severity, container) and the time/text filters to narrow entries.
5. Click any row to open the full JSON detail panel.
6. Click **Trace Request Chain** to see all entries sharing the same `RequestId` or `ConnectionId`.
7. Switch to the **Errors** tab for all ERROR/CRITICAL entries with ±5 context entries.
8. Use the **search bar** in the header to search by ExternalEventId, QueueMessageId, RequestId (UUID), email address, or free text — results appear in the **Search Results** tab grouped by event, with error summaries.

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

Malformed lines are silently skipped and counted in the `skipped` field returned by `/upload`.

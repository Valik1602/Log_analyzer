"""
GKE Log Analyzer — FastAPI backend
Streams large JSON/NDJSON files without loading them fully into memory.
NOTE: Parsed entries are held in a module-level dict. A 30 MB file with
      ~200 k entries will use roughly 300–600 MB of RAM depending on payload
      size. If memory is a concern, swap `_store` for a lightweight SQLite DB.
NOTE: _store is replaced atomically on each upload. This is safe for the
      intended single-user local tool use case. Concurrent uploads would race;
      add a threading.Lock if multi-user support is ever needed.
"""

from __future__ import annotations

import csv
import io
import json
import re
import xml.etree.ElementTree as ET
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any

import ijson
import uvicorn
from fastapi import FastAPI, File, HTTPException, Query, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

app = FastAPI(title="GKE Log Analyzer")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── search type detection ─────────────────────────────────────────────────────

_UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
    re.IGNORECASE,
)
_EMAIL_RE = re.compile(r"[^@\s]+@[^@\s]+\.[^@\s]+")


def _detect_query_type(q: str) -> str:
    if _UUID_RE.match(q.strip()):
        return "uuid"
    if _EMAIL_RE.search(q.strip()):
        return "email"
    return "text"


def _contains_str(obj: Any, needle: str) -> bool:
    """Recursively check whether needle (already lower-cased) appears in any string value.

    An empty needle would match every node; guard against it so callers get a
    predictable False rather than a misleading True for every entry.
    """
    if not needle:
        return False
    if isinstance(obj, str):
        return needle in obj.lower()
    if isinstance(obj, dict):
        return any(_contains_str(v, needle) for v in obj.values())
    if isinstance(obj, list):
        return any(_contains_str(item, needle) for item in obj)
    return False


# ── in-memory store ───────────────────────────────────────────────────────────

_store: dict[str, Any] = {
    "entries": [],            # list[dict], sorted by timestamp
    "by_request": {},         # request_id  → [entry_index, ...]
    "by_connection": {},      # conn_id      → [entry_index, ...]
    "by_external_event": {},  # ExternalEventId → [entry_index, ...]
    "by_queue_message": {},   # QueueMessageId  → [entry_index, ...]
    "skipped": 0,
    "parsed_at": None,
    "format": None,
}

# Second file for comparison (same structure, never overwrites _store)
_compare_store: dict[str, Any] | None = None

# ── template normalisation (for compare) ─────────────────────────────────────

_TMPL_GUID = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
    re.IGNORECASE,
)
_TMPL_EMAIL = re.compile(r"[^\s@]+@[^\s@]+\.[^\s@]+")
_TMPL_FILE  = re.compile(
    r"\b[\w.\-]+\.(?:pdf|docx?|xlsx?|zip|txt|log|jpg|png|json)\b",
    re.IGNORECASE,
)
_TMPL_HEX  = re.compile(r"\b[0-9a-f]{8,}\b", re.IGNORECASE)
_TMPL_NUM  = re.compile(r"\b\d{4,}\b")
# Plain-text logs (Datadog CSV) commonly embed correlation ids as key=value
# pairs rather than a dedicated field; strip the value so e.g.
# "request_id=abc-123" and "request_id=xyz-999" template to the same string
# and get grouped under one root cause instead of two.
_TMPL_KV_ID = re.compile(
    r'\b((?:request|trace|correlation|session|job|task)[_-]?id)\s*[=:]\s*"?[\w.-]+"?',
    re.IGNORECASE,
)


def _normalize_template(msg: str) -> str:
    """Strip dynamic values so the same error pattern from different runs matches."""
    if not msg:
        return ""
    msg = _TMPL_GUID.sub("{GUID}", msg)
    msg = _TMPL_EMAIL.sub("{EMAIL}", msg)
    msg = _TMPL_FILE.sub("{FILE}", msg)
    msg = _TMPL_KV_ID.sub(r"\1={ID}", msg)
    msg = _TMPL_HEX.sub("{HEX}", msg)
    msg = _TMPL_NUM.sub("{NUM}", msg)
    return re.sub(r"\s+", " ", msg).strip()

# ── field extractors ──────────────────────────────────────────────────────────

def _ts(entry: dict) -> str:
    # Returns "" when both timestamp and receiveTimestamp are absent.
    # _parse_dt("") returns None, and the sort key falls back to _EPOCH so
    # timestamp-less entries sort first rather than raising a TypeError.
    return entry.get("timestamp") or entry.get("receiveTimestamp") or ""

def _severity(entry: dict) -> str:
    sev = entry.get("severity")
    # Severity may be missing, None, an integer (some GKE variants), or a string.
    # Coerce to str so .upper() never raises; treat falsy-after-coerce as "DEFAULT".
    if sev is None or (isinstance(sev, str) and not sev.strip()):
        # Fall back to structured-log level field; use DEFAULT (not INFO) so that
        # entries without any severity signal are not mis-classified.
        sev = (entry.get("jsonPayload") or {}).get("level", "DEFAULT")
    return str(sev).upper()

def _message(entry: dict) -> str:
    p = entry.get("jsonPayload") or {}
    # Both fields may be absent; fall back to "" so callers always get a str.
    msg = p.get("message") or p.get("@mt")
    return str(msg) if msg is not None else ""

def _container(entry: dict) -> str:
    return ((entry.get("resource") or {}).get("labels") or {}).get("container_name", "")

def _pod(entry: dict) -> str:
    return ((entry.get("resource") or {}).get("labels") or {}).get("pod_name", "")

def _request_id(entry: dict) -> str:
    return (entry.get("jsonPayload") or {}).get("RequestId", "") or ""

def _connection_id(entry: dict) -> str:
    return (entry.get("jsonPayload") or {}).get("ConnectionId", "") or ""

def _logger_field(entry: dict) -> str:
    return (entry.get("jsonPayload") or {}).get("logger", "") or ""

def _action_field(entry: dict) -> str:
    name = (entry.get("jsonPayload") or {}).get("ActionName", "") or ""
    if not name:
        return ""
    # rsplit(".", 1) returns a single-element list when there is no dot, so
    # [-1] yields the whole string — which is the correct behaviour (the full
    # name IS the action when there is no namespace/class prefix).
    return name.rsplit(".", 1)[-1]

def _external_event_id(entry: dict) -> str:
    return (entry.get("jsonPayload") or {}).get("ExternalEventId", "") or ""

def _queue_message_id(entry: dict) -> str:
    return (entry.get("jsonPayload") or {}).get("QueueMessageId", "") or ""

def _stack_trace_field(entry: dict) -> str:
    """@x is Serilog's structured exception: ExceptionType: msg \\n   at ..."""
    return (entry.get("jsonPayload") or {}).get("@x", "") or ""

def _sender_key(entry: dict) -> str:
    return (entry.get("jsonPayload") or {}).get("SenderKey", "") or ""

def _queue_name_field(entry: dict) -> str:
    p = entry.get("jsonPayload") or {}
    return p.get("queueName", "") or p.get("QueueName", "") or ""

def _parse_dt(ts: str) -> datetime | None:
    if not ts:
        return None
    try:
        dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        # Ensure the datetime is always timezone-aware so comparisons never
        # raise TypeError when mixing aware and naive datetimes.
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except ValueError:
        return None

def _normalise(raw: dict, index: int) -> dict:
    raw["_idx"]               = index
    raw["_severity"]          = _severity(raw)
    raw["_message"]           = _message(raw)
    raw["_container"]         = _container(raw)
    raw["_pod"]               = _pod(raw)
    raw["_ts"]                = _ts(raw)
    raw["_request_id"]        = _request_id(raw)
    raw["_connection_id"]     = _connection_id(raw)
    raw["_logger"]            = _logger_field(raw)
    raw["_action"]            = _action_field(raw)
    raw["_external_event_id"] = _external_event_id(raw)
    raw["_queue_message_id"]  = _queue_message_id(raw)
    raw["_stack_trace"]       = _stack_trace_field(raw)
    raw["_sender_key"]        = _sender_key(raw)
    raw["_queue_name"]        = _queue_name_field(raw)
    return raw


def _stream_entries(data: bytes):
    """Yield dicts from a JSON array or NDJSON byte string.

    Edge-case handling:
    - Empty / whitespace-only input  → yields nothing.
    - JSON array with non-dict items → those items are silently skipped.
    - NDJSON with a malformed line   → that line is skipped; valid lines are
                                       still yielded.
    - ijson parse error mid-array    → stops at the error; yields what came
                                       before it (behaviour documented below).
    """
    if not data or not data.strip():
        return

    stream = io.BytesIO(data)
    first = b""
    while not first.strip():
        first = stream.read(1)
        if not first:
            return
    stream.seek(0)

    if first.strip() == b"[":
        try:
            for item in ijson.items(stream, "item"):
                if isinstance(item, dict):
                    yield item
        except Exception as exc:  # noqa: BLE001
            # ijson raises various parse errors for malformed JSON; swallow them
            # so we surface whatever was successfully parsed before the error.
            # Re-raise anything that is not a parse-level exception.
            if isinstance(exc, (MemoryError, KeyboardInterrupt, SystemExit)):
                raise
    else:
        stream.seek(0)
        for line in stream:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
                if isinstance(obj, dict):
                    yield obj
            except json.JSONDecodeError:
                pass


# ── Datadog CSV support ────────────────────────────────────────────────────────
# Datadog's "Export to CSV" produces a flat table — typically
# Date,Host,Service,Content (or Date,Host,Service,Message, sometimes with an
# extra Status/Level column and/or a Tags column). There is no structured
# jsonPayload, no severity field (usually), and no request/trace id column —
# those live inside the free-text Content/Message if they exist at all.
# The parser below reshapes each row into the same raw-entry shape the GKE
# JSON parser produces (timestamp / severity / jsonPayload / resource.labels)
# so every downstream endpoint (chain, search, errors, compare, summary)
# keeps working unmodified — Service maps to "container", Host maps to "pod".

_SEV_KEYWORDS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"\b(fatal|panic)\b", re.IGNORECASE), "CRITICAL"),
    # "\w*exception\b" (no leading \b) also matches concatenated exception
    # class names like NullPointerException / ArgumentException.
    (re.compile(r"\b(error|traceback|failed|failure)\b|\w*exception\b", re.IGNORECASE), "ERROR"),
    (re.compile(r"\b(warn|warning|deprecat\w*)\b", re.IGNORECASE), "WARNING"),
    (re.compile(r"\b(debug)\b", re.IGNORECASE), "DEBUG"),
]

def _infer_severity_from_text(text: str) -> str:
    """Best-effort severity when the CSV has no explicit status/level column."""
    for pattern, sev in _SEV_KEYWORDS:
        if pattern.search(text):
            return sev
    return "INFO"


# Datadog's own Status/Level column uses its own vocabulary (warn, err, notice,
# emergency, …) — map it onto the app's canonical severity set so filtering,
# badges and the frontend's fixed severity list (CRITICAL/ERROR/WARNING/INFO/DEBUG)
# work the same for CSV uploads as they do for GKE JSON.
_SEV_ALIASES = {
    "emergency": "CRITICAL", "alert": "CRITICAL", "fatal": "CRITICAL",
    "panic": "CRITICAL", "critical": "CRITICAL", "crit": "CRITICAL",
    "error": "ERROR", "err": "ERROR",
    "warn": "WARNING", "warning": "WARNING",
    "notice": "INFO", "info": "INFO", "information": "INFO", "ok": "INFO",
    "debug": "DEBUG", "trace": "DEBUG",
}

def _normalize_csv_severity(raw: str) -> str:
    return _SEV_ALIASES.get(raw.strip().lower(), raw.strip().upper())


# Explicit correlation fields written as key=value or key: value in free text.
_CSV_CORR_PATTERNS = [
    re.compile(r'\brequest[_-]?id\s*[=:]\s*"?([\w.-]+)"?', re.IGNORECASE),
    re.compile(r'\b(?:trace[_-]?id|dd\.trace_id)\s*[=:]\s*"?([\w.-]+)"?', re.IGNORECASE),
    re.compile(r'\bcorrelation[_-]?id\s*[=:]\s*"?([\w.-]+)"?', re.IGNORECASE),
    re.compile(r'\bsession[_-]?id\s*[=:]\s*"?([\w.-]+)"?', re.IGNORECASE),
    re.compile(r'\b(?:job|task)[_-]?id\s*[=:]\s*"?([\w.-]+)"?', re.IGNORECASE),
]
_CSV_UUID_RE = re.compile(
    r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b", re.IGNORECASE
)
# Domain pattern seen in data-pipeline logs (e.g. "iid=DK0010272632.YYYY.DKK ... date=2026-09-21"):
# an entity id plus a date partition — used to reconstruct the fetch/read pipeline for one entity.
_CSV_ENTITY_RE = re.compile(r"\biid=([^\s/]+)")
_CSV_DATE_PART_RE = re.compile(r"\bdate=(\d{4}-\d{2}-\d{2})")


def _extract_csv_attributes(content: str, last_entity: dict[tuple[str, str], str], hs_key: tuple[str, str]) -> dict[str, str]:
    """Pull correlation/dependency ids out of a free-text log line.

    RequestId → finest-grained correlation (explicit id, else inline UUID).
    ExternalEventId → coarser "which entity/resource is this about" grouping,
    used to reconstruct multi-line pipelines (list → fetch → parse → read).
    When a line carries no entity marker of its own, it inherits the most
    recently seen one for the same Host+Service, since Datadog CSV rows for
    a single pipeline run appear as a contiguous block for that host/service.
    """
    attrs: dict[str, str] = {}

    for pattern in _CSV_CORR_PATTERNS:
        m = pattern.search(content)
        if m:
            attrs["RequestId"] = m.group(1)
            break
    if "RequestId" not in attrs:
        m = _CSV_UUID_RE.search(content)
        if m:
            attrs["RequestId"] = m.group(0)

    entity_m = _CSV_ENTITY_RE.search(content)
    if entity_m:
        key = entity_m.group(1)
        date_m = _CSV_DATE_PART_RE.search(content)
        if date_m:
            key = f"{key}|{date_m.group(1)}"
        attrs["ExternalEventId"] = key
        last_entity[hs_key] = key
    elif hs_key in last_entity:
        attrs["ExternalEventId"] = last_entity[hs_key]

    return attrs


def _parse_datadog_csv(data: bytes):
    """Yield raw GKE-shaped entries parsed from a Datadog CSV export or any
    other delimited log export whose columns loosely follow the same shape
    (a timestamp, an optional host/machine and service/component, an
    optional status/level, and a message/description)."""
    text = data.decode("utf-8-sig", errors="replace")
    reader = csv.DictReader(io.StringIO(text))
    if not reader.fieldnames:
        return

    field_map = {f.strip().lower(): f for f in reader.fieldnames if f}

    def pick(*names: str) -> str | None:
        for n in names:
            if n in field_map:
                return field_map[n]
        return None

    date_field    = pick("date", "timestamp", "time", "@timestamp", "datetime",
                          "occurred", "occurred at", "event_time", "eventtime")
    host_field    = pick("host", "hostname", "machine", "machine name", "computer",
                          "node", "server")
    service_field = pick("service", "service_name", "source", "component",
                          "module", "application", "app", "process")
    status_field  = pick("status", "level", "severity", "priority", "loglevel")
    message_field = pick("content", "message", "msg", "description", "details", "text")
    tags_field    = pick("tags")

    consumed = {f for f in (date_field, host_field, service_field, status_field, message_field, tags_field) if f}
    extra_fields = [f for f in reader.fieldnames if f and f not in consumed]

    last_entity: dict[tuple[str, str], str] = {}

    # Datadog CSV exports list rows newest-first. Context (ExternalEventId)
    # must propagate in chronological order — e.g. the "Listing S3 prefix…"
    # line that names an entity comes chronologically before the "block
    # read…" lines that report on it, even though it appears further down
    # the (reverse-ordered) file. Sort a stable copy for propagation only;
    # output order doesn't matter since the caller re-sorts by timestamp.
    _EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)
    rows = [row for row in reader if row is not None]
    rows.sort(key=lambda r: _parse_dt((r.get(date_field, "") if date_field else "") or "") or _EPOCH)

    for row in rows:
        message = (row.get(message_field, "") if message_field else "") or ""
        host    = (row.get(host_field, "") if host_field else "") or ""
        service = (row.get(service_field, "") if service_field else "") or ""
        raw_status = (row.get(status_field, "") if status_field else "") or ""
        explicit_status = _normalize_csv_severity(raw_status) if raw_status else ""

        payload: dict[str, Any] = {
            "message": message,
            "level": explicit_status or _infer_severity_from_text(message),
        }
        payload.update(_extract_csv_attributes(message, last_entity, (host, service)))
        if tags_field and row.get(tags_field):
            payload["tags"] = row.get(tags_field)
        for f in extra_fields:
            v = row.get(f)
            if v:
                payload[f] = v

        yield {
            "timestamp": (row.get(date_field, "") if date_field else "") or "",
            "severity": explicit_status or None,
            "jsonPayload": payload,
            "resource": {"labels": {"container_name": service, "pod_name": host}},
        }


def _is_csv_upload(data: bytes, filename: str | None) -> bool:
    if filename and filename.lower().endswith(".csv"):
        return True
    stripped = data.lstrip()
    if not stripped or stripped[:1] in (b"{", b"[", b"<"):
        return False
    first_line = stripped.split(b"\n", 1)[0].decode("utf-8", errors="replace")
    return "," in first_line and not _line_starts_with_timestamp(first_line)


# ── plain-text log support ──────────────────────────────────────────────────────
# Custom in-house .log/.txt files: one entry starts on each line that begins
# with a recognizable timestamp; any line that doesn't (e.g. a stack trace
# frame) is appended to the previous entry's message instead of becoming its
# own (timestamp-less, unattributable) entry.

_TS_PATTERNS: list[tuple[re.Pattern, str]] = [
    re.compile(r"^\[?(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\]?"),
    re.compile(r"^\[(\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2} [+-]\d{4})\]"),
    re.compile(r"^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\b"),
    re.compile(r"^(\d{1,2}/\d{1,2}/\d{4}[ T]\d{1,2}:\d{2}:\d{2}(?:\s?[AP]M)?)"),
]
_TS_KINDS = ["iso", "apache", "syslog", "us"]

_LEVEL_TOKEN_RE = re.compile(
    r"\b(TRACE|DEBUG|INFO|NOTICE|WARN(?:ING)?|ERROR|CRIT(?:ICAL)?|FATAL|ALERT|EMERGENCY)\b"
)


def _line_starts_with_timestamp(line: str) -> bool:
    return any(pattern.match(line) for pattern in _TS_PATTERNS)


def _parse_plaintext_timestamp(raw: str, kind: str) -> str | None:
    try:
        if kind == "iso":
            iso = raw.replace(" ", "T", 1) if "T" not in raw else raw
            dt = datetime.fromisoformat(iso.replace(",", ".").replace("Z", "+00:00"))
        elif kind == "apache":
            dt = datetime.strptime(raw, "%d/%b/%Y:%H:%M:%S %z")
        elif kind == "syslog":
            # Syslog (RFC3164-style) has no year; assume the current one — best
            # effort, since the raw text carries no better signal.
            dt = datetime.strptime(f"{datetime.now(timezone.utc).year} {raw}", "%Y %b %d %H:%M:%S")
        elif kind == "us":
            fmt = "%m/%d/%Y %I:%M:%S %p" if re.search(r"[AP]M", raw, re.IGNORECASE) else "%m/%d/%Y %H:%M:%S"
            dt = datetime.strptime(raw.replace("T", " "), fmt)
        else:
            return None
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.isoformat().replace("+00:00", "Z")


def _parse_plaintext_log(data: bytes):
    """Yield raw GKE-shaped entries parsed from an unstructured .log/.txt file."""
    text = data.decode("utf-8-sig", errors="replace")
    last_entity: dict[tuple[str, str], str] = {}
    buffered: list[dict[str, str]] = []
    current: dict[str, str] | None = None

    for line in text.splitlines():
        if not line.strip() and current is None:
            continue
        matched = None
        for pattern, kind in zip(_TS_PATTERNS, _TS_KINDS):
            m = pattern.match(line)
            if m:
                iso = _parse_plaintext_timestamp(m.group(1), kind)
                if iso:
                    matched = (iso, m.end())
                    break
        if matched:
            if current is not None:
                buffered.append(current)
            iso, end = matched
            rest = line[end:].lstrip(" -:\t")
            level_m = _LEVEL_TOKEN_RE.search(rest[:40])
            if level_m:
                severity = _normalize_csv_severity(level_m.group(1))
                if level_m.start() <= 1:
                    # Level token sits right after the timestamp — strip it so
                    # it isn't duplicated between the severity badge and the
                    # message. If it fills an enclosing [..]/(..), drop that
                    # too; otherwise leave surrounding brackets alone (they
                    # likely belong to the next token, e.g. "[ServiceName]").
                    start, end = level_m.start(), level_m.end()
                    if start > 0 and rest[start - 1] in "([" and end < len(rest) and rest[end] in ")]":
                        start -= 1
                        end += 1
                    rest = (rest[:start] + rest[end:]).lstrip(" \t:-")
            else:
                severity = _infer_severity_from_text(rest)
            current = {"timestamp": iso, "message": rest, "severity": severity}
        elif current is not None:
            current["message"] += "\n" + line
        # A line before any timestamp has been seen can't be attributed to an
        # entry, so it's dropped — same "skip what can't be parsed" behaviour
        # as malformed NDJSON lines.
    if current is not None:
        buffered.append(current)

    for entry in buffered:
        message = entry["message"]
        payload: dict[str, Any] = {"message": message, "level": entry["severity"]}
        payload.update(_extract_csv_attributes(message, last_entity, ("", "")))
        yield {
            "timestamp": entry["timestamp"],
            "severity": entry["severity"],
            "jsonPayload": payload,
            "resource": {"labels": {"container_name": "", "pod_name": ""}},
        }


# ── Windows Event Log support (CSV / XML exports) ──────────────────────────────

_WIN_EVT_HEADER_TOKENS = (
    "entrytype", "leveldisplayname", "eventid", "event id", "providername",
    "instanceid", "timecreated", "timegenerated", "machinename",
)


def _looks_like_windows_event_csv(first_line: str) -> bool:
    lower = first_line.lower()
    return sum(1 for tok in _WIN_EVT_HEADER_TOKENS if tok in lower) >= 2


_WIN_TIME_FORMATS = (
    "%m/%d/%Y %I:%M:%S %p",
    "%m/%d/%Y %H:%M:%S",
    "%Y-%m-%dT%H:%M:%S.%fZ",
    "%Y-%m-%dT%H:%M:%SZ",
    "%Y-%m-%d %H:%M:%S",
)


def _normalize_win_evt_timestamp(raw: str) -> str:
    raw = raw.strip()
    if not raw:
        return ""
    for fmt in _WIN_TIME_FORMATS:
        try:
            dt = datetime.strptime(raw, fmt)
        except ValueError:
            continue
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.isoformat().replace("+00:00", "Z")
    try:
        dt = datetime.fromisoformat(raw.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.isoformat().replace("+00:00", "Z")
    except ValueError:
        return raw


def _parse_windows_event_csv(data: bytes):
    """Yield raw GKE-shaped entries from a Get-WinEvent/Get-EventLog CSV export."""
    text = data.decode("utf-8-sig", errors="replace")
    reader = csv.DictReader(io.StringIO(text))
    if not reader.fieldnames:
        return

    field_map = {f.strip().lower(): f for f in reader.fieldnames if f}

    def pick(*names: str) -> str | None:
        for n in names:
            if n in field_map:
                return field_map[n]
        return None

    time_field    = pick("timecreated", "time created", "timegenerated", "time generated", "time", "date and time")
    level_field   = pick("leveldisplayname", "entrytype", "level")
    id_field      = pick("id", "eventid", "event id", "instanceid")
    source_field  = pick("providername", "provider name", "source")
    host_field    = pick("machinename", "machine name", "computer")
    message_field = pick("message", "description")

    consumed = {f for f in (time_field, level_field, id_field, source_field, host_field, message_field) if f}
    extra_fields = [f for f in reader.fieldnames if f and f not in consumed]

    _EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)
    rows = [row for row in reader if row is not None]
    rows.sort(key=lambda r: _parse_dt(_normalize_win_evt_timestamp(
        (r.get(time_field, "") if time_field else "") or "")) or _EPOCH)

    last_entity: dict[tuple[str, str], str] = {}

    for row in rows:
        raw_time = (row.get(time_field, "") if time_field else "") or ""
        iso = _normalize_win_evt_timestamp(raw_time)
        raw_level = (row.get(level_field, "") if level_field else "") or ""
        severity = _normalize_csv_severity(raw_level) if raw_level else "INFO"
        source = (row.get(source_field, "") if source_field else "") or ""
        host = (row.get(host_field, "") if host_field else "") or ""
        message = (row.get(message_field, "") if message_field else "") or ""
        event_id = (row.get(id_field, "") if id_field else "") or ""

        payload: dict[str, Any] = {"message": message, "level": severity}
        payload.update(_extract_csv_attributes(message, last_entity, (source, host)))
        if event_id:
            # EventID is the standard way L2/L3 engineers triage Windows logs
            # ("show me every occurrence of 4625") — it's a more reliable
            # correlation key here than anything free-text extraction finds.
            payload["ExternalEventId"] = f"EventID {event_id}"
            payload["EventID"] = event_id
        for f in extra_fields:
            v = row.get(f)
            if v:
                payload[f] = v

        yield {
            "timestamp": iso,
            "severity": None,
            "jsonPayload": payload,
            "resource": {"labels": {"container_name": source, "pod_name": host}},
        }


_WIN_XML_NS = "{http://schemas.microsoft.com/win/2004/08/events/event}"
_WIN_XML_LEVEL_MAP = {"0": "INFO", "1": "CRITICAL", "2": "ERROR", "3": "WARNING", "4": "INFO", "5": "DEBUG"}


def _win_evt_child(el: ET.Element | None, name: str) -> ET.Element | None:
    return el.find(f"{_WIN_XML_NS}{name}") if el is not None else None


def _parse_windows_event_xml(data: bytes):
    """Yield raw GKE-shaped entries from a Windows Event Log XML export.

    Handles both a single <Event>, a proper <Events><Event/>...</Events>
    document, and the common case of several <Event>...</Event> blocks
    concatenated without any wrapping root (not valid XML on its own —
    retried by synthesizing a root).
    """
    text = data.decode("utf-8-sig", errors="replace").strip()
    if not text:
        return
    try:
        root = ET.fromstring(text)
    except ET.ParseError:
        try:
            root = ET.fromstring(f"<Events>{text}</Events>")
        except ET.ParseError:
            return

    root_tag = root.tag.rsplit("}", 1)[-1]
    events = [root] if root_tag == "Event" else list(root)

    last_entity: dict[tuple[str, str], str] = {}

    for ev in events:
        if ev.tag.rsplit("}", 1)[-1] != "Event":
            continue
        system = _win_evt_child(ev, "System")
        if system is None:
            continue

        provider = _win_evt_child(system, "Provider")
        provider_name = provider.get("Name", "") if provider is not None else ""
        event_id_el = _win_evt_child(system, "EventID")
        event_id = (event_id_el.text or "").strip() if event_id_el is not None else ""
        level_el = _win_evt_child(system, "Level")
        level_raw = (level_el.text or "").strip() if level_el is not None else ""
        severity = _WIN_XML_LEVEL_MAP.get(level_raw, "INFO")
        time_el = _win_evt_child(system, "TimeCreated")
        raw_time = time_el.get("SystemTime", "") if time_el is not None else ""
        iso = _normalize_win_evt_timestamp(raw_time)
        computer_el = _win_evt_child(system, "Computer")
        computer = (computer_el.text or "").strip() if computer_el is not None else ""
        channel_el = _win_evt_child(system, "Channel")
        channel = (channel_el.text or "").strip() if channel_el is not None else ""

        # Raw XML exports rarely include the rendered message text; fall back
        # to reconstructing one from the EventData Name=Value pairs.
        message = ""
        rendering = _win_evt_child(ev, "RenderingInfo")
        if rendering is not None:
            msg_el = _win_evt_child(rendering, "Message")
            if msg_el is not None and msg_el.text:
                message = msg_el.text.strip()
        if not message:
            event_data = _win_evt_child(ev, "EventData")
            pairs = []
            if event_data is not None:
                for d in event_data.findall(f"{_WIN_XML_NS}Data"):
                    name = d.get("Name", "")
                    val = (d.text or "").strip()
                    pairs.append(f"{name}={val}" if name else val)
            detail = "; ".join(p for p in pairs if p)
            message = f"Event {event_id} ({provider_name})" + (f": {detail}" if detail else "")

        payload: dict[str, Any] = {"message": message, "level": severity}
        payload.update(_extract_csv_attributes(message, last_entity, (provider_name, computer)))
        if event_id:
            payload["ExternalEventId"] = f"EventID {event_id}"
            payload["EventID"] = event_id
        if channel:
            payload["Channel"] = channel

        yield {
            "timestamp": iso,
            "severity": None,
            "jsonPayload": payload,
            "resource": {"labels": {"container_name": provider_name, "pod_name": computer}},
        }


# ── AWS CloudWatch Logs support (JSON exports) ──────────────────────────────────
# Recognizes: `aws logs filter-log-events` output ({"events":[...]});
# subscription/export dumps ({"logEvents":[...], "logGroup":..., "logStream":...});
# CloudWatch Logs Insights query results exported as JSON
# ([[{"field":"@timestamp","value":...}, ...], ...]); and a batch (list) of any
# of the dict shapes above.

def _cloudwatch_ms_to_iso(ts_ms: Any) -> str:
    if not isinstance(ts_ms, (int, float)):
        return ""
    try:
        return datetime.fromtimestamp(ts_ms / 1000, tz=timezone.utc).isoformat().replace("+00:00", "Z")
    except (ValueError, OSError, OverflowError):
        return ""


def _cloudwatch_insights_ts_to_iso(raw: str) -> str:
    if not raw:
        return ""
    for fmt in ("%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S"):
        try:
            dt = datetime.strptime(raw, fmt)
            return dt.replace(tzinfo=timezone.utc).isoformat().replace("+00:00", "Z")
        except ValueError:
            continue
    return raw


def _cloudwatch_events_to_entries(events: list, log_group: str, log_stream: str):
    last_entity: dict[tuple[str, str], str] = {}
    for ev in events:
        if not isinstance(ev, dict):
            continue
        # `aws logs filter-log-events` puts logStreamName on each event
        # rather than at the top level; prefer it when present.
        stream = ev.get("logStreamName") or log_stream
        message = str(ev.get("message", "") or "")
        iso = _cloudwatch_ms_to_iso(ev.get("timestamp"))
        payload: dict[str, Any] = {"message": message, "level": _infer_severity_from_text(message)}
        payload.update(_extract_csv_attributes(message, last_entity, (log_group, stream)))
        yield {
            "timestamp": iso,
            "severity": None,
            "jsonPayload": payload,
            "resource": {"labels": {"container_name": log_group, "pod_name": stream}},
        }


def _cloudwatch_insights_to_entries(rows: list):
    last_entity: dict[tuple[str, str], str] = {}
    for row in rows:
        if not isinstance(row, list):
            continue
        fields = {f.get("field"): f.get("value") for f in row if isinstance(f, dict)}
        message = fields.get("@message", "") or ""
        log_stream = fields.get("@logStream", "") or ""
        iso = _cloudwatch_insights_ts_to_iso(fields.get("@timestamp", ""))
        payload: dict[str, Any] = {"message": message, "level": _infer_severity_from_text(message)}
        payload.update(_extract_csv_attributes(message, last_entity, ("", log_stream)))
        for k, v in fields.items():
            if k not in ("@timestamp", "@message", "@logStream", "@ptr") and v:
                payload[k] = v
        yield {
            "timestamp": iso,
            "severity": None,
            "jsonPayload": payload,
            "resource": {"labels": {"container_name": "", "pod_name": log_stream}},
        }


def _as_cloudwatch_entries(obj: Any):
    """Return a generator of raw GKE-shaped entries if `obj` looks like one of
    the known CloudWatch JSON export shapes, else None (caller falls back to
    treating the upload as GKE-style JSON)."""
    if isinstance(obj, dict):
        events = obj.get("logEvents") if isinstance(obj.get("logEvents"), list) else obj.get("events")
        if isinstance(events, list) and events and isinstance(events[0], dict) \
                and "message" in events[0] and "timestamp" in events[0]:
            log_group  = obj.get("logGroup") or obj.get("logGroupName") or ""
            log_stream = obj.get("logStream") or obj.get("logStreamName") or ""
            return _cloudwatch_events_to_entries(events, log_group, log_stream)
        return None

    if isinstance(obj, list) and obj:
        first = obj[0]
        if isinstance(first, list) and first and isinstance(first[0], dict) \
                and "field" in first[0] and "value" in first[0]:
            return _cloudwatch_insights_to_entries(obj)
        if isinstance(first, dict) and ("logEvents" in first or "events" in first):
            def _gen():
                for item in obj:
                    sub = _as_cloudwatch_entries(item)
                    if sub is not None:
                        yield from sub
            return _gen()

    return None


# ── format detection ─────────────────────────────────────────────────────────

def _detect_and_parse(data: bytes, filename: str | None) -> tuple[Any, str]:
    """Sniff an upload's shape and return (entries_iterator, format_name)."""
    stripped = data.lstrip()
    if not stripped:
        return iter(()), "gke_json"

    first_byte = stripped[:1]

    if first_byte in (b"{", b"["):
        try:
            obj = json.loads(stripped)
        except (json.JSONDecodeError, RecursionError):
            obj = None
        if obj is not None:
            cw = _as_cloudwatch_entries(obj)
            if cw is not None:
                return cw, "cloudwatch_json"
        return _stream_entries(data), "gke_json"

    if first_byte == b"<":
        return _parse_windows_event_xml(data), "windows_event_xml"

    if _is_csv_upload(data, filename):
        first_line = stripped.split(b"\n", 1)[0].decode("utf-8", errors="replace")
        if _looks_like_windows_event_csv(first_line):
            return _parse_windows_event_csv(data), "windows_event_csv"
        return _parse_datadog_csv(data), "csv"

    return _parse_plaintext_log(data), "plaintext"


# ── upload ────────────────────────────────────────────────────────────────────

@app.post("/upload")
async def upload(file: UploadFile = File(...)):
    global _store

    data = await file.read()
    source, fmt = _detect_and_parse(data, file.filename)
    entries: list[dict] = []
    skipped = 0

    for raw in source:
        try:
            entries.append(_normalise(raw, len(entries)))
        except Exception:
            skipped += 1

    # Sort by parsed datetime so that entries with different UTC-offset
    # representations (e.g. "Z" vs "+00:00") compare correctly.
    # Fall back to the raw string (epoch sentinel) for entries with no timestamp.
    _EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)
    entries.sort(key=lambda e: _parse_dt(e["_ts"]) or _EPOCH)
    for i, e in enumerate(entries):
        e["_idx"] = i

    by_req:   dict[str, list[int]] = defaultdict(list)
    by_conn:  dict[str, list[int]] = defaultdict(list)
    by_event: dict[str, list[int]] = defaultdict(list)
    by_qmsg:  dict[str, list[int]] = defaultdict(list)

    for i, e in enumerate(entries):
        if e["_request_id"]:        by_req[e["_request_id"]].append(i)
        if e["_connection_id"]:     by_conn[e["_connection_id"]].append(i)
        if e["_external_event_id"]: by_event[e["_external_event_id"]].append(i)
        if e["_queue_message_id"]:  by_qmsg[e["_queue_message_id"]].append(i)

    _store = {
        "entries":           entries,
        "by_request":        dict(by_req),
        "by_connection":     dict(by_conn),
        "by_external_event": dict(by_event),
        "by_queue_message":  dict(by_qmsg),
        "skipped":           skipped,
        "parsed_at":         datetime.now(timezone.utc).isoformat(),
        "format":            fmt,
    }

    return {"total": len(entries), "skipped": skipped, "parsed_at": _store["parsed_at"], "format": fmt}


# ── summary ───────────────────────────────────────────────────────────────────

@app.get("/summary")
def summary():
    entries = _store["entries"]
    if not entries:
        return {
            "total": 0, "skipped": _store["skipped"],
            "severity_counts": {}, "containers": {}, "pods": {},
            "time_min": None, "time_max": None,
            "format": _store.get("format"),
        }
    sev_counts: dict[str, int] = defaultdict(int)
    containers: dict[str, int] = defaultdict(int)
    pods: dict[str, int] = defaultdict(int)
    for e in entries:
        sev_counts[e["_severity"]] += 1
        if e["_container"]: containers[e["_container"]] += 1
        if e["_pod"]:       pods[e["_pod"]] += 1
    timestamps = [e["_ts"] for e in entries if e["_ts"]]
    return {
        "total": len(entries),
        "skipped": _store["skipped"],
        "severity_counts": dict(sev_counts),
        "containers": dict(sorted(containers.items(), key=lambda x: -x[1])[:20]),
        "pods":       dict(sorted(pods.items(),       key=lambda x: -x[1])[:20]),
        "time_min": min(timestamps) if timestamps else None,
        "time_max": max(timestamps) if timestamps else None,
        "parsed_at": _store["parsed_at"],
        "format": _store.get("format"),
    }


# ── entry summary helper (defined before first caller) ────────────────────────

def _entry_summary(e: dict) -> dict:
    p = e.get("jsonPayload") or {}
    st = e.get("_stack_trace", "")
    return {
        "idx":              e["_idx"],
        "timestamp":        e["_ts"],
        "severity":         e["_severity"],
        "container":        e["_container"],
        "pod":              e["_pod"],
        "message":          e["_message"],
        "request_id":       e["_request_id"],
        "connection_id":    e["_connection_id"],
        "insert_id":        e.get("insertId", ""),
        "logger":           e.get("_logger", ""),
        "action":           e.get("_action", ""),
        "scope":            p.get("Scope") or [],
        "exception":        p.get("exception") or "",
        "exception_type":   p.get("exceptionType") or "",
        "exception_message":p.get("exceptionMessage") or "",
        "external_event_id":e.get("_external_event_id", ""),
        "queue_message_id": e.get("_queue_message_id", ""),
        "stack_trace":      st[:3000] if st else "",   # Serilog @x field
        "sender_key":       e.get("_sender_key", ""),
    }


# ── entries (paginated) ───────────────────────────────────────────────────────

@app.get("/entries")
def entries_endpoint(
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=500),
    severity: list[str] = Query(default=[]),
    container: str = Query(default=""),
    time_from: str = Query(default="", alias="timeFrom"),
    time_to: str = Query(default="", alias="timeTo"),
    search: str = Query(default=""),
):
    all_entries = _store["entries"]
    severity_set = {s.upper() for s in severity} if severity else set()
    dt_from = _parse_dt(time_from) if time_from else None
    dt_to   = _parse_dt(time_to)   if time_to   else None
    search_lower = search.lower() if search else ""

    filtered = []
    for e in all_entries:
        if severity_set and e["_severity"] not in severity_set: continue
        if container and e["_container"] != container:           continue
        if dt_from or dt_to:
            dt = _parse_dt(e["_ts"])
            if dt is None:                              continue
            if dt_from and dt < dt_from:                continue
            if dt_to   and dt > dt_to:                  continue
        if search_lower and search_lower not in e["_message"].lower(): continue
        filtered.append(e)

    total = len(filtered)
    start = (page - 1) * page_size
    return {
        "total": total, "page": page, "page_size": page_size,
        "entries": [_entry_summary(e) for e in filtered[start: start + page_size]],
    }


# ── entry detail ──────────────────────────────────────────────────────────────

@app.get("/entry/{idx}")
def entry_detail(idx: int):
    entries = _store["entries"]
    if idx < 0 or idx >= len(entries):
        raise HTTPException(404, "Entry not found")
    e = entries[idx]
    return {"entry": {k: v for k, v in e.items() if not k.startswith("_")},
            "meta": _entry_summary(e)}


# ── multi-index chain lookup ─────────────────────────────────────────────────
# NOTE: must be registered BEFORE /chain/{request_id:path}.  The :path converter
# in that route matches slashes, so it would swallow /chain-any/… as
# request_id="any/…" if this route were ordered after it.

@app.get("/chain-any/{id:path}")
def chain_any(id: str):
    """Search all four indexes (request, connection, external_event, queue_message) for an id."""
    entries = _store["entries"]
    for key in ("by_request", "by_connection", "by_external_event", "by_queue_message"):
        indices = _store.get(key, {}).get(id, [])
        if indices:
            grp = sorted([entries[i] for i in indices], key=lambda e: e["_ts"])
            tss = [e["_ts"] for e in grp if e["_ts"]]
            return {
                "id": id, "total": len(grp),
                "source": key,
                "start_time": min(tss) if tss else None,
                "end_time":   max(tss) if tss else None,
                "entries":    [_entry_summary(e) for e in grp],
            }
    return {"id": id, "total": 0, "source": None, "entries": []}


# ── chain ─────────────────────────────────────────────────────────────────────

@app.get("/chain/{request_id:path}")
def chain(request_id: str):
    entries = _store["entries"]
    indices: set[int] = set()
    indices.update(_store["by_request"].get(request_id, []))
    indices.update(_store["by_connection"].get(request_id, []))
    if not indices:
        return {"request_id": request_id, "entries": [], "total": 0}
    chain_entries = sorted([entries[i] for i in indices], key=lambda e: e["_ts"])
    return {
        "request_id": request_id,
        "total": len(chain_entries),
        "entries": [_entry_summary(e) for e in chain_entries],
    }


# ── errors ────────────────────────────────────────────────────────────────────

@app.get("/errors")
def errors(context_size: int = Query(5, ge=0, le=20)):
    entries = _store["entries"]
    result = []
    for i, e in enumerate(entries):
        if e["_severity"] not in {"ERROR", "CRITICAL"}:
            continue
        result.append({
            "error": _entry_summary(e),
            "context_before": [_entry_summary(entries[j]) for j in range(max(0, i - context_size), i)],
            "context_after":  [_entry_summary(entries[j]) for j in range(i + 1, min(len(entries), i + context_size + 1))],
        })
    return {"total": len(result), "errors": result}


# ── containers ────────────────────────────────────────────────────────────────

@app.get("/containers")
def containers():
    counts: dict[str, int] = defaultdict(int)
    for e in _store["entries"]:
        if e["_container"]:
            counts[e["_container"]] += 1
    return {"containers": sorted(counts.keys())}


# ── search ────────────────────────────────────────────────────────────────────

@app.get("/search")
def search(q: str = Query(...)):
    # Strip whitespace immediately so the stripped value is used consistently
    # in both the early-return path and the matching logic below.
    q = q.strip()
    entries = _store["entries"]
    if not entries:
        return {"query": q, "query_type": "text", "total": 0,
                "event_groups": [], "errors": [], "error_summary": []}

    query_type = _detect_query_type(q)
    q_lower = q.lower()
    matched: list[dict] = []

    if query_type == "uuid":
        for e in entries:
            p = e.get("jsonPayload") or {}
            if (e["_external_event_id"].lower() == q_lower or
                e["_queue_message_id"].lower()  == q_lower or
                e["_request_id"].lower()         == q_lower or
                e["_connection_id"].lower()       == q_lower or
                (p.get("ActionId", "") or "").lower() == q_lower):
                matched.append(e)

    elif query_type == "email":
        for e in entries:
            if _contains_str(e.get("jsonPayload") or {}, q_lower):
                matched.append(e)

    else:  # free text
        for e in entries:
            p = e.get("jsonPayload") or {}
            if (q_lower in e["_message"].lower() or
                q_lower in e["_logger"].lower() or
                q_lower in e["_sender_key"].lower() or
                q_lower in e["_queue_name"].lower() or
                q_lower in (p.get("@mt", "") or "").lower()):
                matched.append(e)

    # cap at 2000 matched entries to keep response size reasonable
    truncated = len(matched) > 2000
    matched = matched[:2000]

    event_groups  = _build_event_groups(matched)
    error_list    = _build_error_list(matched)
    error_summary = _build_error_summary(error_list)

    return {
        "query":        q,
        "query_type":   query_type,
        "total":        len(matched),
        "truncated":    truncated,
        "event_groups": event_groups,
        "errors":       error_list,
        "error_summary":error_summary,
    }


def _build_event_groups(matched: list[dict]) -> list[dict]:
    """Group matched entries by their most-specific correlation ID.

    Priority (highest → lowest): ExternalEventId > QueueMessageId > RequestId.
    An entry is placed in exactly ONE group — the first field in the priority
    list that has a non-empty value. This is intentional: an entry that has
    both an ExternalEventId and a RequestId is logically part of the external
    event, which is the coarser/more user-visible grouping.  If you need an
    entry to appear under multiple groups, collect it before calling this
    function and call it once per desired group type.
    """
    groups: dict[tuple, dict] = {}
    for e in matched:
        placed = False
        for field, gtype in [
            ("_external_event_id", "ExternalEventId"),
            ("_queue_message_id",  "QueueMessageId"),
            ("_request_id",        "RequestId"),
        ]:
            val = e.get(field, "")
            if val:
                key = (field, val)
                if key not in groups:
                    groups[key] = {"group_id": val, "group_type": gtype, "entries": []}
                groups[key]["entries"].append(e)
                placed = True
                break
        if not placed:
            key = ("_none", "(ungrouped)")
            if key not in groups:
                groups[key] = {"group_id": "(ungrouped)", "group_type": "Other", "entries": []}
            groups[key]["entries"].append(e)

    result = []
    for g in groups.values():
        grp = sorted(g["entries"], key=lambda x: x["_ts"])
        err_cnt = sum(1 for x in grp if x["_severity"] in {"ERROR", "CRITICAL"})
        tss = [x["_ts"] for x in grp if x["_ts"]]
        dur_ms: int | None = None
        if len(tss) >= 2:
            t1, t2 = _parse_dt(min(tss)), _parse_dt(max(tss))
            if t1 and t2:
                dur_ms = int((t2 - t1).total_seconds() * 1000)
        result.append({
            "group_id":   g["group_id"],
            "group_type": g["group_type"],
            "start_time": min(tss) if tss else None,
            "end_time":   max(tss) if tss else None,
            "duration_ms":dur_ms,
            "total":      len(grp),
            "error_count":err_cnt,
            "entries":    [_entry_summary(x) for x in grp],
        })

    result.sort(key=lambda g: g["start_time"] or "")
    return result


def _build_error_list(matched: list[dict]) -> list[dict]:
    result = []
    for e in matched:
        if e["_severity"] not in {"ERROR", "CRITICAL"}:
            continue
        s = _entry_summary(e)
        st = e.get("_stack_trace", "")
        s["stack_trace"] = st          # full @x (already truncated in _entry_summary)
        # Structured GKE logs carry a Serilog @x stack trace; plain-text logs
        # (e.g. Datadog CSV) don't, so fall back to a template of the message
        # itself — this is what lets similar errors be grouped and counted as
        # a likely-common root cause even without an exception field.
        s["root_cause"] = (
            st.split("\n")[0].strip() if st else _normalize_template(s.get("message", ""))
        )
        result.append(s)
    return result


def _build_error_summary(errors: list[dict]) -> list[dict]:
    counts: dict[str, dict] = {}
    for err in errors:
        key = (err.get("root_cause") or err.get("exception_type") or "Unknown error")[:200]
        if key not in counts:
            counts[key] = {"exception_type": key, "count": 0, "messages": []}
        counts[key]["count"] += 1
        msg = err.get("message", "")
        if msg and len(counts[key]["messages"]) < 3 and msg not in counts[key]["messages"]:
            counts[key]["messages"].append(msg)
    return sorted(counts.values(), key=lambda x: -x["count"])


# ── event timeline ────────────────────────────────────────────────────────────

@app.get("/event/{external_event_id:path}")
def event_detail(external_event_id: str):
    entries  = _store["entries"]
    by_event = _store.get("by_external_event", {})
    indices  = by_event.get(external_event_id, [])
    if not indices:
        return {"external_event_id": external_event_id,
                "total": 0, "entries": [], "errors": [], "error_summary": []}
    grp = sorted([entries[i] for i in indices], key=lambda e: e["_ts"])
    errors       = _build_error_list(grp)
    error_summary = _build_error_summary(errors)
    tss = [e["_ts"] for e in grp if e["_ts"]]
    return {
        "external_event_id": external_event_id,
        "total":      len(grp),
        "start_time": min(tss) if tss else None,
        "end_time":   max(tss) if tss else None,
        "entries":    [_entry_summary(e) for e in grp],
        "errors":     errors,
        "error_summary": error_summary,
    }


# ── upload-compare ───────────────────────────────────────────────────────────

@app.post("/upload-compare")
async def upload_compare(file: UploadFile = File(...)):
    global _compare_store

    data    = await file.read()
    source, fmt = _detect_and_parse(data, file.filename)
    entries: list[dict] = []
    skipped = 0

    for raw in source:
        try:
            entries.append(_normalise(raw, len(entries)))
        except Exception:
            skipped += 1

    _EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)
    entries.sort(key=lambda e: _parse_dt(e["_ts"]) or _EPOCH)
    for i, e in enumerate(entries):
        e["_idx"] = i

    _compare_store = {
        "entries":   entries,
        "skipped":   skipped,
        "parsed_at": datetime.now(timezone.utc).isoformat(),
        "format":    fmt,
    }
    return {"total": len(entries), "skipped": skipped, "parsed_at": _compare_store["parsed_at"], "format": fmt}


# ── compare ───────────────────────────────────────────────────────────────────

@app.get("/compare")
def compare():
    if not _compare_store or not _compare_store["entries"]:
        raise HTTPException(status_code=400, detail="No comparison file loaded. POST to /upload-compare first.")
    if not _store["entries"]:
        raise HTTPException(status_code=400, detail="No main log file loaded.")

    e1 = _store["entries"]
    e2 = _compare_store["entries"]

    def build_groups(entries: list[dict]) -> dict:
        groups: dict[str, dict] = defaultdict(lambda: {
            "count": 0, "first": None, "last": None, "containers": set()
        })
        for e in entries:
            if e["_severity"] not in {"ERROR", "CRITICAL"}:
                continue
            p    = e.get("jsonPayload") or {}
            raw  = e["_message"] or p.get("exceptionType", "") or p.get("@x", "").split("\n")[0]
            tmpl = _normalize_template(raw) or "{unknown}"
            g    = groups[tmpl]
            g["count"] += 1
            ts = e["_ts"]
            if ts:
                if not g["first"] or ts < g["first"]:
                    g["first"] = ts
                if not g["last"] or ts > g["last"]:
                    g["last"] = ts
            if e["_container"]:
                g["containers"].add(e["_container"])
        return groups

    g1 = build_groups(e1)
    g2 = build_groups(e2)
    all_templates = set(g1) | set(g2)

    new_errors: list[dict]      = []
    resolved_errors: list[dict] = []
    worsened: list[dict]        = []
    improved: list[dict]        = []

    for tmpl in all_templates:
        d1 = g1.get(tmpl)
        d2 = g2.get(tmpl)

        if d2 and not d1:
            new_errors.append({
                "template":   tmpl,
                "count":      d2["count"],
                "first_seen": d2["first"],
                "last_seen":  d2["last"],
                "containers": sorted(d2["containers"]),
            })
        elif d1 and not d2:
            resolved_errors.append({
                "template":        tmpl,
                "count":           d1["count"],
                "last_seen_file1": d1["last"],
                "containers":      sorted(d1["containers"]),
            })
        elif d1 and d2:
            c1, c2 = d1["count"], d2["count"]
            pct    = round((c2 - c1) / max(c1, 1) * 100, 1)
            entry  = {
                "template":     tmpl,
                "count_before": c1,
                "count_after":  c2,
                "pct_change":   pct,
                "first_seen":   d2["first"],
                "last_seen":    d2["last"],
                "containers":   sorted(d2["containers"]),
            }
            if c2 > c1:
                worsened.append(entry)
            else:
                improved.append(entry)

    new_errors.sort(      key=lambda x: -x["count"])
    resolved_errors.sort( key=lambda x: -x["count"])
    worsened.sort(        key=lambda x: -x["pct_change"])
    improved.sort(        key=lambda x:  x["pct_change"])

    def file_stats(entries: list[dict]) -> dict:
        sev: dict[str, int] = defaultdict(int)
        for e in entries:
            sev[e["_severity"]] += 1
        tss = [e["_ts"] for e in entries if e["_ts"]]
        return {
            "total":    len(entries),
            "errors":   sev["ERROR"] + sev["CRITICAL"],
            "warnings": sev["WARNING"],
            "time_min": min(tss) if tss else None,
            "time_max": max(tss) if tss else None,
        }

    s1 = file_stats(e1)
    s2 = file_stats(e2)

    return {
        "summary": {
            "file1":          s1,
            "file2":          s2,
            "delta_errors":   s2["errors"]   - s1["errors"],
            "delta_warnings": s2["warnings"] - s1["warnings"],
        },
        "new_errors":      new_errors,
        "resolved_errors": resolved_errors,
        "worsened":        worsened,
        "improved":        improved,
    }


# ── serve frontend ────────────────────────────────────────────────────────────

import os
frontend_dir = os.path.join(os.path.dirname(__file__), "..", "frontend")
if os.path.isdir(frontend_dir):
    app.mount("/", StaticFiles(directory=frontend_dir, html=True), name="frontend")

if __name__ == "__main__":
    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=False)

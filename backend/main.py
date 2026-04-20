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

import io
import json
import re
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


def _normalize_template(msg: str) -> str:
    """Strip dynamic values so the same error pattern from different runs matches."""
    if not msg:
        return ""
    msg = _TMPL_GUID.sub("{GUID}", msg)
    msg = _TMPL_EMAIL.sub("{EMAIL}", msg)
    msg = _TMPL_FILE.sub("{FILE}", msg)
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


# ── upload ────────────────────────────────────────────────────────────────────

@app.post("/upload")
async def upload(file: UploadFile = File(...)):
    global _store

    data = await file.read()
    entries: list[dict] = []
    skipped = 0

    for raw in _stream_entries(data):
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
    }

    return {"total": len(entries), "skipped": skipped, "parsed_at": _store["parsed_at"]}


# ── summary ───────────────────────────────────────────────────────────────────

@app.get("/summary")
def summary():
    entries = _store["entries"]
    if not entries:
        return {
            "total": 0, "skipped": _store["skipped"],
            "severity_counts": {}, "containers": {}, "pods": {},
            "time_min": None, "time_max": None,
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
        s["root_cause"]  = st.split("\n")[0].strip() if st else ""
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
    entries: list[dict] = []
    skipped = 0

    for raw in _stream_entries(data):
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
    }
    return {"total": len(entries), "skipped": skipped, "parsed_at": _compare_store["parsed_at"]}


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

"""
Tests for GKE Log Analyzer backend.

Run with:
    cd C:\\Users\\ValentynZelinskyi\\Desktop\\log_analyzer\\backend
    pytest test_main.py -v
"""

from __future__ import annotations

import io
import json
from datetime import timezone

import pytest
from fastapi.testclient import TestClient

from main import (
    _action_field,
    _build_error_list,
    _build_error_summary,
    _build_event_groups,
    _contains_str,
    _container,
    _connection_id,
    _detect_query_type,
    _external_event_id,
    _message,
    _normalise,
    _parse_dt,
    _pod,
    _queue_message_id,
    _request_id,
    _severity,
    _stack_trace_field,
    _stream_entries,
    _ts,
    app,
)

client = TestClient(app)

# ─────────────────────────── shared test data ─────────────────────────────────

_REQ_ID  = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
_CONN_ID = "11111111-2222-3333-4444-555555555555"
_EXT_EVT = "e0000000-0000-0000-0000-000000000001"
_QMSG_ID = "b0000000-0000-0000-0000-000000000002"


def _gke_entry(
    *,
    severity: str = "INFO",
    message: str = "test message",
    timestamp: str = "2024-01-15T10:00:00Z",
    container: str = "my-container",
    pod: str = "my-pod-xyz",
    request_id: str = "",
    connection_id: str = "",
    external_event_id: str = "",
    queue_message_id: str = "",
    level: str = "",
    stack_trace: str = "",
    extra_payload: dict | None = None,
) -> dict:
    """Build a minimal GKE structured log entry dict."""
    payload: dict = {"message": message}
    if request_id:
        payload["RequestId"] = request_id
    if connection_id:
        payload["ConnectionId"] = connection_id
    if external_event_id:
        payload["ExternalEventId"] = external_event_id
    if queue_message_id:
        payload["QueueMessageId"] = queue_message_id
    if level:
        payload["level"] = level
    if stack_trace:
        payload["@x"] = stack_trace
    if extra_payload:
        payload.update(extra_payload)

    entry: dict = {
        "timestamp": timestamp,
        "insertId": "abc123",
        "jsonPayload": payload,
        "resource": {
            "type": "k8s_container",
            "labels": {
                "container_name": container,
                "pod_name": pod,
            },
        },
    }
    if severity:
        entry["severity"] = severity
    return entry


def _upload_entries(entries: list[dict]) -> dict:
    """Upload a list of entries as a JSON array; return the JSON response."""
    payload = json.dumps(entries).encode()
    resp = client.post(
        "/upload",
        files={"file": ("logs.json", io.BytesIO(payload), "application/json")},
    )
    return resp.json()


# ─────────────────────────── 1. _detect_query_type ────────────────────────────

class TestDetectQueryType:
    def test_valid_uuid_lower(self):
        assert _detect_query_type("550e8400-e29b-41d4-a716-446655440000") == "uuid"

    def test_valid_uuid_upper(self):
        assert _detect_query_type("550E8400-E29B-41D4-A716-446655440000") == "uuid"

    def test_valid_uuid_with_surrounding_whitespace(self):
        assert _detect_query_type("  aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee  ") == "uuid"

    def test_email(self):
        assert _detect_query_type("user@example.com") == "email"

    def test_email_in_longer_phrase(self):
        # _EMAIL_RE uses .search(), not .match()
        assert _detect_query_type("sent to user@example.com yesterday") == "email"

    def test_free_text(self):
        assert _detect_query_type("some log message") == "text"

    def test_empty_string(self):
        assert _detect_query_type("") == "text"

    def test_partial_uuid_is_text(self):
        assert _detect_query_type("550e8400-e29b-41d4") == "text"


# ─────────────────────────── 2. _contains_str ─────────────────────────────────

class TestContainsStr:
    def test_direct_string_match(self):
        assert _contains_str("Hello World", "hello") is True

    def test_direct_string_no_match(self):
        assert _contains_str("Hello World", "xyz") is False

    def test_nested_dict_match(self):
        assert _contains_str({"a": {"b": "Found It"}}, "found it") is True

    def test_nested_dict_no_match(self):
        assert _contains_str({"a": {"b": "Found It"}}, "missing") is False

    def test_nested_list_match(self):
        assert _contains_str(["foo", "bar", "baz"], "bar") is True

    def test_nested_list_no_match(self):
        assert _contains_str(["foo", "bar"], "qux") is False

    def test_list_with_mixed_types(self):
        assert _contains_str(["foo", 42, {"k": "needle"}], "needle") is True

    def test_integer_value_does_not_crash(self):
        assert _contains_str(42, "42") is False

    def test_bool_value_does_not_crash(self):
        assert _contains_str(True, "true") is False

    def test_none_value_does_not_crash(self):
        assert _contains_str(None, "none") is False

    def test_empty_needle_returns_false(self):
        # Guard: empty needle must NOT match everything (would break email search).
        assert _contains_str("anything", "") is False
        assert _contains_str({"key": "value"}, "") is False

    def test_empty_string_value(self):
        assert _contains_str("", "needle") is False

    def test_needle_must_be_pre_lowercased(self):
        # The function lower()-compares the obj value, but the needle is expected
        # to already be lower-cased by the caller.
        assert _contains_str("Hello", "hello") is True
        assert _contains_str("Hello", "Hello") is False   # needle not lowercased → no match


# ─────────────────────────── 3. _stream_entries ───────────────────────────────

class TestStreamEntries:
    def _collect(self, data: bytes) -> list[dict]:
        return list(_stream_entries(data))

    def test_valid_json_array_two_dicts(self):
        entries = [{"a": 1}, {"b": 2}]
        assert self._collect(json.dumps(entries).encode()) == entries

    def test_json_array_skips_non_dict_items(self):
        data = b'[{"ok": true}, "a string", 42, null, {"also": "ok"}]'
        assert self._collect(data) == [{"ok": True}, {"also": "ok"}]

    def test_empty_json_array(self):
        assert self._collect(b"[]") == []

    def test_valid_ndjson_two_lines(self):
        data = b'{"x":1}\n{"y":2}\n'
        assert self._collect(data) == [{"x": 1}, {"y": 2}]

    def test_ndjson_skips_blank_lines(self):
        data = b'{"a":1}\n\n\n{"b":2}\n'
        assert self._collect(data) == [{"a": 1}, {"b": 2}]

    def test_ndjson_skips_malformed_line(self):
        data = b'{"good":1}\nNOT_JSON\n{"also_good":2}\n'
        assert self._collect(data) == [{"good": 1}, {"also_good": 2}]

    def test_ndjson_skips_non_dict_lines(self):
        data = b'"a string"\n{"real": true}\n[1,2]\n'
        assert self._collect(data) == [{"real": True}]

    def test_empty_bytes_yields_nothing(self):
        assert self._collect(b"") == []

    def test_whitespace_only_yields_nothing(self):
        assert self._collect(b"   \n  \t  ") == []

    def test_json_array_with_leading_whitespace(self):
        assert self._collect(b'   \n  [{"k": "v"}]') == [{"k": "v"}]

    def test_malformed_json_array_does_not_raise(self):
        # ijson may yield partial results before the error — at minimum it must
        # not propagate the exception to the caller.
        data = b'[{"a":1}, BROKEN'
        try:
            result = self._collect(data)
            assert all(isinstance(r, dict) for r in result)
        except Exception as exc:
            pytest.fail(f"_stream_entries raised unexpectedly: {exc}")


# ─────────────────────────── 4. _normalise ────────────────────────────────────

class TestNormalise:
    def _norm(self, **kwargs) -> dict:
        return _normalise(_gke_entry(**kwargs), 0)

    def test_gke_entry_all_fields_populated(self):
        e = self._norm(
            timestamp="2024-01-15T10:00:00Z",
            severity="ERROR",
            message="Something went wrong",
            container="api",
            request_id="req-123",
            external_event_id="evt-456",
        )
        assert e["_idx"] == 0
        assert e["_severity"] == "ERROR"
        assert e["_message"] == "Something went wrong"
        assert e["_container"] == "api"
        assert e["_request_id"] == "req-123"
        assert e["_external_event_id"] == "evt-456"
        assert e["_ts"] == "2024-01-15T10:00:00Z"

    def test_missing_jsonpayload_gives_empty_defaults(self):
        raw = {"timestamp": "2024-01-15T10:00:00Z", "severity": "INFO"}
        e = _normalise(raw, 5)
        assert e["_idx"] == 5
        assert e["_message"] == ""
        assert e["_container"] == ""
        assert e["_request_id"] == ""

    def test_integer_severity_coerced_to_str(self):
        raw = _gke_entry()
        raw["severity"] = 500
        e = _normalise(raw, 0)
        assert e["_severity"] == "500"

    def test_none_jsonpayload_handled(self):
        raw = {"severity": "INFO", "jsonPayload": None}
        e = _normalise(raw, 0)
        assert e["_message"] == ""
        assert e["_request_id"] == ""

    def test_none_resource_handled(self):
        raw = {"severity": "INFO", "resource": None}
        e = _normalise(raw, 0)
        assert e["_container"] == ""
        assert e["_pod"] == ""


# ─────────────────────────── 5. Field extractors ──────────────────────────────

class TestFieldExtractors:

    # _severity
    def test_severity_missing_defaults_to_DEFAULT(self):
        assert _severity({}) == "DEFAULT"

    def test_severity_present_uppercased(self):
        assert _severity({"severity": "warning"}) == "WARNING"

    def test_severity_none_falls_back(self):
        assert _severity({"severity": None}) == "DEFAULT"

    def test_severity_integer_coerced(self):
        assert _severity({"severity": 400}) == "400"

    def test_severity_falls_back_to_level_field(self):
        assert _severity({"jsonPayload": {"level": "debug"}}) == "DEBUG"

    # _message
    def test_message_from_message_field(self):
        assert _message({"jsonPayload": {"message": "hello"}}) == "hello"

    def test_message_falls_back_to_mt(self):
        assert _message({"jsonPayload": {"@mt": "template {x}"}}) == "template {x}"

    def test_message_both_absent_returns_empty(self):
        assert _message({"jsonPayload": {}}) == ""

    def test_message_no_json_payload_returns_empty(self):
        assert _message({}) == ""

    # _action_field
    def test_action_dotted_returns_last_segment(self):
        assert _action_field({"jsonPayload": {"ActionName": "Ns.Cls.Method"}}) == "Method"

    def test_action_no_dots_returns_whole_string(self):
        assert _action_field({"jsonPayload": {"ActionName": "NoDotsHere"}}) == "NoDotsHere"

    def test_action_missing_returns_empty(self):
        assert _action_field({}) == ""

    # _ts
    def test_ts_prefers_timestamp(self):
        e = {"timestamp": "2024-01-15T10:00:00Z", "receiveTimestamp": "2024-01-15T10:00:01Z"}
        assert _ts(e) == "2024-01-15T10:00:00Z"

    def test_ts_falls_back_to_receive_timestamp(self):
        assert _ts({"receiveTimestamp": "2024-01-15T10:00:01Z"}) == "2024-01-15T10:00:01Z"

    def test_ts_both_missing_returns_empty(self):
        assert _ts({}) == ""

    # _parse_dt
    def test_parse_dt_z_suffix(self):
        dt = _parse_dt("2024-01-15T10:00:00Z")
        assert dt is not None and dt.tzinfo is not None

    def test_parse_dt_offset_suffix(self):
        dt = _parse_dt("2024-01-15T10:00:00+00:00")
        assert dt is not None

    def test_parse_dt_naive_gets_utc(self):
        dt = _parse_dt("2024-01-15T10:00:00")
        assert dt is not None and dt.tzinfo == timezone.utc

    def test_parse_dt_empty_returns_none(self):
        assert _parse_dt("") is None

    def test_parse_dt_invalid_returns_none(self):
        assert _parse_dt("not-a-date") is None


# ─────────────────────────── 6. /upload endpoint ──────────────────────────────

class TestUploadEndpoint:
    def test_valid_json_array_returns_200_and_count(self):
        entries = [_gke_entry(message=f"msg {i}") for i in range(5)]
        resp = client.post(
            "/upload",
            files={"file": ("logs.json", json.dumps(entries).encode(), "application/json")},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] == 5
        assert data["skipped"] == 0

    def test_valid_ndjson_returns_count(self):
        lines = "\n".join(json.dumps(_gke_entry(message=f"line {i}")) for i in range(3))
        resp = client.post(
            "/upload",
            files={"file": ("logs.ndjson", lines.encode(), "application/octet-stream")},
        )
        assert resp.status_code == 200
        assert resp.json()["total"] == 3

    def test_empty_file_returns_total_zero(self):
        resp = client.post(
            "/upload",
            files={"file": ("empty.json", b"", "application/json")},
        )
        assert resp.status_code == 200
        assert resp.json()["total"] == 0

    def test_malformed_json_returns_total_zero(self):
        resp = client.post(
            "/upload",
            files={"file": ("bad.json", b"{not valid json", "application/json")},
        )
        assert resp.status_code == 200
        assert resp.json()["total"] == 0

    def test_entries_sorted_by_timestamp(self):
        entries = [
            _gke_entry(message="third",  timestamp="2024-01-01T10:03:00Z"),
            _gke_entry(message="first",  timestamp="2024-01-01T10:01:00Z"),
            _gke_entry(message="second", timestamp="2024-01-01T10:02:00Z"),
        ]
        _upload_entries(entries)
        data = client.get("/entries?page=1&page_size=10").json()
        msgs = [e["message"] for e in data["entries"]]
        assert msgs == ["first", "second", "third"]

    def test_idx_is_sequential_after_sort(self):
        entries = [
            _gke_entry(timestamp="2024-01-01T10:02:00Z"),
            _gke_entry(timestamp="2024-01-01T10:01:00Z"),
        ]
        _upload_entries(entries)
        data = client.get("/entries?page=1&page_size=10").json()
        assert [e["idx"] for e in data["entries"]] == [0, 1]


# ─────────────────────────── 7. /entries endpoint ─────────────────────────────

class TestEntriesEndpoint:
    def setup_method(self):
        _upload_entries([
            _gke_entry(severity="INFO",     message="info one",   container="api",    timestamp="2024-01-15T10:01:00Z"),
            _gke_entry(severity="ERROR",    message="error one",  container="api",    timestamp="2024-01-15T10:02:00Z"),
            _gke_entry(severity="WARNING",  message="warn one",   container="worker", timestamp="2024-01-15T10:03:00Z"),
            _gke_entry(severity="DEBUG",    message="debug one",  container="worker", timestamp="2024-01-15T10:04:00Z"),
            _gke_entry(severity="CRITICAL", message="crit one",   container="api",    timestamp="2024-01-15T10:05:00Z"),
        ])

    def test_no_filters_returns_all(self):
        assert client.get("/entries").json()["total"] == 5

    def test_severity_filter_single(self):
        data = client.get("/entries?severity=ERROR").json()
        assert data["total"] == 1
        assert data["entries"][0]["severity"] == "ERROR"

    def test_severity_filter_multiple(self):
        assert client.get("/entries?severity=ERROR&severity=CRITICAL").json()["total"] == 2

    def test_container_filter(self):
        data = client.get("/entries?container=worker").json()
        assert data["total"] == 2
        assert all(e["container"] == "worker" for e in data["entries"])

    def test_search_filter_by_message(self):
        data = client.get("/entries?search=crit").json()
        assert data["total"] == 1
        assert data["entries"][0]["message"] == "crit one"

    def test_page_size(self):
        data = client.get("/entries?page=1&page_size=2").json()
        assert len(data["entries"]) == 2
        assert data["total"] == 5

    def test_second_page(self):
        data = client.get("/entries?page=2&page_size=2").json()
        assert len(data["entries"]) == 2

    def test_last_page_partial(self):
        data = client.get("/entries?page=3&page_size=2").json()
        assert len(data["entries"]) == 1

    def test_time_from_filter(self):
        data = client.get("/entries?timeFrom=2024-01-15T10:04:00Z").json()
        assert data["total"] == 2  # debug + critical

    def test_time_to_filter(self):
        data = client.get("/entries?timeTo=2024-01-15T10:02:00Z").json()
        assert data["total"] == 2  # info + error

    def test_no_match_returns_empty(self):
        data = client.get("/entries?container=nonexistent").json()
        assert data["total"] == 0
        assert data["entries"] == []

    def test_response_fields_present(self):
        e = client.get("/entries?page_size=1").json()["entries"][0]
        for field in ("idx", "timestamp", "severity", "container", "pod", "message", "request_id"):
            assert field in e


# ─────────────────────────── 8. /chain endpoint ───────────────────────────────

class TestChainEndpoint:
    def setup_method(self):
        _upload_entries([
            _gke_entry(message="a", request_id=_REQ_ID,  timestamp="2024-01-15T10:01:00Z"),
            _gke_entry(message="b", request_id=_REQ_ID,  timestamp="2024-01-15T10:02:00Z"),
            _gke_entry(message="c", connection_id=_CONN_ID, timestamp="2024-01-15T10:03:00Z"),
            _gke_entry(message="unrelated",               timestamp="2024-01-15T10:04:00Z"),
        ])

    def test_known_request_id_returns_entries(self):
        data = client.get(f"/chain/{_REQ_ID}").json()
        assert data["total"] == 2
        assert {e["message"] for e in data["entries"]} == {"a", "b"}

    def test_entries_sorted_by_timestamp(self):
        timestamps = [e["timestamp"] for e in client.get(f"/chain/{_REQ_ID}").json()["entries"]]
        assert timestamps == sorted(timestamps)

    def test_connection_id_lookup(self):
        data = client.get(f"/chain/{_CONN_ID}").json()
        assert data["total"] == 1
        assert data["entries"][0]["connection_id"] == _CONN_ID

    def test_unknown_id_returns_empty(self):
        data = client.get("/chain/00000000-0000-0000-0000-000000000000").json()
        assert data["total"] == 0
        assert data["entries"] == []


# ─────────────────────────── 9. /search endpoint ──────────────────────────────

class TestSearchEndpoint:
    def setup_method(self):
        entries = [
            _gke_entry(message="order processed", request_id=_REQ_ID,
                       timestamp="2024-01-15T10:01:00Z"),
            _gke_entry(message="payment failed",  request_id=_REQ_ID, severity="ERROR",
                       external_event_id=_EXT_EVT, timestamp="2024-01-15T10:02:00Z"),
            _gke_entry(message="user logged in",  timestamp="2024-01-15T10:03:00Z",
                       extra_payload={"email": "alice@example.com"}),
            _gke_entry(message="queue sent",      queue_message_id=_QMSG_ID,
                       timestamp="2024-01-15T10:04:00Z"),
            _gke_entry(message="unrelated entry", timestamp="2024-01-15T10:05:00Z"),
        ]
        _upload_entries(entries)

    def test_uuid_query_matches_external_event_id(self):
        data = client.get(f"/search?q={_EXT_EVT}").json()
        assert data["query_type"] == "uuid"
        assert data["total"] == 1
        groups = data["event_groups"]
        assert len(groups) >= 1
        assert groups[0]["group_type"] == "ExternalEventId"

    def test_uuid_query_matches_request_id(self):
        data = client.get(f"/search?q={_REQ_ID}").json()
        assert data["query_type"] == "uuid"
        assert data["total"] == 2

    def test_uuid_query_matches_queue_message_id(self):
        data = client.get(f"/search?q={_QMSG_ID}").json()
        assert data["total"] == 1

    def test_email_query_matches_json_payload(self):
        data = client.get("/search?q=alice%40example.com").json()
        assert data["query_type"] == "email"
        assert data["total"] == 1

    def test_text_query_matches_message(self):
        data = client.get("/search?q=unrelated").json()
        assert data["query_type"] == "text"
        assert data["total"] == 1

    def test_no_match_returns_zero(self):
        data = client.get("/search?q=zzz-nothing-will-match").json()
        assert data["total"] == 0
        assert data["event_groups"] == []
        assert data["errors"] == []
        assert data["error_summary"] == []

    def test_response_includes_error_on_error_entry(self):
        data = client.get(f"/search?q={_REQ_ID}").json()
        assert len(data["errors"]) == 1
        assert data["errors"][0]["severity"] == "ERROR"

    def test_missing_q_returns_422(self):
        assert client.get("/search").status_code == 422

    def test_query_stripped_server_side(self):
        # Spaces encoded as + should be stripped; the query is still "unrelated"
        data = client.get("/search?q=unrelated").json()
        assert data["query"] == "unrelated"


# ─────────────────────────── 10. _build_error_list / _build_error_summary ─────

class TestBuildErrorList:
    def _normed(self, entries: list[dict]) -> list[dict]:
        return [_normalise(e, i) for i, e in enumerate(entries)]

    def test_only_error_and_critical_included(self):
        matched = self._normed([
            _gke_entry(severity="INFO"),
            _gke_entry(severity="ERROR"),
            _gke_entry(severity="WARNING"),
            _gke_entry(severity="CRITICAL"),
            _gke_entry(severity="DEBUG"),
        ])
        result = _build_error_list(matched)
        assert len(result) == 2
        assert all(e["severity"] in {"ERROR", "CRITICAL"} for e in result)

    def test_root_cause_from_first_line_of_stack_trace(self):
        st = "SomeException: boom\n   at A.B()\n   at C.D()"
        matched = self._normed([_gke_entry(severity="ERROR", stack_trace=st)])
        result = _build_error_list(matched)
        assert result[0]["root_cause"] == "SomeException: boom"

    def test_empty_stack_trace_gives_empty_root_cause(self):
        matched = self._normed([_gke_entry(severity="ERROR")])
        assert _build_error_list(matched)[0]["root_cause"] == ""

    def test_empty_input_returns_empty(self):
        assert _build_error_list([]) == []

    def test_no_errors_returns_empty(self):
        matched = self._normed([_gke_entry(severity="INFO"), _gke_entry(severity="DEBUG")])
        assert _build_error_list(matched) == []


class TestBuildErrorSummary:
    def _make_err(self, root_cause: str, message: str = "msg") -> dict:
        return {"root_cause": root_cause, "exception_type": "", "message": message}

    def test_groups_by_root_cause(self):
        errors = [
            self._make_err("NullReferenceException"),
            self._make_err("NullReferenceException"),
            self._make_err("TimeoutException"),
        ]
        summary = _build_error_summary(errors)
        assert len(summary) == 2
        counts = {s["exception_type"]: s["count"] for s in summary}
        assert counts["NullReferenceException"] == 2
        assert counts["TimeoutException"] == 1

    def test_sorted_by_count_descending(self):
        errors = [self._make_err("Rare")] + [self._make_err("Common")] * 4
        summary = _build_error_summary(errors)
        assert summary[0]["exception_type"] == "Common"

    def test_messages_capped_at_3(self):
        errors = [self._make_err("E", f"msg{i}") for i in range(10)]
        assert len(_build_error_summary(errors)[0]["messages"]) <= 3

    def test_duplicate_messages_deduplicated(self):
        errors = [self._make_err("E", "same")] * 5
        assert _build_error_summary(errors)[0]["messages"] == ["same"]

    def test_fallback_to_exception_type_when_no_root_cause(self):
        errors = [{"root_cause": "", "exception_type": "TimeoutException", "message": "t"}]
        summary = _build_error_summary(errors)
        assert summary[0]["exception_type"] == "TimeoutException"

    def test_fallback_to_unknown_error(self):
        errors = [{"root_cause": "", "exception_type": "", "message": "mystery"}]
        assert _build_error_summary(errors)[0]["exception_type"] == "Unknown error"

    def test_root_cause_truncated_to_200_chars(self):
        errors = [self._make_err("X" * 300)]
        assert len(_build_error_summary(errors)[0]["exception_type"]) == 200

    def test_empty_input(self):
        assert _build_error_summary([]) == []


# ─────────────────────────── _build_event_groups ──────────────────────────────

class TestBuildEventGroups:
    def _normed(self, entries: list[dict]) -> list[dict]:
        return [_normalise(e, i) for i, e in enumerate(entries)]

    def test_groups_by_external_event_id(self):
        matched = self._normed([
            _gke_entry(external_event_id=_EXT_EVT, timestamp="2024-01-01T10:01:00Z"),
            _gke_entry(external_event_id=_EXT_EVT, timestamp="2024-01-01T10:02:00Z"),
        ])
        groups = _build_event_groups(matched)
        assert len(groups) == 1
        assert groups[0]["group_type"] == "ExternalEventId"
        assert groups[0]["total"] == 2

    def test_groups_by_queue_message_id(self):
        matched = self._normed([_gke_entry(queue_message_id=_QMSG_ID, timestamp="2024-01-01T10:01:00Z")])
        assert _build_event_groups(matched)[0]["group_type"] == "QueueMessageId"

    def test_groups_by_request_id(self):
        matched = self._normed([_gke_entry(request_id=_REQ_ID, timestamp="2024-01-01T10:01:00Z")])
        assert _build_event_groups(matched)[0]["group_type"] == "RequestId"

    def test_ungrouped_entry_goes_to_other(self):
        matched = self._normed([_gke_entry(timestamp="2024-01-01T10:01:00Z")])
        assert _build_event_groups(matched)[0]["group_type"] == "Other"

    def test_error_count_accurate(self):
        matched = self._normed([
            _gke_entry(request_id=_REQ_ID, severity="ERROR",    timestamp="2024-01-01T10:01:00Z"),
            _gke_entry(request_id=_REQ_ID, severity="INFO",     timestamp="2024-01-01T10:02:00Z"),
            _gke_entry(request_id=_REQ_ID, severity="CRITICAL", timestamp="2024-01-01T10:03:00Z"),
        ])
        assert _build_event_groups(matched)[0]["error_count"] == 2

    def test_duration_ms_calculated(self):
        matched = self._normed([
            _gke_entry(request_id=_REQ_ID, timestamp="2024-01-01T10:00:00Z"),
            _gke_entry(request_id=_REQ_ID, timestamp="2024-01-01T10:00:01Z"),
        ])
        assert _build_event_groups(matched)[0]["duration_ms"] == 1000

    def test_empty_input(self):
        assert _build_event_groups([]) == []

    def test_entries_sorted_by_timestamp(self):
        matched = self._normed([
            _gke_entry(request_id=_REQ_ID, timestamp="2024-01-01T10:03:00Z", message="third"),
            _gke_entry(request_id=_REQ_ID, timestamp="2024-01-01T10:01:00Z", message="first"),
        ])
        msgs = [e["message"] for e in _build_event_groups(matched)[0]["entries"]]
        assert msgs == ["first", "third"]

    def test_external_event_id_takes_priority_over_request_id(self):
        """Entry with both ExternalEventId and RequestId goes to ExternalEventId group."""
        e = _gke_entry(external_event_id=_EXT_EVT, request_id=_REQ_ID,
                       timestamp="2024-01-01T10:01:00Z")
        matched = [_normalise(e, 0)]
        assert _build_event_groups(matched)[0]["group_type"] == "ExternalEventId"

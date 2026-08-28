from __future__ import annotations

import csv
import sys
from collections import Counter
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from bgp_incident_detection.mrt_parser import (  # noqa: E402
    PARSED_FIELDS,
    classify_message_type,
    isoformat_ms_from_epoch,
    origin_asn_from_path,
    parse_as_path,
    parse_bgpdump_line,
)


def _read_csv(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def test_timestamp_conversion_to_utc_iso8601_milliseconds() -> None:
    assert isoformat_ms_from_epoch("1761832822.388866") == "2025-10-30T14:00:22.388Z"


def test_as_path_and_origin_asn_extraction() -> None:
    as_path = "22652 6939 138840 138840 58495"

    assert parse_as_path(as_path) == ["22652", "6939", "138840", "138840", "58495"]
    assert origin_asn_from_path(as_path) == "58495"


def test_announcement_and_withdrawal_classification() -> None:
    assert classify_message_type("A") == "announcement"
    assert classify_message_type("W") == "withdrawal"
    assert classify_message_type("STATE") == "other"


def test_parse_bgpdump_announcement_schema_and_incident_uid() -> None:
    line = (
        "BGP4MP_ET|1761832822.388866|A|45.61.0.85|22652|36.50.100.0/23|"
        "22652 6939 138840 58495|IGP|45.61.0.85|0|0||NAG||"
    )

    parsed = parse_bgpdump_line(line, "Leak:426871", Path("updates.20251030.1400.bz2"), "route-views2")

    assert parsed is not None
    assert list(parsed) == PARSED_FIELDS
    assert parsed["incident_uid"] == "Leak:426871"
    assert parsed["bgp_timestamp_utc"] == "2025-10-30T14:00:22.388Z"
    assert parsed["announcement_or_withdrawal"] == "announcement"
    assert parsed["prefix"] == "36.50.100.0/23"
    assert parsed["origin_asn"] == "58495"
    assert parsed["next_hop"] == "45.61.0.85"


def test_parse_bgpdump_withdrawal_schema() -> None:
    line = "BGP4MP_ET|1761832822.388866|W|45.61.0.85|22652|36.50.100.0/23"

    parsed = parse_bgpdump_line(line, "Hijack:125889", Path("updates.20251030.1400.bz2"), "route-views2")

    assert parsed is not None
    assert list(parsed) == PARSED_FIELDS
    assert parsed["incident_uid"] == "Hijack:125889"
    assert parsed["announcement_or_withdrawal"] == "withdrawal"
    assert parsed["as_path"] == ""
    assert parsed["origin_asn"] == ""


def test_parser_environment_documents_bgpdump() -> None:
    rows = _read_csv(ROOT / "data/pilot/mrt_parser_environment_v1.csv")

    assert rows == [
        {
            "tool_or_library": "bgpdump",
            "version": "1.6.2",
            "exact_command_or_function": "bgpdump -q -m <input-file.bz2>",
            "input_format": "RouteViews MRT UPDATE .bz2",
            "output_fields": "|".join(PARSED_FIELDS),
            "row_granularity": "one prefix-level announcement or withdrawal observation emitted by bgpdump -m",
        }
    ]


def test_raw_message_counts_preserve_mrt_and_prefix_observation_counts() -> None:
    rows = _read_csv(ROOT / "data/pilot/raw_bgp_message_counts_v1.csv")
    totals = next(row for row in rows if row["incident_uid"] == "ALL_PILOT_INCIDENTS")

    assert totals["mrt_files"] == "216"
    assert totals["parsed_mrt_records"] == "58065989"
    assert totals["bgp_update_messages"] == "58065989"
    assert totals["announcement_nlri_observations"] == "54591089"
    assert totals["withdrawal_nlri_observations"] == "3474900"
    assert totals["total_prefix_level_observations"] == "58065989"
    assert totals["aggregation_level"] == "all_pilot"


def test_parsed_sample_has_required_schema_and_class_coverage() -> None:
    rows = _read_csv(ROOT / "data/pilot/parsed_bgp_sample_v1.csv")

    assert len(rows) == 60
    assert list(rows[0]) == PARSED_FIELDS
    assert Counter(row["incident_uid"].split(":", 1)[0] for row in rows) == {
        "Hijack": 20,
        "Leak": 20,
        "Outage": 20,
    }
    assert all(row["announcement_or_withdrawal"] in {"announcement", "withdrawal"} for row in rows)
    assert any(row["announcement_or_withdrawal"] == "announcement" for row in rows)
    assert any(row["announcement_or_withdrawal"] == "withdrawal" for row in rows)


def test_all_pilot_incidents_pass_parsing_audit_and_are_observable() -> None:
    audit = _read_csv(ROOT / "data/pilot/mrt_parsing_audit_v1.csv")
    relevance = _read_csv(ROOT / "data/pilot/incident_relevance_summary_v1.csv")

    assert len(audit) == 9
    assert {row["status"] for row in audit} == {"PASS"}
    assert all(int(row["parsed_observations"]) > 0 for row in audit)
    assert all(int(row["directly_matching_observations"]) > 0 for row in relevance)

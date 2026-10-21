from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from bgp_incident_detection import rib_index_engine as engine  # noqa: E402


def test_parse_matching_lines_is_deterministic():
    lines = [
        "TABLE_DUMP2|1710000000|B|192.0.2.1|64500|203.0.113.0/24|64496 64511|IGP|192.0.2.254|0|0||NAG||",
        "TABLE_DUMP2|1710000000|B|192.0.2.2|64501|198.51.100.0/24|64520 64521|IGP|192.0.2.253|0|0||NAG||",
    ]
    targets = [
        {"affected_asn": "64511", "affected_prefix": "", "target_kind": "asn", "target_value": "64511"},
        {"affected_asn": "64599", "affected_prefix": "198.51.100.0/24", "target_kind": "prefix", "target_value": "198.51.100.0/24"},
    ]
    first = engine.parse_matching_lines(lines, "route-views2", "2024-03-09T16:00:00Z", "sample.bz2", targets)
    second = engine.parse_matching_lines(lines, "route-views2", "2024-03-09T16:00:00Z", "sample.bz2", targets)
    assert first == second
    assert {row["target_kind"] for row in first} == {"asn", "prefix"}


def test_sqlite_lookup_returns_expected_prefixes_and_origins(tmp_path):
    db = tmp_path / "rib_index.sqlite"
    conn = engine.db_connect(db)
    engine.initialize_db(conn)
    rib = {
        "collector": "route-views2",
        "rib_timestamp": "2024-03-09T16:00:00Z",
        "source_file": str(tmp_path / "rib.20240309.1600.bz2"),
    }
    source = Path(rib["source_file"])
    source.write_bytes(b"BZh91AY&SY")
    checksum = engine.sha256(source)
    rows = [
        {
            "collector": "route-views2",
            "rib_timestamp": "2024-03-09T16:00:00Z",
            "prefix": "203.0.113.0/24",
            "origin_asn": "64511",
            "peer_asn": "64500",
            "as_path": "64496 64511",
            "source_file": str(source),
            "target_kind": "asn",
            "target_value": "64511",
        }
    ]
    engine.insert_index_rows(conn, rib, checksum, rows, "INDEXED", "2024-03-09T16:00:00Z", 0.1, "test", "unit test")
    asn_rows, _ = engine.lookup_asn(conn, "route-views2", "2024-03-09T16:00:00Z", "64511")
    prefix_rows, _ = engine.lookup_prefix(conn, "route-views2", "2024-03-09T16:00:00Z", "203.0.113.0/24")
    assert asn_rows[0]["prefix"] == "203.0.113.0/24"
    assert prefix_rows[0]["origin_asn"] == "64511"
    conn.close()


def test_index_rib_skips_when_checksum_unchanged(tmp_path, monkeypatch):
    db = tmp_path / "rib_index.sqlite"
    conn = engine.db_connect(db)
    engine.initialize_db(conn)
    source = tmp_path / "rib.20240309.1600.bz2"
    source.write_bytes(b"BZh91AY&SY")
    rib = {"collector": "route-views2", "rib_timestamp": "2024-03-09T16:00:00Z", "source_file": str(source)}
    checksum = engine.sha256(source)
    engine.insert_index_rows(conn, rib, checksum, [], "INDEXED", "2024-03-09T16:00:00Z", 0.1, "test", "unit test")
    monkeypatch.setattr(engine, "validate_bzip2", lambda _: True)
    result = engine.index_rib(conn, rib, [], timeout_seconds=1)
    assert result["index_status"] == "INDEXED"
    assert result["elapsed_seconds"] == 0
    assert "skipped unchanged" in result["notes"]
    conn.close()


def test_guardrail_paths_do_not_include_update_mrt_or_holdout():
    protected_outputs = " ".join(str(path) for path in [engine.METHOD_BENCHMARK, engine.BUILD_AUDIT, engine.LOOKUP_BENCHMARK])
    assert "raw_mrt" not in protected_outputs
    assert "updates" not in protected_outputs.lower()
    assert "holdout" not in protected_outputs.lower()

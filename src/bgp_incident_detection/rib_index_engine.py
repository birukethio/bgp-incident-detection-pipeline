from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import signal
import sqlite3
import subprocess
import time
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from statistics import mean, median

try:
    from bgp_incident_detection.audit import write_csv
    from bgp_incident_detection.normal_pool_scale import PRESCREEN_PASS
    from bgp_incident_detection.normal_rib_scale import RIB_REVIEW, ROUTE_PRESENCE_UNSTABLE
    from bgp_incident_detection.rib_cache_index import NO_OBSERVABILITY, ORIGIN_UNSTABLE
    from bgp_incident_detection.rib_normal import parse_rib_line, row_matches_target, validate_bzip2
except ModuleNotFoundError:
    from src.bgp_incident_detection.audit import write_csv
    from src.bgp_incident_detection.normal_pool_scale import PRESCREEN_PASS
    from src.bgp_incident_detection.normal_rib_scale import RIB_REVIEW, ROUTE_PRESENCE_UNSTABLE
    from src.bgp_incident_detection.rib_cache_index import NO_OBSERVABILITY, ORIGIN_UNSTABLE
    from src.bgp_incident_detection.rib_normal import parse_rib_line, row_matches_target, validate_bzip2


MANIFEST = Path("data/normal_scale/rib_cache_fill_benchmark_manifest_v1.csv")
PREVIOUS_RESULTS = Path("data/normal_scale/rib_cache_fill_benchmark_results_v1.csv")
RIB_CACHE_INDEX = Path("data/normal_scale/rib_cache_index_v1.csv")

DB_PATH = Path("data/cache/routeviews_rib/index/rib_index.sqlite")
METHOD_BENCHMARK = Path("data/normal_scale/rib_index_method_benchmark_v1.csv")
ARCHITECTURE_DOC = Path("data/normal_scale/rib_index_architecture_v1.md")
BUILD_AUDIT = Path("data/normal_scale/rib_index_build_audit_v1.csv")
LOOKUP_BENCHMARK = Path("data/normal_scale/rib_indexed_lookup_benchmark_v1.csv")
NO_OBSERVABILITY_REVALIDATION = Path("data/normal_scale/no_observability_revalidation_v1.csv")
NOTEBOOK = Path("notebooks/23_rib_index_engineering.ipynb")

INDEX_TIMEOUT_SECONDS = 180
BENCHMARK_TIMEOUT_SECONDS = 30
USER_AGENT = "bgp-incident-detection-pipeline/0.1"


def load_csv(path: Path) -> list[dict[str, str]]:
    if not path.exists():
        return []
    with path.open(newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def isoformat_z(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def bgpdump_version() -> str:
    try:
        result = subprocess.run(["bgpdump", "-v"], capture_output=True, text=True, timeout=5)
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return "UNAVAILABLE"
    text = "\n".join([result.stdout, result.stderr])
    for line in text.splitlines():
        if "bgpdump version" in line.lower():
            return line.strip()
    return "bgpdump available"


def mrtparse_version() -> str:
    try:
        import mrtparse
    except ModuleNotFoundError:
        return "UNAVAILABLE"
    return getattr(mrtparse, "__version__", "installed-version-unknown")


def sqlite_version() -> str:
    return sqlite3.sqlite_version


def parse_timestamp_from_rib_name(path: Path) -> str:
    # rib.YYYYMMDD.HHMM.bz2
    parts = path.name.split(".")
    if len(parts) < 3:
        return ""
    raw = f"{parts[1]}{parts[2]}"
    parsed = datetime.strptime(raw, "%Y%m%d%H%M").replace(tzinfo=timezone.utc)
    return isoformat_z(parsed)


def cached_rib_paths() -> dict[tuple[str, str], Path]:
    paths: dict[tuple[str, str], Path] = {}
    for row in load_csv(RIB_CACHE_INDEX):
        collector = row.get("collector") or "route-views2"
        ts = row.get("rib_timestamp", "")
        path = Path(row.get("local_path", ""))
        if path.exists() and path.stat().st_size > 0:
            paths[(collector, ts)] = path
    for path in Path("data/cache/routeviews_rib").glob("**/rib.*.bz2"):
        ts = parse_timestamp_from_rib_name(path)
        collector = "route-views2"
        if ts and path.exists() and path.stat().st_size > 0:
            paths.setdefault((collector, ts), path)
    return paths


def benchmark_manifest_rows() -> list[dict[str, str]]:
    rows = load_csv(MANIFEST)
    if len(rows) != 12:
        raise ValueError(f"expected the fixed 12-candidate manifest, found {len(rows)} rows")
    return rows


def required_ribs(manifest: list[dict[str, str]]) -> list[dict[str, str]]:
    paths = cached_rib_paths()
    by_key: dict[tuple[str, str], dict[str, str]] = {}
    for row in manifest:
        for side in ("before", "after"):
            collector = row.get("collector") or "route-views2"
            ts = row[f"rib_{side}_timestamp"]
            path = paths.get((collector, ts))
            by_key[(collector, ts)] = {
                "collector": collector,
                "rib_timestamp": ts,
                "source_file": str(path) if path else "",
            }
    return [by_key[key] for key in sorted(by_key)]


def targets_by_rib(manifest: list[dict[str, str]]) -> dict[tuple[str, str], list[dict[str, str]]]:
    targets: dict[tuple[str, str], dict[tuple[str, str, str], dict[str, str]]] = defaultdict(dict)
    for row in manifest:
        for side in ("before", "after"):
            key = (row.get("collector") or "route-views2", row[f"rib_{side}_timestamp"])
            target_kind = "prefix" if row.get("affected_prefix") else "asn"
            target_value = row.get("affected_prefix") or row["affected_asn"]
            targets[key][(row["candidate_period_id"], target_kind, target_value)] = {
                "candidate_period_id": row["candidate_period_id"],
                "affected_asn": row["affected_asn"],
                "affected_prefix": row.get("affected_prefix", ""),
                "target_kind": target_kind,
                "target_value": target_value,
            }
    return {key: list(value.values()) for key, value in targets.items()}


def representative_ribs(ribs: list[dict[str, str]]) -> list[dict[str, str]]:
    existing = [row for row in ribs if row.get("source_file") and Path(row["source_file"]).exists()]
    ordered = sorted(existing, key=lambda row: Path(row["source_file"]).stat().st_size)
    if len(ordered) < 3:
        return ordered
    return [ordered[0], ordered[len(ordered) // 2], ordered[-1]]


def db_connect(db_path: Path = DB_PATH) -> sqlite3.Connection:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    return conn


def initialize_db(conn: sqlite3.Connection) -> None:
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS rib_routes (
            collector TEXT NOT NULL,
            rib_timestamp TEXT NOT NULL,
            prefix TEXT NOT NULL,
            origin_asn TEXT,
            peer_asn TEXT,
            as_path TEXT,
            source_file TEXT NOT NULL,
            target_kind TEXT NOT NULL,
            target_value TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS rib_index_metadata (
            collector TEXT NOT NULL,
            rib_timestamp TEXT NOT NULL,
            source_file TEXT NOT NULL,
            checksum TEXT NOT NULL,
            index_status TEXT NOT NULL,
            rows_indexed INTEGER NOT NULL,
            started_at TEXT NOT NULL,
            completed_at TEXT NOT NULL,
            elapsed_seconds REAL NOT NULL,
            parser TEXT NOT NULL,
            parser_version TEXT NOT NULL,
            raw_size_bytes INTEGER NOT NULL,
            notes TEXT,
            PRIMARY KEY (collector, rib_timestamp)
        );

        CREATE INDEX IF NOT EXISTS idx_rib_routes_asn
            ON rib_routes (collector, rib_timestamp, origin_asn);
        CREATE INDEX IF NOT EXISTS idx_rib_routes_prefix
            ON rib_routes (collector, rib_timestamp, prefix);
        CREATE INDEX IF NOT EXISTS idx_rib_routes_peer
            ON rib_routes (collector, rib_timestamp, peer_asn);
        CREATE INDEX IF NOT EXISTS idx_rib_routes_target
            ON rib_routes (collector, rib_timestamp, target_kind, target_value);
        """
    )
    conn.commit()


def indexed_metadata(conn: sqlite3.Connection, collector: str, rib_timestamp: str) -> dict[str, object] | None:
    cur = conn.execute(
        """
        SELECT collector, rib_timestamp, source_file, checksum, index_status, rows_indexed
        FROM rib_index_metadata
        WHERE collector = ? AND rib_timestamp = ?
        """,
        (collector, rib_timestamp),
    )
    row = cur.fetchone()
    if row is None:
        return None
    return {
        "collector": row[0],
        "rib_timestamp": row[1],
        "source_file": row[2],
        "checksum": row[3],
        "index_status": row[4],
        "rows_indexed": row[5],
    }


def target_terms(targets: list[dict[str, str]]) -> list[str]:
    terms = sorted({target.get("affected_prefix") or target.get("affected_asn") for target in targets if target.get("affected_prefix") or target.get("affected_asn")})
    return [term for term in terms if term]


def bgpdump_filtered_lines(path: Path, terms: list[str], timeout_seconds: int) -> tuple[list[str], str]:
    if not terms:
        return [], "NO_TARGET_TERMS"
    bgp = subprocess.Popen(
        ["bgpdump", "-q", "-m", str(path)],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
        start_new_session=True,
    )
    grep_cmd = ["grep", "-F"]
    for term in terms:
        grep_cmd.extend(["-e", term])
    grep = subprocess.Popen(
        grep_cmd,
        stdin=bgp.stdout,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
        start_new_session=True,
    )
    if bgp.stdout is not None:
        bgp.stdout.close()
    try:
        output, _ = grep.communicate(timeout=timeout_seconds)
        status = "PASS" if grep.returncode in (0, 1) else f"GREP_RC_{grep.returncode}"
    except subprocess.TimeoutExpired:
        os.killpg(grep.pid, signal.SIGTERM)
        if bgp.poll() is None:
            os.killpg(bgp.pid, signal.SIGTERM)
        output, _ = grep.communicate()
        status = "TIMEOUT"
    finally:
        if bgp.poll() is None:
            os.killpg(bgp.pid, signal.SIGTERM)
        try:
            bgp.wait(timeout=5)
        except subprocess.TimeoutExpired:
            os.killpg(bgp.pid, signal.SIGKILL)
    return output.splitlines(), status


def parse_matching_lines(lines: list[str], collector: str, rib_timestamp: str, source_file: str, targets: list[dict[str, str]]) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    seen: set[tuple[str, str, str, str, str, str, str, str]] = set()
    for line in lines:
        parsed = parse_rib_line(line)
        if parsed is None:
            continue
        for target in targets:
            if not row_matches_target(parsed, target["affected_asn"], target.get("affected_prefix", "")):
                continue
            route = (
                collector,
                rib_timestamp,
                parsed["prefix"],
                parsed["origin_asn"],
                parsed["peer_asn"],
                parsed["as_path"],
                target["target_kind"],
                target["target_value"],
            )
            if route in seen:
                continue
            seen.add(route)
            rows.append(
                {
                    "collector": collector,
                    "rib_timestamp": rib_timestamp,
                    "prefix": parsed["prefix"],
                    "origin_asn": parsed["origin_asn"],
                    "peer_asn": parsed["peer_asn"],
                    "as_path": parsed["as_path"],
                    "source_file": source_file,
                    "target_kind": target["target_kind"],
                    "target_value": target["target_value"],
                }
            )
    return rows


def insert_index_rows(conn: sqlite3.Connection, rib: dict[str, str], checksum: str, rows: list[dict[str, str]], status: str, started: str, elapsed: float, parser_version: str, notes: str) -> None:
    collector = rib["collector"]
    rib_timestamp = rib["rib_timestamp"]
    conn.execute("DELETE FROM rib_routes WHERE collector = ? AND rib_timestamp = ?", (collector, rib_timestamp))
    conn.executemany(
        """
        INSERT INTO rib_routes
        (collector, rib_timestamp, prefix, origin_asn, peer_asn, as_path, source_file, target_kind, target_value)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        [
            (
                row["collector"],
                row["rib_timestamp"],
                row["prefix"],
                row["origin_asn"],
                row["peer_asn"],
                row["as_path"],
                row["source_file"],
                row["target_kind"],
                row["target_value"],
            )
            for row in rows
        ],
    )
    conn.execute(
        """
        INSERT OR REPLACE INTO rib_index_metadata
        (collector, rib_timestamp, source_file, checksum, index_status, rows_indexed, started_at,
         completed_at, elapsed_seconds, parser, parser_version, raw_size_bytes, notes)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            collector,
            rib_timestamp,
            rib["source_file"],
            checksum,
            status,
            len(rows),
            started,
            isoformat_z(datetime.now(timezone.utc)),
            round(elapsed, 3),
            "bgpdump_stream_filtered_to_sqlite",
            parser_version,
            Path(rib["source_file"]).stat().st_size if rib.get("source_file") and Path(rib["source_file"]).exists() else 0,
            notes,
        ),
    )
    conn.commit()


def index_rib(conn: sqlite3.Connection, rib: dict[str, str], targets: list[dict[str, str]], timeout_seconds: int = INDEX_TIMEOUT_SECONDS) -> dict[str, object]:
    path = Path(rib.get("source_file", ""))
    started = isoformat_z(datetime.now(timezone.utc))
    if not path.exists() or not validate_bzip2(path):
        return {
            "collector": rib["collector"],
            "rib_timestamp": rib["rib_timestamp"],
            "source_file": str(path),
            "checksum": "",
            "index_status": "FAILED",
            "rows_indexed": 0,
            "started_at": started,
            "completed_at": isoformat_z(datetime.now(timezone.utc)),
            "elapsed_seconds": 0,
            "parser": "bgpdump_stream_filtered_to_sqlite",
            "parser_version": bgpdump_version(),
            "raw_size_bytes": 0,
            "notes": "raw RIB missing or invalid bzip2",
        }
    checksum = sha256(path)
    current = indexed_metadata(conn, rib["collector"], rib["rib_timestamp"])
    if current and current["index_status"] == "INDEXED" and current["checksum"] == checksum:
        return {
            "collector": rib["collector"],
            "rib_timestamp": rib["rib_timestamp"],
            "source_file": str(path),
            "checksum": checksum,
            "index_status": "INDEXED",
            "rows_indexed": current["rows_indexed"],
            "started_at": started,
            "completed_at": isoformat_z(datetime.now(timezone.utc)),
            "elapsed_seconds": 0,
            "parser": "bgpdump_stream_filtered_to_sqlite",
            "parser_version": bgpdump_version(),
            "raw_size_bytes": path.stat().st_size,
            "notes": "skipped unchanged already-indexed RIB",
        }
    parser_version = bgpdump_version()
    start = time.perf_counter()
    lines, scan_status = bgpdump_filtered_lines(path, target_terms(targets), timeout_seconds)
    rows = parse_matching_lines(lines, rib["collector"], rib["rib_timestamp"], str(path), targets)
    elapsed = time.perf_counter() - start
    status = "INDEXED" if scan_status == "PASS" else "FAILED"
    notes = f"scan_status={scan_status}; targets={len(targets)}; filtered_lines={len(lines)}"
    insert_index_rows(conn, rib, checksum, rows, status, started, elapsed, parser_version, notes)
    return {
        "collector": rib["collector"],
        "rib_timestamp": rib["rib_timestamp"],
        "source_file": str(path),
        "checksum": checksum,
        "index_status": status,
        "rows_indexed": len(rows),
        "started_at": started,
        "completed_at": isoformat_z(datetime.now(timezone.utc)),
        "elapsed_seconds": round(elapsed, 3),
        "parser": "bgpdump_stream_filtered_to_sqlite",
        "parser_version": parser_version,
        "raw_size_bytes": path.stat().st_size,
        "notes": notes,
    }


def lookup_asn(conn: sqlite3.Connection, collector: str, rib_timestamp: str, asn: str) -> tuple[list[dict[str, str]], float]:
    start = time.perf_counter()
    cur = conn.execute(
        """
        SELECT prefix, origin_asn, peer_asn, as_path
        FROM rib_routes
        WHERE collector = ? AND rib_timestamp = ? AND target_kind = 'asn' AND target_value = ?
        """,
        (collector, rib_timestamp, asn),
    )
    rows = [{"prefix": r[0], "origin_asn": r[1] or "", "peer_asn": r[2] or "", "as_path": r[3] or ""} for r in cur.fetchall()]
    return rows, (time.perf_counter() - start) * 1000


def lookup_prefix(conn: sqlite3.Connection, collector: str, rib_timestamp: str, prefix: str) -> tuple[list[dict[str, str]], float]:
    start = time.perf_counter()
    cur = conn.execute(
        """
        SELECT prefix, origin_asn, peer_asn, as_path
        FROM rib_routes
        WHERE collector = ? AND rib_timestamp = ? AND prefix = ?
        """,
        (collector, rib_timestamp, prefix),
    )
    rows = [{"prefix": r[0], "origin_asn": r[1] or "", "peer_asn": r[2] or "", "as_path": r[3] or ""} for r in cur.fetchall()]
    return rows, (time.perf_counter() - start) * 1000


def classify_candidate(row: dict[str, str], before: list[dict[str, str]], after: list[dict[str, str]]) -> dict[str, object]:
    before_origins = sorted({item["origin_asn"] for item in before if item["origin_asn"]})
    after_origins = sorted({item["origin_asn"] for item in after if item["origin_asn"]})
    before_visible = bool(before)
    after_visible = bool(after)
    origin_stable = bool(before_origins) and before_origins == after_origins
    route_stable = before_visible and after_visible
    if route_stable and origin_stable:
        status = PRESCREEN_PASS
        reason = "persistent RIB index confirms before/after visibility and stable origin"
    elif before_visible != after_visible:
        status = ROUTE_PRESENCE_UNSTABLE
        reason = "persistent RIB index found target evidence on only one side"
    elif route_stable and not origin_stable:
        status = ORIGIN_UNSTABLE
        reason = "persistent RIB index found visibility but unstable or missing origin"
    elif not before_visible and not after_visible:
        status = NO_OBSERVABILITY
        reason = "persistent RIB index found no target evidence before or after"
    else:
        status = RIB_REVIEW
        reason = "persistent RIB index evidence remains unresolved"
    return {
        "candidate_period_id": row["candidate_period_id"],
        "associated_incident_uid": row["associated_incident_uid"],
        "associated_category": row["associated_category"],
        "affected_asn": row["affected_asn"],
        "affected_prefix": row.get("affected_prefix", ""),
        "collector": row.get("collector") or "route-views2",
        "rib_before_timestamp": row["rib_before_timestamp"],
        "rib_after_timestamp": row["rib_after_timestamp"],
        "asn_visible_before": str(before_visible),
        "asn_visible_after": str(after_visible),
        "prefix_visible_before": str(bool(before)) if row.get("affected_prefix") else "NOT_APPLICABLE",
        "prefix_visible_after": str(bool(after)) if row.get("affected_prefix") else "NOT_APPLICABLE",
        "origin_before": json.dumps(before_origins, separators=(",", ":")),
        "origin_after": json.dumps(after_origins, separators=(",", ":")),
        "origin_stable": str(origin_stable),
        "route_presence_stable": str(route_stable),
        "prescreen_status": status,
        "reason": reason,
    }


def rerun_candidate_lookups(conn: sqlite3.Connection, manifest: list[dict[str, str]]) -> tuple[list[dict[str, object]], list[float], list[float]]:
    rows: list[dict[str, object]] = []
    asn_times: list[float] = []
    prefix_times: list[float] = []
    for candidate in manifest:
        states = {}
        for side in ("before", "after"):
            collector = candidate.get("collector") or "route-views2"
            ts = candidate[f"rib_{side}_timestamp"]
            if candidate.get("affected_prefix"):
                matched, elapsed = lookup_prefix(conn, collector, ts, candidate["affected_prefix"])
                prefix_times.append(elapsed)
            else:
                matched, elapsed = lookup_asn(conn, collector, ts, candidate["affected_asn"])
                asn_times.append(elapsed)
            states[side] = matched
        result = classify_candidate(candidate, states["before"], states["after"])
        result["before_indexed_rows"] = len(states["before"])
        result["after_indexed_rows"] = len(states["after"])
        result["lookup_backend"] = "sqlite"
        rows.append(result)
    return rows, asn_times, prefix_times


def method_benchmark_row(method: str, rib: dict[str, str], targets: list[dict[str, str]]) -> dict[str, object]:
    path = Path(rib["source_file"])
    start = time.perf_counter()
    rows_indexed = 0
    status = "PASS"
    notes = ""
    parser = method
    parser_version = ""
    if method == "current_bgpdump_target_csv":
        parser_version = bgpdump_version()
        lines, scan_status = bgpdump_filtered_lines(path, target_terms(targets[:1]), BENCHMARK_TIMEOUT_SECONDS)
        rows_indexed = len(parse_matching_lines(lines, rib["collector"], rib["rib_timestamp"], str(path), targets[:1]))
        status = "PASS" if scan_status == "PASS" else "REVIEW"
        notes = f"baseline target scan; scan_status={scan_status}"
    elif method == "python_mrtparse":
        parser_version = mrtparse_version()
        if parser_version == "UNAVAILABLE":
            status = "FAILED"
            notes = "mrtparse not installed"
        else:
            # Keep this benchmark light. It proves practicality without building the production index.
            import mrtparse

            deadline = time.monotonic() + BENCHMARK_TIMEOUT_SECONDS
            try:
                for record in mrtparse.Reader(str(path)):
                    if time.monotonic() > deadline:
                        status = "REVIEW"
                        notes = "timeout before completing representative RIB"
                        break
                    data = record.data
                    if "rib_entries" in data:
                        rows_indexed += 1
                    if rows_indexed >= 5000:
                        notes = "sampled 5000 RIB entries"
                        break
            except Exception as error:  # pragma: no cover - parser errors depend on local binary data
                status = "FAILED"
                notes = f"mrtparse error: {error}"
    else:
        parser_version = f"bgpdump={bgpdump_version()}; sqlite={sqlite_version()}"
        lines, scan_status = bgpdump_filtered_lines(path, target_terms(targets), BENCHMARK_TIMEOUT_SECONDS)
        rows_indexed = len(parse_matching_lines(lines, rib["collector"], rib["rib_timestamp"], str(path), targets))
        status = "PASS" if scan_status == "PASS" else "REVIEW"
        notes = f"multi-target streaming scan; scan_status={scan_status}"
    elapsed = time.perf_counter() - start
    return {
        "method": method,
        "collector": rib["collector"],
        "rib_timestamp": rib["rib_timestamp"],
        "source_file": rib["source_file"],
        "raw_rib_size_bytes": path.stat().st_size,
        "parse_time_seconds": round(elapsed, 3),
        "index_build_time_seconds": round(elapsed, 3),
        "index_size_bytes": 0,
        "rows_indexed": rows_indexed,
        "asn_lookup_latency_ms": "",
        "prefix_lookup_latency_ms": "",
        "repeated_lookup_latency_ms": "",
        "memory_usage_mb": "",
        "parser": parser,
        "parser_version": parser_version,
        "status": status,
        "notes": notes,
    }


def write_architecture_doc(db_path: Path, method_rows: list[dict[str, object]]) -> None:
    ARCHITECTURE_DOC.parent.mkdir(parents=True, exist_ok=True)
    duckdb_note = "DuckDB is not installed in the current Python environment, so this run uses the standard-library SQLite backend with the same relational schema shape."
    ARCHITECTURE_DOC.write_text(
        "\n".join(
            [
                "# RouteViews RIB Index Architecture v1",
                "",
                "## Selected Method",
                "",
                "Streaming `bgpdump -q -m` into a persistent relational index was selected for this step. The index is target-aware: each cached RIB is parsed once for the benchmark targets required by that RIB, and subsequent candidate screening performs SQL lookups instead of rescanning raw RIB files.",
                "",
                duckdb_note,
                "",
                f"Database path: `{db_path}`",
                "",
                "## Tables",
                "",
                "`rib_routes(collector, rib_timestamp, prefix, origin_asn, peer_asn, as_path, source_file, target_kind, target_value)`",
                "",
                "`rib_index_metadata(collector, rib_timestamp, source_file, checksum, index_status, rows_indexed, started_at, completed_at, elapsed_seconds, parser, parser_version, raw_size_bytes, notes)`",
                "",
                "## Lookup Patterns",
                "",
                "- ASN lookup: `collector + rib_timestamp + target_kind='asn' + target_value` returns route count, prefixes, peers, origins, and AS paths.",
                "- Prefix lookup: `collector + rib_timestamp + prefix` returns origin ASNs, peer ASNs, and AS paths.",
                "",
                "## Resumability",
                "",
                "A rerun computes each raw RIB SHA-256 checksum and skips an already indexed RIB when the metadata checksum and `INDEXED` status match. Raw binary RIB files are never modified and are not copied into the database.",
                "",
                "## Scope",
                "",
                "This is not a full global RIB materialization. It indexes only the target evidence needed for the existing 12-candidate benchmark. No UPDATE MRT files are downloaded, no Normal labels are created, and no Validation/Holdout data is accessed.",
            ]
        )
        + "\n",
        encoding="utf-8",
    )


def percentile(values: list[float], pct: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    index = min(len(ordered) - 1, int(round((pct / 100) * (len(ordered) - 1))))
    return ordered[index]


def no_observability_revalidation_rows(results: list[dict[str, object]], previous: list[dict[str, str]]) -> list[dict[str, object]]:
    current_by_id = {row["candidate_period_id"]: row for row in results}
    rows: list[dict[str, object]] = []
    for row in previous:
        if row.get("prescreen_status") != NO_OBSERVABILITY:
            continue
        current = current_by_id.get(row["candidate_period_id"], {})
        before = int(current.get("before_indexed_rows") or 0)
        after = int(current.get("after_indexed_rows") or 0)
        origins = set()
        for field in ("origin_before", "origin_after"):
            try:
                origins.update(json.loads(str(current.get(field) or "[]")))
            except json.JSONDecodeError:
                pass
        exact_prefix_observed = bool(row.get("affected_prefix")) and (before > 0 or after > 0)
        different_origin = exact_prefix_observed and bool(origins) and row.get("affected_asn") not in origins
        if current.get("prescreen_status") == NO_OBSERVABILITY:
            conclusion = "CONFIRMED_ASN_OR_PREFIX_ABSENT_FROM_INDEXED_TARGET_EVIDENCE"
        elif current.get("prescreen_status") == PRESCREEN_PASS:
            conclusion = "CHANGED_TO_VISIBLE_AFTER_PERSISTENT_INDEX"
        else:
            conclusion = "REQUIRES_REVIEW_AFTER_PERSISTENT_INDEX"
        rows.append(
            {
                "candidate_period_id": row["candidate_period_id"],
                "associated_category": row["associated_category"],
                "affected_asn": row["affected_asn"],
                "affected_prefix": row.get("affected_prefix", ""),
                "previous_status": row["prescreen_status"],
                "indexed_status": current.get("prescreen_status", ""),
                "before_indexed_rows": before,
                "after_indexed_rows": after,
                "asn_truly_absent": str(before == 0 and after == 0 and not row.get("affected_prefix")),
                "exact_prefix_absent_but_asn_prefixes_exist": "False" if exact_prefix_observed else ("UNVERIFIED" if row.get("affected_prefix") else "NOT_APPLICABLE"),
                "prefix_exists_under_different_origin": str(different_origin) if row.get("affected_prefix") else "NOT_APPLICABLE",
                "parser_or_index_issue_suspected": str(current.get("prescreen_status") != row["prescreen_status"]),
                "conclusion": conclusion,
            }
        )
    return rows


def write_notebook() -> None:
    NOTEBOOK.parent.mkdir(parents=True, exist_ok=True)
    nb = {
        "cells": [
            {
                "cell_type": "markdown",
                "metadata": {},
                "source": [
                    "# RIB Index Engineering\n",
                    "\n",
                    "Benchmark and build the persistent RouteViews RIB index for the fixed 12-candidate TRAIN-only Normal benchmark. This notebook does not download UPDATE MRT files, create Normal labels, or access Validation/Holdout data.\n",
                ],
            },
            {
                "cell_type": "code",
                "execution_count": None,
                "metadata": {},
                "outputs": [],
                "source": ["from bgp_incident_detection.rib_index_engine import run\n", "summary = run()\n", "summary\n"],
            },
        ],
        "metadata": {"kernelspec": {"display_name": "Python 3", "language": "python", "name": "python3"}, "language_info": {"name": "python", "pygments_lexer": "ipython3"}},
        "nbformat": 4,
        "nbformat_minor": 5,
    }
    NOTEBOOK.write_text(json.dumps(nb, indent=2) + "\n", encoding="utf-8")


def run() -> dict[str, object]:
    started = time.perf_counter()
    manifest = benchmark_manifest_rows()
    ribs = required_ribs(manifest)
    targets = targets_by_rib(manifest)
    reps = representative_ribs(ribs)
    method_rows: list[dict[str, object]] = []
    for rib in reps:
        key = (rib["collector"], rib["rib_timestamp"])
        for method in ("current_bgpdump_target_csv", "python_mrtparse", "streaming_bgpdump_to_persistent_index"):
            method_rows.append(method_benchmark_row(method, rib, targets.get(key, [])))
    conn = db_connect()
    initialize_db(conn)
    build_rows: list[dict[str, object]] = []
    for index, rib in enumerate(ribs, start=1):
        build_row = index_rib(conn, rib, targets.get((rib["collector"], rib["rib_timestamp"]), []))
        build_rows.append(build_row)
        print(
            f"[{index}/{len(ribs)}] {rib['collector']} {rib['rib_timestamp']} "
            f"{build_row['index_status']} rows={build_row['rows_indexed']} "
            f"elapsed={build_row['elapsed_seconds']}s",
            flush=True,
        )
    lookup_rows, asn_times, prefix_times = rerun_candidate_lookups(conn, manifest)
    previous_rows = load_csv(PREVIOUS_RESULTS)
    revalidation = no_observability_revalidation_rows(lookup_rows, previous_rows)
    db_size = DB_PATH.stat().st_size if DB_PATH.exists() else 0
    for row in method_rows:
        if row["method"] == "streaming_bgpdump_to_persistent_index":
            row["index_size_bytes"] = db_size
    write_csv(
        METHOD_BENCHMARK,
        method_rows,
        ["method", "collector", "rib_timestamp", "source_file", "raw_rib_size_bytes", "parse_time_seconds", "index_build_time_seconds", "index_size_bytes", "rows_indexed", "asn_lookup_latency_ms", "prefix_lookup_latency_ms", "repeated_lookup_latency_ms", "memory_usage_mb", "parser", "parser_version", "status", "notes"],
    )
    write_csv(
        BUILD_AUDIT,
        build_rows,
        ["collector", "rib_timestamp", "source_file", "checksum", "index_status", "rows_indexed", "started_at", "completed_at", "elapsed_seconds", "parser", "parser_version", "raw_size_bytes", "notes"],
    )
    write_csv(
        LOOKUP_BENCHMARK,
        lookup_rows,
        ["candidate_period_id", "associated_incident_uid", "associated_category", "affected_asn", "affected_prefix", "collector", "rib_before_timestamp", "rib_after_timestamp", "asn_visible_before", "asn_visible_after", "prefix_visible_before", "prefix_visible_after", "origin_before", "origin_after", "origin_stable", "route_presence_stable", "prescreen_status", "reason", "before_indexed_rows", "after_indexed_rows", "lookup_backend"],
    )
    write_csv(
        NO_OBSERVABILITY_REVALIDATION,
        revalidation,
        ["candidate_period_id", "associated_category", "affected_asn", "affected_prefix", "previous_status", "indexed_status", "before_indexed_rows", "after_indexed_rows", "asn_truly_absent", "exact_prefix_absent_but_asn_prefixes_exist", "prefix_exists_under_different_origin", "parser_or_index_issue_suspected", "conclusion"],
    )
    write_architecture_doc(DB_PATH, method_rows)
    write_notebook()
    conn.close()
    build_times = [float(row["elapsed_seconds"]) for row in build_rows if row["index_status"] == "INDEXED" and float(row["elapsed_seconds"]) > 0]
    lookup_times = asn_times + prefix_times
    status_counts = Counter(row["index_status"] for row in build_rows)
    result_counts = Counter(row["prescreen_status"] for row in lookup_rows)
    changed = sum(
        1
        for row in lookup_rows
        for previous in previous_rows
        if previous["candidate_period_id"] == row["candidate_period_id"] and previous["prescreen_status"] != row["prescreen_status"]
    )
    median_lookup = median(lookup_times) if lookup_times else 0.0
    estimates = {
        "50_candidates_seconds": round(50 * 2 * median_lookup / 1000, 3),
        "100_candidates_seconds": round(100 * 2 * median_lookup / 1000, 3),
        "180_candidates_seconds": round(180 * 2 * median_lookup / 1000, 3),
    }
    return {
        "expected_ribs": len(ribs),
        "index_status_counts": dict(status_counts),
        "total_indexed_rows": sum(int(row["rows_indexed"]) for row in build_rows),
        "index_size_bytes": db_size,
        "average_index_seconds_per_rib": round(mean(build_times), 3) if build_times else 0.0,
        "median_index_seconds_per_rib": round(median(build_times), 3) if build_times else 0.0,
        "median_asn_lookup_ms": round(median(asn_times), 3) if asn_times else 0.0,
        "median_prefix_lookup_ms": round(median(prefix_times), 3) if prefix_times else 0.0,
        "p95_lookup_ms": round(percentile(lookup_times, 95), 3),
        "lookup_status_counts": dict(result_counts),
        "no_observability_revalidated": len(revalidation),
        "visibility_status_changes": changed,
        "runtime_estimates_indexed_lookup_only": estimates,
        "elapsed_seconds": round(time.perf_counter() - started, 3),
        "outputs": [str(METHOD_BENCHMARK), str(ARCHITECTURE_DOC), str(BUILD_AUDIT), str(LOOKUP_BENCHMARK), str(NO_OBSERVABILITY_REVALIDATION), str(NOTEBOOK)],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Build persistent RIB index for the fixed 12-candidate benchmark")
    parser.add_argument("--run", action="store_true")
    args = parser.parse_args()
    if not args.run:
        parser.error("choose --run")
    print(json.dumps(run(), indent=2, sort_keys=True))


if __name__ == "__main__":
    main()

import fs from "node:fs";
import path from "node:path";

const ROOT = path.resolve("cloudflare_incidents");
const CF_RAW = path.join(ROOT, "raw_leaks_2023-01_to_2026-01.json");
const OUT_MATCHES = path.join(ROOT, "cloudflare_qrator_route_leak_matched_incidents_2024-2025.csv");
const OUT_AUDIT = path.join(ROOT, "cloudflare_qrator_route_leak_audit_2024-2025.csv");
const OUT_SUMMARY = path.join(ROOT, "cloudflare_qrator_route_leak_summary_2024-2025.csv");

const START = Date.parse(process.env.MATCH_START || "2024-01-01T00:00:00Z");
const END = Date.parse(process.env.MATCH_END || "2025-12-31T23:59:59Z");
const QRATOR_BASE = "https://radar.qrator.net/api/storage";
const QRATOR_PAGE_SIZE = Number(process.env.QRATOR_PAGE_SIZE || 100);
const QRATOR_ASN_LIMIT = Number(process.env.QRATOR_ASN_LIMIT || 0);
const QRATOR_COOKIE = process.env.QRATOR_COOKIE || "";
const QRATOR_BEARER = process.env.QRATOR_BEARER || "";

const QRATOR_TABS = [
  { name: "created_route_leaks", path: "created" },
  { name: "prefixes_in_route_leaks", path: "prefixes" },
  { name: "accepted_route_leaks", path: "accepted" },
];

function iso(value) {
  if (!value) return "";
  const d = new Date(value);
  return Number.isNaN(d.getTime()) ? "" : d.toISOString();
}

function ts(value) {
  if (!value) return NaN;
  const parsed = Date.parse(value);
  return Number.isNaN(parsed) ? NaN : parsed;
}

function csvCell(value) {
  if (value === null || value === undefined) return "";
  const s = Array.isArray(value) || typeof value === "object" ? JSON.stringify(value) : String(value);
  return /[",\n\r]/.test(s) ? `"${s.replaceAll('"', '""')}"` : s;
}

function writeCsv(file, rows, headers) {
  const body = [
    headers.join(","),
    ...rows.map((row) => headers.map((h) => csvCell(row[h])).join(",")),
  ].join("\n");
  fs.writeFileSync(file, `${body}\n`);
}

function normalizeAsn(value) {
  if (value === null || value === undefined || value === "") return null;
  if (typeof value === "number") return value;
  if (typeof value === "string") {
    const m = value.match(/\d+/);
    return m ? Number(m[0]) : null;
  }
  if (typeof value === "object") return normalizeAsn(value.asn ?? value.id ?? value.value);
  return null;
}

function asnListFromPath(asPath) {
  if (!Array.isArray(asPath)) return [];
  return asPath.map(normalizeAsn).filter((v) => Number.isFinite(v));
}

function prefixesFromQrator(row) {
  const values = [
    row.prefix,
    row.target_prefix,
    row.affected_prefix,
    row.conflict_prefix,
    row.ipPrefix,
  ].filter(Boolean);
  return [...new Set(values.map(String))];
}

function qratorStart(row) {
  return row.first_seen ?? row.firstSeen ?? row.start_time ?? row.startTime ?? row.start ?? row.created_at;
}

function qratorEnd(row) {
  return row.last_seen ?? row.lastSeen ?? row.end_time ?? row.endTime ?? row.end ?? row.updated_at ?? qratorStart(row);
}

function qratorLeakerAsn(row, tabPath, endpointAsn) {
  return normalizeAsn(
    row.leaker ??
      row.leaker_as ??
      row.leaker_asn ??
      row.target_as ??
      row.target_asn ??
      (tabPath === "created" ? endpointAsn : null),
  );
}

function qratorOriginAsn(row) {
  return normalizeAsn(row.origin ?? row.origin_as ?? row.origin_asn ?? row.conflict_as ?? row.conflict_asn);
}

function overlaps(aStart, aEnd, bStart, bEnd) {
  return Number.isFinite(aStart) && Number.isFinite(aEnd) && Number.isFinite(bStart) && Number.isFinite(bEnd) && aStart <= bEnd && bStart <= aEnd;
}

function loadCloudflareLeaks() {
  const records = JSON.parse(fs.readFileSync(CF_RAW, "utf8"));
  return records
    .filter((r) => {
      const start = ts(r.min_ts || r.detected_ts || r.incident_date);
      return Number.isFinite(start) && start >= START && start <= END;
    })
    .map((r) => ({
      ...r,
      cf_start_ms: ts(r.min_ts || r.detected_ts),
      cf_end_ms: ts(r.max_ts || r.min_ts || r.detected_ts),
    }));
}

function authHeaders() {
  const headers = { accept: "application/json" };
  if (QRATOR_COOKIE) headers.cookie = QRATOR_COOKIE;
  if (QRATOR_BEARER) headers.authorization = `Bearer ${QRATOR_BEARER}`;
  return headers;
}

async function fetchQratorPage(asn, tab, page) {
  const params = new URLSearchParams({
    ip: "all",
    page: String(page),
    "page-size": String(QRATOR_PAGE_SIZE),
    from: new Date(START).toISOString().replace(".000Z", ""),
    until: new Date(END).toISOString().replace(".000Z", ""),
  });
  const url = `${QRATOR_BASE}/v2/incidents/leaks/${tab.path}/asn/${asn}?${params}`;
  const res = await fetch(url, { headers: authHeaders() });
  const text = await res.text();
  let json = null;
  try {
    json = text ? JSON.parse(text) : null;
  } catch {
    json = { raw: text.slice(0, 500) };
  }
  if (!res.ok) {
    const message = json?.message || json?.error || text.slice(0, 200);
    throw new Error(`${res.status} ${message}`);
  }
  return { url, json };
}

async function fetchQratorRowsForAsn(asn) {
  const rows = [];
  const errors = [];
  for (const tab of QRATOR_TABS) {
    for (let page = 1; page < 10000; page += 1) {
      try {
        const { url, json } = await fetchQratorPage(asn, tab, page);
        const data = Array.isArray(json?.data) ? json.data : Array.isArray(json) ? json : [];
        rows.push(...data.map((row) => ({ ...row, _qrator_tab: tab.name, _qrator_path: tab.path, _qrator_url: url })));
        const pageCount = Number(json?.page_count || json?.pages || 0);
        if (!data.length || (pageCount && page >= pageCount)) break;
      } catch (err) {
        errors.push({ asn, tab: tab.name, error: err.message });
        break;
      }
    }
  }
  return { rows, errors };
}

function scoreMatch(cf, qr, endpointAsn) {
  const qStart = ts(qratorStart(qr));
  const qEnd = ts(qratorEnd(qr));
  const leaker = qratorLeakerAsn(qr, qr._qrator_path, endpointAsn);
  const origin = qratorOriginAsn(qr);
  const qPrefixes = prefixesFromQrator(qr);
  const pathAsns = asnListFromPath(qr.aspath ?? qr.as_path ?? qr.asPaths ?? qr.paths);

  const timeOverlap = overlaps(cf.cf_start_ms, cf.cf_end_ms, qStart, qEnd);
  const leakAsnMatch = leaker === cf.leak_asn;
  const leakSeg = Array.isArray(cf.leak_seg) ? cf.leak_seg : [];
  const pathContainsLeakSeg = leakSeg.length > 0 && leakSeg.every((asn) => pathAsns.includes(asn));

  return {
    timeOverlap,
    leakAsnMatch,
    pathContainsLeakSeg,
    prefixAvailable: qPrefixes.length > 0,
    originAvailable: Number.isFinite(origin),
    qStart,
    qEnd,
    leaker,
    origin,
    qPrefixes,
    pathAsns,
  };
}

async function main() {
  fs.mkdirSync(ROOT, { recursive: true });
  const cloudflareLeaks = loadCloudflareLeaks();
  const asns = [...new Set(cloudflareLeaks.map((r) => r.leak_asn).filter(Number.isFinite))].sort((a, b) => a - b);
  const selectedAsns = QRATOR_ASN_LIMIT > 0 ? asns.slice(0, QRATOR_ASN_LIMIT) : asns;
  const byAsn = new Map();
  for (const r of cloudflareLeaks) {
    if (!byAsn.has(r.leak_asn)) byAsn.set(r.leak_asn, []);
    byAsn.get(r.leak_asn).push(r);
  }

  const matches = [];
  const audit = [];
  let qratorRowsSeen = 0;
  let qratorErrors = 0;

  for (const asn of selectedAsns) {
    const { rows, errors } = await fetchQratorRowsForAsn(asn);
    qratorRowsSeen += rows.length;
    qratorErrors += errors.length;
    for (const err of errors) {
      audit.push({ cloudflare_leak_asn: asn, status: "qrator_fetch_error", qrator_tab: err.tab, error: err.error });
    }

    const cfRows = byAsn.get(asn) || [];
    for (const cf of cfRows) {
      let cfMatched = false;
      for (const qr of rows) {
        const score = scoreMatch(cf, qr, asn);
        if (!(score.timeOverlap && score.leakAsnMatch)) continue;
        cfMatched = true;
        matches.push({
          cloudflare_id: cf.id,
          category: "Leak",
          cloudflare_leak_asn: cf.leak_asn,
          cloudflare_start_utc: iso(cf.min_ts || cf.detected_ts),
          cloudflare_end_utc: iso(cf.max_ts || cf.min_ts || cf.detected_ts),
          cloudflare_leak_seg: cf.leak_seg,
          cloudflare_prefix_count: cf.prefix_count,
          cloudflare_peer_count: cf.peer_count,
          cloudflare_leak_count: cf.leak_count,
          cloudflare_countries: cf.countries,
          qrator_tab: qr._qrator_tab,
          qrator_start_utc: iso(qratorStart(qr)),
          qrator_end_utc: iso(qratorEnd(qr)),
          qrator_leaker_asn: score.leaker,
          qrator_origin_asn: score.origin,
          qrator_prefixes: score.qPrefixes,
          qrator_as_path_asns: score.pathAsns,
          qrator_propagation: qr.propagation ?? qr.propagation_count ?? "",
          qrator_severity: qr.severity ?? "",
          match_time_overlap: score.timeOverlap,
          match_leak_asn: score.leakAsnMatch,
          match_path_contains_cloudflare_leak_seg: score.pathContainsLeakSeg,
          qrator_source_url: qr._qrator_url,
          qrator_raw_record: qr,
        });
      }
      if (!cfMatched && rows.length) {
        audit.push({
          cloudflare_id: cf.id,
          cloudflare_leak_asn: cf.leak_asn,
          cloudflare_start_utc: iso(cf.min_ts || cf.detected_ts),
          cloudflare_end_utc: iso(cf.max_ts || cf.min_ts || cf.detected_ts),
          status: "no_time_overlap_and_leak_asn_match",
        });
      }
    }
  }

  writeCsv(OUT_MATCHES, matches, [
    "cloudflare_id",
    "category",
    "cloudflare_leak_asn",
    "cloudflare_start_utc",
    "cloudflare_end_utc",
    "cloudflare_leak_seg",
    "cloudflare_prefix_count",
    "cloudflare_peer_count",
    "cloudflare_leak_count",
    "cloudflare_countries",
    "qrator_tab",
    "qrator_start_utc",
    "qrator_end_utc",
    "qrator_leaker_asn",
    "qrator_origin_asn",
    "qrator_prefixes",
    "qrator_as_path_asns",
    "qrator_propagation",
    "qrator_severity",
    "match_time_overlap",
    "match_leak_asn",
    "match_path_contains_cloudflare_leak_seg",
    "qrator_source_url",
    "qrator_raw_record",
  ]);
  writeCsv(OUT_AUDIT, audit, [
    "cloudflare_id",
    "cloudflare_leak_asn",
    "cloudflare_start_utc",
    "cloudflare_end_utc",
    "status",
    "qrator_tab",
    "error",
  ]);
  writeCsv(OUT_SUMMARY, [
    {
      cloudflare_leaks_2024_2025: cloudflareLeaks.length,
      unique_cloudflare_leak_asns: asns.length,
      queried_qrator_asns: selectedAsns.length,
      qrator_rows_seen: qratorRowsSeen,
      matched_rows: matches.length,
      qrator_fetch_errors: qratorErrors,
      auth_mode: QRATOR_COOKIE ? "cookie" : QRATOR_BEARER ? "bearer" : "none",
    },
  ], [
    "cloudflare_leaks_2024_2025",
    "unique_cloudflare_leak_asns",
    "queried_qrator_asns",
    "qrator_rows_seen",
    "matched_rows",
    "qrator_fetch_errors",
    "auth_mode",
  ]);

  console.log(`Wrote ${OUT_MATCHES}`);
  console.log(`Wrote ${OUT_AUDIT}`);
  console.log(`Wrote ${OUT_SUMMARY}`);
}

main().catch((err) => {
  console.error(err);
  process.exitCode = 1;
});

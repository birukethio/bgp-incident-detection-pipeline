import fs from "node:fs";
import path from "node:path";

process.env.TZ = "America/New_York";

const ROOT = path.resolve("cloudflare_incidents");
const CF_RAW = path.join(ROOT, "raw_leaks_2023-01_to_2026-01.json");
const OUT_MATCHES = path.join(ROOT, "cloudflare_mauch_route_leak_matched_incidents_2024-2025.csv");
const OUT_AUDIT = path.join(ROOT, "cloudflare_mauch_route_leak_audit_2024-2025.csv");
const OUT_SUMMARY = path.join(ROOT, "cloudflare_mauch_route_leak_summary_2024-2025.csv");

const START = parseUtc(process.env.MATCH_START || "2024-01-01T00:00:00Z");
const END = parseUtc(process.env.MATCH_END || "2025-12-31T23:59:59Z");
const CF_LIMIT = Number(process.env.CF_LIMIT || 100);
const RECENT = Number(process.env.MAUCH_RECENT || 1000);
const BASE_URL = "http://puck.nether.net/bgp/leakinfo.cgi/";

function parseUtc(value) {
  if (!value) return NaN;
  const s = String(value);
  const normalized = /(?:Z|[+-]\d\d:?\d\d)$/.test(s) ? s : `${s}Z`;
  return Date.parse(normalized);
}

function isoUtc(value) {
  const t = typeof value === "number" ? value : parseUtc(value);
  return Number.isFinite(t) ? new Date(t).toISOString() : "";
}

function parseEasternToUtc(value) {
  const [date, time] = String(value).trim().split(/\s+/);
  if (!date || !time) return NaN;
  const d = new Date(`${date}T${time}`);
  return d.getTime();
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

function stripTags(value) {
  return String(value)
    .replace(/<[^>]*>/g, "")
    .replace(/&nbsp;/g, " ")
    .replace(/&amp;/g, "&")
    .trim();
}

function parseMauchRows(html) {
  const rows = [];
  const trRe = /<TR><TD>(.*?)<\/TD><TD>(.*?)<\/TD><TD>(.*?)<\/TD><TD>(.*?)<\/TD><TD>(.*?)<\/TD><TD>(.*?)<\/TD><TD>(.*?)<\/TD><\/TR>/gis;
  let m;
  while ((m = trRe.exec(html))) {
    if (m[1] === "Source") continue;
    const asPath = stripTags(m[4]).split(/\s+/).filter(Boolean).map(Number).filter(Number.isFinite);
    rows.push({
      source: stripTags(m[1]),
      time_eastern: stripTags(m[2]),
      time_utc: isoUtc(parseEasternToUtc(stripTags(m[2]))),
      time_ms: parseEasternToUtc(stripTags(m[2])),
      prefix: stripTags(m[3]),
      as_path: asPath,
      contact_asn: Number(stripTags(m[5])) || "",
      score: Number(stripTags(m[6])) || "",
      blame_asn: Number(stripTags(m[7])) || "",
    });
  }
  return rows;
}

function containsSubsequence(pathAsns, segment) {
  if (!Array.isArray(pathAsns) || !Array.isArray(segment) || !segment.length) return false;
  for (let i = 0; i <= pathAsns.length - segment.length; i += 1) {
    let ok = true;
    for (let j = 0; j < segment.length; j += 1) {
      if (pathAsns[i + j] !== segment[j]) {
        ok = false;
        break;
      }
    }
    if (ok) return true;
  }
  return false;
}

function overlaps(aStart, aEnd, bInstant) {
  return Number.isFinite(aStart) && Number.isFinite(aEnd) && Number.isFinite(bInstant) && aStart <= bInstant && bInstant <= aEnd;
}

function loadCloudflareLeaks() {
  const rows = JSON.parse(fs.readFileSync(CF_RAW, "utf8"))
    .map((r) => ({
      ...r,
      start_ms: parseUtc(r.min_ts || r.detected_ts),
      end_ms: parseUtc(r.max_ts || r.min_ts || r.detected_ts),
    }))
    .filter((r) => Number.isFinite(r.start_ms) && r.start_ms >= START && r.start_ms <= END && Array.isArray(r.leak_seg) && r.leak_seg.length)
    .sort((a, b) => Number(b.prefix_count || 0) - Number(a.prefix_count || 0));
  return CF_LIMIT > 0 ? rows.slice(0, CF_LIMIT) : rows;
}

async function fetchMauchByAsPath(segment) {
  const params = new URLSearchParams({
    search: "do",
    search_prefix: "",
    search_aspath: segment.join("_"),
    search_asn: "",
    recent: String(RECENT),
  });
  const url = `${BASE_URL}?${params}`;
  const res = await fetch(url, { headers: { accept: "text/html" } });
  const text = await res.text();
  if (!res.ok) throw new Error(`${res.status} ${text.slice(0, 120)}`);
  return { url, rows: parseMauchRows(text) };
}

async function main() {
  fs.mkdirSync(ROOT, { recursive: true });
  const cfRows = loadCloudflareLeaks();
  const matches = [];
  const audit = [];
  const cache = new Map();

  for (const cf of cfRows) {
    const key = cf.leak_seg.join("_");
    if (!cache.has(key)) {
      try {
        cache.set(key, await fetchMauchByAsPath(cf.leak_seg));
      } catch (err) {
        cache.set(key, { url: "", rows: [], error: err.message });
      }
    }
    const result = cache.get(key);
    if (result.error) {
      audit.push({ cloudflare_id: cf.id, leak_seg: cf.leak_seg, status: "mauch_fetch_error", error: result.error });
      continue;
    }

    const candidateRows = result.rows.filter((row) => containsSubsequence(row.as_path, cf.leak_seg));
    const overlappingRows = candidateRows.filter((row) => overlaps(cf.start_ms, cf.end_ms, row.time_ms));
    if (!overlappingRows.length) {
      audit.push({
        cloudflare_id: cf.id,
        leak_seg: cf.leak_seg,
        status: candidateRows.length ? "as_path_match_but_no_time_overlap" : "no_as_path_match",
        mauch_candidate_rows: candidateRows.length,
        mauch_search_url: result.url,
      });
      continue;
    }

    for (const row of overlappingRows) {
      matches.push({
        cloudflare_id: cf.id,
        category: "Leak",
        match_status: "time_overlap_and_leak_seg_in_as_path",
        cloudflare_start_utc: isoUtc(cf.start_ms),
        cloudflare_end_utc: isoUtc(cf.end_ms),
        cloudflare_leak_asn: cf.leak_asn,
        cloudflare_leak_seg: cf.leak_seg,
        cloudflare_prefix_count: cf.prefix_count,
        cloudflare_peer_count: cf.peer_count,
        cloudflare_origin_count: cf.origin_count,
        cloudflare_leak_count: cf.leak_count,
        cloudflare_countries: cf.countries,
        mauch_time_utc: row.time_utc,
        mauch_time_eastern_source: row.time_eastern,
        mauch_prefix: row.prefix,
        mauch_as_path: row.as_path,
        mauch_contact_asn: row.contact_asn,
        mauch_score: row.score,
        mauch_blame_asn: row.blame_asn,
        mauch_source: row.source,
        mauch_search_url: result.url,
      });
    }
  }

  writeCsv(OUT_MATCHES, matches, [
    "cloudflare_id",
    "category",
    "match_status",
    "cloudflare_start_utc",
    "cloudflare_end_utc",
    "cloudflare_leak_asn",
    "cloudflare_leak_seg",
    "cloudflare_prefix_count",
    "cloudflare_peer_count",
    "cloudflare_origin_count",
    "cloudflare_leak_count",
    "cloudflare_countries",
    "mauch_time_utc",
    "mauch_time_eastern_source",
    "mauch_prefix",
    "mauch_as_path",
    "mauch_contact_asn",
    "mauch_score",
    "mauch_blame_asn",
    "mauch_source",
    "mauch_search_url",
  ]);
  writeCsv(OUT_AUDIT, audit, ["cloudflare_id", "leak_seg", "status", "mauch_candidate_rows", "mauch_search_url", "error"]);
  writeCsv(OUT_SUMMARY, [
    {
      source: "Jared Mauch BGP Routing Leak Detection System",
      cloudflare_rows_checked: cfRows.length,
      unique_cloudflare_leak_segments_checked: cache.size,
      matched_rows: matches.length,
      cloudflare_incidents_with_match: new Set(matches.map((r) => r.cloudflare_id)).size,
      audit_rows: audit.length,
      match_rule: "Mauch row timestamp falls inside Cloudflare min_ts/max_ts AND Cloudflare leak_seg appears as contiguous subsequence in Mauch AS_PATH",
      note: "Mauch source timestamps are labeled US/Eastern by the source and converted to UTC here.",
    },
  ], [
    "source",
    "cloudflare_rows_checked",
    "unique_cloudflare_leak_segments_checked",
    "matched_rows",
    "cloudflare_incidents_with_match",
    "audit_rows",
    "match_rule",
    "note",
  ]);

  console.log(`Wrote ${OUT_MATCHES}`);
  console.log(`Wrote ${OUT_AUDIT}`);
  console.log(`Wrote ${OUT_SUMMARY}`);
}

main().catch((err) => {
  console.error(err);
  process.exitCode = 1;
});

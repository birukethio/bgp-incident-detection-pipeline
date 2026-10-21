import fs from "node:fs";
import path from "node:path";

const ROOT = path.resolve("cloudflare_incidents");
const CF_RAW = path.join(ROOT, "raw_leaks_2023-01_to_2026-01.json");
const LACNIC_GLOBAL_HTML = process.env.LACNIC_GLOBAL_HTML || "/tmp/lacnic_bgpstream.html";
const LACNIC_LAC_HTML = process.env.LACNIC_LAC_HTML || "/tmp/lacnic_bgpstream_lac_region.html";

const OUT_LACNIC_AGG = path.join(ROOT, "lacnic_bgpstream_route_leak_country_pair_aggregates.csv");
const OUT_CF_AGG = path.join(ROOT, "cloudflare_route_leak_country_pair_aggregates_for_lacnic_window.csv");
const OUT_CANDIDATES = path.join(ROOT, "cloudflare_lacnic_route_leak_candidate_incidents.csv");
const OUT_SUMMARY = path.join(ROOT, "cloudflare_lacnic_route_leak_validation_summary.csv");

const GLOBAL_START = Date.parse("2023-02-14T00:00:00Z");
const GLOBAL_END = Date.parse("2024-02-27T23:59:59Z");
const LAC_START = Date.parse("2023-02-15T00:00:00Z");
const LAC_END = Date.parse("2024-02-27T23:59:59Z");

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

function iso(value) {
  if (!value) return "";
  const parsed = parseUtc(value);
  return Number.isNaN(parsed) ? "" : new Date(parsed).toISOString();
}

function parseUtc(value) {
  if (!value) return NaN;
  const s = String(value);
  const normalized = /(?:Z|[+-]\d\d:?\d\d)$/.test(s) ? s : `${s}Z`;
  const parsed = Date.parse(normalized);
  return Number.isNaN(parsed) ? NaN : parsed;
}

function extractCaption(html) {
  const match = html.match(/<caption>\s*Rango\s+([0-9-]+)\s+a\s+([0-9-]+)\s*<\/caption>/i);
  return match ? { start: match[1], end: match[2] } : { start: "", end: "" };
}

function extractLeakPairs(html, sourceName) {
  const caption = extractCaption(html);
  const marker = "data.addColumn('string', 'Origin CC');";
  const start = html.indexOf(marker);
  if (start < 0) return [];
  const rowsStart = html.indexOf("data.addRows([", start);
  const rowsEnd = html.indexOf("]);", rowsStart);
  if (rowsStart < 0 || rowsEnd < 0) return [];
  const block = html.slice(rowsStart, rowsEnd);
  const rows = [];
  const re = /\[\s*'([^']+)'\s*,\s*'([^']+)'\s*,\s*(\d+)\s*\]/g;
  let match;
  while ((match = re.exec(block))) {
    rows.push({
      lacnic_source: sourceName,
      lacnic_window_start: caption.start,
      lacnic_window_end: caption.end,
      origin_cc: match[1].trim(),
      leaker_cc: match[2].trim(),
      lacnic_event_count: Number(match[3]),
    });
  }
  return rows;
}

function countryKey(originCc, leakerCc) {
  return `${originCc || "UNVERIFIED"}|${leakerCc || "UNVERIFIED"}`;
}

function loadCloudflareLeaks() {
  const records = JSON.parse(fs.readFileSync(CF_RAW, "utf8"));
  return records.filter((r) => {
    const t = parseUtc(r.min_ts || r.detected_ts || r.incident_date || "");
    return Number.isFinite(t) && t >= GLOBAL_START && t <= GLOBAL_END;
  });
}

function aggregateCloudflare(records) {
  const agg = new Map();
  for (const r of records) {
    const countries = Array.isArray(r.countries) ? r.countries : [];
    const originCc = countries[0] || "UNVERIFIED";
    const leakerCc = countries[1] || "UNVERIFIED";
    const key = countryKey(originCc, leakerCc);
    if (!agg.has(key)) {
      agg.set(key, {
        origin_cc: originCc,
        leaker_cc: leakerCc,
        cloudflare_event_count: 0,
        cloudflare_prefix_count_sum: 0,
        cloudflare_peer_count_sum: 0,
        cloudflare_leak_count_sum: 0,
        first_cloudflare_start_utc: "",
        last_cloudflare_end_utc: "",
        cloudflare_ids: [],
      });
    }
    const row = agg.get(key);
    row.cloudflare_event_count += 1;
    row.cloudflare_prefix_count_sum += Number(r.prefix_count || 0);
    row.cloudflare_peer_count_sum += Number(r.peer_count || 0);
    row.cloudflare_leak_count_sum += Number(r.leak_count || 0);
    row.cloudflare_ids.push(r.id);
    const startIso = iso(r.min_ts || r.detected_ts);
    const endIso = iso(r.max_ts || r.min_ts || r.detected_ts);
    if (startIso && (!row.first_cloudflare_start_utc || startIso < row.first_cloudflare_start_utc)) row.first_cloudflare_start_utc = startIso;
    if (endIso && (!row.last_cloudflare_end_utc || endIso > row.last_cloudflare_end_utc)) row.last_cloudflare_end_utc = endIso;
  }
  return [...agg.values()].sort((a, b) => b.cloudflare_event_count - a.cloudflare_event_count);
}

function candidateRows(records, lacnicPairs) {
  const pairSet = new Set(lacnicPairs.map((r) => countryKey(r.origin_cc, r.leaker_cc)));
  return records
    .filter((r) => {
      const countries = Array.isArray(r.countries) ? r.countries : [];
      return pairSet.has(countryKey(countries[0], countries[1]));
    })
    .map((r) => {
      const countries = Array.isArray(r.countries) ? r.countries : [];
      return {
        cloudflare_id: r.id,
        category: "Leak",
        validation_status: "candidate_country_pair_match_only",
        validation_note: "LACNIC public BGPStream data is aggregate by origin/leaker country pair, not incident-level; this is not a per-incident confirmation.",
        cloudflare_start_utc: iso(r.min_ts || r.detected_ts),
        cloudflare_end_utc: iso(r.max_ts || r.min_ts || r.detected_ts),
        cloudflare_leak_asn: r.leak_asn,
        cloudflare_leak_seg: r.leak_seg,
        cloudflare_origin_cc_assumed_from_countries_0: countries[0] || "",
        cloudflare_leaker_cc_assumed_from_countries_1: countries[1] || "",
        cloudflare_countries_raw: countries,
        cloudflare_prefix_count: r.prefix_count,
        cloudflare_peer_count: r.peer_count,
        cloudflare_origin_count: r.origin_count,
        cloudflare_leak_count: r.leak_count,
        cloudflare_raw_record: r,
      };
    })
    .sort((a, b) => b.cloudflare_prefix_count - a.cloudflare_prefix_count);
}

function main() {
  fs.mkdirSync(ROOT, { recursive: true });
  const globalHtml = fs.readFileSync(LACNIC_GLOBAL_HTML, "utf8");
  const lacHtml = fs.readFileSync(LACNIC_LAC_HTML, "utf8");
  const lacnicPairs = [
    ...extractLeakPairs(globalHtml, "lacnic_global_bgpstream_public_page"),
    ...extractLeakPairs(lacHtml, "lacnic_lac_region_bgpstream_public_page"),
  ];
  const cfLeaks = loadCloudflareLeaks();
  const cfAgg = aggregateCloudflare(cfLeaks);
  const candidates = candidateRows(cfLeaks, lacnicPairs);
  const lacnicPairSet = new Set(lacnicPairs.map((r) => countryKey(r.origin_cc, r.leaker_cc)));
  const matchedAggPairs = cfAgg.filter((r) => lacnicPairSet.has(countryKey(r.origin_cc, r.leaker_cc)));

  writeCsv(OUT_LACNIC_AGG, lacnicPairs, [
    "lacnic_source",
    "lacnic_window_start",
    "lacnic_window_end",
    "origin_cc",
    "leaker_cc",
    "lacnic_event_count",
  ]);
  writeCsv(OUT_CF_AGG, cfAgg, [
    "origin_cc",
    "leaker_cc",
    "cloudflare_event_count",
    "cloudflare_prefix_count_sum",
    "cloudflare_peer_count_sum",
    "cloudflare_leak_count_sum",
    "first_cloudflare_start_utc",
    "last_cloudflare_end_utc",
    "cloudflare_ids",
  ]);
  writeCsv(OUT_CANDIDATES, candidates, [
    "cloudflare_id",
    "category",
    "validation_status",
    "validation_note",
    "cloudflare_start_utc",
    "cloudflare_end_utc",
    "cloudflare_leak_asn",
    "cloudflare_leak_seg",
    "cloudflare_origin_cc_assumed_from_countries_0",
    "cloudflare_leaker_cc_assumed_from_countries_1",
    "cloudflare_countries_raw",
    "cloudflare_prefix_count",
    "cloudflare_peer_count",
    "cloudflare_origin_count",
    "cloudflare_leak_count",
    "cloudflare_raw_record",
  ]);
  writeCsv(OUT_SUMMARY, [
    {
      validation_level: "aggregate_country_pair_only",
      lacnic_global_window_start: new Date(GLOBAL_START).toISOString(),
      lacnic_global_window_end: new Date(GLOBAL_END).toISOString(),
      cloudflare_records_in_lacnic_global_window: cfLeaks.length,
      lacnic_country_pair_rows: lacnicPairs.length,
      cloudflare_country_pair_rows: cfAgg.length,
      country_pairs_seen_in_both_sources: matchedAggPairs.length,
      cloudflare_candidate_incidents_in_lacnic_country_pairs: candidates.length,
      incident_level_match_possible_from_public_lacnic_page: false,
      notes: "Public LACNIC BGPStream pages expose route leak counts by Origin CC and Leaker CC. They do not expose raw event IDs/timestamps/prefixes. Candidate rows are useful for source triangulation, not final labels.",
    },
  ], [
    "validation_level",
    "lacnic_global_window_start",
    "lacnic_global_window_end",
    "cloudflare_records_in_lacnic_global_window",
    "lacnic_country_pair_rows",
    "cloudflare_country_pair_rows",
    "country_pairs_seen_in_both_sources",
    "cloudflare_candidate_incidents_in_lacnic_country_pairs",
    "incident_level_match_possible_from_public_lacnic_page",
    "notes",
  ]);

  console.log(`Wrote ${OUT_LACNIC_AGG}`);
  console.log(`Wrote ${OUT_CF_AGG}`);
  console.log(`Wrote ${OUT_CANDIDATES}`);
  console.log(`Wrote ${OUT_SUMMARY}`);
}

main();

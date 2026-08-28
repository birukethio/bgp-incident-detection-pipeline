import { readFile, writeFile } from "node:fs/promises";

const OUT_DIR = new URL("./", import.meta.url);
const LEAK_INPUT = "raw_leaks_all_available_to_2026-01_cloudflare.json";
const HIJACK_INPUT = "raw_hijacks_all_available_to_2026-01_cloudflare.json";
const OUTAGE_POOL = "clean_cloudflare_outage_recommended_final_pool_all_asns.csv";

const LEAK_OUTPUT = "stratified_quality_leak_sample_473.csv";
const HIJACK_OUTPUT = "stratified_quality_hijack_sample_473.csv";
const COMBINED_OUTPUT = "balanced_incident_level_roster_473_each_leak_hijack_outage.csv";
const AUDIT_OUTPUT = "stratified_quality_sampling_audit.csv";
const SUMMARY_OUTPUT = "stratified_quality_sampling_summary.csv";

const SAMPLE_TARGET = Number(process.env.SAMPLE_TARGET || 473);

const ROSTER_HEADERS = [
  "incident_id",
  "incident_name",
  "category",
  "incident_date",
  "start_utc",
  "end_utc",
  "duration_minutes",
  "primary_asn",
  "affected_asns",
  "affected_prefixes",
  "prefix_count",
  "peer_count",
  "countries",
  "source_url",
  "confidence_score",
  "routeviews_collection_start",
  "routeviews_collection_end",
  "five_minute_window_count",
  "partition",
  "notes",
  "sampling_stratum",
  "quality_score",
  "quality_rank_within_stratum",
];

function parseTime(value) {
  if (!value) return NaN;
  return Date.parse(String(value).endsWith("Z") ? value : `${value}Z`);
}

function toUtcIso(value) {
  const ms = parseTime(value);
  return Number.isFinite(ms) ? new Date(ms).toISOString() : null;
}

function toDateKey(value) {
  const iso = toUtcIso(value);
  return iso ? iso.slice(0, 10) : null;
}

function durationMinutes(start, end) {
  const startMs = parseTime(start);
  const endMs = parseTime(end);
  if (!Number.isFinite(startMs) || !Number.isFinite(endMs) || endMs < startMs) return null;
  return Math.ceil((endMs - startMs) / 60000);
}

function fiveMinuteWindowCount(minutes) {
  return Number.isFinite(minutes) ? Math.ceil(minutes / 5) : null;
}

function jsonList(value) {
  if (value == null) return null;
  return JSON.stringify(Array.isArray(value) ? value : [value]);
}

function csvCell(value) {
  if (value == null) return "";
  const text = String(value).replaceAll(/\s*\r?\n\s*/g, " ");
  return /[",\n\r]/.test(text) ? `"${text.replaceAll('"', '""')}"` : text;
}

async function writeCsv(filename, headers, rows) {
  const body = [
    headers.map(csvCell).join(","),
    ...rows.map((row) => headers.map((header) => csvCell(row[header])).join(",")),
  ].join("\n");
  await writeFile(new URL(filename, OUT_DIR), `${body}\n`);
}

function parseCsv(text) {
  const lines = text.trim().split(/\n/);
  function parse(line) {
    const cells = [];
    let current = "";
    let quoted = false;
    for (let i = 0; i < line.length; i += 1) {
      const char = line[i];
      if (char === '"' && line[i + 1] === '"') {
        current += '"';
        i += 1;
      } else if (char === '"') {
        quoted = !quoted;
      } else if (char === "," && !quoted) {
        cells.push(current);
        current = "";
      } else {
        current += char;
      }
    }
    cells.push(current);
    return cells;
  }
  const headers = parse(lines[0]);
  return lines.slice(1).map((line) => Object.fromEntries(parse(line).map((value, index) => [headers[index], value])));
}

function generatedName(prefix, id, date) {
  return `${prefix}_${id}_${date ?? "UNVERIFIED_DATE"}`;
}

function bucket(value, breaks, labels) {
  const n = Number(value);
  if (!Number.isFinite(n)) return "missing";
  for (let i = 0; i < breaks.length; i += 1) {
    if (n <= breaks[i]) return labels[i];
  }
  return labels.at(-1);
}

function logScore(value) {
  const n = Number(value) || 0;
  return Math.log10(n + 1);
}

function asnBand(asn) {
  const n = Number(asn);
  if (!Number.isFinite(n)) return "asn_missing";
  if (n < 64512) return "public_16bit";
  if (n < 131072) return "private_or_transition";
  if (n < 262144) return "public_32bit_low";
  return "public_32bit_high";
}

function normalizeLeak(row) {
  const start = toUtcIso(row.min_ts ?? row.detected_ts);
  const end = toUtcIso(row.max_ts);
  const duration = durationMinutes(start, end);
  const country = Array.isArray(row.countries) ? row.countries[1] || row.countries[0] || "UNVERIFIED" : "UNVERIFIED";
  const qualityScore = (
    logScore(duration) * 4 +
    logScore(row.prefix_count) * 5 +
    logScore(row.peer_count) * 3 +
    logScore(row.leak_count) * 3 +
    logScore(row.origin_count) * 2 +
    (row.finished ? 0.5 : 0)
  );
  const stratum = [
    toDateKey(start)?.slice(0, 4) ?? "year_missing",
    asnBand(row.leak_asn),
    country,
    bucket(duration, [5, 60, 360, 1440], ["dur_0_5m", "dur_6_60m", "dur_61_360m", "dur_361_1440m", "dur_over_24h"]),
    bucket(row.prefix_count, [1, 10, 100, 1000], ["pfx_1", "pfx_2_10", "pfx_11_100", "pfx_101_1000", "pfx_gt_1000"]),
    bucket(row.peer_count, [1, 10, 50, 100], ["peer_1", "peer_2_10", "peer_11_50", "peer_51_100", "peer_gt_100"]),
  ].join("|");

  return {
    incident_id: row.id,
    incident_name: generatedName(`Leak_AS${row.leak_asn ?? "UNVERIFIED"}`, row.id, toDateKey(start)),
    category: "Leak",
    incident_date: toDateKey(start),
    start_utc: start,
    end_utc: end,
    duration_minutes: duration,
    primary_asn: row.leak_asn ?? null,
    affected_asns: jsonList(row.leak_seg),
    affected_prefixes: null,
    prefix_count: row.prefix_count ?? null,
    peer_count: row.peer_count ?? null,
    countries: jsonList(row.countries),
    source_url: null,
    confidence_score: null,
    routeviews_collection_start: null,
    routeviews_collection_end: null,
    five_minute_window_count: fiveMinuteWindowCount(duration),
    partition: null,
    notes: `stratified quality sample; source=Cloudflare Radar; origin_count=${row.origin_count ?? "UNVERIFIED"}; leak_count=${row.leak_count ?? "UNVERIFIED"}; leak_type=${row.leak_type ?? "UNVERIFIED"}; quality favors longer duration, more prefixes, more peers, and higher leak/origin counts`,
    sampling_stratum: stratum,
    quality_score: qualityScore.toFixed(6),
  };
}

function normalizeHijack(row) {
  const start = toUtcIso(row.min_hijack_ts);
  const end = toUtcIso(row.max_hijack_ts);
  const duration = durationMinutes(start, end);
  const countries = [
    ...(row.hijacker_country ? [row.hijacker_country] : []),
    ...(row.victim_countries ?? []),
  ];
  const qualityScore = (
    logScore(duration) * 4 +
    logScore(row.hijack_msgs_count) * 5 +
    logScore(row.peer_ip_count) * 3 +
    logScore((row.peer_asns ?? []).length) * 2 +
    logScore((row.prefixes ?? []).length) * 3 +
    Math.max(0, Number(row.confidence_score) || 0) * 1.5 +
    (row.is_stale ? -0.75 : 0)
  );
  const stratum = [
    toDateKey(start)?.slice(0, 4) ?? "year_missing",
    asnBand(row.hijacker_asn),
    row.hijacker_country ?? "country_missing",
    bucket(duration, [5, 60, 360, 1440], ["dur_0_5m", "dur_6_60m", "dur_61_360m", "dur_361_1440m", "dur_over_24h"]),
    bucket((row.prefixes ?? []).length, [1, 2, 10, 100], ["pfx_1", "pfx_2", "pfx_3_10", "pfx_11_100", "pfx_gt_100"]),
    bucket(row.hijack_msgs_count, [10, 100, 1000, 10000], ["msg_0_10", "msg_11_100", "msg_101_1000", "msg_1001_10000", "msg_gt_10000"]),
  ].join("|");
  const tags = (row.tags ?? []).map((tag) => `${tag.name}:${tag.score}`);

  return {
    incident_id: row.id,
    incident_name: generatedName(`Hijack_AS${row.hijacker_asn ?? "UNVERIFIED"}`, row.id, toDateKey(start)),
    category: "Hijack",
    incident_date: toDateKey(start),
    start_utc: start,
    end_utc: end,
    duration_minutes: duration,
    primary_asn: row.hijacker_asn ?? null,
    affected_asns: jsonList(row.victim_asns),
    affected_prefixes: jsonList(row.prefixes),
    prefix_count: Array.isArray(row.prefixes) ? row.prefixes.length : null,
    peer_count: Array.isArray(row.peer_asns) ? row.peer_asns.length : null,
    countries: jsonList(countries),
    source_url: null,
    confidence_score: row.confidence_score ?? null,
    routeviews_collection_start: null,
    routeviews_collection_end: null,
    five_minute_window_count: fiveMinuteWindowCount(duration),
    partition: null,
    notes: `stratified quality sample; source=Cloudflare Radar; tags=${tags.length ? tags.join(";") : "UNVERIFIED"}; hijack_msgs_count=${row.hijack_msgs_count ?? "UNVERIFIED"}; peer_ip_count=${row.peer_ip_count ?? "UNVERIFIED"}; event_type=${row.event_type ?? "UNVERIFIED"}; max_msg_ts preserved in raw source only; quality favors longer duration, more messages, more peer visibility, more prefixes, and higher confidence`,
    sampling_stratum: stratum,
    quality_score: qualityScore.toFixed(6),
  };
}

function selectStratified(rows, target) {
  const sorted = rows
    .filter((row) => row.start_utc && row.end_utc && Number(row.duration_minutes) >= 0 && row.primary_asn)
    .toSorted((a, b) => Number(b.quality_score) - Number(a.quality_score));

  const groups = new Map();
  for (const row of sorted) {
    if (!groups.has(row.sampling_stratum)) groups.set(row.sampling_stratum, []);
    groups.get(row.sampling_stratum).push(row);
  }

  const selected = [];
  const seen = new Set();
  const strata = [...groups.entries()].sort((a, b) =>
    Number(b[1][0].quality_score) - Number(a[1][0].quality_score) ||
    b[1].length - a[1].length
  );

  for (const [, group] of strata) {
    const row = group[0];
    if (selected.length >= target) break;
    selected.push(row);
    seen.add(String(row.incident_id));
  }

  let depth = 1;
  while (selected.length < target) {
    let added = 0;
    for (const [, group] of strata) {
      const row = group[depth];
      if (!row || seen.has(String(row.incident_id))) continue;
      selected.push(row);
      seen.add(String(row.incident_id));
      added += 1;
      if (selected.length >= target) break;
    }
    if (!added) break;
    depth += 1;
  }

  return selected
    .toSorted((a, b) => (parseTime(a.start_utc) || 0) - (parseTime(b.start_utc) || 0))
    .map((row, index) => ({ ...row, quality_rank_within_stratum: rankWithinStratum(row, groups), sample_order: index + 1 }));
}

function rankWithinStratum(row, groups) {
  const group = groups.get(row.sampling_stratum) ?? [];
  const index = group.findIndex((candidate) => String(candidate.incident_id) === String(row.incident_id));
  return index >= 0 ? index + 1 : "";
}

function summarizeSample(category, universe, sample) {
  const years = new Set(sample.map((row) => row.incident_date?.slice(0, 4)).filter(Boolean));
  const asns = new Set(sample.map((row) => String(row.primary_asn)).filter(Boolean));
  const countries = new Set(sample.flatMap((row) => {
    try { return JSON.parse(row.countries || "[]"); } catch { return []; }
  }));
  const strata = new Set(sample.map((row) => row.sampling_stratum));
  return [
    { category, metric: "universe_count_after_basic_quality_filter", value: universe.length },
    { category, metric: "sample_count", value: sample.length },
    { category, metric: "unique_years_in_sample", value: years.size },
    { category, metric: "unique_primary_asns_in_sample", value: asns.size },
    { category, metric: "unique_countries_in_sample", value: countries.size },
    { category, metric: "unique_strata_in_sample", value: strata.size },
    { category, metric: "median_duration_minutes_in_sample", value: median(sample.map((row) => Number(row.duration_minutes)).filter(Number.isFinite)) },
    { category, metric: "max_duration_minutes_in_sample", value: Math.max(...sample.map((row) => Number(row.duration_minutes)).filter(Number.isFinite)) },
    { category, metric: "median_quality_score_in_sample", value: median(sample.map((row) => Number(row.quality_score)).filter(Number.isFinite)).toFixed(6) },
  ];
}

function median(values) {
  const sorted = values.toSorted((a, b) => a - b);
  if (!sorted.length) return 0;
  const mid = Math.floor(sorted.length / 2);
  return sorted.length % 2 ? sorted[mid] : (sorted[mid - 1] + sorted[mid]) / 2;
}

function outageToCombined(row) {
  return {
    incident_id: row.incident_id,
    incident_name: row.incident_name,
    category: "Outage",
    incident_date: row.start_utc?.slice(0, 10) ?? "",
    start_utc: row.start_utc,
    end_utc: row.end_utc,
    duration_minutes: row.duration_minutes,
    primary_asn: "",
    affected_asns: row.affected_asns,
    affected_prefixes: "",
    prefix_count: "",
    peer_count: "",
    countries: row.country,
    source_url: row.source_url,
    confidence_score: "",
    routeviews_collection_start: "",
    routeviews_collection_end: "",
    five_minute_window_count: fiveMinuteWindowCount(Number(row.duration_minutes)),
    partition: "",
    notes: `recommended final outage pool; outage_type=${row.outage_type}; outage_cause=${row.outage_cause}; affected_organization_network=${row.affected_organization_network}; verification_status=${row.verification_status}; ${row.qc_notes}`,
    sampling_stratum: "outage_qc_final_pool",
    quality_score: "",
    quality_rank_within_stratum: "",
  };
}

const [rawLeaks, rawHijacks, outageCsv] = await Promise.all([
  readFile(new URL(LEAK_INPUT, OUT_DIR), "utf8").then(JSON.parse),
  readFile(new URL(HIJACK_INPUT, OUT_DIR), "utf8").then(JSON.parse),
  readFile(new URL(OUTAGE_POOL, OUT_DIR), "utf8"),
]);

const normalizedLeaks = rawLeaks.map(normalizeLeak);
const normalizedHijacks = rawHijacks.map(normalizeHijack);
const leakSample = selectStratified(normalizedLeaks, SAMPLE_TARGET);
const hijackSample = selectStratified(normalizedHijacks, SAMPLE_TARGET);
const outageRows = parseCsv(outageCsv).map(outageToCombined);

const combined = [...leakSample, ...hijackSample, ...outageRows]
  .sort((a, b) => String(a.category).localeCompare(String(b.category)) || (parseTime(a.start_utc) || 0) - (parseTime(b.start_utc) || 0));

const summaryRows = [
  ...summarizeSample("Leak", normalizedLeaks, leakSample),
  ...summarizeSample("Hijack", normalizedHijacks, hijackSample),
  { category: "Outage", metric: "recommended_final_pool_count", value: outageRows.length },
  { category: "ALL", metric: "combined_balanced_roster_count", value: combined.length },
  { category: "ALL", metric: "sampling_method", value: "one high-quality incident per stratum first, then round-robin by next-best quality within strata until target count" },
  { category: "ALL", metric: "sample_target_per_leak_and_hijack", value: SAMPLE_TARGET },
];

const auditRows = [
  { category: "Leak", raw_count: rawLeaks.length, eligible_count: normalizedLeaks.filter((row) => row.start_utc && row.end_utc && row.primary_asn).length, selected_count: leakSample.length, target: SAMPLE_TARGET },
  { category: "Hijack", raw_count: rawHijacks.length, eligible_count: normalizedHijacks.filter((row) => row.start_utc && row.end_utc && row.primary_asn).length, selected_count: hijackSample.length, target: SAMPLE_TARGET },
  { category: "Outage", raw_count: "", eligible_count: outageRows.length, selected_count: outageRows.length, target: outageRows.length },
];

await Promise.all([
  writeCsv(LEAK_OUTPUT, ROSTER_HEADERS, leakSample),
  writeCsv(HIJACK_OUTPUT, ROSTER_HEADERS, hijackSample),
  writeCsv(COMBINED_OUTPUT, ROSTER_HEADERS, combined),
  writeCsv(AUDIT_OUTPUT, ["category", "raw_count", "eligible_count", "selected_count", "target"], auditRows),
  writeCsv(SUMMARY_OUTPUT, ["category", "metric", "value"], summaryRows),
]);

console.log(JSON.stringify({
  outputs: {
    leak_sample: LEAK_OUTPUT,
    hijack_sample: HIJACK_OUTPUT,
    combined_balanced_roster: COMBINED_OUTPUT,
    audit: AUDIT_OUTPUT,
    summary: SUMMARY_OUTPUT,
  },
  audit: auditRows,
  summary: summaryRows,
}, null, 2));

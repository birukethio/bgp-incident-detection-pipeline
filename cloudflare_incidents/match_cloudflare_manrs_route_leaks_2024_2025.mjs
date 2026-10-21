import { readFile, writeFile } from "node:fs/promises";

const OUT_DIR = new URL("./", import.meta.url);
const INPUT = "raw_leaks_2023-01_to_2026-01.json";
const MATCHED_OUTPUT = "cloudflare_manrs_route_leak_matched_incidents_2024-2025.csv";
const AUDIT_OUTPUT = "cloudflare_manrs_route_leak_audit_2024-2025.csv";
const SUMMARY_OUTPUT = "cloudflare_manrs_route_leak_summary_2024-2025.csv";
const MANRS_SUMMARY = "https://observatory.manrs.org/api/v2/scores/summary";
const START_DAY = "2024-01-01";
const END_DAY = "2025-12-31";

function parseTime(value) {
  if (!value) return NaN;
  const text = String(value);
  return Date.parse(text.endsWith("Z") ? text : `${text}Z`);
}

function toIso(value) {
  const ms = typeof value === "number" ? value : parseTime(value);
  return Number.isFinite(ms) ? new Date(ms).toISOString() : "";
}

function day(value) {
  return value ? String(value).slice(0, 10) : "";
}

function monthStartIso(value) {
  const d = day(value);
  return d ? `${d.slice(0, 7)}-01T00:00:00Z` : "";
}

function durationMinutes(start, end) {
  const a = parseTime(start);
  const b = parseTime(end);
  if (!Number.isFinite(a) || !Number.isFinite(b) || b < a) return "";
  return Math.ceil((b - a) / 60000);
}

function windowCount(minutes) {
  const n = Number(minutes);
  return Number.isFinite(n) ? Math.ceil(n / 5) : "";
}

function csvCell(value) {
  if (value == null) return "";
  const text = typeof value === "object" ? JSON.stringify(value) : String(value);
  return /[",\n\r]/.test(text) ? `"${text.replaceAll('"', '""')}"` : text;
}

async function writeCsv(filename, headers, rows) {
  const csv = [
    headers.map(csvCell).join(","),
    ...rows.map((row) => headers.map((header) => csvCell(row[header])).join(",")),
  ].join("\n");
  await writeFile(new URL(filename, OUT_DIR), `${csv}\n`);
}

async function fetchJson(url) {
  const response = await fetch(url, { headers: { accept: "application/json" } });
  if (!response.ok) throw new Error(`${response.status} ${response.statusText}`);
  return response.json();
}

async function fetchManrsGlobalMonth(month) {
  const url = new URL(MANRS_SUMMARY);
  url.searchParams.set("month", month);
  try {
    const json = await fetchJson(url);
    return {
      ok: true,
      url: url.toString(),
      routeLeaks: json.scores?.incidents?.routeLeaks ?? null,
      routeMisoriginations: json.scores?.incidents?.routeMisoriginations ?? null,
      bogonAnnouncements: json.scores?.incidents?.bogonAnnouncements ?? null,
      raw: json.scores?.incidents ?? null,
      error: "",
    };
  } catch (error) {
    return {
      ok: false,
      url: url.toString(),
      routeLeaks: null,
      routeMisoriginations: null,
      bogonAnnouncements: null,
      raw: null,
      error: error.message,
    };
  }
}

function normalizeCloudflareLeak(record) {
  const start = toIso(record.min_ts ?? record.detected_ts);
  const end = toIso(record.max_ts);
  const duration = durationMinutes(start, end);
  return {
    cloudflare_source_id: record.id,
    category: "Leak",
    incident_date: day(start),
    start_utc: start,
    end_utc: end,
    duration_minutes: duration,
    five_minute_window_count: windowCount(duration),
    leak_asn: record.leak_asn ?? "",
    leak_segment: record.leak_seg ?? [],
    countries: record.countries ?? [],
    leak_count: record.leak_count ?? "",
    leak_type: record.leak_type ?? "",
    origin_count: record.origin_count ?? "",
    peer_count: record.peer_count ?? "",
    prefix_count: record.prefix_count ?? "",
    cloudflare_raw_record: record,
  };
}

const raw = JSON.parse(await readFile(new URL(INPUT, OUT_DIR), "utf8"));
const cloudflareLeaks = raw
  .map(normalizeCloudflareLeak)
  .filter((record) => record.incident_date >= START_DAY && record.incident_date <= END_DAY);

const months = [...new Set(cloudflareLeaks.map((record) => monthStartIso(record.start_utc)).filter(Boolean))].sort();
const monthResults = new Map();
for (const month of months) {
  monthResults.set(month, await fetchManrsGlobalMonth(month));
}

const auditRows = cloudflareLeaks.map((record) => {
  const month = monthStartIso(record.start_utc);
  const manrs = monthResults.get(month);
  const match = manrs?.ok && Number(manrs.routeLeaks) > 0;
  return {
    ...record,
    match_status: match ? "POSSIBLE_MATCH_MANRS_GLOBAL_MONTH_ROUTE_LEAK" : "NO_MATCH",
    match_rule: "Cloudflare leak event month must overlap a MANRS Observatory public monthly routeLeaks count greater than zero. Incident IDs are not used.",
    manrs_month: month,
    manrs_route_leaks_global_month_count: manrs?.routeLeaks ?? "",
    manrs_route_misoriginations_global_month_count: manrs?.routeMisoriginations ?? "",
    manrs_bogon_announcements_global_month_count: manrs?.bogonAnnouncements ?? "",
    manrs_source_url: manrs?.url ?? "",
    manrs_error: manrs?.error ?? "",
    notes: match
      ? "MANRS public summary has routeLeaks in this month; per-ASN details require an authenticated MANRS endpoint."
      : "MANRS public summary reports zero routeLeaks globally for this month, so no Cloudflare leak can be independently matched through the public MANRS routeLeaks summary.",
  };
});

const matchedRows = auditRows.filter((row) => row.match_status !== "NO_MATCH");
const totalManrsRouteLeaks = [...monthResults.values()].reduce((sum, item) => sum + (Number(item.routeLeaks) || 0), 0);

const summaryRows = [
  { metric: "cloudflare_leaks_checked", value: cloudflareLeaks.length },
  { metric: "date_range_start", value: START_DAY },
  { metric: "date_range_end", value: END_DAY },
  { metric: "manrs_months_checked", value: months.length },
  { metric: "manrs_global_route_leaks_total_across_checked_months", value: totalManrsRouteLeaks },
  { metric: "matched_cloudflare_leaks", value: matchedRows.length },
  { metric: "not_matched_cloudflare_leaks", value: auditRows.length - matchedRows.length },
  { metric: "match_percent", value: cloudflareLeaks.length ? ((matchedRows.length / cloudflareLeaks.length) * 100).toFixed(2) : "0.00" },
  { metric: "important_limitation", value: "MANRS public /scores/summary exposes monthly aggregate incident counts. Public per-ASN /scores and /scores/details calls returned 401 without MANRS credentials." },
];

const headers = [
  "cloudflare_source_id",
  "category",
  "incident_date",
  "start_utc",
  "end_utc",
  "duration_minutes",
  "five_minute_window_count",
  "leak_asn",
  "leak_segment",
  "countries",
  "leak_count",
  "leak_type",
  "origin_count",
  "peer_count",
  "prefix_count",
  "match_status",
  "match_rule",
  "manrs_month",
  "manrs_route_leaks_global_month_count",
  "manrs_route_misoriginations_global_month_count",
  "manrs_bogon_announcements_global_month_count",
  "manrs_source_url",
  "manrs_error",
  "notes",
  "cloudflare_raw_record",
];

await writeCsv(MATCHED_OUTPUT, headers, matchedRows);
await writeCsv(AUDIT_OUTPUT, headers, auditRows);
await writeCsv(SUMMARY_OUTPUT, ["metric", "value"], summaryRows);

console.log(JSON.stringify({
  cloudflare_leaks_checked: cloudflareLeaks.length,
  manrs_months_checked: months.length,
  manrs_route_leaks_total: totalManrsRouteLeaks,
  matched_cloudflare_leaks: matchedRows.length,
  match_percent: summaryRows.find((row) => row.metric === "match_percent")?.value,
  outputs: {
    matched: MATCHED_OUTPUT,
    audit: AUDIT_OUTPUT,
    summary: SUMMARY_OUTPUT,
  },
}, null, 2));

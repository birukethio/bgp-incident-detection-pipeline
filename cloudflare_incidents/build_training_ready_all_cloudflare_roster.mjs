import { readFile, writeFile } from "node:fs/promises";

const OUT_DIR = new URL("./", import.meta.url);

const INPUTS = {
  leaks: "raw_leaks_all_available_to_2026-01_cloudflare.json",
  hijacks: "raw_hijacks_all_available_to_2026-01_cloudflare.json",
  outages: "raw_outages_all_available_to_2026-01_cloudflare.json",
};

const OUTPUT = "training_ready_bgp_incident_roster_all_available_to_2026-01.csv";
const SUMMARY_OUTPUT = "training_ready_bgp_incident_roster_all_available_to_2026-01_summary.csv";
const MISSING_OUTPUT = "training_ready_bgp_incident_roster_all_available_to_2026-01_missing_unverified.csv";
const WINDOWS_OUTPUT = "training_ready_bgp_incident_roster_all_available_to_2026-01_window_counts.csv";

const HEADERS = [
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

function generatedName(prefix, id, date) {
  return `${prefix}_${id}_${date ?? "UNVERIFIED_DATE"}`;
}

function normalizeLeak(incident) {
  const start = toUtcIso(incident.min_ts ?? incident.detected_ts);
  const end = toUtcIso(incident.max_ts);
  const duration = durationMinutes(start, end);
  const incidentDate = toDateKey(start ?? incident.detected_ts);
  return {
    incident_id: incident.id,
    incident_name: generatedName(`Leak_AS${incident.leak_asn ?? "UNVERIFIED"}`, incident.id, incidentDate),
    category: "Leak",
    incident_date: incidentDate,
    start_utc: start,
    end_utc: end,
    duration_minutes: duration,
    primary_asn: incident.leak_asn ?? null,
    affected_asns: jsonList(incident.leak_seg),
    affected_prefixes: null,
    prefix_count: incident.prefix_count ?? null,
    peer_count: incident.peer_count ?? null,
    countries: jsonList(incident.countries),
    source_url: null,
    confidence_score: null,
    routeviews_collection_start: null,
    routeviews_collection_end: null,
    five_minute_window_count: fiveMinuteWindowCount(duration),
    partition: null,
    notes: `incident_name generated; affected_asns mapped from leak_seg; origin_count=${incident.origin_count ?? "UNVERIFIED"}; leak_type=${incident.leak_type ?? "UNVERIFIED"}; source=Cloudflare Radar BGP route leak events`,
  };
}

function normalizeHijack(incident) {
  const start = toUtcIso(incident.min_hijack_ts);
  const end = toUtcIso(incident.max_hijack_ts);
  const duration = durationMinutes(start, end);
  const incidentDate = toDateKey(start);
  const countries = [
    ...(incident.hijacker_country ? [incident.hijacker_country] : []),
    ...(incident.victim_countries ?? []),
  ];
  const tags = (incident.tags ?? []).map((tag) => `${tag.name}:${tag.score}`);
  return {
    incident_id: incident.id,
    incident_name: generatedName(`Hijack_AS${incident.hijacker_asn ?? "UNVERIFIED"}`, incident.id, incidentDate),
    category: "Hijack",
    incident_date: incidentDate,
    start_utc: start,
    end_utc: end,
    duration_minutes: duration,
    primary_asn: incident.hijacker_asn ?? null,
    affected_asns: jsonList(incident.victim_asns),
    affected_prefixes: jsonList(incident.prefixes),
    prefix_count: Array.isArray(incident.prefixes) ? incident.prefixes.length : null,
    peer_count: Array.isArray(incident.peer_asns) ? incident.peer_asns.length : null,
    countries: jsonList(countries),
    source_url: null,
    confidence_score: incident.confidence_score ?? null,
    routeviews_collection_start: null,
    routeviews_collection_end: null,
    five_minute_window_count: fiveMinuteWindowCount(duration),
    partition: null,
    notes: `incident_name generated; tags=${tags.length ? tags.join(";") : "UNVERIFIED"}; hijack_msgs_count=${incident.hijack_msgs_count ?? "UNVERIFIED"}; event_type=${incident.event_type ?? "UNVERIFIED"}; is_stale=${incident.is_stale ?? "UNVERIFIED"}; on_going_count=${incident.on_going_count ?? "UNVERIFIED"}; source=Cloudflare Radar BGP hijack events; max_msg_ts preserved in raw source only, not used as end_utc`,
  };
}

function normalizeOutage(incident) {
  const start = toUtcIso(incident.startDate);
  const end = toUtcIso(incident.endDate);
  const duration = durationMinutes(start, end);
  const incidentDate = toDateKey(start);
  const cause = incident.outage?.outageCause ?? "UNVERIFIED";
  const type = incident.outage?.outageType ?? "UNVERIFIED";
  return {
    incident_id: incident.id,
    incident_name: incident.description || generatedName("Outage", incident.id, incidentDate),
    category: "Outage",
    incident_date: incidentDate,
    start_utc: start,
    end_utc: end,
    duration_minutes: duration,
    primary_asn: null,
    affected_asns: jsonList(incident.asns),
    affected_prefixes: null,
    prefix_count: null,
    peer_count: null,
    countries: jsonList(incident.locations),
    source_url: incident.linkedUrl ?? null,
    confidence_score: null,
    routeviews_collection_start: null,
    routeviews_collection_end: null,
    five_minute_window_count: fiveMinuteWindowCount(duration),
    partition: null,
    notes: `outageCause=${cause}; outageType=${type}; dataSource=${incident.dataSource ?? "UNVERIFIED"}; scope=${incident.scope ?? "UNVERIFIED"}; eventType=${incident.eventType ?? "UNVERIFIED"}; source=Cloudflare Radar outage annotations`,
  };
}

function missingReasons(row) {
  const reasons = [];
  if (!row.start_utc) reasons.push("start_utc");
  if (!row.end_utc) reasons.push("end_utc");
  if (row.duration_minutes == null || row.duration_minutes === "") reasons.push("duration_minutes");
  if (!row.primary_asn && row.category !== "Outage") reasons.push("primary_asn");
  if (!row.affected_asns) reasons.push("affected_asns");
  if (!row.affected_prefixes && row.category === "Hijack") reasons.push("affected_prefixes");
  if (!row.source_url) reasons.push("source_url");
  return reasons;
}

function summarizeCategory(category, rows) {
  const starts = rows.map((row) => parseTime(row.start_utc)).filter(Number.isFinite).sort((a, b) => a - b);
  const windows = rows.reduce((sum, row) => sum + (Number(row.five_minute_window_count) || 0), 0);
  return {
    category,
    count: rows.length,
    first_start_utc: starts.length ? new Date(starts[0]).toISOString() : "",
    last_start_utc: starts.length ? new Date(starts.at(-1)).toISOString() : "",
    five_minute_window_count_sum: windows,
  };
}

const [leaks, hijacks, outages] = await Promise.all([
  readFile(new URL(INPUTS.leaks, OUT_DIR), "utf8").then(JSON.parse),
  readFile(new URL(INPUTS.hijacks, OUT_DIR), "utf8").then(JSON.parse),
  readFile(new URL(INPUTS.outages, OUT_DIR), "utf8").then(JSON.parse),
]);

const roster = [
  ...leaks.map(normalizeLeak),
  ...hijacks.map(normalizeHijack),
  ...outages.map(normalizeOutage),
].sort((a, b) => (parseTime(a.start_utc) || 0) - (parseTime(b.start_utc) || 0) || String(a.category).localeCompare(String(b.category)));

const missingRows = roster
  .map((row) => ({ ...row, missing_or_unverified_fields: missingReasons(row).join(";") }))
  .filter((row) => row.missing_or_unverified_fields);

const summary = ["Leak", "Hijack", "Outage"].map((category) =>
  summarizeCategory(category, roster.filter((row) => row.category === category))
);
summary.push(summarizeCategory("ALL", roster));

const windowRows = roster.map((row) => ({
  incident_id: row.incident_id,
  category: row.category,
  start_utc: row.start_utc,
  end_utc: row.end_utc,
  duration_minutes: row.duration_minutes,
  five_minute_window_count: row.five_minute_window_count,
}));

await Promise.all([
  writeCsv(OUTPUT, HEADERS, roster),
  writeCsv(SUMMARY_OUTPUT, ["category", "count", "first_start_utc", "last_start_utc", "five_minute_window_count_sum"], summary),
  writeCsv(MISSING_OUTPUT, [...HEADERS, "missing_or_unverified_fields"], missingRows),
  writeCsv(WINDOWS_OUTPUT, ["incident_id", "category", "start_utc", "end_utc", "duration_minutes", "five_minute_window_count"], windowRows),
]);

console.log(JSON.stringify({
  output: OUTPUT,
  summary_output: SUMMARY_OUTPUT,
  missing_output: MISSING_OUTPUT,
  windows_output: WINDOWS_OUTPUT,
  total_rows: roster.length,
  missing_rows: missingRows.length,
  summary,
}, null, 2));

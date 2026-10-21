import { readFile, writeFile } from "node:fs/promises";

const OUT_DIR = new URL("./", import.meta.url);
const INPUT = "raw_leaks_2023-01_to_2026-01.json";
const OUTPUT = "cloudflare_grip_route_leak_diagnostic_top25_2024-2025.csv";
const START_DAY = "2024-01-01";
const END_DAY = "2025-12-31";
const GRIP_BASE = "https://api.grip.inetintel.cc.gatech.edu:443/json/events";
const EVENT_TYPES = ["moas", "submoas", "edges", "defcon"];

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

function gripTime(value) {
  return value ? String(value).slice(0, 16) : "";
}

function withMargin(iso, minutes) {
  const ms = parseTime(iso);
  return Number.isFinite(ms) ? new Date(ms + minutes * 60000).toISOString() : "";
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

async function fetchGrip({ eventType, start, end, asns }) {
  const url = new URL(GRIP_BASE);
  url.searchParams.set("length", "10");
  url.searchParams.set("start", "0");
  url.searchParams.set("ts_start", gripTime(start));
  url.searchParams.set("ts_end", gripTime(end));
  url.searchParams.set("min_susp", "0");
  url.searchParams.set("max_susp", "100");
  url.searchParams.set("event_type", eventType);
  url.searchParams.set("asns", asns.join(","));
  try {
    const response = await fetch(url, { headers: { accept: "application/json" } });
    if (!response.ok) throw new Error(`${response.status} ${response.statusText}`);
    const json = await response.json();
    return { ok: true, url: url.toString(), total: json.recordsTotal ?? 0, events: json.data ?? [], error: "" };
  } catch (error) {
    return { ok: false, url: url.toString(), total: 0, events: [], error: error.message };
  }
}

const raw = JSON.parse(await readFile(new URL(INPUT, OUT_DIR), "utf8"));
const sample = raw
  .map((record) => ({
    ...record,
    start_utc: toIso(record.min_ts ?? record.detected_ts),
    end_utc: toIso(record.max_ts),
  }))
  .filter((record) => day(record.start_utc) >= START_DAY && day(record.start_utc) <= END_DAY)
  .sort((a, b) =>
    (b.leak_count ?? 0) - (a.leak_count ?? 0) ||
    (b.peer_count ?? 0) - (a.peer_count ?? 0) ||
    (b.prefix_count ?? 0) - (a.prefix_count ?? 0)
  )
  .slice(0, 25);

const rows = [];
for (const leak of sample) {
  const start = withMargin(leak.start_utc, -60);
  const end = withMargin(leak.end_utc || leak.start_utc, 60);
  const asns = [...new Set([leak.leak_asn, ...(leak.leak_seg ?? [])].filter(Boolean))];
  const checks = [];
  for (const eventType of EVENT_TYPES) {
    checks.push(await fetchGrip({ eventType, start, end, asns }));
  }
  const hits = checks.filter((check) => check.total > 0);
  rows.push({
    cloudflare_source_id: leak.id,
    cloudflare_start_utc: leak.start_utc,
    cloudflare_end_utc: leak.end_utc,
    cloudflare_leak_asn: leak.leak_asn ?? "",
    cloudflare_leak_segment: leak.leak_seg ?? [],
    cloudflare_countries: leak.countries ?? [],
    cloudflare_leak_count: leak.leak_count ?? "",
    cloudflare_peer_count: leak.peer_count ?? "",
    cloudflare_prefix_count: leak.prefix_count ?? "",
    grip_match_status: hits.length ? "GRIP_EVENT_FOUND_FOR_LEAK_ASN_OR_SEGMENT" : "NO_GRIP_EVENT_FOUND",
    grip_event_types_with_hits: hits.map((hit) => hit.url.match(/event_type=([^&]+)/)?.[1] ?? "").filter(Boolean),
    grip_records_total_by_type: Object.fromEntries(checks.map((check) => [check.url.match(/event_type=([^&]+)/)?.[1] ?? "unknown", check.total])),
    grip_event_ids: hits.flatMap((hit) => hit.events.map((event) => event.id)).slice(0, 20),
    grip_source_urls: checks.map((check) => check.url),
    grip_errors: checks.filter((check) => !check.ok).map((check) => check.error),
  });
}

const headers = [
  "cloudflare_source_id",
  "cloudflare_start_utc",
  "cloudflare_end_utc",
  "cloudflare_leak_asn",
  "cloudflare_leak_segment",
  "cloudflare_countries",
  "cloudflare_leak_count",
  "cloudflare_peer_count",
  "cloudflare_prefix_count",
  "grip_match_status",
  "grip_event_types_with_hits",
  "grip_records_total_by_type",
  "grip_event_ids",
  "grip_source_urls",
  "grip_errors",
];

await writeCsv(OUTPUT, headers, rows);
console.log(JSON.stringify({
  checked_cloudflare_top_leaks: rows.length,
  with_any_grip_event: rows.filter((row) => row.grip_match_status !== "NO_GRIP_EVENT_FOUND").length,
  output: OUTPUT,
}, null, 2));

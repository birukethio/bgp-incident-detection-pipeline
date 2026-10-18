import { readFile, writeFile } from "node:fs/promises";
import { execFile } from "node:child_process";
import { promisify } from "node:util";

const TOKEN = process.env.CLOUDFLARE_API_TOKEN;
const OUT_DIR = new URL("./", import.meta.url);
const CF_API = "https://api.cloudflare.com/client/v4";
const MANRS_API = "https://observatory.manrs.org/api/v2/scores/summary";
const IODA_API = "https://api.ioda.caida.org/v2/outages/events";
const START_DAY = "2021-01-01";
const END_DAY = "2025-12-31";
const execFileAsync = promisify(execFile);

function parseTime(value) {
  if (!value) return NaN;
  const text = String(value);
  return Date.parse(text.endsWith("Z") ? text : `${text}Z`);
}

function toIso(value) {
  const ms = typeof value === "number" ? value : parseTime(value);
  return Number.isFinite(ms) ? new Date(ms).toISOString() : null;
}

function day(value) {
  return value ? String(value).slice(0, 10) : "";
}

function monthStart(value) {
  const d = day(value);
  return d ? `${d.slice(0, 7)}-01T00:00:00Z` : "";
}

function inRange(value) {
  const d = day(value);
  return d >= START_DAY && d <= END_DAY;
}

function durationMinutes(start, end) {
  const a = parseTime(start);
  const b = parseTime(end);
  if (!Number.isFinite(a) || !Number.isFinite(b) || b < a) return null;
  return Math.ceil((b - a) / 60000);
}

function windowCount(minutes) {
  return Number.isFinite(minutes) ? Math.ceil(minutes / 5) : null;
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

async function curlJson(url, timeoutSeconds = 12) {
  try {
    const { stdout } = await execFileAsync("curl", ["-fsS", "--max-time", String(timeoutSeconds), url], {
      maxBuffer: 128 * 1024 * 1024,
    });
    return { ok: true, json: JSON.parse(stdout), error: null, url };
  } catch (error) {
    return { ok: false, json: null, error: error.message, url };
  }
}

async function fetchCloudflareOutages2021To2022() {
  if (!TOKEN) return [];
  const url = new URL(`${CF_API}/radar/annotations/outages`);
  url.searchParams.set("format", "json");
  url.searchParams.set("limit", "1000");
  url.searchParams.set("offset", "0");
  url.searchParams.set("dateStart", "2021-01-01T00:00:00Z");
  url.searchParams.set("dateEnd", "2023-01-01T00:00:00Z");

  try {
    const { stdout } = await execFileAsync("curl", [
      "-fsS",
      "--max-time",
      "30",
      "-H",
      `Authorization: Bearer ${TOKEN}`,
      url.toString(),
    ], { maxBuffer: 64 * 1024 * 1024 });
    const json = JSON.parse(stdout);
    return json.result?.annotations ?? [];
  } catch {
    return [];
  }
}

function normalizeLeak(record) {
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
    primary_asn: record.leak_asn ?? null,
    affected_asns: record.leak_seg ?? [],
    affected_prefixes: [],
    prefix_count: record.prefix_count ?? null,
    peer_count: record.peer_count ?? null,
    countries: record.countries ?? [],
    cloudflare_metric: record.leak_count ?? 0,
    cloudflare_raw_fields: record,
  };
}

function normalizeHijack(record) {
  const start = toIso(record.min_hijack_ts);
  const end = toIso(record.max_hijack_ts);
  const duration = durationMinutes(start, end);
  return {
    cloudflare_source_id: record.id,
    category: "Hijack",
    incident_date: day(start),
    start_utc: start,
    end_utc: end,
    duration_minutes: duration,
    five_minute_window_count: windowCount(duration),
    primary_asn: record.hijacker_asn ?? null,
    affected_asns: record.victim_asns ?? [],
    affected_prefixes: record.prefixes ?? [],
    prefix_count: Array.isArray(record.prefixes) ? record.prefixes.length : null,
    peer_count: Array.isArray(record.peer_asns) ? record.peer_asns.length : null,
    countries: [record.hijacker_country, ...(record.victim_countries ?? [])].filter(Boolean),
    confidence_score: record.confidence_score ?? null,
    cloudflare_metric: record.hijack_msgs_count ?? 0,
    cloudflare_raw_fields: record,
  };
}

function normalizeOutage(record) {
  const start = toIso(record.startDate);
  const end = toIso(record.endDate);
  const duration = durationMinutes(start, end);
  return {
    cloudflare_source_id: record.id,
    category: "Outage",
    incident_date: day(start),
    start_utc: start,
    end_utc: end,
    duration_minutes: duration,
    five_minute_window_count: windowCount(duration),
    primary_asn: null,
    affected_asns: record.asns ?? [],
    affected_prefixes: [],
    prefix_count: null,
    peer_count: null,
    countries: record.locations ?? [],
    source_url: record.linkedUrl ?? null,
    cloudflare_metric: duration ?? 0,
    cloudflare_raw_fields: record,
  };
}

function groupTopByDay(events, limitPerDay) {
  const grouped = new Map();
  for (const event of events) {
    if (!event.incident_date) continue;
    if (!grouped.has(event.incident_date)) grouped.set(event.incident_date, []);
    grouped.get(event.incident_date).push(event);
  }
  const selected = [];
  for (const items of grouped.values()) {
    items.sort((a, b) =>
      (b.cloudflare_metric ?? 0) - (a.cloudflare_metric ?? 0) ||
      (b.duration_minutes ?? 0) - (a.duration_minutes ?? 0) ||
      (b.prefix_count ?? 0) - (a.prefix_count ?? 0)
    );
    selected.push(...items.slice(0, limitPerDay));
  }
  return selected;
}

const manrsCache = new Map();
async function fetchManrs(country, month) {
  const key = `${country}|${month}`;
  if (manrsCache.has(key)) return manrsCache.get(key);
  const url = new URL(MANRS_API);
  url.searchParams.set("economies", country);
  url.searchParams.set("month", month);
  const promise = curlJson(url.toString(), 12).then((result) => {
    const incidents = result.json?.scores?.incidents ?? null;
    return { ...result, incidents };
  });
  manrsCache.set(key, promise);
  return promise;
}

async function matchManrs(event) {
  const month = monthStart(event.start_utc);
  const countries = [...new Set(event.countries ?? [])].filter(Boolean);
  const metric = event.category === "Leak" ? "routeLeaks" : "routeMisoriginations";
  const results = await Promise.all(countries.map((country) => fetchManrs(country, month)));
  const matches = results.filter((result) => (result.incidents?.[metric] ?? 0) > 0);
  return {
    match_status: matches.length ? "MATCH_MONTH_COUNTRY" : "NO_MATCH",
    match_source: "MANRS Observatory public summary",
    match_logic: `${event.category} matched by category + country/economy + calendar month; source IDs not used`,
    match_key: {
      category: event.category,
      countries,
      month,
      manrs_metric: metric,
    },
    external_source_urls: results.map((result) => result.url),
    external_evidence: matches.map((result) => result.incidents),
    external_errors: results.filter((result) => !result.ok).map((result) => result.error),
  };
}

async function matchIoda(event) {
  const start = Math.floor(parseTime(event.start_utc) / 1000);
  const end = Math.floor(parseTime(event.end_utc ?? event.start_utc) / 1000);
  const until = Number.isFinite(end) ? end : start + 3600;
  const countries = [...new Set(event.countries ?? [])].filter(Boolean);
  const results = await Promise.all(countries.map((country) => {
    const url = `${IODA_API}/country/${encodeURIComponent(country)}?from=${start}&until=${until}&format=ioda&limit=100&includeAlerts=true`;
    return curlJson(url, 8).then((result) => ({ ...result, country }));
  }));
  const events = results.flatMap((result) => (result.json?.data ?? []).map((item) => ({ ...item, country: result.country })));
  const matches = events.filter((item) => {
    const itemStart = item.from ?? item.start;
    const itemEnd = item.until ?? (item.start && item.duration ? item.start + item.duration : null);
    return itemStart != null && itemEnd != null && itemStart <= until && itemEnd >= start;
  });
  return {
    match_status: matches.length ? "MATCH_COUNTRY_TIME_OVERLAP" : "NO_MATCH",
    match_source: "CAIDA IODA outage events",
    match_logic: "Outage matched by country + overlapping outage time window; source IDs not used",
    match_key: {
      category: event.category,
      countries,
      start_epoch: start,
      end_epoch: until,
    },
    external_source_urls: results.map((result) => result.url),
    external_evidence: matches.slice(0, 5),
    external_errors: results.filter((result) => !result.ok).map((result) => result.error),
  };
}

async function mapLimit(items, limit, fn) {
  const results = new Array(items.length);
  let next = 0;
  const workers = Array.from({ length: limit }, async () => {
    while (next < items.length) {
      const index = next++;
      results[index] = await fn(items[index], index);
      if ((index + 1) % 50 === 0) console.log(`checked ${index + 1}/${items.length}`);
    }
  });
  await Promise.all(workers);
  return results;
}

const [rawLeaks, rawHijacks, rawOutages2023, rawOutages2021To2022] = await Promise.all([
  readFile(new URL("raw_leaks_2023-01_to_2026-01.json", OUT_DIR), "utf8").then(JSON.parse),
  readFile(new URL("raw_hijacks_2023-01_to_2026-01.json", OUT_DIR), "utf8").then(JSON.parse),
  readFile(new URL("raw_outages_2023-01_to_2026-01.json", OUT_DIR), "utf8").then(JSON.parse),
  fetchCloudflareOutages2021To2022(),
]);

await writeFile(new URL("raw_outages_2021-01_to_2022-12_cloudflare.json", OUT_DIR), JSON.stringify(rawOutages2021To2022, null, 2));

const cloudflareAvailability = [
  { category: "Leak", requested_range: "2021-01-01 to 2025-12-31", available_records: rawLeaks.filter((r) => inRange(r.detected_ts)).length, note: "Cloudflare returned 0 leak records for 2021-2022 in availability test" },
  { category: "Hijack", requested_range: "2021-01-01 to 2025-12-31", available_records: rawHijacks.filter((r) => inRange(r.min_hijack_ts)).length, note: "Cloudflare returned 0 hijack records for 2021-2022 in availability test" },
  { category: "Outage", requested_range: "2021-01-01 to 2025-12-31", available_records: [...rawOutages2021To2022, ...rawOutages2023].filter((r) => inRange(r.startDate)).length, note: "Cloudflare outage annotations available from late 2022 in this extraction" },
];

const leaks = groupTopByDay(rawLeaks.filter((r) => inRange(r.detected_ts)).map(normalizeLeak), 1);
const hijacks = groupTopByDay(rawHijacks.filter((r) => inRange(r.min_hijack_ts)).map(normalizeHijack), 1);
const outages = groupTopByDay([...rawOutages2021To2022, ...rawOutages2023].filter((r) => inRange(r.startDate)).map(normalizeOutage), 1);
const candidates = [...leaks, ...hijacks, ...outages].sort((a, b) => parseTime(a.start_utc) - parseTime(b.start_utc));

console.log(`Cloudflare daily candidates: leaks=${leaks.length}, hijacks=${hijacks.length}, outages=${outages.length}, total=${candidates.length}`);

const auditRows = await mapLimit(candidates, 8, async (event) => {
  const match = event.category === "Outage" ? await matchIoda(event) : await matchManrs(event);
  return {
    cloudflare_source_id: event.cloudflare_source_id,
    category: event.category,
    incident_date: event.incident_date,
    start_utc: event.start_utc,
    end_utc: event.end_utc,
    duration_minutes: event.duration_minutes,
    five_minute_window_count: event.five_minute_window_count,
    primary_asn: event.primary_asn,
    affected_asns: event.affected_asns,
    affected_prefixes: event.affected_prefixes,
    prefix_count: event.prefix_count,
    peer_count: event.peer_count,
    countries: event.countries,
    confidence_score: event.confidence_score ?? null,
    cloudflare_metric: event.cloudflare_metric,
    match_status: match.match_status,
    match_source: match.match_source,
    match_logic: match.match_logic,
    match_key: match.match_key,
    external_source_urls: match.external_source_urls,
    external_evidence: match.external_evidence,
    external_errors: match.external_errors,
    cloudflare_raw_fields: event.cloudflare_raw_fields,
  };
});

const matchedRows = auditRows.filter((row) => row.match_status.startsWith("MATCH"));
const summaryRows = ["Hijack", "Leak", "Outage"].flatMap((category) => {
  const subset = auditRows.filter((row) => row.category === category);
  return [...new Set(subset.map((row) => row.match_status))].sort().map((status) => ({
    category,
    match_status: status,
    incident_count: subset.filter((row) => row.match_status === status).length,
  }));
});

const headers = [
  "cloudflare_source_id",
  "category",
  "incident_date",
  "start_utc",
  "end_utc",
  "duration_minutes",
  "five_minute_window_count",
  "primary_asn",
  "affected_asns",
  "affected_prefixes",
  "prefix_count",
  "peer_count",
  "countries",
  "confidence_score",
  "cloudflare_metric",
  "match_status",
  "match_source",
  "match_logic",
  "match_key",
  "external_source_urls",
  "external_evidence",
  "external_errors",
  "cloudflare_raw_fields",
];

await Promise.all([
  writeCsv("cloudflare_manrs_ioda_matched_incidents_2021-2025.csv", headers, matchedRows),
  writeCsv("cloudflare_manrs_ioda_audit_incidents_2021-2025.csv", headers, auditRows),
  writeCsv("cloudflare_manrs_ioda_summary_2021-2025.csv", ["category", "match_status", "incident_count"], summaryRows),
  writeCsv("cloudflare_availability_2021-2025.csv", ["category", "requested_range", "available_records", "note"], cloudflareAvailability),
]);

console.log(JSON.stringify({
  candidates: {
    leaks: leaks.length,
    hijacks: hijacks.length,
    outages: outages.length,
    total: auditRows.length,
  },
  matched: matchedRows.length,
  summary: summaryRows,
  availability: cloudflareAvailability,
}, null, 2));

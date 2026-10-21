import { readFile, writeFile } from "node:fs/promises";
import { execFile } from "node:child_process";
import { promisify } from "node:util";

const OUT_DIR = new URL("./", import.meta.url);
const RIPESTAT = "https://stat.ripe.net/data/bgp-updates/data.json";
const START_DAY = "2024-01-01";
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

function toRipeTime(ms) {
  return new Date(ms).toISOString().replace(/\.\d{3}Z$/, "");
}

function day(value) {
  return value ? String(value).slice(0, 10) : "";
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

function inRange(value) {
  const d = day(value);
  return d >= START_DAY && d <= END_DAY;
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

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

const cache = new Map();
async function fetchRipeUpdates(resource, start, end, attempt = 1) {
  const key = `${resource}|${start}|${end}`;
  if (cache.has(key)) return cache.get(key);

  const url = new URL(RIPESTAT);
  url.searchParams.set("resource", resource);
  url.searchParams.set("starttime", start);
  url.searchParams.set("endtime", end);
  url.searchParams.set("data_overload_limit", "ignore");
  url.searchParams.set("sourceapp", "codex-incident-research");

  const promise = (async () => {
    try {
      const { stdout } = await execFileAsync("curl", ["-fsS", "--max-time", "8", url.toString()], {
        maxBuffer: 256 * 1024 * 1024,
      });
      const json = JSON.parse(stdout);
      const responseStatus = json.status === "ok" ? 200 : 500;
      if (json.status !== "ok" && attempt < 4) {
        await sleep(1000 * attempt * attempt);
        cache.delete(key);
        return fetchRipeUpdates(resource, start, end, attempt + 1);
      }
      if (json.status !== "ok") {
        return { error: `${responseStatus} ${json.status ?? ""}`, updates: [], nr_updates: 0, url: url.toString() };
      }
      return {
        error: null,
        updates: json.data?.updates ?? [],
        nr_updates: json.data?.nr_updates ?? 0,
        url: url.toString(),
      };
    } catch (error) {
      return { error: error.killed || error.signal ? "RIPESTAT_TIMEOUT" : error.message, updates: [], nr_updates: 0, url: url.toString() };
    }
  })();

  cache.set(key, promise);
  return promise;
}

function announcementPath(update) {
  return update.type === "A" ? update.attrs?.path ?? [] : [];
}

function targetPrefix(update) {
  return update.attrs?.target_prefix ?? "";
}

function containsSubsequence(path, segment) {
  if (!Array.isArray(path) || !Array.isArray(segment) || !segment.length) return false;
  const full = path.map(String);
  const sub = segment.map(String);
  for (let i = 0; i <= full.length - sub.length; i++) {
    if (sub.every((asn, j) => full[i + j] === asn)) return true;
  }
  return false;
}

function pathOverlapCount(path, asns) {
  const set = new Set((path ?? []).map(String));
  return [...new Set((asns ?? []).map(String))].filter((asn) => set.has(asn)).length;
}

function queryWindow(startUtc, endUtc, maxHours = 2) {
  const start = parseTime(startUtc);
  const queryStart = start - 30 * 60_000;
  const queryEnd = start + maxHours * 60 * 60_000;
  return [toRipeTime(queryStart), toRipeTime(queryEnd)];
}

function normalizeLeak(record) {
  const start = toIso(record.min_ts ?? record.detected_ts);
  const end = toIso(record.max_ts);
  const duration = durationMinutes(start, end);
  return {
    incident_id: record.id,
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
    cloudflare_details: { leak_count: record.leak_count, leak_seg: record.leak_seg, origin_count: record.origin_count, leak_type: record.leak_type },
    raw: record,
  };
}

function normalizeHijack(record) {
  const start = toIso(record.min_hijack_ts);
  const end = toIso(record.max_hijack_ts);
  const duration = durationMinutes(start, end);
  return {
    incident_id: record.id,
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
    cloudflare_details: { hijack_msgs_count: record.hijack_msgs_count, tags: record.tags },
    raw: record,
  };
}

function normalizeOutage(record) {
  const start = toIso(record.startDate);
  const end = toIso(record.endDate);
  const duration = durationMinutes(start, end);
  return {
    incident_id: record.id,
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
    cloudflare_details: { description: record.description, outage: record.outage, dataSource: record.dataSource },
    raw: record,
  };
}

function groupTopByDay(events, category, limitPerDay) {
  const grouped = new Map();
  for (const event of events) {
    if (!event.incident_date) continue;
    if (!grouped.has(event.incident_date)) grouped.set(event.incident_date, []);
    grouped.get(event.incident_date).push(event);
  }
  const result = [];
  for (const items of grouped.values()) {
    items.sort((a, b) =>
      (b.cloudflare_metric ?? 0) - (a.cloudflare_metric ?? 0) ||
      (b.duration_minutes ?? 0) - (a.duration_minutes ?? 0) ||
      (b.prefix_count ?? 0) - (a.prefix_count ?? 0)
    );
    result.push(...items.slice(0, limitPerDay));
  }
  console.log(`${category}: ${grouped.size} days, ${result.length} daily candidates`);
  return result;
}

async function verifyLeak(event) {
  const [queryStart, queryEnd] = queryWindow(event.start_utc, event.end_utc, 2);
  const resources = [...new Set([event.primary_asn, ...(event.affected_asns ?? [])].filter(Boolean).map((asn) => `AS${asn}`))];
  const queryResource = resources.slice(0, 4).join(",");
  const results = [await fetchRipeUpdates(queryResource, queryStart, queryEnd)];
  const allUpdates = results.flatMap((result) => result.updates.map((update) => ({ update, result })));
  const announcements = allUpdates.filter(({ update }) => update.type === "A");
  const exact = announcements.filter(({ update }) => containsSubsequence(announcementPath(update), event.affected_asns));
  const overlap = announcements
    .map(({ update, result }) => ({ update, result, overlap: pathOverlapCount(announcementPath(update), event.affected_asns) }))
    .filter((item) => item.overlap >= Math.min(2, event.affected_asns.length));
  const best = exact[0] ?? overlap[0];
  const updateCount = results.reduce((sum, result) => sum + (result.nr_updates ?? 0), 0);
  const matchCount = exact.length || overlap.length;
  return {
    status: exact.length ? "MATCH_STRONG" : (overlap.length ? "MATCH_RELAXED" : "NO_MATCH"),
    evidence_level: exact.length ? "exact leak_seg subsequence" : (overlap.length ? "same RIPEstat path contains at least two leak_seg ASNs" : "none"),
    source: "RIPEstat bgp-updates",
    source_url: results.map((result) => result.url),
    query_resource: queryResource,
    query_start: queryStart,
    query_end: queryEnd,
    update_count: updateCount,
    matching_update_count: matchCount,
    match_percent: updateCount ? Number(((matchCount / updateCount) * 100).toFixed(2)) : 0,
    evidence: best ? { timestamp: best.update.timestamp, prefix: targetPrefix(best.update), path: announcementPath(best.update) } : null,
    errors: results.map((result) => result.error).filter(Boolean),
  };
}

async function verifyHijack(event) {
  const [queryStart, queryEnd] = queryWindow(event.start_utc, event.end_utc, 2);
  const prefixes = event.affected_prefixes.slice(0, 3);
  const resources = prefixes.length ? prefixes : [`AS${event.primary_asn}`];
  const queryResource = resources.join(",");
  const results = [await fetchRipeUpdates(queryResource, queryStart, queryEnd)];
  const allUpdates = results.flatMap((result) => result.updates.map((update) => ({ update, result })));
  const matches = allUpdates.filter(({ update }) => {
    const path = announcementPath(update).map(String);
    return update.type === "A" && path.at(-1) === String(event.primary_asn);
  });
  const updateCount = results.reduce((sum, result) => sum + (result.nr_updates ?? 0), 0);
  return {
    status: matches.length ? "MATCH_STRONG" : "NO_MATCH",
    evidence_level: matches.length ? "hijacker_asn observed as origin for affected prefix" : "none",
    source: "RIPEstat bgp-updates",
    source_url: results.map((result) => result.url),
    query_resource: queryResource,
    query_start: queryStart,
    query_end: queryEnd,
    update_count: updateCount,
    matching_update_count: matches.length,
    match_percent: updateCount ? Number(((matches.length / updateCount) * 100).toFixed(2)) : 0,
    evidence: matches[0] ? { timestamp: matches[0].update.timestamp, prefix: targetPrefix(matches[0].update), path: announcementPath(matches[0].update) } : null,
    errors: results.map((result) => result.error).filter(Boolean),
  };
}

async function verifyOutage(event) {
  const [queryStart, queryEnd] = queryWindow(event.start_utc, event.end_utc, 2);
  const resources = [...new Set((event.affected_asns ?? []).filter(Boolean).map((asn) => `AS${asn}`))].slice(0, 8);
  if (!resources.length) {
    return {
      status: "NO_MATCH",
      evidence_level: "no affected ASN available to query",
      source: "RIPEstat bgp-updates",
      query_start: queryStart,
      query_end: queryEnd,
      update_count: 0,
      matching_update_count: 0,
      match_percent: 0,
    };
  }
  const queryResource = resources.join(",");
  const results = [await fetchRipeUpdates(queryResource, queryStart, queryEnd)];
  const withdrawals = results.flatMap((result) => result.updates.filter((update) => update.type === "W").map((update) => ({ update, result })));
  const updateCount = results.reduce((sum, result) => sum + (result.nr_updates ?? 0), 0);
  const heavyActivity = updateCount >= Math.max(100, resources.length * 25);
  const status = withdrawals.length ? "MATCH_STRONG" : (heavyActivity ? "MATCH_RELAXED" : "NO_MATCH");
  return {
    status,
    evidence_level: withdrawals.length ? "withdrawals observed for affected outage ASN(s)" : (heavyActivity ? "high BGP update activity across affected ASN(s)" : "none"),
    source: "RIPEstat bgp-updates",
    source_url: results.map((result) => result.url),
    query_resource: queryResource,
    query_start: queryStart,
    query_end: queryEnd,
    update_count: updateCount,
    matching_update_count: withdrawals.length || (heavyActivity ? updateCount : 0),
    match_percent: withdrawals.length && updateCount ? Number(((withdrawals.length / updateCount) * 100).toFixed(2)) : (heavyActivity ? 100 : 0),
    evidence: withdrawals[0] ? { timestamp: withdrawals[0].update.timestamp, prefix: targetPrefix(withdrawals[0].update) } : null,
    errors: results.map((result) => result.error).filter(Boolean),
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

const [rawLeaks, rawHijacks, rawOutages] = await Promise.all([
  readFile(new URL("raw_leaks_2023-01_to_2026-01.json", OUT_DIR), "utf8").then(JSON.parse),
  readFile(new URL("raw_hijacks_2023-01_to_2026-01.json", OUT_DIR), "utf8").then(JSON.parse),
  readFile(new URL("raw_outages_2023-01_to_2026-01.json", OUT_DIR), "utf8").then(JSON.parse),
]);

const leaks = rawLeaks.filter((r) => inRange(r.detected_ts)).map(normalizeLeak);
const hijacks = rawHijacks.filter((r) => inRange(r.min_hijack_ts)).map(normalizeHijack);
const outages = rawOutages.filter((r) => inRange(r.startDate)).map(normalizeOutage);

const candidates = [
  ...groupTopByDay(leaks, "Leak", 1),
  ...groupTopByDay(hijacks, "Hijack", 1),
  ...groupTopByDay(outages, "Outage", 1),
].sort((a, b) => parseTime(a.start_utc) - parseTime(b.start_utc));

console.log(`total daily candidates: ${candidates.length}`);

const auditRows = await mapLimit(candidates, 8, async (event) => {
  const external = event.category === "Leak"
    ? await verifyLeak(event)
    : event.category === "Hijack"
      ? await verifyHijack(event)
      : await verifyOutage(event);
  return {
    incident_id: event.incident_id,
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
    cloudflare_details: event.cloudflare_details,
    ripestat_status: external.status,
    evidence_level: external.evidence_level,
    ripestat_query_resource: external.query_resource,
    ripestat_query_start: external.query_start,
    ripestat_query_end: external.query_end,
    ripestat_update_count: external.update_count,
    ripestat_matching_update_count: external.matching_update_count,
    ripestat_match_percent: external.match_percent,
    ripestat_evidence: external.evidence,
    ripestat_source_url: external.source_url,
    ripestat_errors: external.errors,
  };
});

const matchedRows = auditRows.filter((row) => row.ripestat_status === "MATCH_STRONG" || row.ripestat_status === "MATCH_RELAXED");
const strongRows = auditRows.filter((row) => row.ripestat_status === "MATCH_STRONG");
const summaryRows = ["Hijack", "Leak", "Outage"].flatMap((category) => {
  const subset = auditRows.filter((row) => row.category === category);
  return [
    {
      category,
      status: "MATCH_STRONG",
      incident_count: subset.filter((row) => row.ripestat_status === "MATCH_STRONG").length,
    },
    {
      category,
      status: "MATCH_RELAXED",
      incident_count: subset.filter((row) => row.ripestat_status === "MATCH_RELAXED").length,
    },
    {
      category,
      status: "NO_MATCH",
      incident_count: subset.filter((row) => row.ripestat_status === "NO_MATCH").length,
    },
  ];
});

const headers = [
  "incident_id",
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
  "cloudflare_details",
  "ripestat_status",
  "evidence_level",
  "ripestat_query_resource",
  "ripestat_query_start",
  "ripestat_query_end",
  "ripestat_update_count",
  "ripestat_matching_update_count",
  "ripestat_match_percent",
  "ripestat_evidence",
  "ripestat_source_url",
  "ripestat_errors",
];

await Promise.all([
  writeCsv("exhaustive_daily_cloudflare_ripestat_matches_2024-2025.csv", headers, matchedRows),
  writeCsv("exhaustive_daily_cloudflare_ripestat_strong_matches_2024-2025.csv", headers, strongRows),
  writeCsv("exhaustive_daily_cloudflare_ripestat_audit_2024-2025.csv", headers, auditRows),
  writeCsv("exhaustive_daily_cloudflare_ripestat_summary_2024-2025.csv", ["category", "status", "incident_count"], summaryRows),
]);

console.log(JSON.stringify({
  candidates_checked: auditRows.length,
  matched: matchedRows.length,
  strong_matches: strongRows.length,
  summary: summaryRows,
}, null, 2));

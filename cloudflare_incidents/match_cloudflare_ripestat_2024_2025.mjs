import { readFile, writeFile } from "node:fs/promises";

const OUT_DIR = new URL("./", import.meta.url);
const RIPESTAT = "https://stat.ripe.net/data/bgp-updates/data.json";
const START = "2024-01-01";
const END = "2025-12-31";

function parseCsv(text) {
  const rows = [];
  let row = [];
  let cell = "";
  let quoted = false;

  for (let i = 0; i < text.length; i++) {
    const char = text[i];
    const next = text[i + 1];
    if (quoted) {
      if (char === '"' && next === '"') {
        cell += '"';
        i++;
      } else if (char === '"') {
        quoted = false;
      } else {
        cell += char;
      }
      continue;
    }
    if (char === '"') quoted = true;
    else if (char === ",") {
      row.push(cell);
      cell = "";
    } else if (char === "\n") {
      row.push(cell);
      rows.push(row);
      row = [];
      cell = "";
    } else if (char !== "\r") {
      cell += char;
    }
  }
  if (cell || row.length) {
    row.push(cell);
    rows.push(row);
  }
  const [header, ...dataRows] = rows.filter((line) => line.length > 1 || line[0]);
  return dataRows.map((values) => Object.fromEntries(header.map((key, index) => [key, values[index] ?? ""])));
}

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

function minutesBetween(start, end) {
  const a = parseTime(start);
  const b = parseTime(end);
  if (!Number.isFinite(a) || !Number.isFinite(b) || b < a) return null;
  return Math.ceil((b - a) / 60000);
}

function day(value) {
  return value ? String(value).slice(0, 10) : "";
}

function inRange(value) {
  const d = day(value);
  return d >= START && d <= END;
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

function containsSubsequence(path, segment) {
  if (!Array.isArray(path) || !Array.isArray(segment) || segment.length === 0) return false;
  const full = path.map(String);
  const sub = segment.map(String);
  for (let i = 0; i <= full.length - sub.length; i++) {
    if (sub.every((asn, j) => full[i + j] === asn)) return true;
  }
  return false;
}

function announcementPath(update) {
  return update.type === "A" ? update.attrs?.path ?? [] : [];
}

function targetPrefix(update) {
  return update.attrs?.target_prefix ?? "";
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function fetchRipeUpdates(resource, start, end, attempt = 1) {
  const url = new URL(RIPESTAT);
  url.searchParams.set("resource", resource);
  url.searchParams.set("starttime", start);
  url.searchParams.set("endtime", end);
  url.searchParams.set("data_overload_limit", "ignore");
  url.searchParams.set("sourceapp", "codex-incident-research");

  try {
    const response = await fetch(url);
    const json = await response.json();
    if ((response.status === 429 || response.status >= 500) && attempt < 4) {
      await sleep(1000 * attempt * attempt);
      return fetchRipeUpdates(resource, start, end, attempt + 1);
    }
    if (!response.ok || json.status !== "ok") {
      return { error: `${response.status} ${json.status ?? ""}`, updates: [], nr_updates: 0, url: url.toString() };
    }
    return {
      error: null,
      updates: json.data?.updates ?? [],
      nr_updates: json.data?.nr_updates ?? 0,
      url: url.toString(),
    };
  } catch (error) {
    return { error: error.message, updates: [], nr_updates: 0, url: url.toString() };
  }
}

function queryWindow(startUtc, endUtc) {
  const start = parseTime(startUtc);
  const end = parseTime(endUtc);
  const queryStart = start - 30 * 60_000;
  const queryEnd = Number.isFinite(end)
    ? Math.min(end + 30 * 60_000, start + 6 * 60 * 60_000)
    : start + 6 * 60 * 60_000;
  return [toRipeTime(queryStart), toRipeTime(queryEnd)];
}

function normalizeLeak(record) {
  const start = toIso(record.min_ts ?? record.detected_ts);
  const end = toIso(record.max_ts);
  return {
    incident_id: record.id,
    category: "Leak",
    start_utc: start,
    end_utc: end,
    duration_minutes: minutesBetween(start, end),
    five_minute_window_count: Math.ceil((minutesBetween(start, end) ?? 0) / 5),
    primary_asn: record.leak_asn,
    affected_asns: record.leak_seg ?? [],
    affected_prefixes: [],
    prefix_count: record.prefix_count ?? null,
    peer_count: record.peer_count ?? null,
    countries: record.countries ?? [],
    cloudflare_metrics: { leak_count: record.leak_count, origin_count: record.origin_count, leak_type: record.leak_type },
    raw: record,
  };
}

function normalizeHijack(record) {
  const start = toIso(record.min_hijack_ts);
  const end = toIso(record.max_hijack_ts);
  return {
    incident_id: record.id,
    category: "Hijack",
    start_utc: start,
    end_utc: end,
    duration_minutes: minutesBetween(start, end),
    five_minute_window_count: Math.ceil((minutesBetween(start, end) ?? 0) / 5),
    primary_asn: record.hijacker_asn,
    affected_asns: record.victim_asns ?? [],
    affected_prefixes: record.prefixes ?? [],
    prefix_count: Array.isArray(record.prefixes) ? record.prefixes.length : null,
    peer_count: Array.isArray(record.peer_asns) ? record.peer_asns.length : null,
    countries: [record.hijacker_country, ...(record.victim_countries ?? [])].filter(Boolean),
    confidence_score: record.confidence_score ?? null,
    cloudflare_metrics: { hijack_msgs_count: record.hijack_msgs_count, tags: record.tags },
    raw: record,
  };
}

function normalizeOutage(record) {
  const start = toIso(record.startDate);
  const end = toIso(record.endDate);
  return {
    incident_id: record.id,
    category: "Outage",
    start_utc: start,
    end_utc: end,
    duration_minutes: minutesBetween(start, end),
    five_minute_window_count: Math.ceil((minutesBetween(start, end) ?? 0) / 5),
    primary_asn: null,
    affected_asns: record.asns ?? [],
    affected_prefixes: [],
    prefix_count: null,
    peer_count: null,
    countries: record.locations ?? [],
    source_url: record.linkedUrl ?? null,
    cloudflare_metrics: { outage: record.outage, description: record.description },
    raw: record,
  };
}

async function verify(event) {
  if (!event.start_utc) return { status: "SKIPPED_NO_START_TIME" };
  const [queryStart, queryEnd] = queryWindow(event.start_utc, event.end_utc);

  if (event.category === "Leak") {
    const resource = `AS${event.primary_asn}`;
    const result = await fetchRipeUpdates(resource, queryStart, queryEnd);
    const matches = result.updates.filter((update) => containsSubsequence(announcementPath(update), event.affected_asns));
    return {
      status: matches.length ? "MATCH" : "NO_MATCH",
      match_rule: "RIPEstat announcement AS path contains Cloudflare leak_seg",
      resource,
      queryStart,
      queryEnd,
      updateCount: result.nr_updates,
      matchCount: matches.length,
      matchPercent: result.nr_updates ? Number(((matches.length / result.nr_updates) * 100).toFixed(2)) : 0,
      evidence: matches[0] ? { timestamp: matches[0].timestamp, prefix: targetPrefix(matches[0]), path: announcementPath(matches[0]) } : null,
      sourceUrl: result.url,
      error: result.error,
    };
  }

  if (event.category === "Hijack") {
    const resource = event.affected_prefixes[0] ?? `AS${event.primary_asn}`;
    const result = await fetchRipeUpdates(resource, queryStart, queryEnd);
    const matches = result.updates.filter((update) => {
      const path = announcementPath(update).map(String);
      return update.type === "A" && path.at(-1) === String(event.primary_asn);
    });
    return {
      status: matches.length ? "MATCH" : "NO_MATCH",
      match_rule: "RIPEstat announcement for affected prefix has hijacker_asn as origin",
      resource,
      queryStart,
      queryEnd,
      updateCount: result.nr_updates,
      matchCount: matches.length,
      matchPercent: result.nr_updates ? Number(((matches.length / result.nr_updates) * 100).toFixed(2)) : 0,
      evidence: matches[0] ? { timestamp: matches[0].timestamp, prefix: targetPrefix(matches[0]), path: announcementPath(matches[0]) } : null,
      sourceUrl: result.url,
      error: result.error,
    };
  }

  const resource = event.affected_asns.length ? `AS${event.affected_asns[0]}` : null;
  if (!resource) return { status: "SKIPPED_NO_ASN" };
  const result = await fetchRipeUpdates(resource, queryStart, queryEnd);
  const matches = result.updates.filter((update) => update.type === "W");
  return {
    status: matches.length ? "MATCH" : "NO_MATCH",
    match_rule: "RIPEstat withdrawals observed for first affected outage ASN",
    resource,
    queryStart,
    queryEnd,
    updateCount: result.nr_updates,
    matchCount: matches.length,
    matchPercent: result.nr_updates ? Number(((matches.length / result.nr_updates) * 100).toFixed(2)) : 0,
    evidence: matches[0] ? { timestamp: matches[0].timestamp, prefix: targetPrefix(matches[0]) } : null,
    sourceUrl: result.url,
    error: result.error,
  };
}

async function mapLimit(items, limit, fn) {
  const results = new Array(items.length);
  let next = 0;
  const workers = Array.from({ length: limit }, async () => {
    while (next < items.length) {
      const index = next++;
      results[index] = await fn(items[index], index);
      if ((index + 1) % 25 === 0) console.log(`checked ${index + 1}/${items.length}`);
    }
  });
  await Promise.all(workers);
  return results;
}

const [leaks, hijacks, outages] = await Promise.all([
  readFile(new URL("raw_leaks_2023-01_to_2026-01.json", OUT_DIR), "utf8").then(JSON.parse),
  readFile(new URL("raw_hijacks_2023-01_to_2026-01.json", OUT_DIR), "utf8").then(JSON.parse),
  readFile(new URL("raw_outages_2023-01_to_2026-01.json", OUT_DIR), "utf8").then(JSON.parse),
]);

const rosterRows = parseCsv(await readFile(new URL("normalized_master_incident_roster_2023-01_to_2026-01.csv", OUT_DIR), "utf8"))
  .filter((row) => row.incident_date >= START && row.incident_date <= END);

const source = {
  Leak: new Map(leaks.map((record) => [String(record.id), normalizeLeak(record)])),
  Hijack: new Map(hijacks.map((record) => [String(record.id), normalizeHijack(record)])),
  Outage: new Map(outages.map((record) => [String(record.id), normalizeOutage(record)])),
};

const limitedCandidates = rosterRows
  .map((row) => source[row.category]?.get(String(row.incident_id)))
  .filter(Boolean)
  .sort((a, b) => parseTime(a.start_utc) - parseTime(b.start_utc));

console.log(`reviewed roster candidate incidents selected for external matching: ${limitedCandidates.length}`);

const auditRows = await mapLimit(limitedCandidates, 4, async (event) => {
  const external = await verify(event);
  return {
    incident_id: event.incident_id,
    category: event.category,
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
    cloudflare_metrics: event.cloudflare_metrics,
    ripestat_status: external.status,
    ripestat_match_rule: external.match_rule,
    ripestat_query_resource: external.resource,
    ripestat_query_start: external.queryStart,
    ripestat_query_end: external.queryEnd,
    ripestat_update_count: external.updateCount ?? 0,
    ripestat_matching_update_count: external.matchCount ?? 0,
    ripestat_match_percent: external.matchPercent ?? 0,
    ripestat_evidence: external.evidence,
    ripestat_source_url: external.sourceUrl,
    error: external.error,
  };
});

const matchedRows = auditRows.filter((row) => row.ripestat_status === "MATCH");
const summaryRows = ["Hijack", "Leak", "Outage"].map((category) => ({
  category,
  candidates_checked: auditRows.filter((row) => row.category === category).length,
  matched_incidents: matchedRows.filter((row) => row.category === category).length,
}));

const headers = [
  "incident_id",
  "category",
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
  "cloudflare_metrics",
  "ripestat_status",
  "ripestat_match_rule",
  "ripestat_query_resource",
  "ripestat_query_start",
  "ripestat_query_end",
  "ripestat_update_count",
  "ripestat_matching_update_count",
  "ripestat_match_percent",
  "ripestat_evidence",
  "ripestat_source_url",
  "error",
];

await Promise.all([
  writeCsv("cloudflare_ripestat_matched_incidents_2024-2025.csv", headers, matchedRows),
  writeCsv("cloudflare_ripestat_audit_incidents_2024-2025.csv", headers, auditRows),
  writeCsv("cloudflare_ripestat_match_summary_2024-2025.csv", ["category", "candidates_checked", "matched_incidents"], summaryRows),
]);

console.log(JSON.stringify({
  overlap_interval: "2024-01-01 through 2025-12-31",
  candidates_checked: auditRows.length,
  matched: matchedRows.length,
  summary: summaryRows,
}, null, 2));

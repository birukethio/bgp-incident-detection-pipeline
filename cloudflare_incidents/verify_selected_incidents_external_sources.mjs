import { readFile, writeFile } from "node:fs/promises";

const OUT_DIR = new URL("./", import.meta.url);
const RIPESTAT = "https://stat.ripe.net/data/bgp-updates/data.json";

const selectedIds = [
  [741, "Outage"],
  [221926, "Leak"],
  [36977, "Hijack"],
  [222206, "Leak"],
  [37251, "Hijack"],
  [222500, "Leak"],
  [37771, "Hijack"],
  [222665, "Leak"],
  [38046, "Hijack"],
  [222896, "Leak"],
  [38518, "Hijack"],
  [778, "Outage"],
  [223178, "Leak"],
  [39007, "Hijack"],
  [781, "Outage"],
  [223398, "Leak"],
  [39437, "Hijack"],
  [786, "Outage"],
  [223650, "Leak"],
  [39864, "Hijack"],
  [223881, "Leak"],
  [40261, "Hijack"],
  [802, "Outage"],
  [224140, "Leak"],
  [40835, "Hijack"],
  [224415, "Leak"],
  [41214, "Hijack"],
];

function parseTime(value) {
  if (!value) return NaN;
  const text = String(value);
  return Date.parse(text.endsWith("Z") ? text : `${text}Z`);
}

function toRipeTime(ms) {
  return new Date(ms).toISOString().replace(/\.\d{3}Z$/, "");
}

function addMinutes(value, minutes) {
  return parseTime(value) + minutes * 60_000;
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
      query_starttime: json.data?.query_starttime,
      query_endtime: json.data?.query_endtime,
      url: url.toString(),
    };
  } catch (error) {
    return { error: error.message, updates: [], nr_updates: 0, url: url.toString() };
  }
}

function containsSubsequence(path, segment) {
  if (!Array.isArray(path) || !Array.isArray(segment) || segment.length === 0) return false;
  const asPath = path.map(String);
  const leakSeg = segment.map(String);
  for (let i = 0; i <= asPath.length - leakSeg.length; i++) {
    if (leakSeg.every((asn, offset) => asPath[i + offset] === asn)) return true;
  }
  return false;
}

function announcementPath(update) {
  return update.type === "A" ? update.attrs?.path ?? update.path ?? [] : [];
}

function targetPrefix(update) {
  return update.attrs?.target_prefix ?? update.target_prefix ?? "";
}

function normalizeLeak(record) {
  return {
    incident_id: record.id,
    category: "Leak",
    start_utc: new Date(parseTime(record.min_ts ?? record.detected_ts)).toISOString(),
    end_utc: record.max_ts ? new Date(parseTime(record.max_ts)).toISOString() : null,
    resource: `AS${record.leak_asn}`,
    leak_seg: record.leak_seg ?? [],
  };
}

function normalizeHijack(record) {
  return {
    incident_id: record.id,
    category: "Hijack",
    start_utc: new Date(parseTime(record.min_hijack_ts)).toISOString(),
    end_utc: record.max_hijack_ts ? new Date(parseTime(record.max_hijack_ts)).toISOString() : null,
    hijacker_asn: record.hijacker_asn,
    victim_asns: record.victim_asns ?? [],
    prefixes: record.prefixes ?? [],
  };
}

function normalizeOutage(record) {
  return {
    incident_id: record.id,
    category: "Outage",
    start_utc: record.startDate ? new Date(parseTime(record.startDate)).toISOString() : null,
    end_utc: record.endDate ? new Date(parseTime(record.endDate)).toISOString() : null,
    asns: record.asns ?? [],
    countries: record.locations ?? [],
  };
}

async function verifyLeak(record) {
  const event = normalizeLeak(record);
  const start = toRipeTime(addMinutes(event.start_utc, -30));
  const end = toRipeTime(Math.min(addMinutes(event.start_utc, 360), parseTime(event.end_utc) || addMinutes(event.start_utc, 360)));
  const result = await fetchRipeUpdates(event.resource, start, end);
  const announcements = result.updates.filter((update) => update.type === "A");
  const pathMatches = announcements.filter((update) => containsSubsequence(announcementPath(update), event.leak_seg));
  return {
    ...event,
    external_source: "RIPEstat bgp-updates",
    external_source_url: result.url,
    external_query_resource: event.resource,
    external_query_start: start,
    external_query_end: end,
    external_status: pathMatches.length ? "MATCHING_AS_PATH_OBSERVED" : (result.nr_updates ? "BGP_ACTIVITY_ONLY_NO_EXACT_LEAK_SEGMENT" : "NO_RIPESTAT_UPDATES_RETURNED"),
    external_update_count: result.nr_updates,
    matching_update_count: pathMatches.length,
    sample_evidence: pathMatches[0] ? {
      timestamp: pathMatches[0].timestamp,
      target_prefix: targetPrefix(pathMatches[0]),
      path: announcementPath(pathMatches[0]),
    } : null,
    error: result.error,
  };
}

async function verifyHijack(record) {
  const event = normalizeHijack(record);
  const resource = event.prefixes[0] ?? `AS${event.hijacker_asn}`;
  const start = toRipeTime(addMinutes(event.start_utc, -30));
  const end = toRipeTime(Math.min(addMinutes(event.start_utc, 360), parseTime(event.end_utc) || addMinutes(event.start_utc, 360)));
  const result = await fetchRipeUpdates(resource, start, end);
  const announcements = result.updates.filter((update) => update.type === "A");
  const originMatches = announcements.filter((update) => {
    const path = announcementPath(update).map(String);
    return path.at(-1) === String(event.hijacker_asn);
  });
  return {
    ...event,
    external_source: "RIPEstat bgp-updates",
    external_source_url: result.url,
    external_query_resource: resource,
    external_query_start: start,
    external_query_end: end,
    external_status: originMatches.length ? "HIJACKER_ORIGIN_ANNOUNCEMENT_OBSERVED" : (result.nr_updates ? "BGP_ACTIVITY_ONLY_NO_HIJACKER_ORIGIN_MATCH" : "NO_RIPESTAT_UPDATES_RETURNED"),
    external_update_count: result.nr_updates,
    matching_update_count: originMatches.length,
    sample_evidence: originMatches[0] ? {
      timestamp: originMatches[0].timestamp,
      target_prefix: targetPrefix(originMatches[0]),
      path: announcementPath(originMatches[0]),
    } : null,
    error: result.error,
  };
}

async function verifyOutage(record) {
  const event = normalizeOutage(record);
  const resource = event.asns.length ? `AS${event.asns[0]}` : (event.countries[0] ?? "");
  if (!resource) {
    return {
      ...event,
      external_source: "RIPEstat bgp-updates",
      external_status: "UNVERIFIED_NO_ASN_OR_COUNTRY_TO_QUERY",
    };
  }
  const start = toRipeTime(addMinutes(event.start_utc, -30));
  const end = toRipeTime(addMinutes(event.end_utc ?? event.start_utc, 30));
  const result = await fetchRipeUpdates(resource, start, end);
  const withdrawals = result.updates.filter((update) => update.type === "W");
  return {
    ...event,
    external_source: "RIPEstat bgp-updates",
    external_source_url: result.url,
    external_query_resource: resource,
    external_query_start: start,
    external_query_end: end,
    external_status: withdrawals.length ? "BGP_WITHDRAWALS_OBSERVED_DURING_OUTAGE_WINDOW" : (result.nr_updates ? "BGP_ACTIVITY_ONLY_NO_WITHDRAWALS" : "NO_RIPESTAT_UPDATES_RETURNED"),
    external_update_count: result.nr_updates,
    matching_update_count: withdrawals.length,
    sample_evidence: withdrawals[0] ? {
      timestamp: withdrawals[0].timestamp,
      target_prefix: targetPrefix(withdrawals[0]),
    } : null,
    error: result.error,
  };
}

const [leaks, hijacks, outages] = await Promise.all([
  readFile(new URL("raw_leaks_2023-01_to_2026-01.json", OUT_DIR), "utf8").then(JSON.parse),
  readFile(new URL("raw_hijacks_2023-01_to_2026-01.json", OUT_DIR), "utf8").then(JSON.parse),
  readFile(new URL("raw_outages_2023-01_to_2026-01.json", OUT_DIR), "utf8").then(JSON.parse),
]);

const source = {
  Leak: new Map(leaks.map((record) => [String(record.id), record])),
  Hijack: new Map(hijacks.map((record) => [String(record.id), record])),
  Outage: new Map(outages.map((record) => [String(record.id), record])),
};

const rows = [];
for (const [id, category] of selectedIds) {
  const record = source[category].get(String(id));
  if (!record) {
    rows.push({
      incident_id: id,
      category,
      external_source: "RIPEstat bgp-updates",
      external_status: "SOURCE_RECORD_NOT_FOUND_LOCALLY",
    });
    continue;
  }
  if (category === "Leak") rows.push(await verifyLeak(record));
  if (category === "Hijack") rows.push(await verifyHijack(record));
  if (category === "Outage") rows.push(await verifyOutage(record));
}

const headers = [
  "incident_id",
  "category",
  "start_utc",
  "end_utc",
  "external_source",
  "external_source_url",
  "external_query_resource",
  "external_query_start",
  "external_query_end",
  "external_status",
  "external_update_count",
  "matching_update_count",
  "resource",
  "leak_seg",
  "hijacker_asn",
  "victim_asns",
  "prefixes",
  "asns",
  "countries",
  "sample_evidence",
  "error",
];

const summary = [...new Set(rows.map((row) => row.external_status))].sort().map((external_status) => ({
  external_status,
  incident_count: rows.filter((row) => row.external_status === external_status).length,
}));

await Promise.all([
  writeCsv("external_ripe_verification_selected_incidents_2024-02-15_to_2024-03-18.csv", headers, rows),
  writeCsv("external_ripe_verification_summary_2024-02-15_to_2024-03-18.csv", ["external_status", "incident_count"], summary),
]);

console.log(JSON.stringify({
  checked: rows.length,
  summary,
}, null, 2));

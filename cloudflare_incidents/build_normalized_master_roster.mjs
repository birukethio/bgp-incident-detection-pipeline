import { readFile, writeFile } from "node:fs/promises";

const OUT_DIR = new URL("./", import.meta.url);
const START_DAY = "2023-01-01";
const END_DAY = "2026-01-31";

const rosterHeaders = [
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

function toDateKey(value) {
  return value ? String(value).slice(0, 10) : null;
}

function parseTime(value) {
  if (!value) return NaN;
  const text = String(value);
  return Date.parse(text.endsWith("Z") ? text : `${text}Z`);
}

function toUtcIso(value) {
  const ms = parseTime(value);
  return Number.isFinite(ms) ? new Date(ms).toISOString() : null;
}

function durationMinutes(start, end) {
  const startMs = parseTime(start);
  const endMs = parseTime(end);
  if (!Number.isFinite(startMs) || !Number.isFinite(endMs) || endMs < startMs) {
    return null;
  }
  return Math.ceil((endMs - startMs) / 60000);
}

function fiveMinuteWindowCount(minutes) {
  return Number.isFinite(minutes) ? Math.ceil(minutes / 5) : null;
}

function jsonList(value) {
  if (value == null) return null;
  return JSON.stringify(Array.isArray(value) ? value : [value]);
}

function jsonValue(value) {
  if (value == null) return null;
  return JSON.stringify(value);
}

function csvCell(value) {
  if (value == null) return "";
  const text = String(value);
  return /[",\n\r]/.test(text) ? `"${text.replaceAll('"', '""')}"` : text;
}

async function writeCsv(filename, headers, rows) {
  const csv = [
    headers.map(csvCell).join(","),
    ...rows.map((row) => headers.map((header) => csvCell(row[header])).join(",")),
  ].join("\n");
  await writeFile(new URL(filename, OUT_DIR), `${csv}\n`);
}

function dayKeys() {
  const days = [];
  for (let date = new Date(`${START_DAY}T00:00:00Z`); date <= new Date(`${END_DAY}T00:00:00Z`); date.setUTCDate(date.getUTCDate() + 1)) {
    days.push(date.toISOString().slice(0, 10));
  }
  return days;
}

function groupByDate(items, dateSelector) {
  const grouped = new Map();
  for (const item of items) {
    const key = dateSelector(item);
    if (!key) continue;
    if (!grouped.has(key)) grouped.set(key, []);
    grouped.get(key).push(item);
  }
  return grouped;
}

function pickLeak(items) {
  return items.toSorted((a, b) =>
    (b.leak_count ?? 0) - (a.leak_count ?? 0) ||
    (b.prefix_count ?? 0) - (a.prefix_count ?? 0) ||
    (b.peer_count ?? 0) - (a.peer_count ?? 0)
  )[0];
}

function pickHijack(items) {
  return items.toSorted((a, b) =>
    (b.hijack_msgs_count ?? 0) - (a.hijack_msgs_count ?? 0) ||
    (b.duration ?? 0) - (a.duration ?? 0) ||
    (b.confidence_score ?? 0) - (a.confidence_score ?? 0)
  )[0];
}

function pickOutage(items) {
  return items.toSorted((a, b) =>
    (durationMinutes(b.startDate, b.endDate) ?? -1) - (durationMinutes(a.startDate, a.endDate) ?? -1) ||
    (b.asns?.length ?? 0) - (a.asns?.length ?? 0)
  )[0];
}

function generatedName(prefix, id, date) {
  return `${prefix}_${id}_${date ?? "UNVERIFIED_DATE"}`;
}

function normalizeLeak(incident, assignedDate) {
  const start = toUtcIso(incident.min_ts ?? incident.detected_ts);
  const end = toUtcIso(incident.max_ts);
  const duration = durationMinutes(start, end);
  const incidentDate = assignedDate;
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
    notes: `incident_name generated; affected_asns mapped from leak_seg; origin_count=${incident.origin_count ?? "UNVERIFIED"}; leak_type=${incident.leak_type ?? "UNVERIFIED"}`,
  };
}

function normalizeHijack(incident, assignedDate) {
  const start = toUtcIso(incident.min_hijack_ts);
  const end = toUtcIso(incident.max_hijack_ts);
  const duration = durationMinutes(start, end);
  const countries = [
    ...(incident.hijacker_country ? [incident.hijacker_country] : []),
    ...(incident.victim_countries ?? []),
  ];
  const tags = (incident.tags ?? []).map((tag) => `${tag.name}:${tag.score}`);
  const incidentDate = assignedDate;
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
    notes: `incident_name generated; tags=${tags.length ? tags.join(";") : "UNVERIFIED"}; hijack_msgs_count=${incident.hijack_msgs_count ?? "UNVERIFIED"}; event_type=${incident.event_type ?? "UNVERIFIED"}; max_msg_ts preserved in raw source only, not used as end_utc`,
  };
}

function normalizeOutage(incident, assignedDate) {
  const start = toUtcIso(incident.startDate);
  const end = toUtcIso(incident.endDate);
  const providedDuration = durationMinutes(start, end);
  const incidentDate = assignedDate;
  const cause = incident.outage?.outageCause ?? "UNVERIFIED";
  const type = incident.outage?.outageType ?? "UNVERIFIED";
  return {
    incident_id: incident.id,
    incident_name: incident.description || generatedName("Outage", incident.id, incidentDate),
    category: "Outage",
    incident_date: incidentDate,
    start_utc: start,
    end_utc: end,
    duration_minutes: providedDuration,
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
    five_minute_window_count: fiveMinuteWindowCount(providedDuration),
    partition: null,
    notes: `outageCause=${cause}; outageType=${type}; dataSource=${incident.dataSource ?? "UNVERIFIED"}`,
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

const [leaks, hijacks, outages] = await Promise.all([
  readFile(new URL("raw_leaks_2023-01_to_2026-01.json", OUT_DIR), "utf8").then(JSON.parse),
  readFile(new URL("raw_hijacks_2023-01_to_2026-01.json", OUT_DIR), "utf8").then(JSON.parse),
  readFile(new URL("raw_outages_2023-01_to_2026-01.json", OUT_DIR), "utf8").then(JSON.parse),
]);

const groups = {
  leaks: groupByDate(leaks, (item) => toDateKey(item.detected_ts)),
  hijacks: groupByDate(hijacks, (item) => toDateKey(item.min_hijack_ts)),
  outages: groupByDate(outages, (item) => toDateKey(item.startDate)),
};

const roster = [];
for (const [index, day] of dayKeys().entries()) {
  if (index % 3 === 0) {
    const incident = groups.leaks.get(day)?.length ? pickLeak(groups.leaks.get(day)) : null;
    if (incident) roster.push(normalizeLeak(incident, day));
  } else if (index % 3 === 1) {
    const incident = groups.hijacks.get(day)?.length ? pickHijack(groups.hijacks.get(day)) : null;
    if (incident) roster.push(normalizeHijack(incident, day));
  } else {
    const incident = groups.outages.get(day)?.length ? pickOutage(groups.outages.get(day)) : null;
    if (incident) roster.push(normalizeOutage(incident, day));
  }
}
roster.sort((a, b) => a.incident_date.localeCompare(b.incident_date));

const counts = ["Hijack", "Leak", "Outage"].map((category) => ({
  category,
  incident_count: roster.filter((row) => row.category === category).length,
}));

const missing = roster.flatMap((row) => {
  const reasons = missingReasons(row);
  return reasons.length
    ? [{
        incident_id: row.incident_id,
        category: row.category,
        incident_date: row.incident_date,
        missing_or_unverified_fields: jsonList(reasons),
        notes: row.notes,
      }]
    : [];
});

const windows = roster.map((row) => ({
  incident_id: row.incident_id,
  category: row.category,
  start_utc: row.start_utc,
  end_utc: row.end_utc,
  duration_minutes: row.duration_minutes,
  five_minute_window_count: row.five_minute_window_count,
}));

await Promise.all([
  writeCsv("normalized_master_incident_roster_2023-01_to_2026-01.csv", rosterHeaders, roster),
  writeCsv("normalized_master_summary_counts_2023-01_to_2026-01.csv", ["category", "incident_count"], counts),
  writeCsv("normalized_master_missing_unverified_2023-01_to_2026-01.csv", ["incident_id", "category", "incident_date", "missing_or_unverified_fields", "notes"], missing),
  writeCsv("normalized_master_window_counts_2023-01_to_2026-01.csv", ["incident_id", "category", "start_utc", "end_utc", "duration_minutes", "five_minute_window_count"], windows),
]);

console.log(JSON.stringify({
  roster_rows: roster.length,
  counts,
  missing_or_unverified_rows: missing.length,
  window_rows: windows.length,
}, null, 2));

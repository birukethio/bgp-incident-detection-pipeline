import { readFile, writeFile } from "node:fs/promises";

const OUT_DIR = new URL("./", import.meta.url);
const START_DAY = "2023-01-01";
const END_DAY = "2026-01-31";

const files = {
  leaks: "raw_leaks_2023-01_to_2026-01.json",
  hijacks: "raw_hijacks_2023-01_to_2026-01.json",
  outages: "raw_outages_2023-01_to_2026-01.json",
};

const rawHeaders = {
  leaks: [
    "countries", "detected_ts", "finished", "id", "leak_asn", "leak_count",
    "leak_seg", "leak_type", "max_ts", "min_ts", "origin_count", "peer_count",
    "prefix_count",
  ],
  hijacks: [
    "confidence_score", "duration", "event_type", "hijack_msgs_count",
    "hijacker_asn", "hijacker_country", "id", "is_stale", "max_hijack_ts",
    "max_msg_ts", "min_hijack_ts", "on_going_count", "peer_asns",
    "peer_ip_count", "prefixes", "tags", "victim_asns", "victim_countries",
  ],
  outages: [
    "asns", "asnsDetails", "dataSource", "description", "endDate",
    "eventType", "id", "linkedUrl", "locations", "locationsDetails",
    "origins", "originsDetails", "outage", "scope", "startDate",
  ],
};

const outputHeaders = {
  leaks: [
    "category", "assigned_date", "incident_date", "selection_primary_metric",
    "selection_secondary_metric", ...rawHeaders.leaks,
  ],
  hijacks: [
    "category", "assigned_date", "incident_date", "selection_primary_metric",
    "selection_secondary_metric", ...rawHeaders.hijacks,
  ],
  outages: [
    "category", "assigned_date", "incident_date", "selection_primary_metric",
    "selection_secondary_metric", "duration_minutes", ...rawHeaders.outages,
  ],
};

function toDateKey(value) {
  return value ? String(value).slice(0, 10) : "";
}

function parseTime(value) {
  return value ? Date.parse(value.endsWith("Z") ? value : `${value}Z`) : NaN;
}

function durationMinutes(start, end) {
  const startMs = parseTime(start);
  const endMs = parseTime(end);
  if (!Number.isFinite(startMs) || !Number.isFinite(endMs) || endMs < startMs) {
    return "";
  }
  return Math.round((endMs - startMs) / 60000);
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
    (durationMinutes(b.startDate, b.endDate) || 0) - (durationMinutes(a.startDate, a.endDate) || 0) ||
    (b.asns?.length ?? 0) - (a.asns?.length ?? 0)
  )[0];
}

function csvCell(value) {
  if (value == null) return "";
  const text = typeof value === "object" ? JSON.stringify(value) : String(value);
  return /[",\n\r]/.test(text) ? `"${text.replaceAll('"', '""')}"` : text;
}

function rowFor(kind, assignedDate, incident) {
  if (kind === "leaks") {
    return {
      category: "leak",
      assigned_date: assignedDate,
      incident_date: toDateKey(incident.detected_ts),
      selection_primary_metric: incident.leak_count,
      selection_secondary_metric: incident.prefix_count,
      ...incident,
    };
  }

  if (kind === "hijacks") {
    return {
      category: "hijack",
      assigned_date: assignedDate,
      incident_date: toDateKey(incident.min_hijack_ts),
      selection_primary_metric: incident.hijack_msgs_count,
      selection_secondary_metric: incident.duration,
      ...incident,
    };
  }

  return {
    category: "outage",
    assigned_date: assignedDate,
    incident_date: toDateKey(incident.startDate),
    selection_primary_metric: durationMinutes(incident.startDate, incident.endDate),
    selection_secondary_metric: incident.asns?.length ?? 0,
    duration_minutes: durationMinutes(incident.startDate, incident.endDate),
    ...incident,
  };
}

async function writeCsv(filename, headers, rows) {
  const csv = [
    headers.map(csvCell).join(","),
    ...rows.map((row) => headers.map((header) => csvCell(row[header])).join(",")),
  ].join("\n");
  await writeFile(new URL(filename, OUT_DIR), `${csv}\n`);
}

const [leaks, hijacks, outages] = await Promise.all([
  readFile(new URL(files.leaks, OUT_DIR), "utf8").then(JSON.parse),
  readFile(new URL(files.hijacks, OUT_DIR), "utf8").then(JSON.parse),
  readFile(new URL(files.outages, OUT_DIR), "utf8").then(JSON.parse),
]);

const groups = {
  leaks: groupByDate(leaks, (item) => toDateKey(item.detected_ts)),
  hijacks: groupByDate(hijacks, (item) => toDateKey(item.min_hijack_ts)),
  outages: groupByDate(outages, (item) => toDateKey(item.startDate)),
};

const selected = { leaks: [], hijacks: [], outages: [] };

for (const [index, day] of dayKeys().entries()) {
  if (index % 3 === 0) {
    const incident = groups.leaks.get(day)?.length ? pickLeak(groups.leaks.get(day)) : null;
    if (incident) selected.leaks.push(rowFor("leaks", day, incident));
  } else if (index % 3 === 1) {
    const incident = groups.hijacks.get(day)?.length ? pickHijack(groups.hijacks.get(day)) : null;
    if (incident) selected.hijacks.push(rowFor("hijacks", day, incident));
  } else {
    const incident = groups.outages.get(day)?.length ? pickOutage(groups.outages.get(day)) : null;
    if (incident) selected.outages.push(rowFor("outages", day, incident));
  }
}

await Promise.all([
  writeCsv("sample_leaks_FULL_FIELDS_2023-01_to_2026-01.csv", outputHeaders.leaks, selected.leaks),
  writeCsv("sample_hijacks_FULL_FIELDS_2023-01_to_2026-01.csv", outputHeaders.hijacks, selected.hijacks),
  writeCsv("sample_outages_FULL_FIELDS_2023-01_to_2026-01.csv", outputHeaders.outages, selected.outages),
]);

console.log(JSON.stringify({
  leaks: selected.leaks.length,
  hijacks: selected.hijacks.length,
  outages: selected.outages.length,
}, null, 2));

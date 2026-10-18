const TOKEN = process.env.CLOUDFLARE_API_TOKEN;
const API = "https://api.cloudflare.com/client/v4";
const OUT_DIR = new URL("./", import.meta.url);
const { writeFile } = await import("node:fs/promises");

if (!TOKEN) {
  console.error("Set CLOUDFLARE_API_TOKEN before running this script.");
  process.exit(1);
}

const RANGE_START = "2023-01-01T00:00:00Z";
const RANGE_END = "2026-02-01T00:00:00Z";
const START_DAY = "2023-01-01";
const END_DAY = "2026-01-31";
const PAGE_SIZE = 1000;

const endpoints = {
  leaks: "/radar/bgp/leaks/events",
  hijacks: "/radar/bgp/hijacks/events",
  outages: "/radar/annotations/outages",
};

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

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

function csvCell(value) {
  if (value == null) return "";
  const text = Array.isArray(value) ? value.join(";") : String(value);
  return /[",\n\r]/.test(text) ? `"${text.replaceAll('"', '""')}"` : text;
}

function writeCsv(path, headers, rows) {
  const body = [
    headers.map(csvCell).join(","),
    ...rows.map((row) => headers.map((header) => csvCell(row[header])).join(",")),
  ].join("\n");
  return writeFile(new URL(path, OUT_DIR), `${body}\n`);
}

async function fetchJson(path, params, attempt = 1) {
  const url = new URL(`${API}${path}`);
  for (const [key, value] of Object.entries(params)) {
    url.searchParams.set(key, value);
  }

  const response = await fetch(url, {
    headers: { Authorization: `Bearer ${TOKEN}` },
  });

  if ((response.status === 429 || response.status >= 500) && attempt < 5) {
    const backoff = 1000 * attempt * attempt;
    await sleep(backoff);
    return fetchJson(path, params, attempt + 1);
  }

  const json = await response.json();
  if (!response.ok || !json.success) {
    throw new Error(`${path} failed: ${response.status} ${JSON.stringify(json.errors)}`);
  }
  return json;
}

async function fetchPagedEvents(kind) {
  const first = await fetchJson(endpoints[kind], {
    format: "json",
    page: "1",
    per_page: String(PAGE_SIZE),
    dateStart: RANGE_START,
    dateEnd: RANGE_END,
  });
  const total = first.result_info?.total_count ?? first.result.events.length;
  const pages = Math.ceil(total / PAGE_SIZE);
  const events = [...first.result.events];

  console.log(`${kind}: fetched page 1/${pages} (${events.length}/${total})`);

  let nextPage = 2;
  const workers = Array.from({ length: 8 }, async () => {
    while (nextPage <= pages) {
      const page = nextPage++;
      const json = await fetchJson(endpoints[kind], {
        format: "json",
        page: String(page),
        per_page: String(PAGE_SIZE),
        dateStart: RANGE_START,
        dateEnd: RANGE_END,
      });
      events.push(...json.result.events);
      if (page % 10 === 0 || page === pages) {
        console.log(`${kind}: fetched page ${page}/${pages}`);
      }
    }
  });

  await Promise.all(workers);
  return events;
}

async function fetchOutages() {
  const json = await fetchJson(endpoints.outages, {
    format: "json",
    limit: "1000",
    offset: "0",
    dateStart: RANGE_START,
    dateEnd: RANGE_END,
  });
  return json.result.annotations;
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

function makeLeakRow(day, incident) {
  return {
    category: "leak",
    assigned_date: day,
    incident_date: toDateKey(incident.detected_ts),
    id: incident.id,
    primary_metric: incident.leak_count,
    secondary_metric: incident.prefix_count,
    detected_ts: incident.detected_ts,
    finished: incident.finished,
    leak_asn: incident.leak_asn,
    countries: incident.countries,
    leak_count: incident.leak_count,
    leak_segment: incident.leak_seg,
    leak_type: incident.leak_type,
    min_ts: incident.min_ts,
    max_ts: incident.max_ts,
    origin_count: incident.origin_count,
    peer_count: incident.peer_count,
    prefix_count: incident.prefix_count,
  };
}

function makeHijackRow(day, incident) {
  return {
    category: "hijack",
    assigned_date: day,
    incident_date: toDateKey(incident.min_hijack_ts),
    id: incident.id,
    primary_metric: incident.hijack_msgs_count,
    secondary_metric: incident.duration,
    min_hijack_ts: incident.min_hijack_ts,
    max_hijack_ts: incident.max_hijack_ts,
    duration: incident.duration,
    event_type: incident.event_type,
    hijacker_asn: incident.hijacker_asn,
    hijacker_country: incident.hijacker_country,
    victim_asns: incident.victim_asns,
    victim_countries: incident.victim_countries,
    prefixes: incident.prefixes,
    peer_asns: incident.peer_asns,
    peer_ip_count: incident.peer_ip_count,
    hijack_msgs_count: incident.hijack_msgs_count,
    on_going_count: incident.on_going_count,
    confidence_score: incident.confidence_score,
    is_stale: incident.is_stale,
    tags: incident.tags?.map((tag) => `${tag.name}:${tag.score}`),
  };
}

function makeOutageRow(day, incident) {
  return {
    category: "outage",
    assigned_date: day,
    incident_date: toDateKey(incident.startDate),
    id: incident.id,
    primary_metric: durationMinutes(incident.startDate, incident.endDate),
    secondary_metric: incident.asns?.length ?? 0,
    startDate: incident.startDate,
    endDate: incident.endDate,
    duration_minutes: durationMinutes(incident.startDate, incident.endDate),
    eventType: incident.eventType,
    description: incident.description,
    scope: incident.scope,
    locations: incident.locations,
    asns: incident.asns,
    outageCause: incident.outage?.outageCause,
    outageType: incident.outage?.outageType,
    linkedUrl: incident.linkedUrl,
  };
}

const leaks = await fetchPagedEvents("leaks");
const hijacks = await fetchPagedEvents("hijacks");
const outages = await fetchOutages();

await writeFile(new URL("raw_leaks_2023-01_to_2026-01.json", OUT_DIR), JSON.stringify(leaks, null, 2));
await writeFile(new URL("raw_hijacks_2023-01_to_2026-01.json", OUT_DIR), JSON.stringify(hijacks, null, 2));
await writeFile(new URL("raw_outages_2023-01_to_2026-01.json", OUT_DIR), JSON.stringify(outages, null, 2));

const leaksByDay = groupByDate(leaks, (item) => toDateKey(item.detected_ts));
const hijacksByDay = groupByDate(hijacks, (item) => toDateKey(item.min_hijack_ts));
const outagesByDay = groupByDate(outages, (item) => toDateKey(item.startDate));

const selectedLeaks = [];
const selectedHijacks = [];
const selectedOutages = [];
const skipped = [];

for (const [index, day] of dayKeys().entries()) {
  const slot = index % 3;
  if (slot === 0) {
    const items = leaksByDay.get(day) ?? [];
    const incident = items.length ? pickLeak(items) : null;
    if (incident) selectedLeaks.push(makeLeakRow(day, incident));
    else skipped.push({ assigned_date: day, category: "leak", reason: "no incident found on assigned date" });
  } else if (slot === 1) {
    const items = hijacksByDay.get(day) ?? [];
    const incident = items.length ? pickHijack(items) : null;
    if (incident) selectedHijacks.push(makeHijackRow(day, incident));
    else skipped.push({ assigned_date: day, category: "hijack", reason: "no incident found on assigned date" });
  } else {
    const items = outagesByDay.get(day) ?? [];
    const incident = items.length ? pickOutage(items) : null;
    if (incident) selectedOutages.push(makeOutageRow(day, incident));
    else skipped.push({ assigned_date: day, category: "outage", reason: "no incident found on assigned date" });
  }
}

const leakHeaders = [
  "category", "assigned_date", "incident_date", "id", "primary_metric", "secondary_metric",
  "detected_ts", "finished", "leak_asn", "countries", "leak_count", "leak_segment",
  "leak_type", "min_ts", "max_ts", "origin_count", "peer_count", "prefix_count",
];
const hijackHeaders = [
  "category", "assigned_date", "incident_date", "id", "primary_metric", "secondary_metric",
  "min_hijack_ts", "max_hijack_ts", "duration", "event_type", "hijacker_asn",
  "hijacker_country", "victim_asns", "victim_countries", "prefixes", "peer_asns",
  "peer_ip_count", "hijack_msgs_count", "on_going_count", "confidence_score", "is_stale", "tags",
];
const outageHeaders = [
  "category", "assigned_date", "incident_date", "id", "primary_metric", "secondary_metric",
  "startDate", "endDate", "duration_minutes", "eventType", "description", "scope",
  "locations", "asns", "outageCause", "outageType", "linkedUrl",
];

await writeCsv("sample_leaks_2023-01_to_2026-01.csv", leakHeaders, selectedLeaks);
await writeCsv("sample_hijacks_2023-01_to_2026-01.csv", hijackHeaders, selectedHijacks);
await writeCsv("sample_outages_2023-01_to_2026-01.csv", outageHeaders, selectedOutages);
await writeCsv("sample_all_incidents_2023-01_to_2026-01.csv", [
  "category", "assigned_date", "incident_date", "id", "primary_metric", "secondary_metric",
], [...selectedLeaks, ...selectedHijacks, ...selectedOutages].sort((a, b) => a.assigned_date.localeCompare(b.assigned_date)));
await writeCsv("sample_skipped_dates_2023-01_to_2026-01.csv", ["assigned_date", "category", "reason"], skipped);

console.log(JSON.stringify({
  raw: {
    leaks: leaks.length,
    hijacks: hijacks.length,
    outages: outages.length,
  },
  selected: {
    leaks: selectedLeaks.length,
    hijacks: selectedHijacks.length,
    outages: selectedOutages.length,
    combined: selectedLeaks.length + selectedHijacks.length + selectedOutages.length,
    skipped: skipped.length,
  },
}, null, 2));

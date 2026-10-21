import { writeFile } from "node:fs/promises";

const TOKEN = process.env.CLOUDFLARE_API_TOKEN;
const API = "https://api.cloudflare.com/client/v4";
const OUT_DIR = new URL("./", import.meta.url);

if (!TOKEN) {
  console.error("Set CLOUDFLARE_API_TOKEN before running this script.");
  process.exit(1);
}

const expectedRows = [
  [741, "Outage", "2024-02-15T15:45:33.000Z", "2024-02-15T16:15:00.000Z", 30, 6],
  [221926, "Leak", "2024-02-16T02:00:51.000Z", "2024-02-19T15:18:11.000Z", 5118, 1024],
  [36977, "Hijack", "2024-02-17T20:27:12.920Z", "2024-02-24T00:11:51.665Z", 8865, 1773],
  [222206, "Leak", "2024-02-19T15:53:59.000Z", "2024-02-19T19:31:09.000Z", 218, 44],
  [37251, "Hijack", "2024-02-20T03:01:40.010Z", "2024-03-01T16:02:26.817Z", 15181, 3037],
  [222500, "Leak", "2024-02-22T14:21:00.000Z", "2024-02-25T00:36:39.000Z", 3496, 700],
  [37771, "Hijack", "2024-02-23T23:25:13.117Z", "2024-02-24T07:05:43.666Z", 461, 93],
  [222665, "Leak", "2024-02-25T04:31:43.000Z", "2024-02-27T02:07:50.000Z", 2737, 548],
  [38046, "Hijack", "2024-02-26T11:08:35.202Z", "2024-02-26T14:12:37.022Z", 185, 37],
  [222896, "Leak", "2024-02-28T05:50:34.000Z", "2024-02-29T02:34:01.000Z", 1244, 249],
  [38518, "Hijack", "2024-02-29T19:12:39.056Z", "2024-03-04T06:05:49.832Z", 4974, 995],
  [778, "Outage", "2024-03-01T06:15:00.000Z", "2024-03-01T12:15:56.000Z", 361, 73],
  [223178, "Leak", "2024-03-02T12:14:27.000Z", "2024-03-26T14:39:28.000Z", 34706, 6942],
  [39007, "Hijack", "2024-03-03T13:44:36.425Z", "2024-03-05T13:34:46.324Z", 2871, 575],
  [781, "Outage", "2024-03-04T10:30:18.000Z", "2024-03-04T20:00:11.000Z", 570, 114],
  [223398, "Leak", "2024-03-05T16:58:44.000Z", "2024-03-07T07:31:20.000Z", 2313, 463],
  [39437, "Hijack", "2024-03-06T04:38:11.848Z", "2024-03-07T07:18:49.677Z", 1601, 321],
  [786, "Outage", "2024-03-07T01:30:00.000Z", "2024-03-07T07:15:25.000Z", 346, 70],
  [223650, "Leak", "2024-03-08T19:03:30.000Z", "2024-03-09T15:07:49.000Z", 1205, 241],
  [39864, "Hijack", "2024-03-09T00:04:41.323Z", "2024-03-09T00:39:12.240Z", 35, 7],
  [223881, "Leak", "2024-03-11T14:40:07.000Z", "2024-03-12T16:35:06.000Z", 1555, 311],
  [40261, "Hijack", "2024-03-12T05:01:30.527Z", "2024-03-12T06:08:10.552Z", 67, 14],
  [802, "Outage", "2024-03-13T09:30:51.000Z", "2024-03-13T16:30:03.000Z", 420, 84],
  [224140, "Leak", "2024-03-14T06:41:38.000Z", "2024-03-14T22:57:39.000Z", 977, 196],
  [40835, "Hijack", "2024-03-15T10:36:52.281Z", "2024-03-17T06:14:16.199Z", 2618, 524],
  [224415, "Leak", "2024-03-17T15:08:01.000Z", "2024-03-18T02:26:20.000Z", 679, 136],
  [41214, "Hijack", "2024-03-18T14:20:09.551Z", "2024-03-18T14:23:12.139Z", 4, 1],
].map(([incident_id, category, start_utc, end_utc, duration_minutes, five_minute_window_count]) => ({
  incident_id,
  category,
  start_utc,
  end_utc,
  duration_minutes,
  five_minute_window_count,
}));

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
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
  if (!Number.isFinite(startMs) || !Number.isFinite(endMs) || endMs < startMs) return null;
  return Math.ceil((endMs - startMs) / 60000);
}

function fiveMinuteWindowCount(minutes) {
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

async function fetchJson(path, params, attempt = 1) {
  const url = new URL(`${API}${path}`);
  for (const [key, value] of Object.entries(params)) url.searchParams.set(key, value);
  const response = await fetch(url, { headers: { Authorization: `Bearer ${TOKEN}` } });
  const json = await response.json();
  if ((response.status === 429 || response.status >= 500) && attempt < 5) {
    await sleep(1000 * attempt * attempt);
    return fetchJson(path, params, attempt + 1);
  }
  if (!response.ok || !json.success) {
    throw new Error(`${path} failed: ${response.status} ${JSON.stringify(json.errors)}`);
  }
  return json;
}

async function fetchPagedEvents(kind, path) {
  const first = await fetchJson(path, {
    format: "json",
    page: "1",
    per_page: "1000",
    dateStart: "2024-02-15T00:00:00Z",
    dateEnd: "2024-03-27T00:00:00Z",
  });
  const total = first.result_info?.total_count ?? first.result.events.length;
  const pages = Math.ceil(total / 1000);
  const events = [...first.result.events];
  for (let page = 2; page <= pages; page++) {
    const json = await fetchJson(path, {
      format: "json",
      page: String(page),
      per_page: "1000",
      dateStart: "2024-02-15T00:00:00Z",
      dateEnd: "2024-03-27T00:00:00Z",
    });
    events.push(...json.result.events);
  }
  console.log(`${kind}: fetched ${events.length} live events`);
  return events;
}

async function fetchOutages() {
  const json = await fetchJson("/radar/annotations/outages", {
    format: "json",
    limit: "1000",
    offset: "0",
    dateStart: "2024-02-15T00:00:00Z",
    dateEnd: "2024-03-27T00:00:00Z",
  });
  const annotations = json.result.annotations;
  console.log(`outages: fetched ${annotations.length} live annotations`);
  return annotations;
}

function liveTiming(category, record) {
  if (!record) return { api_start_utc: null, api_end_utc: null };
  if (category === "Leak") {
    return {
      api_start_utc: toUtcIso(record.min_ts ?? record.detected_ts),
      api_end_utc: toUtcIso(record.max_ts),
    };
  }
  if (category === "Hijack") {
    return {
      api_start_utc: toUtcIso(record.min_hijack_ts),
      api_end_utc: toUtcIso(record.max_hijack_ts),
    };
  }
  return {
    api_start_utc: toUtcIso(record.startDate),
    api_end_utc: toUtcIso(record.endDate),
  };
}

function idsByCategory(records, category) {
  return new Map(records.map((record) => [String(record.id), record]));
}

const [leaks, hijacks, outages] = await Promise.all([
  fetchPagedEvents("leaks", "/radar/bgp/leaks/events"),
  fetchPagedEvents("hijacks", "/radar/bgp/hijacks/events"),
  fetchOutages(),
]);

await writeFile(new URL("online_verification_live_extract_2024-02-15_to_2024-03-27.json", OUT_DIR), JSON.stringify({
  fetched_at_utc: new Date().toISOString(),
  leaks,
  hijacks,
  outages,
}, null, 2));

const indexes = {
  Leak: idsByCategory(leaks, "Leak"),
  Hijack: idsByCategory(hijacks, "Hijack"),
  Outage: idsByCategory(outages, "Outage"),
};

const rows = expectedRows.map((expected) => {
  const live = indexes[expected.category].get(String(expected.incident_id));
  const { api_start_utc, api_end_utc } = liveTiming(expected.category, live);
  const api_duration_minutes = durationMinutes(api_start_utc, api_end_utc);
  const api_five_minute_window_count = fiveMinuteWindowCount(api_duration_minutes);
  const start_match = expected.start_utc === api_start_utc;
  const end_match = expected.end_utc === api_end_utc;
  const duration_match = expected.duration_minutes === api_duration_minutes;
  const five_minute_window_match = expected.five_minute_window_count === api_five_minute_window_count;
  const matched = Boolean(live) && start_match && end_match && duration_match && five_minute_window_match;
  return {
    incident_id: expected.incident_id,
    category: expected.category,
    online_status: live ? (matched ? "VERIFIED" : "MISMATCH") : "NOT_FOUND_ONLINE",
    expected_start_utc: expected.start_utc,
    api_start_utc,
    start_match,
    expected_end_utc: expected.end_utc,
    api_end_utc,
    end_match,
    expected_duration_minutes: expected.duration_minutes,
    api_duration_minutes,
    duration_match,
    expected_five_minute_window_count: expected.five_minute_window_count,
    api_five_minute_window_count,
    five_minute_window_match,
    api_primary_asn: live?.leak_asn ?? live?.hijacker_asn ?? null,
    api_affected_asns: live?.leak_seg ?? live?.victim_asns ?? live?.asns ?? null,
    api_prefixes: live?.prefixes ?? null,
    api_prefix_count: live?.prefix_count ?? (Array.isArray(live?.prefixes) ? live.prefixes.length : null),
    api_peer_count: live?.peer_count ?? (Array.isArray(live?.peer_asns) ? live.peer_asns.length : null),
    notes: live ? "Matched by category and Cloudflare source id from live Radar API list endpoint." : "ID not returned by live Radar API list endpoint for verification window.",
  };
});

const summary = ["VERIFIED", "MISMATCH", "NOT_FOUND_ONLINE"].map((online_status) => ({
  online_status,
  incident_count: rows.filter((row) => row.online_status === online_status).length,
}));

await Promise.all([
  writeCsv("online_verification_selected_incidents_2024-02-15_to_2024-03-18.csv", [
    "incident_id",
    "category",
    "online_status",
    "expected_start_utc",
    "api_start_utc",
    "start_match",
    "expected_end_utc",
    "api_end_utc",
    "end_match",
    "expected_duration_minutes",
    "api_duration_minutes",
    "duration_match",
    "expected_five_minute_window_count",
    "api_five_minute_window_count",
    "five_minute_window_match",
    "api_primary_asn",
    "api_affected_asns",
    "api_prefixes",
    "api_prefix_count",
    "api_peer_count",
    "notes",
  ], rows),
  writeCsv("online_verification_summary_selected_incidents_2024-02-15_to_2024-03-18.csv", [
    "online_status",
    "incident_count",
  ], summary),
]);

console.log(JSON.stringify({
  checked: rows.length,
  summary,
}, null, 2));

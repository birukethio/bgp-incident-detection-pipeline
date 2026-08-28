const TOKEN = process.env.CLOUDFLARE_API_TOKEN;
const API = "https://api.cloudflare.com/client/v4";
const OUT_DIR = new URL("./", import.meta.url);
const { writeFile } = await import("node:fs/promises");

if (!TOKEN) {
  console.error("Set CLOUDFLARE_API_TOKEN before running this script.");
  process.exit(1);
}

const RANGE_START = process.env.CF_RANGE_START || "2019-01-01T00:00:00Z";
const RANGE_END = process.env.CF_RANGE_END || "2026-02-01T00:00:00Z";
const PAGE_SIZE = Number(process.env.CF_PAGE_SIZE || 1000);

const endpoints = {
  leaks: "/radar/bgp/leaks/events",
  hijacks: "/radar/bgp/hijacks/events",
  outages: "/radar/annotations/outages",
};

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function parseTime(value) {
  if (!value) return NaN;
  return Date.parse(String(value).endsWith("Z") ? value : `${value}Z`);
}

function yearlyWindows(start, end) {
  const windows = [];
  let cursor = new Date(start);
  const final = new Date(end);
  while (cursor < final) {
    const next = new Date(Date.UTC(cursor.getUTCFullYear() + 1, 0, 1));
    const windowEnd = next < final ? next : final;
    windows.push([cursor.toISOString(), windowEnd.toISOString()]);
    cursor = windowEnd;
  }
  return windows;
}

async function fetchJson(path, params, attempt = 1) {
  const url = new URL(`${API}${path}`);
  for (const [key, value] of Object.entries(params)) {
    url.searchParams.set(key, String(value));
  }

  const response = await fetch(url, {
    headers: { Authorization: `Bearer ${TOKEN}` },
  });
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

async function fetchPagedEvents(kind, start, end) {
  const first = await fetchJson(endpoints[kind], {
    format: "json",
    page: 1,
    per_page: PAGE_SIZE,
    dateStart: start,
    dateEnd: end,
  });
  const firstEvents = first.result?.events ?? [];
  const total = first.result_info?.total_count ?? firstEvents.length;
  const pages = Math.ceil(total / PAGE_SIZE);
  const events = [...firstEvents];
  console.log(`${kind} ${start.slice(0, 10)}..${end.slice(0, 10)} page 1/${pages || 1} (${events.length}/${total})`);

  for (let page = 2; page <= pages; page += 1) {
    const json = await fetchJson(endpoints[kind], {
      format: "json",
      page,
      per_page: PAGE_SIZE,
      dateStart: start,
      dateEnd: end,
    });
    events.push(...(json.result?.events ?? []));
    if (page % 10 === 0 || page === pages) {
      console.log(`${kind} ${start.slice(0, 10)}..${end.slice(0, 10)} page ${page}/${pages}`);
    }
  }
  return events;
}

async function fetchOutages(start, end) {
  const rows = [];
  let offset = 0;
  while (true) {
    const json = await fetchJson(endpoints.outages, {
      format: "json",
      limit: PAGE_SIZE,
      offset,
      dateStart: start,
      dateEnd: end,
    });
    const batch = json.result?.annotations ?? [];
    rows.push(...batch);
    console.log(`outages ${start.slice(0, 10)}..${end.slice(0, 10)} offset ${offset} (${batch.length})`);
    if (batch.length < PAGE_SIZE) break;
    offset += PAGE_SIZE;
  }
  return rows;
}

function dedupeById(rows) {
  const map = new Map();
  for (const row of rows) {
    if (row?.id == null) continue;
    map.set(String(row.id), row);
  }
  return [...map.values()];
}

function summarize(kind, rows, startField, endField) {
  const starts = rows.map((row) => parseTime(row[startField])).filter(Number.isFinite).sort((a, b) => a - b);
  const ends = rows.map((row) => parseTime(row[endField] || row[startField])).filter(Number.isFinite).sort((a, b) => a - b);
  return {
    kind,
    rows: rows.length,
    first_start_utc: starts.length ? new Date(starts[0]).toISOString() : null,
    last_end_utc: ends.length ? new Date(ends.at(-1)).toISOString() : null,
  };
}

const windows = yearlyWindows(RANGE_START, RANGE_END);
const all = { leaks: [], hijacks: [], outages: [] };

for (const [start, end] of windows) {
  all.leaks.push(...await fetchPagedEvents("leaks", start, end));
  all.hijacks.push(...await fetchPagedEvents("hijacks", start, end));
  all.outages.push(...await fetchOutages(start, end));
}

all.leaks = dedupeById(all.leaks);
all.hijacks = dedupeById(all.hijacks);
all.outages = dedupeById(all.outages);

await writeFile(new URL("raw_leaks_all_available_to_2026-01_cloudflare.json", OUT_DIR), JSON.stringify(all.leaks, null, 2));
await writeFile(new URL("raw_hijacks_all_available_to_2026-01_cloudflare.json", OUT_DIR), JSON.stringify(all.hijacks, null, 2));
await writeFile(new URL("raw_outages_all_available_to_2026-01_cloudflare.json", OUT_DIR), JSON.stringify(all.outages, null, 2));

const summary = [
  summarize("Leak", all.leaks, "min_ts", "max_ts"),
  summarize("Hijack", all.hijacks, "min_hijack_ts", "max_hijack_ts"),
  summarize("Outage", all.outages, "startDate", "endDate"),
];
await writeFile(new URL("raw_cloudflare_all_available_to_2026-01_summary.json", OUT_DIR), JSON.stringify({
  requested_start: RANGE_START,
  requested_end: RANGE_END,
  fetched_at_utc: new Date().toISOString(),
  summary,
}, null, 2));

console.log(JSON.stringify(summary, null, 2));

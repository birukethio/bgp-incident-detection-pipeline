const TOKEN = process.env.CLOUDFLARE_API_TOKEN;
const API = "https://api.cloudflare.com/client/v4";
const OUT_DIR = new URL("./", import.meta.url);
const { writeFile } = await import("node:fs/promises");

if (!TOKEN) {
  console.error("Set CLOUDFLARE_API_TOKEN before running this script.");
  process.exit(1);
}

const RANGE_START = process.env.CF_RANGE_START || "2026-02-01T00:00:00Z";
const RANGE_END = process.env.CF_RANGE_END || "2026-08-28T00:00:00Z";
const OUTPUT = process.env.CF_OUTPUT || "raw_leaks_2026-02_to_2026-08_cloudflare.json";
const PAGE_SIZE = 1000;

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
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
    await sleep(1000 * attempt * attempt);
    return fetchJson(path, params, attempt + 1);
  }

  const json = await response.json();
  if (!response.ok || !json.success) {
    throw new Error(`${path} failed: ${response.status} ${JSON.stringify(json.errors)}`);
  }
  return json;
}

async function fetchPagedLeaks() {
  const first = await fetchJson("/radar/bgp/leaks/events", {
    format: "json",
    page: "1",
    per_page: String(PAGE_SIZE),
    dateStart: RANGE_START,
    dateEnd: RANGE_END,
  });

  const firstEvents = first.result?.events ?? [];
  const total = first.result_info?.total_count ?? firstEvents.length;
  const pages = Math.ceil(total / PAGE_SIZE);
  const events = [...firstEvents];
  console.log(`leaks: fetched page 1/${pages || 1} (${events.length}/${total})`);

  for (let page = 2; page <= pages; page += 1) {
    const json = await fetchJson("/radar/bgp/leaks/events", {
      format: "json",
      page: String(page),
      per_page: String(PAGE_SIZE),
      dateStart: RANGE_START,
      dateEnd: RANGE_END,
    });
    events.push(...(json.result?.events ?? []));
    if (page % 10 === 0 || page === pages) {
      console.log(`leaks: fetched page ${page}/${pages}`);
    }
  }

  return events;
}

const leaks = await fetchPagedLeaks();
await writeFile(new URL(OUTPUT, OUT_DIR), JSON.stringify(leaks, null, 2));

const starts = leaks.map((row) => row.min_ts || row.detected_ts).filter(Boolean).sort();
console.log(JSON.stringify({
  output: OUTPUT,
  rows: leaks.length,
  requested_start: RANGE_START,
  requested_end: RANGE_END,
  min_ts: starts[0] || null,
  max_ts: starts.at(-1) || null,
}, null, 2));

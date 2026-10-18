import { readFile, writeFile } from "node:fs/promises";

const OUT_DIR = new URL("./", import.meta.url);

const inputs = [
  "sample_leaks_2023-01_to_2026-01.csv",
  "sample_hijacks_2023-01_to_2026-01.csv",
  "sample_outages_2023-01_to_2026-01.csv",
];

const headers = [
  "category", "assigned_date", "incident_date", "id", "primary_metric", "secondary_metric",
  "start_time", "end_time", "duration", "prefixes", "messages", "origin",
  "leak_asn", "countries", "leak_count", "leak_segment", "leak_type", "origin_count",
  "peer_count", "prefix_count", "hijacker_asn", "hijacker_country", "victim_asns",
  "victim_countries", "peer_asns", "peer_ip_count", "hijack_msgs_count",
  "on_going_count", "confidence_score", "is_stale", "tags", "event_type",
  "description", "scope", "locations", "asns", "outageCause", "outageType", "linkedUrl",
];

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

function csvCell(value) {
  const text = value == null ? "" : String(value);
  return /[",\n\r]/.test(text) ? `"${text.replaceAll('"', '""')}"` : text;
}

function normalize(row) {
  if (row.category === "leak") {
    return {
      ...row,
      start_time: row.min_ts,
      end_time: row.max_ts,
      prefixes: row.prefix_count,
      messages: row.leak_count,
      origin: row.origin_count,
      duration: "",
    };
  }

  if (row.category === "hijack") {
    return {
      ...row,
      start_time: row.min_hijack_ts,
      end_time: row.max_hijack_ts,
      prefixes: row.prefixes,
      messages: row.hijack_msgs_count,
      origin: row.victim_asns,
    };
  }

  return {
    ...row,
    start_time: row.startDate,
    end_time: row.endDate,
    duration: row.duration_minutes,
    prefixes: "",
    messages: "",
    origin: "",
  };
}

const rows = [];
for (const input of inputs) {
  rows.push(...parseCsv(await readFile(new URL(input, OUT_DIR), "utf8")).map(normalize));
}

rows.sort((a, b) => a.assigned_date.localeCompare(b.assigned_date));

const csv = [
  headers.join(","),
  ...rows.map((row) => headers.map((header) => csvCell(row[header])).join(",")),
].join("\n");

await writeFile(new URL("sample_rotating_detailed_2023-01_to_2026-01.csv", OUT_DIR), `${csv}\n`);
console.log(`Wrote ${rows.length} rows`);

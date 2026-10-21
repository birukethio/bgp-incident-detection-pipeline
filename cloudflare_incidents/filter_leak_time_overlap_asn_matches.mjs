import { readFile, writeFile } from "node:fs/promises";

const OUT_DIR = new URL("./", import.meta.url);
const INPUT = "exhaustive_daily_cloudflare_ripestat_audit_2024-2025.csv";
const OUTPUT = "leak_matches_time_overlap_and_leak_asn_only_2024-2025.csv";
const SUMMARY = "leak_matches_time_overlap_and_leak_asn_only_summary_2024-2025.csv";

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

  if (cell || row.length) row.push(cell);
  if (row.length) rows.push(row);

  const [headers, ...dataRows] = rows.filter((line) => line.length > 1 || line[0]);
  return dataRows.map((values) => Object.fromEntries(headers.map((key, index) => [key, values[index] ?? ""])));
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

const rows = parseCsv(await readFile(new URL(INPUT, OUT_DIR), "utf8"));
const leaks = rows.filter((row) => row.category === "Leak");

const evaluated = leaks.map((row) => {
  const leakAsn = row.primary_asn;
  const queryResources = row.ripestat_query_resource ?? "";
  const updateCount = Number(row.ripestat_update_count || 0);
  const timeOverlap = Boolean(row.ripestat_query_start && row.ripestat_query_end);
  const leakAsnMatch = leakAsn ? queryResources.split(",").includes(`AS${leakAsn}`) : false;
  const simpleMatch = timeOverlap && leakAsnMatch && updateCount > 0;

  return {
    ...row,
    simple_match_status: simpleMatch ? "MATCH_TIME_OVERLAP_AND_LEAK_ASN" : "NO_MATCH",
    time_overlap: timeOverlap,
    leak_asn_match: leakAsnMatch,
    simple_match_note: simpleMatch
      ? "Matched using only RIPEstat query-window time overlap and Cloudflare leak_asn presence in the RIPEstat query resource; AS-path/prefix evidence not required."
      : "Did not satisfy the simplified time-overlap + leak_asn rule, usually because RIPEstat returned no updates.",
  };
});

const matched = evaluated.filter((row) => row.simple_match_status === "MATCH_TIME_OVERLAP_AND_LEAK_ASN");
const summaryRows = [
  { metric: "leak_candidates_checked", value: leaks.length },
  { metric: "matched_time_overlap_and_leak_asn", value: matched.length },
  { metric: "not_matched", value: evaluated.length - matched.length },
  { metric: "match_percent", value: leaks.length ? ((matched.length / leaks.length) * 100).toFixed(2) : "0.00" },
];

const headers = [
  "cloudflare_source_id",
  "incident_id",
  "category",
  "incident_date",
  "start_utc",
  "end_utc",
  "duration_minutes",
  "five_minute_window_count",
  "primary_asn",
  "affected_asns",
  "prefix_count",
  "peer_count",
  "countries",
  "cloudflare_metric",
  "simple_match_status",
  "time_overlap",
  "leak_asn_match",
  "ripestat_query_resource",
  "ripestat_query_start",
  "ripestat_query_end",
  "ripestat_update_count",
  "ripestat_matching_update_count",
  "ripestat_match_percent",
  "ripestat_status",
  "evidence_level",
  "ripestat_source_url",
  "simple_match_note",
];

await writeCsv(OUTPUT, headers, matched);
await writeCsv(SUMMARY, ["metric", "value"], summaryRows);

console.log(JSON.stringify({
  leak_candidates_checked: leaks.length,
  matched_time_overlap_and_leak_asn: matched.length,
  not_matched: evaluated.length - matched.length,
  match_percent: summaryRows.at(-1).value,
}, null, 2));

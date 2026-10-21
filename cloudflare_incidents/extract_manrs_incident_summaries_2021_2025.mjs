import { writeFile } from "node:fs/promises";

const OUT_DIR = new URL("./", import.meta.url);
const API_KEY = process.env.MANRS_API_KEY;
const OUTPUT = "manrs_incident_summaries_2021-2025.csv";
const ROUTE_LEAK_OUTPUT = "manrs_route_leak_incident_summaries_2021-2025.csv";
const SUMMARY = "manrs_incident_summaries_counts_2021-2025.csv";

if (!API_KEY) throw new Error("Set MANRS_API_KEY before running.");

function* monthsBetween(startMonth, endMonth) {
  let [year, month] = startMonth.split("-").map(Number);
  const [endYear, endMon] = endMonth.split("-").map(Number);
  while (year < endYear || (year === endYear && month <= endMon)) {
    yield `${year}-${String(month).padStart(2, "0")}`;
    month += 1;
    if (month === 13) {
      year += 1;
      month = 1;
    }
  }
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

async function fetchSummary(month) {
  const url = new URL("https://observatory.manrs.org/api/v2/incidents/summary");
  url.searchParams.set("reportMonth", `${month}-01T00:00:00Z`);
  const response = await fetch(url, {
    headers: {
      accept: "application/json",
      authorization: `Bearer ${API_KEY}`,
    },
  });
  if (!response.ok) throw new Error(`${response.status} ${response.statusText} for ${url}`);
  return { url: url.toString(), json: await response.json() };
}

const rows = [];
const counts = [];

for (const month of monthsBetween("2021-01", "2025-12")) {
  const { url, json } = await fetchSummary(month);
  const incidents = json.incidents ?? [];
  let m1Total = 0;
  let m1cTotal = 0;
  let m2Total = 0;
  let m2cTotal = 0;
  for (const row of incidents) {
    const out = {
      report_month: month,
      asn: row.asn ?? "",
      asn_holder: row.asnHolder ?? "",
      m1_route_leaks_culprit: row.m1 ?? 0,
      m1c_route_leaks_accomplice: row.m1c ?? 0,
      m2_misoriginations_culprit: row.m2 ?? 0,
      m2c_misoriginations_accomplice: row.m2c ?? 0,
      manrs_source_url: url,
      raw_summary_row: row,
    };
    rows.push(out);
    m1Total += Number(row.m1 ?? 0);
    m1cTotal += Number(row.m1c ?? 0);
    m2Total += Number(row.m2 ?? 0);
    m2cTotal += Number(row.m2c ?? 0);
  }
  counts.push({
    report_month: month,
    summary_rows: incidents.length,
    m1_route_leaks_total: m1Total,
    m1c_route_leaks_accomplice_total: m1cTotal,
    m2_misoriginations_total: m2Total,
    m2c_misoriginations_accomplice_total: m2cTotal,
    manrs_source_url: url,
  });
}

const headers = [
  "report_month",
  "asn",
  "asn_holder",
  "m1_route_leaks_culprit",
  "m1c_route_leaks_accomplice",
  "m2_misoriginations_culprit",
  "m2c_misoriginations_accomplice",
  "manrs_source_url",
  "raw_summary_row",
];

const leakRows = rows.filter((row) => Number(row.m1_route_leaks_culprit) > 0 || Number(row.m1c_route_leaks_accomplice) > 0);

await writeCsv(OUTPUT, headers, rows);
await writeCsv(ROUTE_LEAK_OUTPUT, headers, leakRows);
await writeCsv(SUMMARY, [
  "report_month",
  "summary_rows",
  "m1_route_leaks_total",
  "m1c_route_leaks_accomplice_total",
  "m2_misoriginations_total",
  "m2c_misoriginations_accomplice_total",
  "manrs_source_url",
], counts);

console.log(JSON.stringify({
  months_checked: counts.length,
  summary_rows: rows.length,
  route_leak_summary_rows: leakRows.length,
  m1_total: counts.reduce((sum, row) => sum + row.m1_route_leaks_total, 0),
  m1c_total: counts.reduce((sum, row) => sum + row.m1c_route_leaks_accomplice_total, 0),
  outputs: {
    all_summaries: OUTPUT,
    route_leak_summaries: ROUTE_LEAK_OUTPUT,
    counts: SUMMARY,
  },
}, null, 2));

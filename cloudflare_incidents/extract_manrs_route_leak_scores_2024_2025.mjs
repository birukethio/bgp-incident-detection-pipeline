import { writeFile } from "node:fs/promises";

const OUT_DIR = new URL("./", import.meta.url);
const API_KEY = process.env.MANRS_API_KEY;
const START_MONTH = "2024-01";
const END_MONTH = "2025-12";
const OUTPUT = "manrs_route_leak_monthly_scores_2024-2025.csv";
const SUMMARY = "manrs_route_leak_monthly_scores_summary_2024-2025.csv";

if (!API_KEY) {
  throw new Error("Set MANRS_API_KEY in the environment before running this script.");
}

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

function getPath(obj, path, fallback = "") {
  return path.split(".").reduce((value, key) => value?.[key], obj) ?? fallback;
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

async function fetchScores(month) {
  const url = new URL("https://observatory.manrs.org/api/v2/scores");
  url.searchParams.set("month", `${month}-01T00:00:00Z`);
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
const summaryRows = [];

for (const month of monthsBetween(START_MONTH, END_MONTH)) {
  const { url, json } = await fetchScores(month);
  const scores = json.scores ?? [];
  let monthRouteLeaks = 0;
  let monthAccomplice = 0;
  let rowsWithLeaks = 0;

  for (const score of scores) {
    const routeLeaks = Number(getPath(score, "incidents.routeLeaks", 0));
    const routeLeaksAccomplice = Number(getPath(score, "incidents.routeLeaksAccomplice", 0));
    const actionM1 = getPath(score, "actions.m1", "");
    const actionM1c = getPath(score, "actions.m1c", "");
    if (routeLeaks > 0 || routeLeaksAccomplice > 0 || Number(actionM1) < 1 || Number(actionM1c) < 1) {
      rowsWithLeaks += 1;
      rows.push({
        month,
        asn: score.asn ?? getPath(score, "as.number", ""),
        as_name: getPath(score, "as.name", score.name ?? ""),
        economy: getPath(score, "as.economy", score.economy ?? ""),
        routeLeaks,
        routeLeaksAccomplice,
        action_m1: actionM1,
        action_m1c: actionM1c,
        filtering_score: getPath(score, "scores.filtering.value", ""),
        manrs_source_url: url,
        raw_score: score,
      });
    }
    monthRouteLeaks += routeLeaks;
    monthAccomplice += routeLeaksAccomplice;
  }

  summaryRows.push({
    month,
    scores_returned: scores.length,
    rows_with_route_leak_signal: rowsWithLeaks,
    routeLeaks_total: monthRouteLeaks,
    routeLeaksAccomplice_total: monthAccomplice,
    manrs_source_url: url,
  });
}

await writeCsv(OUTPUT, [
  "month",
  "asn",
  "as_name",
  "economy",
  "routeLeaks",
  "routeLeaksAccomplice",
  "action_m1",
  "action_m1c",
  "filtering_score",
  "manrs_source_url",
  "raw_score",
], rows);

await writeCsv(SUMMARY, [
  "month",
  "scores_returned",
  "rows_with_route_leak_signal",
  "routeLeaks_total",
  "routeLeaksAccomplice_total",
  "manrs_source_url",
], summaryRows);

console.log(JSON.stringify({
  months_checked: summaryRows.length,
  route_leak_rows_written: rows.length,
  routeLeaks_total: summaryRows.reduce((sum, row) => sum + row.routeLeaks_total, 0),
  routeLeaksAccomplice_total: summaryRows.reduce((sum, row) => sum + row.routeLeaksAccomplice_total, 0),
  outputs: { scores: OUTPUT, summary: SUMMARY },
}, null, 2));

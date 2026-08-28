import { readFile, writeFile } from "node:fs/promises";

const OUT_DIR = new URL("./", import.meta.url);
const INPUT = "raw_outages_all_available_to_2026-01_cloudflare.json";

const QC_ALL_OUTPUT = "quality_controlled_cloudflare_outage_events_all_audit.csv";
const QC_ROSTER_OUTPUT = "quality_controlled_cloudflare_outage_roster_deduplicated.csv";
const FINAL_POOL_OUTPUT = "recommended_final_cloudflare_outage_pool.csv";
const SUMMARY_OUTPUT = "quality_controlled_cloudflare_outage_summary.csv";
const CAUSE_OUTPUT = "quality_controlled_cloudflare_outage_counts_by_cause.csv";
const DURATION_OUTPUT = "quality_controlled_cloudflare_outage_counts_by_duration_range.csv";
const YEAR_OUTPUT = "quality_controlled_cloudflare_outage_counts_by_year.csv";

const ROSTER_HEADERS = [
  "incident_id",
  "incident_name",
  "category",
  "affected_organization_network",
  "affected_asns",
  "country",
  "outage_type",
  "outage_cause",
  "start_utc",
  "end_utc",
  "duration_minutes",
  "source_url",
  "description",
  "verification_status",
  "qc_notes",
];

function parseTime(value) {
  if (!value) return NaN;
  return Date.parse(String(value).endsWith("Z") ? value : `${value}Z`);
}

function toUtcIso(value) {
  const ms = parseTime(value);
  return Number.isFinite(ms) ? new Date(ms).toISOString() : null;
}

function durationMinutes(start, end) {
  const startMs = parseTime(start);
  const endMs = parseTime(end);
  if (!Number.isFinite(startMs) || !Number.isFinite(endMs) || endMs <= startMs) return null;
  return Math.ceil((endMs - startMs) / 60000);
}

function jsonList(value) {
  if (value == null) return null;
  return JSON.stringify(Array.isArray(value) ? value : [value]);
}

function csvCell(value) {
  if (value == null) return "";
  const text = String(value).replaceAll(/\s*\r?\n\s*/g, " ");
  return /[",\n\r]/.test(text) ? `"${text.replaceAll('"', '""')}"` : text;
}

async function writeCsv(filename, headers, rows) {
  const body = [
    headers.map(csvCell).join(","),
    ...rows.map((row) => headers.map((header) => csvCell(row[header])).join(",")),
  ].join("\n");
  await writeFile(new URL(filename, OUT_DIR), `${body}\n`);
}

function unique(values) {
  return [...new Set(values.filter((value) => value != null && value !== ""))];
}

function namesFromDetails(row) {
  const asnNames = (row.asnsDetails ?? [])
    .map((detail) => detail.name ? `${detail.name}${detail.asn ? ` (AS${detail.asn})` : ""}` : null);
  const originNames = (row.originsDetails ?? [])
    .map((detail) => detail.name || detail.domain || detail.origin || null);
  return unique([...asnNames, ...originNames]);
}

function countryNames(row) {
  const details = (row.locationsDetails ?? []).map((detail) => detail.name || detail.code);
  return unique(details.length ? details : (row.locations ?? []));
}

function signature(row) {
  return JSON.stringify([
    toUtcIso(row.startDate),
    toUtcIso(row.endDate),
    row.linkedUrl || "",
    row.outage?.outageCause || "",
    row.outage?.outageType || "",
    [...(row.locations ?? [])].sort(),
  ]);
}

function mergeRows(rows) {
  const primary = rows.toSorted((a, b) => Number(a.id) - Number(b.id))[0];
  const ids = unique(rows.map((row) => row.id)).sort((a, b) => Number(a) - Number(b));
  const asns = unique(rows.flatMap((row) => row.asns ?? [])).sort((a, b) => Number(a) - Number(b));
  const orgs = unique(rows.flatMap(namesFromDetails));
  const countries = unique(rows.flatMap(countryNames));
  const descriptions = unique(rows.map((row) => row.description));
  const scopes = unique(rows.map((row) => row.scope));

  return {
    ...primary,
    _merged_ids: ids,
    _merged_asns: asns,
    _merged_orgs: orgs,
    _merged_countries: countries,
    _merged_descriptions: descriptions,
    _merged_scopes: scopes,
    _source_record_count: rows.length,
  };
}

function durationRange(minutes) {
  if (!Number.isFinite(minutes)) return "missing_or_invalid";
  if (minutes <= 30) return "00-30_min";
  if (minutes <= 120) return "31-120_min";
  if (minutes <= 360) return "121-360_min";
  if (minutes <= 1440) return "361-1440_min";
  return "over_24h_manual_review";
}

function rowDescription(row) {
  return unique([
    ...(row._merged_descriptions ?? []),
    ...(row._merged_scopes ?? []),
    row.description,
    row.scope,
  ]).join(" | ");
}

function normalizedOutage(row, duplicateStatus = null) {
  const start = toUtcIso(row.startDate);
  const end = toUtcIso(row.endDate);
  const duration = durationMinutes(start, end);
  const asns = row._merged_asns ?? (row.asns ?? []);
  const orgs = row._merged_orgs ?? namesFromDetails(row);
  const countries = row._merged_countries ?? countryNames(row);
  const outageType = row.outage?.outageType ?? "UNVERIFIED";
  const outageCause = row.outage?.outageCause ?? "UNVERIFIED";
  const description = rowDescription(row) || "";
  const hasTime = Boolean(start && end && Number.isFinite(duration));
  const hasAsn = asns.length > 0;
  const hasNetwork = hasAsn || orgs.length > 0 || /\bAS\d+\b/i.test(description);
  const pureRegionalNoNetwork = !hasNetwork && ["REGIONAL", "NATIONWIDE"].includes(outageType);

  let verificationStatus = "verified";
  const notes = [];
  if (duplicateStatus) {
    verificationStatus = duplicateStatus;
  } else if (!hasTime) {
    verificationStatus = "rejected_missing_or_invalid_time";
  } else if (!row.linkedUrl) {
    verificationStatus = "review_missing_source_url";
  } else if (duration > 1440) {
    verificationStatus = "manual_review_long_duration_over_24h";
  } else if (pureRegionalNoNetwork) {
    verificationStatus = "rejected_no_bgp_visible_network";
  } else if (!hasAsn && hasNetwork) {
    verificationStatus = "review_identifiable_network_no_asn";
  }

  if (!hasAsn) notes.push("no_asn_list");
  if (!hasNetwork) notes.push("no_identifiable_network_operator");
  if (duration > 1440) notes.push("duration_over_24h");
  if (!row.linkedUrl) notes.push("missing_source_url");
  if ((row._source_record_count ?? 1) > 1) notes.push(`merged_cloudflare_ids=${JSON.stringify(row._merged_ids)}`);
  notes.push(`duration_range=${durationRange(duration)}`);
  notes.push(`dataSource=${row.dataSource ?? "UNVERIFIED"}`);
  notes.push(`eventType=${row.eventType ?? "UNVERIFIED"}`);

  return {
    incident_id: row._merged_ids?.[0] ?? row.id,
    incident_name: description || `Cloudflare_Outage_${row._merged_ids?.[0] ?? row.id}_${start ? start.slice(0, 10) : "UNVERIFIED_DATE"}`,
    category: "outage",
    affected_organization_network: jsonList(orgs),
    affected_asns: jsonList(asns),
    country: jsonList(countries),
    outage_type: outageType,
    outage_cause: outageCause,
    start_utc: start,
    end_utc: end,
    duration_minutes: duration,
    source_url: row.linkedUrl ?? null,
    description,
    verification_status: verificationStatus,
    qc_notes: notes.join("; "),
  };
}

function countBy(rows, key) {
  const counts = new Map();
  for (const row of rows) {
    const value = row[key] || "UNVERIFIED";
    counts.set(value, (counts.get(value) || 0) + 1);
  }
  return [...counts.entries()]
    .sort((a, b) => b[1] - a[1] || String(a[0]).localeCompare(String(b[0])))
    .map(([value, count]) => ({ [key]: value, count }));
}

const raw = JSON.parse(await readFile(new URL(INPUT, OUT_DIR), "utf8"));

const groups = new Map();
for (const row of raw) {
  const key = signature(row);
  if (!groups.has(key)) groups.set(key, []);
  groups.get(key).push(row);
}

const mergedRows = [...groups.values()].map(mergeRows);
const duplicateRows = [];
for (const group of groups.values()) {
  if (group.length <= 1) continue;
  const sorted = group.toSorted((a, b) => Number(a.id) - Number(b.id));
  for (const row of sorted.slice(1)) {
    duplicateRows.push(normalizedOutage(row, "duplicate_excluded_merged_with_same_outage"));
  }
}

const rosterRows = mergedRows.map((row) => normalizedOutage(row));
const allAuditRows = [
  ...rosterRows,
  ...duplicateRows,
].sort((a, b) => (parseTime(a.start_utc) || 0) - (parseTime(b.start_utc) || 0) || String(a.incident_id).localeCompare(String(b.incident_id)));

const finalPool = rosterRows
  .filter((row) => row.verification_status === "verified")
  .filter((row) => row.source_url)
  .filter((row) => row.affected_asns && row.affected_asns !== "[]")
  .sort((a, b) => (parseTime(a.start_utc) || 0) - (parseTime(b.start_utc) || 0));

const statusCounts = countBy(allAuditRows, "verification_status");
const summaryRows = [
  { metric: "total_candidate_outages_raw_cloudflare_records", value: raw.length },
  { metric: "total_deduplicated_real_world_outages", value: rosterRows.length },
  { metric: "total_verified_outages_deduplicated", value: rosterRows.filter((row) => row.verification_status === "verified").length },
  { metric: "total_rejected_or_review_events_audit", value: allAuditRows.filter((row) => row.verification_status !== "verified").length },
  { metric: "number_with_asn_information_deduplicated", value: rosterRows.filter((row) => row.affected_asns && row.affected_asns !== "[]").length },
  { metric: "recommended_final_outage_pool_count", value: finalPool.length },
  { metric: "duplicate_source_records_excluded", value: duplicateRows.length },
  ...statusCounts.map((row) => ({ metric: `verification_status_${row.verification_status}`, value: row.count })),
];

const durationRows = countBy(rosterRows.map((row) => ({ duration_range: durationRange(Number(row.duration_minutes)) })), "duration_range");
const yearRows = countBy(rosterRows.map((row) => ({ year: row.start_utc ? row.start_utc.slice(0, 4) : "UNVERIFIED" })), "year");
const causeRows = countBy(rosterRows, "outage_cause");

await Promise.all([
  writeCsv(QC_ALL_OUTPUT, ROSTER_HEADERS, allAuditRows),
  writeCsv(QC_ROSTER_OUTPUT, ROSTER_HEADERS, rosterRows.sort((a, b) => (parseTime(a.start_utc) || 0) - (parseTime(b.start_utc) || 0))),
  writeCsv(FINAL_POOL_OUTPUT, ROSTER_HEADERS, finalPool),
  writeCsv(SUMMARY_OUTPUT, ["metric", "value"], summaryRows),
  writeCsv(CAUSE_OUTPUT, ["outage_cause", "count"], causeRows),
  writeCsv(DURATION_OUTPUT, ["duration_range", "count"], durationRows),
  writeCsv(YEAR_OUTPUT, ["year", "count"], yearRows),
]);

console.log(JSON.stringify({
  outputs: {
    all_audit: QC_ALL_OUTPUT,
    deduplicated_roster: QC_ROSTER_OUTPUT,
    recommended_final_pool: FINAL_POOL_OUTPUT,
    summary: SUMMARY_OUTPUT,
    by_cause: CAUSE_OUTPUT,
    by_duration: DURATION_OUTPUT,
    by_year: YEAR_OUTPUT,
  },
  summary: Object.fromEntries(summaryRows.map((row) => [row.metric, row.value])),
  by_cause: causeRows,
  by_duration: durationRows,
  by_year: yearRows,
}, null, 2));

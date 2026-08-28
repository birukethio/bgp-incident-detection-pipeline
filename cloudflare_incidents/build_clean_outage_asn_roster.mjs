import { readFile, writeFile } from "node:fs/promises";

const OUT_DIR = new URL("./", import.meta.url);
const INPUT = "raw_outages_all_available_to_2026-01_cloudflare.json";

const ALL_OUTPUT = "clean_cloudflare_outage_roster_all_asns.csv";
const FINAL_OUTPUT = "clean_cloudflare_outage_recommended_final_pool_all_asns.csv";
const NO_ASN_OUTPUT = "clean_cloudflare_outage_records_without_asn.csv";
const SUMMARY_OUTPUT = "clean_cloudflare_outage_asn_summary.csv";

const HEADERS = [
  "incident_id",
  "merged_cloudflare_ids",
  "incident_name",
  "category",
  "affected_organization_network",
  "affected_asns",
  "affected_asn_count",
  "country",
  "outage_type",
  "outage_cause",
  "start_utc",
  "end_utc",
  "duration_minutes",
  "source_url",
  "description",
  "verification_status",
  "asn_completeness",
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

function unique(values) {
  return [...new Set(values.filter((value) => value != null && value !== ""))];
}

function sortedAsns(values) {
  return unique(values.map((value) => Number(value)).filter(Number.isFinite)).sort((a, b) => a - b);
}

function jsonList(value) {
  return JSON.stringify(Array.isArray(value) ? value : value == null ? [] : [value]);
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

function sourceAsns(row) {
  return sortedAsns([
    ...(row.asns ?? []),
    ...(row.asnsDetails ?? []).map((detail) => detail.asn),
  ]);
}

function networkNames(row) {
  return unique([
    ...(row.asnsDetails ?? []).map((detail) => {
      const asn = detail.asn ? `AS${detail.asn}` : null;
      if (detail.name && asn) return `${detail.name} (${asn})`;
      return detail.name || asn;
    }),
    ...(row.originsDetails ?? []).map((detail) => detail.name || detail.domain || detail.origin),
    ...(row.origins ?? []),
  ]);
}

function countryNames(row) {
  return unique([
    ...(row.locationsDetails ?? []).map((detail) => detail.name || detail.code),
    ...(row.locations ?? []),
  ]);
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

function durationRange(minutes) {
  if (!Number.isFinite(minutes)) return "missing_or_invalid";
  if (minutes <= 30) return "00-30_min";
  if (minutes <= 120) return "31-120_min";
  if (minutes <= 360) return "121-360_min";
  if (minutes <= 1440) return "361-1440_min";
  return "over_24h_manual_review";
}

function mergeGroup(group) {
  const sorted = group.toSorted((a, b) => Number(a.id) - Number(b.id));
  return {
    primary: sorted[0],
    ids: sorted.map((row) => row.id),
    asns: sortedAsns(group.flatMap(sourceAsns)),
    networks: unique(group.flatMap(networkNames)),
    countries: unique(group.flatMap(countryNames)),
    descriptions: unique(group.flatMap((row) => [row.description, row.scope])),
    sourceRecordCount: group.length,
  };
}

function normalize(group) {
  const merged = mergeGroup(group);
  const row = merged.primary;
  const start = toUtcIso(row.startDate);
  const end = toUtcIso(row.endDate);
  const duration = durationMinutes(start, end);
  const outageType = row.outage?.outageType ?? "UNVERIFIED";
  const outageCause = row.outage?.outageCause ?? "UNVERIFIED";
  const description = merged.descriptions.join(" | ");
  const hasTime = Boolean(start && end && Number.isFinite(duration));
  const hasAsn = merged.asns.length > 0;
  const hasNetworkName = merged.networks.length > 0;
  const purelyRegionalNoNetwork = !hasAsn && !hasNetworkName && ["REGIONAL", "NATIONWIDE"].includes(outageType);

  let verificationStatus = "verified";
  if (!hasTime) verificationStatus = "rejected_missing_or_invalid_time";
  else if (!row.linkedUrl) verificationStatus = "review_missing_source_url";
  else if (duration > 1440) verificationStatus = "manual_review_long_duration_over_24h";
  else if (purelyRegionalNoNetwork) verificationStatus = "rejected_no_bgp_visible_network";
  else if (!hasAsn && hasNetworkName) verificationStatus = "review_identifiable_network_no_asn";

  const notes = [
    `duration_range=${durationRange(duration)}`,
    `source_record_count=${merged.sourceRecordCount}`,
    `dataSource=${row.dataSource ?? "UNVERIFIED"}`,
    `eventType=${row.eventType ?? "UNVERIFIED"}`,
  ];
  if (merged.sourceRecordCount > 1) notes.push(`deduplicated_from_cloudflare_ids=${JSON.stringify(merged.ids)}`);
  if (!hasAsn) notes.push("Cloudflare supplied no affected ASN list for this outage");

  return {
    incident_id: merged.ids[0],
    merged_cloudflare_ids: jsonList(merged.ids),
    incident_name: description || `Cloudflare_Outage_${merged.ids[0]}_${start ? start.slice(0, 10) : "UNVERIFIED_DATE"}`,
    category: "outage",
    affected_organization_network: jsonList(merged.networks),
    affected_asns: jsonList(merged.asns),
    affected_asn_count: merged.asns.length,
    country: jsonList(merged.countries),
    outage_type: outageType,
    outage_cause: outageCause,
    start_utc: start,
    end_utc: end,
    duration_minutes: duration,
    source_url: row.linkedUrl ?? null,
    description,
    verification_status: verificationStatus,
    asn_completeness: hasAsn ? "asn_listed_from_cloudflare" : "no_asn_supplied_by_cloudflare",
    qc_notes: notes.join("; "),
  };
}

const raw = JSON.parse(await readFile(new URL(INPUT, OUT_DIR), "utf8"));
const groups = new Map();
for (const row of raw) {
  const key = signature(row);
  if (!groups.has(key)) groups.set(key, []);
  groups.get(key).push(row);
}

const roster = [...groups.values()]
  .map(normalize)
  .sort((a, b) => (parseTime(a.start_utc) || 0) - (parseTime(b.start_utc) || 0) || Number(a.incident_id) - Number(b.incident_id));

const finalPool = roster.filter((row) =>
  row.verification_status === "verified" &&
  row.affected_asn_count > 0 &&
  row.source_url
);

const noAsnRows = roster.filter((row) => row.affected_asn_count === 0);

const byStatus = new Map();
const byAsnCompleteness = new Map();
for (const row of roster) {
  byStatus.set(row.verification_status, (byStatus.get(row.verification_status) || 0) + 1);
  byAsnCompleteness.set(row.asn_completeness, (byAsnCompleteness.get(row.asn_completeness) || 0) + 1);
}

const summaryRows = [
  { metric: "raw_cloudflare_outage_records", value: raw.length },
  { metric: "deduplicated_outage_records", value: roster.length },
  { metric: "recommended_final_pool_records", value: finalPool.length },
  { metric: "records_with_affected_asns", value: roster.filter((row) => row.affected_asn_count > 0).length },
  { metric: "records_without_affected_asns", value: noAsnRows.length },
  { metric: "max_affected_asn_count", value: Math.max(...roster.map((row) => Number(row.affected_asn_count) || 0)) },
  ...[...byStatus.entries()].map(([status, count]) => ({ metric: `verification_status_${status}`, value: count })),
  ...[...byAsnCompleteness.entries()].map(([status, count]) => ({ metric: `asn_completeness_${status}`, value: count })),
];

await Promise.all([
  writeCsv(ALL_OUTPUT, HEADERS, roster),
  writeCsv(FINAL_OUTPUT, HEADERS, finalPool),
  writeCsv(NO_ASN_OUTPUT, HEADERS, noAsnRows),
  writeCsv(SUMMARY_OUTPUT, ["metric", "value"], summaryRows),
]);

console.log(JSON.stringify({
  outputs: {
    all_clean_roster: ALL_OUTPUT,
    recommended_final_pool: FINAL_OUTPUT,
    no_asn_records: NO_ASN_OUTPUT,
    summary: SUMMARY_OUTPUT,
  },
  summary: Object.fromEntries(summaryRows.map((row) => [row.metric, row.value])),
}, null, 2));

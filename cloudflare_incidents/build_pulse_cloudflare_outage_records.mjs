import { readFile, writeFile } from "node:fs/promises";

const OUT_DIR = new URL("./", import.meta.url);

const pulseLabel = {
  pulse_country: "Iraq",
  pulse_country_code: "IQ",
  pulse_start_utc: "2025-02-18T11:00:00.000Z",
  pulse_end_utc: null,
  pulse_cause: "Government Action",
  pulse_shutdown_reach: "Regional shutdown",
  pulse_verification_level: "Acknowledged",
  pulse_source_url: "https://pulse.internetsociety.org/en/shutdowns/",
  pulse_source_note: "Visible on Internet Society Pulse shutdowns page as ongoing Iraq shutdown since 18 February 2025 11:00 UTC.",
};

function parseTime(value) {
  return value ? Date.parse(value) : NaN;
}

function toIso(value) {
  const ms = parseTime(value);
  return Number.isFinite(ms) ? new Date(ms).toISOString() : null;
}

function durationMinutes(start, end) {
  const a = parseTime(start);
  const b = parseTime(end);
  if (!Number.isFinite(a) || !Number.isFinite(b) || b < a) return null;
  return Math.ceil((b - a) / 60000);
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

const outages = JSON.parse(await readFile(new URL("raw_outages_2023-01_to_2026-01.json", OUT_DIR), "utf8"));

const rows = outages
  .filter((record) => (record.locations ?? []).includes(pulseLabel.pulse_country_code))
  .filter((record) => parseTime(record.startDate) >= parseTime(pulseLabel.pulse_start_utc))
  .filter((record) => record.outage?.outageCause === "GOVERNMENT_DIRECTED")
  .filter((record) => parseTime(record.startDate) <= Date.parse("2025-12-31T23:59:59Z"))
  .map((record) => {
    const start = toIso(record.startDate);
    const end = toIso(record.endDate);
    const duration = durationMinutes(start, end);
    return {
      cloudflare_outage_id: record.id,
      category: "Outage",
      match_status: "MATCH_CLOUDFLARE_PULSE_COUNTRY_TIME_CAUSE",
      match_rule: "Cloudflare locations includes IQ; Cloudflare start overlaps Pulse ongoing Iraq shutdown after 2025-02-18T11:00Z; Cloudflare outageCause is GOVERNMENT_DIRECTED.",
      cloudflare_start_utc: start,
      cloudflare_end_utc: end,
      cloudflare_duration_minutes: duration,
      five_minute_window_count: duration == null ? null : Math.ceil(duration / 5),
      cloudflare_locations: record.locations,
      cloudflare_asns: record.asns,
      cloudflare_description: record.description,
      cloudflare_outage_cause: record.outage?.outageCause ?? null,
      cloudflare_outage_type: record.outage?.outageType ?? null,
      cloudflare_source_url: record.linkedUrl,
      ...pulseLabel,
      source_separation_note: "Cloudflare ID is retained as source metadata only; match is based on country, time overlap, and outage cause/type evidence.",
      cloudflare_raw_record: record,
    };
  })
  .sort((a, b) => a.cloudflare_start_utc.localeCompare(b.cloudflare_start_utc));

const headers = [
  "cloudflare_outage_id",
  "category",
  "match_status",
  "match_rule",
  "cloudflare_start_utc",
  "cloudflare_end_utc",
  "cloudflare_duration_minutes",
  "five_minute_window_count",
  "cloudflare_locations",
  "cloudflare_asns",
  "cloudflare_description",
  "cloudflare_outage_cause",
  "cloudflare_outage_type",
  "cloudflare_source_url",
  "pulse_country",
  "pulse_country_code",
  "pulse_start_utc",
  "pulse_end_utc",
  "pulse_cause",
  "pulse_shutdown_reach",
  "pulse_verification_level",
  "pulse_source_url",
  "pulse_source_note",
  "source_separation_note",
  "cloudflare_raw_record",
];

await writeCsv("cloudflare_pulse_matched_outage_records_2025_iq.csv", headers, rows);
await writeCsv("cloudflare_pulse_matched_outage_summary_2025_iq.csv", ["metric", "value"], [
  { metric: "pulse_label", value: "Iraq ongoing regional shutdown since 2025-02-18T11:00:00Z" },
  { metric: "matched_cloudflare_outage_records", value: rows.length },
  { metric: "match_rule", value: "country + time overlap + government-directed outage cause" },
]);

console.log(JSON.stringify({ matched_cloudflare_outage_records: rows.length }, null, 2));

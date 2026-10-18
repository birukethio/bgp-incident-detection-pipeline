import { readFile, writeFile } from "node:fs/promises";

const OUT_DIR = new URL("./", import.meta.url);

const pulseLabels = [
  {
    pulse_label_id: "pulse_pk_election_2024_02_08",
    pulse_country: "Pakistan",
    pulse_country_code: "PK",
    pulse_start_utc: "2024-02-08T01:45:00.000Z",
    pulse_end_utc: "2024-02-08T15:00:00.000Z",
    pulse_cause: "Elections / Government Action",
    pulse_shutdown_reach: "Nationwide mobile services disruption",
    pulse_verification_level: "Pulse blog documented",
    pulse_source_url: "https://pulse.internetsociety.org/en/blog/2024/02/pakistan-elections-2024-reports-of-internet-and-mobile-services-disrupted/",
    pulse_source_note: "Pulse reported Pakistan mobile Internet/phone service disruptions on election day; Cloudflare Radar observed outages on CMPak, Jazz, and Telenor starting around 02:00 UTC.",
    match_keywords: ["election", "mobile"],
  },
  {
    pulse_label_id: "pulse_sy_exams_2024_05_26",
    pulse_country: "Syria",
    pulse_country_code: "SY",
    pulse_start_utc: "2024-05-26T03:00:00.000Z",
    pulse_end_utc: "2024-05-26T08:00:00.000Z",
    pulse_cause: "Exams",
    pulse_shutdown_reach: "National shutdown",
    pulse_verification_level: "Pulse shutdown page",
    pulse_source_url: "https://pulse.internetsociety.org/en/shutdowns/internet-shutdown-for-syrian-exams-26-may-2024/",
    pulse_source_note: "Pulse states the Internet in Syria was suspended for exams from 03:00 to 08:00 UTC.",
    match_keywords: ["exam"],
  },
  {
    pulse_label_id: "pulse_sy_exams_2024_06_09",
    pulse_country: "Syria",
    pulse_country_code: "SY",
    pulse_start_utc: "2024-06-09T03:00:00.000Z",
    pulse_end_utc: "2024-06-09T08:00:00.000Z",
    pulse_cause: "Exams",
    pulse_shutdown_reach: "National shutdown",
    pulse_verification_level: "Pulse shutdown page; page mentions IODA and Cloudflare drops",
    pulse_source_url: "https://pulse.internetsociety.org/en/shutdowns/internet-shutdown-for-syrian-exams-9-june-2024/",
    pulse_source_note: "Pulse states Cloudflare Radar and IODA recorded drops from 03:00 to 08:00 UTC.",
    match_keywords: ["exam"],
  },
  {
    pulse_label_id: "pulse_sy_exams_2024_06_13",
    pulse_country: "Syria",
    pulse_country_code: "SY",
    pulse_start_utc: "2024-06-13T03:00:00.000Z",
    pulse_end_utc: "2024-06-13T07:00:00.000Z",
    pulse_cause: "Exams",
    pulse_shutdown_reach: "National shutdown",
    pulse_verification_level: "Pulse shutdown page; page mentions IODA and Cloudflare drops",
    pulse_source_url: "https://pulse.internetsociety.org/en/shutdowns/internet-shutdown-for-syrian-exams-13-june-2024/",
    pulse_source_note: "Pulse states Cloudflare Radar and IODA recorded drops from 03:00 to 07:00 UTC.",
    match_keywords: ["exam"],
  },
  {
    pulse_label_id: "pulse_sy_exams_2024_07_28",
    pulse_country: "Syria",
    pulse_country_code: "SY",
    pulse_start_utc: "2024-07-28T04:00:00.000Z",
    pulse_end_utc: "2024-07-28T07:30:00.000Z",
    pulse_cause: "Exams",
    pulse_shutdown_reach: "National shutdown",
    pulse_verification_level: "Pulse shutdown page",
    pulse_source_url: "https://pulse.internetsociety.org/en/shutdowns/internet-shutdown-for-syrian-exams-second-round-28-july-2024/",
    pulse_source_note: "Pulse states a Syria exam shutdown on 28 July 2024 from 04:00 to 07:30 UTC.",
    match_keywords: ["exam"],
  },
  {
    pulse_label_id: "pulse_sy_exams_2024_07_29",
    pulse_country: "Syria",
    pulse_country_code: "SY",
    pulse_start_utc: "2024-07-29T04:00:00.000Z",
    pulse_end_utc: "2024-07-29T07:45:00.000Z",
    pulse_cause: "Exams",
    pulse_shutdown_reach: "National shutdown",
    pulse_verification_level: "Pulse shutdown page",
    pulse_source_url: "https://pulse.internetsociety.org/en/shutdowns/internet-shutdown-for-syrian-exams-second-round-29-july-2024/",
    pulse_source_note: "Pulse states a Syria exam shutdown on 29 July 2024 from 04:00 to 07:45 UTC.",
    match_keywords: ["exam"],
  },
];

function parseTime(value) {
  return value ? Date.parse(value) : NaN;
}

function toIso(value) {
  const ms = parseTime(value);
  return Number.isFinite(ms) ? new Date(ms).toISOString() : null;
}

function overlaps(aStart, aEnd, bStart, bEnd) {
  return parseTime(aStart) <= parseTime(bEnd) && parseTime(bStart) <= parseTime(aEnd);
}

function durationMinutes(start, end) {
  const a = parseTime(start);
  const b = parseTime(end);
  if (!Number.isFinite(a) || !Number.isFinite(b) || b < a) return null;
  return Math.ceil((b - a) / 60000);
}

function keywordMatch(description, keywords) {
  const text = String(description ?? "").toLowerCase();
  return keywords.some((keyword) => text.includes(keyword));
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

const rows = [];
for (const label of pulseLabels) {
  const matches = outages
    .filter((record) => (record.locations ?? []).includes(label.pulse_country_code))
    .filter((record) => overlaps(record.startDate, record.endDate, label.pulse_start_utc, label.pulse_end_utc))
    .filter((record) => keywordMatch(record.description, label.match_keywords) || record.outage?.outageCause === "GOVERNMENT_DIRECTED")
    .sort((a, b) => parseTime(a.startDate) - parseTime(b.startDate));

  for (const record of matches) {
    const start = toIso(record.startDate);
    const end = toIso(record.endDate);
    const duration = durationMinutes(start, end);
    rows.push({
      cloudflare_outage_id: record.id,
      category: "Outage",
      match_status: "MATCH_CLOUDFLARE_PULSE_COUNTRY_TIME_CAUSE",
      match_rule: "Country/location match + outage time overlap + compatible shutdown cause/description. Cloudflare source ID is metadata only.",
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
      pulse_label_id: label.pulse_label_id,
      pulse_country: label.pulse_country,
      pulse_country_code: label.pulse_country_code,
      pulse_start_utc: label.pulse_start_utc,
      pulse_end_utc: label.pulse_end_utc,
      pulse_cause: label.pulse_cause,
      pulse_shutdown_reach: label.pulse_shutdown_reach,
      pulse_verification_level: label.pulse_verification_level,
      pulse_source_url: label.pulse_source_url,
      pulse_source_note: label.pulse_source_note,
      cloudflare_raw_record: record,
    });
  }
}

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
  "pulse_label_id",
  "pulse_country",
  "pulse_country_code",
  "pulse_start_utc",
  "pulse_end_utc",
  "pulse_cause",
  "pulse_shutdown_reach",
  "pulse_verification_level",
  "pulse_source_url",
  "pulse_source_note",
  "cloudflare_raw_record",
];

const summary = Object.entries(rows.reduce((acc, row) => {
  acc[row.pulse_label_id] = (acc[row.pulse_label_id] ?? 0) + 1;
  return acc;
}, {})).map(([pulse_label_id, matched_cloudflare_records]) => ({ pulse_label_id, matched_cloudflare_records }));

await writeCsv("cloudflare_pulse_additional_matched_outage_records.csv", headers, rows);
await writeCsv("cloudflare_pulse_additional_matched_outage_summary.csv", ["pulse_label_id", "matched_cloudflare_records"], summary);

console.log(JSON.stringify({ matched_rows: rows.length, summary }, null, 2));

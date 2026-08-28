const { readFile, writeFile } = await import("node:fs/promises");
const ROOT = new URL("./", import.meta.url);

const LATEST_EXTERNAL = "latest_timed_bgp_route_leak_incidents_2025_onward.csv";
const CLOUDFLARE_FILES = [
  "raw_leaks_2023-01_to_2026-01.json",
  "raw_leaks_2026-02_to_2026-08_cloudflare.json",
];
const OUTPUT = "latest_leaks_compared_to_cloudflare_extended.csv";

function parseCsv(text) {
  const lines = text.trim().split(/\n/);
  function parse(line) {
    const cells = [];
    let current = "";
    let quoted = false;
    for (let i = 0; i < line.length; i += 1) {
      const char = line[i];
      if (char === '"' && line[i + 1] === '"') {
        current += '"';
        i += 1;
      } else if (char === '"') {
        quoted = !quoted;
      } else if (char === "," && !quoted) {
        cells.push(current);
        current = "";
      } else {
        current += char;
      }
    }
    cells.push(current);
    return cells;
  }
  const headers = parse(lines[0]);
  return lines.slice(1).map((line) => Object.fromEntries(parse(line).map((value, index) => [headers[index], value])));
}

function csvCell(value) {
  const text = String(value ?? "");
  return /[",\n\r]/.test(text) ? `"${text.replaceAll('"', '""')}"` : text;
}

function writeCsv(path, rows, headers) {
  const body = [
    headers.map(csvCell).join(","),
    ...rows.map((row) => headers.map((header) => csvCell(row[header])).join(",")),
  ].join("\n");
  return writeFile(new URL(path, ROOT), `${body}\n`);
}

function parseTime(value) {
  if (!value) return NaN;
  return Date.parse(String(value).endsWith("Z") ? value : `${value}Z`);
}

function iso(value) {
  const parsed = parseTime(value);
  return Number.isFinite(parsed) ? new Date(parsed).toISOString() : "";
}

function overlaps(aStart, aEnd, bStart, bEnd) {
  return aStart <= bEnd && bStart <= aEnd;
}

function numbersFrom(value) {
  return [...String(value || "").matchAll(/\b\d{2,6}\b/g)].map((match) => Number(match[0]));
}

const externalRows = parseCsv(await readFile(new URL(LATEST_EXTERNAL, ROOT), "utf8"));
const allCloudflare = [];
for (const file of CLOUDFLARE_FILES) {
  const rows = JSON.parse(await readFile(new URL(file, ROOT), "utf8"));
  for (const row of rows) {
    allCloudflare.push(row);
  }
}

const cloudflareById = new Map();
for (const row of allCloudflare) {
  cloudflareById.set(String(row.id), row);
}
const cloudflareRows = [...cloudflareById.values()];

let cloudflareMin = Infinity;
let cloudflareMax = -Infinity;
for (const row of cloudflareRows) {
  const start = parseTime(row.min_ts || row.detected_ts);
  const end = parseTime(row.max_ts || row.detected_ts);
  if (Number.isFinite(start) && start < cloudflareMin) cloudflareMin = start;
  if (Number.isFinite(end) && end > cloudflareMax) cloudflareMax = end;
}

const outputRows = [];
for (const external of externalRows) {
  const externalStart = parseTime(external.start_utc);
  const externalEnd = parseTime(external.end_utc);
  const leakerAsn = Number(external.leaker_asn || NaN);
  const upstreamAsns = numbersFrom(external.propagator_or_upstream_asn);
  const pathAsns = numbersFrom(external.path_evidence);
  const evidenceAsns = [...new Set([leakerAsn, ...upstreamAsns, ...pathAsns].filter(Number.isFinite))];

  let status = "no_match";
  let candidates = [];

  if (externalEnd < cloudflareMin || externalStart > cloudflareMax) {
    status = "outside_cloudflare_extract_window";
  } else {
    candidates = cloudflareRows
      .filter((row) => overlaps(parseTime(row.min_ts), parseTime(row.max_ts), externalStart, externalEnd))
      .map((row) => {
        const leakSegment = row.leak_seg || [];
        const leakerExact = Number.isFinite(leakerAsn) && row.leak_asn === leakerAsn;
        const leakerInSegment = Number.isFinite(leakerAsn) && leakSegment.includes(leakerAsn);
        const upstreamHits = upstreamAsns.filter((asn) => leakSegment.includes(asn));
        const pathHits = pathAsns.filter((asn) => leakSegment.includes(asn));
        const anyEvidence = evidenceAsns.filter((asn) => row.leak_asn === asn || leakSegment.includes(asn));
        let score = 0;
        if (leakerExact) score += 10;
        if (leakerInSegment) score += 6;
        score += Math.min(upstreamHits.length, 2) * 3;
        score += Math.min(pathHits.length, 3);
        score += Math.min(anyEvidence.length, 5);
        score += Math.min((row.prefix_count || 0) / 1000, 5);
        return { row, score, leakerExact, leakerInSegment, upstreamHits, pathHits, anyEvidence };
      })
      .filter((candidate) =>
        candidate.leakerExact ||
        candidate.leakerInSegment ||
        candidate.upstreamHits.length ||
        candidate.pathHits.length ||
        candidate.anyEvidence.length
      )
      .sort((a, b) => b.score - a.score);

    if (candidates.length) {
      const best = candidates[0];
      status = best.leakerExact
        ? "strong_time_leaker_asn_match"
        : "candidate_time_path_asn_match";
    }
  }

  const best = candidates[0];
  outputRows.push({
    incident_name: external.incident_name,
    external_start_utc: external.start_utc,
    external_end_utc: external.end_utc,
    external_duration_minutes: external.duration_minutes,
    external_leaker_asn: external.leaker_asn,
    external_upstream_asn: external.propagator_or_upstream_asn,
    external_path_evidence: external.path_evidence,
    external_source: external.source,
    external_source_url: external.source_url,
    cloudflare_match_status: status,
    cloudflare_id: best?.row.id || "",
    cloudflare_start_utc: best ? iso(best.row.min_ts) : "",
    cloudflare_end_utc: best ? iso(best.row.max_ts) : "",
    cloudflare_leak_asn: best?.row.leak_asn || "",
    cloudflare_leak_seg: best ? JSON.stringify(best.row.leak_seg) : "",
    cloudflare_prefix_count: best?.row.prefix_count || "",
    cloudflare_peer_count: best?.row.peer_count || "",
    cloudflare_countries: best ? JSON.stringify(best.row.countries) : "",
    match_evidence: best
      ? `score=${best.score}; leakerExact=${best.leakerExact}; leakerInSegment=${best.leakerInSegment}; upstreamHits=${JSON.stringify(best.upstreamHits)}; pathHits=${JSON.stringify(best.pathHits)}`
      : "",
    candidate_count: candidates.length,
  });
}

const headers = [
  "incident_name",
  "external_start_utc",
  "external_end_utc",
  "external_duration_minutes",
  "external_leaker_asn",
  "external_upstream_asn",
  "external_path_evidence",
  "external_source",
  "external_source_url",
  "cloudflare_match_status",
  "cloudflare_id",
  "cloudflare_start_utc",
  "cloudflare_end_utc",
  "cloudflare_leak_asn",
  "cloudflare_leak_seg",
  "cloudflare_prefix_count",
  "cloudflare_peer_count",
  "cloudflare_countries",
  "match_evidence",
  "candidate_count",
];

await writeCsv(OUTPUT, outputRows, headers);

const summary = outputRows.reduce((acc, row) => {
  acc[row.cloudflare_match_status] = (acc[row.cloudflare_match_status] || 0) + 1;
  return acc;
}, {});

console.log(JSON.stringify({
  output: OUTPUT,
  external_rows: outputRows.length,
  cloudflare_rows: cloudflareRows.length,
  cloudflare_extract_start: new Date(cloudflareMin).toISOString(),
  cloudflare_extract_end: new Date(cloudflareMax).toISOString(),
  summary,
}, null, 2));

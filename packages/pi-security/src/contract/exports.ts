// CSV projection of sealed findings. Port of csv_cell, finding_candidate_id, and build_csv_projection in
// scripts/finalize_scan_contract.py (Python's csv module, excel dialect).
import { isBlank, isJsonObject, pythonLstrip, type JsonObject } from "./contract-error.js";
import { hasLoneSurrogate, PyFloat, pythonFloatRepr } from "./python-json.js";

// Spreadsheet formula prefixes, ASCII and fullwidth.
const FORMULA_PREFIXES = ["=", "+", "-", "@", ...[0xff1d, 0xff0b, 0xff0d, 0xff20].map((code) => String.fromCodePoint(code))];

/** Neutralize values a spreadsheet would treat as formulas. */
export function csvCell(value: unknown): unknown {
  if (typeof value !== "string") return value;
  const lstripped = pythonLstrip(value);
  if (/^[\t\r\n]/.test(value) || FORMULA_PREFIXES.some((prefix) => lstripped.startsWith(prefix))) return `'${value}`;
  return value;
}

export function findingCandidateId(finding: JsonObject): string | null {
  const provenance = finding.provenance;
  if (isJsonObject(provenance) && typeof provenance.candidateId === "string" && !isBlank(provenance.candidateId)) {
    return provenance.candidateId;
  }
  const extensions = finding.extensions;
  if (!isJsonObject(extensions)) return null;
  for (const field of ["candidateId", "reportId", "ledgerRowId"]) {
    const value = extensions[field];
    if (typeof value === "string" && !isBlank(value)) return value;
  }
  return null;
}

function csvField(value: unknown): string {
  let text: string;
  if (value === null || value === undefined) text = "";
  else if (typeof value === "string") text = value;
  else if (value instanceof PyFloat) text = pythonFloatRepr(value.value);
  else if (typeof value === "number") text = Number.isInteger(value) ? String(value) : pythonFloatRepr(value);
  else if (typeof value === "boolean") text = value ? "True" : "False";
  else text = String(value);
  // QUOTE_MINIMAL: the delimiter, the quote character, or a line-terminator character forces quoting.
  return /[",\r\n]/.test(text) ? `"${text.replaceAll('"', '""')}"` : text;
}

const csvRow = (fields: unknown[]) => `${fields.map(csvField).join(",")}\r\n`;

export function buildCsvProjection(findings: JsonObject, coverage: JsonObject): Buffer {
  const items = findings.findings as JsonObject[];
  const deepScan =
    coverage.mode === "deep_repository" ||
    (coverage.mode === "scoped_path" &&
      items.some((finding) => {
        const extensions = finding.extensions;
        return (
          isJsonObject(extensions) &&
          ["candidateId", "reportId"].some((field) => typeof extensions[field] === "string" && !isBlank(extensions[field] as string))
        );
      }));
  let text = csvRow([
    "occurrence_id",
    "finding_id",
    ...(deepScan ? ["candidate_id"] : []),
    "title",
    "summary",
    "severity",
    "confidence",
    "status",
    "close_reason",
    "note",
    "remediation",
    "path",
    "start_line",
    "end_line"
  ]);
  for (const finding of items) {
    const locations = finding.locations as JsonObject[];
    const location = locations.find((candidate) => candidate.role === "root_control") ?? locations[0]!;
    text += csvRow([
      csvCell(finding.occurrenceId),
      csvCell(finding.findingId),
      ...(deepScan ? [csvCell(findingCandidateId(finding))] : []),
      csvCell(finding.title),
      csvCell(finding.summary),
      csvCell((finding.severity as JsonObject).level),
      csvCell((finding.confidence as JsonObject).level),
      "open",
      "",
      "",
      csvCell(finding.remediation),
      csvCell(location.path),
      location.startLine,
      Object.hasOwn(location, "endLine") ? location.endLine : location.startLine
    ]);
  }
  if (hasLoneSurrogate(text)) throw new Error("surrogates not allowed");
  return Buffer.from(text, "utf8");
}

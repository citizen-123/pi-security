// The deterministic parts of a Standard scan (design D4): planning discovery packets from the threat model's surfaces,
// checking the reducer's accounting, mapping each reduced finding's validation and attack-path records to an outcome,
// and assembling the draft manifest, findings, and coverage the finalizer seals. No model output is trusted here
// beyond the schema its report tool enforced; every cross-reference is checked.
//
// Outcomes follow references/final-report.md: validation reportable plus attack path reportable is a finding; otherwise
// a deferred record from either phase is follow-up work; otherwise not_applicable; otherwise suppressed or ignored is
// rejected. A missing record leaves the item unresolved, which also keeps coverage partial.
import type { JsonObject } from "../contract/contract-error.js";
import type { CombinedCandidate } from "../contract/candidates.js";

export class StandardScanError extends Error {
  override name = "StandardScanError";
}

export type ThreatSurface = { id: string; label: string; description?: string; paths: string[] };
export type Packet = { id: string; label: string; description?: string; files: string[] };
export type Plan = { packets: Packet[]; unmatched: ThreatSurface[] };

const byteOrder = (left: string, right: string) => Buffer.compare(Buffer.from(left), Buffer.from(right));
const stripDot = (path: string) => (path === "." ? "" : path.startsWith("./") ? path.slice(2) : path);

/**
 * One packet per threat-model surface (its files: inventory entries equal to or below one of its paths), then one
 * packet per top-level directory of the files no surface claimed. A surface matching no file is returned unmatched.
 */
export function planPackets(files: readonly string[], surfaces: readonly ThreatSurface[]): Plan {
  const ids = new Set<string>();
  for (const surface of surfaces) {
    if (ids.has(surface.id)) throw new StandardScanError(`threat model names surface ${surface.id} more than once`);
    ids.add(surface.id);
  }
  const claimed = new Set<string>();
  const packets: Packet[] = [];
  const unmatched: ThreatSurface[] = [];
  for (const surface of surfaces) {
    const prefixes = surface.paths.map(stripDot);
    const matched = files.filter((file) => prefixes.some((prefix) => prefix === "" || file === prefix || file.startsWith(`${prefix}/`)));
    if (matched.length === 0) {
      unmatched.push(surface);
      continue;
    }
    for (const file of matched) claimed.add(file);
    packets.push({
      id: `threat-model/${surface.id}`,
      label: surface.label,
      ...(surface.description === undefined ? {} : { description: surface.description }),
      files: [...matched].sort(byteOrder)
    });
  }
  const groups = new Map<string, string[]>();
  for (const file of files) {
    if (claimed.has(file)) continue;
    const slash = file.indexOf("/");
    const group = slash === -1 ? "" : file.slice(0, slash);
    groups.set(group, [...(groups.get(group) ?? []), file]);
  }
  [...groups.keys()].sort(byteOrder).forEach((group, index) => {
    packets.push({
      id: `inventory/${index + 1}`,
      label: group === "" ? "Files at the top of the scope no threat-model surface covers" : `Files in ${group}/ no threat-model surface covers`,
      files: groups.get(group)!.sort(byteOrder)
    });
  });
  return { packets, unmatched };
}

export type ReducedFinding = JsonObject & { candidateIds: string[] };
export type Reduction = { findings: ReducedFinding[]; rejected: { candidateId: string; reason: string }[] };

/** Every candidate must be represented exactly once: in one finding's candidateIds or in rejected. */
export function checkReduction(candidateIds: readonly string[], reduction: Reduction): void {
  const known = new Set(candidateIds);
  const seen = new Set<string>();
  const claim = (id: string, where: string) => {
    if (!known.has(id)) throw new StandardScanError(`${where} names unknown candidate ${id}`);
    if (seen.has(id)) throw new StandardScanError(`${where} accounts for candidate ${id} a second time`);
    seen.add(id);
  };
  reduction.findings.forEach((finding, index) => finding.candidateIds.forEach((id) => claim(id, `findings[${index}]`)));
  reduction.rejected.forEach((row, index) => claim(row.candidateId, `rejected[${index}]`));
  const missing = candidateIds.filter((id) => !seen.has(id));
  if (missing.length > 0) throw new StandardScanError(`reduction does not account for candidates ${missing.join(", ")}`);
}

/** A reduced finding's key: its primary candidate. */
export const findingKey = (finding: ReducedFinding) => finding.candidateIds[0]!;

/** The one record a validator or attack-path analyst reported for `key`; any other entry is an error. */
export function recordFor(updates: readonly JsonObject[], field: "validation" | "attackPath", key: string): JsonObject {
  const others = updates.filter((update) => update.candidateId !== key).map((update) => update.candidateId);
  if (others.length > 0) throw new StandardScanError(`reported ${field} records for ${others.join(", ")} instead of only ${key}`);
  if (updates.length !== 1) throw new StandardScanError(`expected one ${field} record for ${key}, got ${updates.length}`);
  return updates[0]![field] as JsonObject;
}

/** A phase result: the admitted record, or why there is none. */
export type Outcome<T> = { ok: true; value: T } | { ok: false; error: string };

export type FindingOutcome =
  | { kind: "finding" }
  | { kind: "deferred"; reason: string }
  | { kind: "not_applicable"; reason: string }
  | { kind: "rejected"; reason: string }
  | { kind: "unresolved"; reason: string };

const nonBlank = (value: unknown): value is string => typeof value === "string" && value.trim() !== "";
const firstText = (...values: unknown[]) => values.find(nonBlank);

/** The final-report.md outcome of one reduced finding. `attackPath` is undefined when the phase did not run. */
export function findingOutcome(validation: Outcome<JsonObject> | undefined, attackPath: Outcome<JsonObject> | undefined): FindingOutcome {
  if (validation === undefined) return { kind: "unresolved", reason: "Validation did not run." };
  if (!validation.ok) return { kind: "unresolved", reason: `Validation did not complete: ${validation.error}` };
  const record = validation.value;
  const uncertainty = firstText(record.counterevidence_or_proof_gap, record.remaining_uncertainty, record.confidence_rationale) as string;
  switch (record.disposition) {
    case "deferred":
      return { kind: "deferred", reason: uncertainty };
    case "not_applicable":
      return { kind: "not_applicable", reason: uncertainty };
    case "suppressed":
      return { kind: "rejected", reason: uncertainty };
  }
  if (attackPath === undefined) return { kind: "unresolved", reason: "Attack-path analysis did not run." };
  if (!attackPath.ok) return { kind: "unresolved", reason: `Attack-path analysis did not complete: ${attackPath.error}` };
  const path = attackPath.value;
  if (path.decision === "deferred") return { kind: "deferred", reason: path.proof_gap as string };
  if (path.decision === "ignore") return { kind: "rejected", reason: path.severity_rationale as string };
  return { kind: "finding" };
}

const textList = (value: unknown): string[] => (Array.isArray(value) ? value.filter(nonBlank) : nonBlank(value) ? [value] : []);
const optional = (key: string, value: unknown) => (value === undefined || (Array.isArray(value) && value.length === 0) ? {} : { [key]: value });

/** A scan-draft finding from a reduced finding and its reportable validation and attack-path records. */
export function draftFinding(reduced: ReducedFinding, validation: JsonObject, attackPath: JsonObject): JsonObject {
  const { candidateIds, rootCause, codeEvidence, ...fields } = reduced;
  return {
    ruleId: fields.ruleId,
    identity: fields.identity,
    title: fields.title,
    summary: fields.summary,
    severity: { level: attackPath.severity, rationale: attackPath.severity_rationale, changeConditions: attackPath.change_conditions },
    confidence: { level: validation.confidence, rationale: validation.confidence_rationale },
    taxonomy: fields.taxonomy,
    locations: fields.locations,
    ...optional("codeEvidence", codeEvidence),
    ...optional("rootCause", rootCause),
    remediation: fields.remediation,
    validation: {
      disposition: validation.disposition,
      method: validation.method,
      evidence: validation.evidence,
      ...optional("counterEvidence", [
        ...textList(validation.counterevidence_or_proof_gap),
        ...textList(validation.remaining_uncertainty),
        ...textList(attackPath.counterevidence)
      ])
    },
    attackPath: {
      dataflow: {
        summary: attackPath.dataflow,
        ...optional("source", firstText(validation.source)),
        ...optional("sink", firstText(validation.sink))
      },
      reachability: attackPath.reachability,
      ...optional("controls", textList(validation.control)),
      ...optional("preconditions", textList(validation.preconditions)),
      impact: attackPath.impact,
      likelihood: attackPath.likelihood
    },
    provenance: { source: "local_package" },
    extensions: { candidateId: candidateIds[0], candidateIds }
  };
}

export type StandardScanResults = {
  scanId: string;
  producer: JsonObject;
  startedAt: string;
  completedAt: string;
  /** The target binding (kind, targetId, displayName, revision, snapshotDigest). */
  target: JsonObject;
  /** The inventory scope, "." for the whole repository. */
  scope: string;
  threatModel: string;
  plan: Plan;
  /** Per packet: the candidate IDs its discovery worker reported, or why it has none. */
  discovery: ReadonlyMap<string, Outcome<readonly string[]>>;
  candidates: readonly CombinedCandidate[];
  /** Undefined when discovery found no candidates, so no reducer ran. A failed reduction fails the scan (D6). */
  reduction?: Reduction;
  validations: ReadonlyMap<string, Outcome<JsonObject>>;
  attackPaths: ReadonlyMap<string, Outcome<JsonObject>>;
};

const DISPOSITION = { finding: "reported", deferred: "needs_follow_up", unresolved: "needs_follow_up", not_applicable: "not_applicable", rejected: "rejected" } as const;

/** The draft manifest, findings, and coverage of a completed Standard scan, ready for prepareScanFinalization. */
export function assembleStandardDraft(results: StandardScanResults): [JsonObject, JsonObject, JsonObject] {
  const { plan, discovery, candidates, reduction, validations, attackPaths } = results;
  const candidateById = new Map(candidates.map((candidate) => [candidate.candidate_id, candidate]));
  const packetsOf = new Map<string, string[]>();
  for (const packet of plan.packets) {
    const found = discovery.get(packet.id);
    if (found?.ok) for (const id of found.value) packetsOf.set(id, [...(packetsOf.get(id) ?? []), packet.id]);
  }
  const outcomeOf = new Map<string, FindingOutcome["kind"]>();
  const findings: JsonObject[] = [];
  const itemSurfaces: JsonObject[] = [];
  const deferred: JsonObject[] = [];
  const pathsOf = (ids: readonly string[]) => [...new Set(ids.flatMap((id) => candidateById.get(id)?.locations.map((location) => location.path) ?? []))].sort(byteOrder);
  const surfaceIdsOf = (ids: readonly string[]) => [...new Set(ids.flatMap((id) => packetsOf.get(id) ?? []))].sort(byteOrder);
  const record = (key: string, label: string, ids: readonly string[], outcome: FindingOutcome) => {
    for (const id of ids) outcomeOf.set(id, outcome.kind);
    itemSurfaces.push({
      id: key,
      label,
      disposition: DISPOSITION[outcome.kind],
      receiptRefs: [],
      ...(outcome.kind === "finding" ? {} : { notes: outcome.reason })
    });
    if (outcome.kind === "deferred" || outcome.kind === "unresolved") {
      deferred.push({ id: key, candidateId: key, reason: outcome.reason, paths: pathsOf(ids), surfaceIds: surfaceIdsOf(ids) });
    }
  };
  const candidateLabel = (id: string) => `Candidate ${id}: ${candidateById.get(id)!.summary.split("\n")[0]}`;

  if (reduction !== undefined) {
    for (const reduced of reduction.findings) {
      const key = findingKey(reduced);
      const validation = validations.get(key);
      const attackPath = attackPaths.get(key);
      const outcome = findingOutcome(validation, attackPath);
      if (outcome.kind === "finding") findings.push(draftFinding(reduced, (validation as { value: JsonObject }).value, (attackPath as { value: JsonObject }).value));
      record(key, reduced.title as string, reduced.candidateIds, outcome);
    }
    for (const rejected of reduction.rejected) {
      record(rejected.candidateId, candidateLabel(rejected.candidateId), [rejected.candidateId], { kind: "rejected", reason: rejected.reason });
    }
  }

  const packetSurfaces: JsonObject[] = plan.packets.map((packet) => {
    const found = discovery.get(packet.id);
    const base = { id: packet.id, label: packet.label, receiptRefs: [], ...optional("notes", packet.description) };
    if (found === undefined || !found.ok) {
      return { ...base, disposition: "needs_follow_up", notes: `Discovery did not complete: ${found?.error ?? "it did not run"}` };
    }
    const kinds = found.value.map((id) => outcomeOf.get(id));
    const disposition = kinds.includes("finding")
      ? "reported"
      : kinds.some((kind) => kind === "deferred" || kind === "unresolved")
        ? "needs_follow_up"
        : "no_issue_found";
    return { ...base, disposition };
  });
  const unmatchedSurfaces: JsonObject[] = plan.unmatched.map((surface) => ({
    id: `threat-model/${surface.id}`,
    label: surface.label,
    disposition: "needs_follow_up",
    receiptRefs: [],
    notes: `No inventoried file matched the threat model's paths for this surface: ${surface.paths.join(", ")}.`
  }));
  const surfaces = [...packetSurfaces, ...unmatchedSurfaces, ...itemSurfaces];
  // Every deferred entry has a needs_follow_up surface, so this also rules out deferred work.
  const complete = surfaces.every((surface) => surface.disposition !== "needs_follow_up");

  const mode = results.scope === "." ? "repository" : "scoped_path";
  const includePaths = [results.scope];
  const manifest: JsonObject = {
    documentType: "pi-security.scan-manifest",
    schemaVersion: "1.0",
    scan: {
      id: results.scanId,
      producer: results.producer,
      status: "completed",
      startedAt: results.startedAt,
      completedAt: results.completedAt,
      target: results.target,
      scope: {
        includePaths,
        excludePaths: [],
        context: "The threat model was generated during this scan by the threat_modeler role; it is not an external input."
      },
      threatModel: { summary: results.threatModel },
      coverageRef: "coverage.json",
      findingsRef: "findings.json"
    }
  };
  const findingsDocument: JsonObject = { documentType: "pi-security.findings", schemaVersion: "1.0", scanId: results.scanId, findings };
  const coverage: JsonObject = {
    documentType: "pi-security.coverage",
    schemaVersion: "1.0",
    scanId: results.scanId,
    mode,
    completeness: complete ? "complete" : "partial",
    inventoryStrategy: mode,
    includePaths,
    excludePaths: [],
    surfaces,
    explicitExclusions: [],
    deferred
  };
  return [manifest, findingsDocument, coverage];
}

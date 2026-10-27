// Finding identity: the pi-security/v1 fingerprint and the stable finding and occurrence IDs derived from it.
// Port of _fingerprint, _stable_id, and _derived_finding_identity_rows in scripts/finalize_scan_contract.py,
// held to tests/parity (vectors and finalize goldens).
import { createHash } from "node:crypto";
import { isDeepStrictEqual } from "node:util";
import {
  ContractError,
  isJsonObject,
  requireArray,
  requireObject,
  requireString,
  type JsonObject
} from "./contract-error.js";

export const FINGERPRINT_ALGORITHM = "pi-security/v1";

const SLUG = /^[a-z0-9][a-z0-9._/-]*$/;

export type Fingerprints = { algorithm: typeof FINGERPRINT_ALGORITHM; primary: string };

export type FindingIdentity = {
  /** Location of the finding in the findings document, for error messages. */
  context: string;
  finding: JsonObject;
  findingId: string;
  occurrenceId: string;
  fingerprints: Fingerprints;
};

// In u-mode a surrogate pair is one code point, so this matches only unpaired surrogates.
const LONE_SURROGATE = /\p{Cs}/u;

/** SHA-256 of UTF-8 text. Python refuses to encode lone surrogates; so does this, rather than substituting U+FFFD. */
function sha256Text(value: string): string {
  if (LONE_SURROGATE.test(value)) throw new ContractError("cannot encode text containing a lone surrogate as UTF-8");
  return createHash("sha256").update(value, "utf8").digest("hex");
}

export function fingerprint(targetId: string, finding: JsonObject): string {
  const identity = requireObject(finding, "identity", "finding");
  const anchor = requireString(identity, "anchor", "finding.identity");
  if (!SLUG.test(anchor)) {
    throw new ContractError("finding.identity.anchor: expected a stable lowercase semantic slug");
  }
  const instance = Object.hasOwn(identity, "instance") ? identity.instance : "";
  if (typeof instance !== "string") throw new ContractError("finding.identity.instance: expected a string");
  if (instance !== "" && !SLUG.test(instance)) {
    throw new ContractError("finding.identity.instance: expected a stable lowercase semantic slug");
  }
  const ruleId = requireString(finding, "ruleId", "finding");
  if (!SLUG.test(ruleId)) throw new ContractError("finding.ruleId: expected a stable lowercase rule slug");
  const material = [FINGERPRINT_ALGORITHM, targetId, ruleId, anchor, instance].join("\0");
  return `${FINGERPRINT_ALGORITHM}:sha256:${sha256Text(material)}`;
}

export function stableId(prefix: string, ...parts: string[]): string {
  return `${prefix}_${sha256Text(parts.join("\0")).slice(0, 24)}`;
}

/** Derive every finding's identity in a scan, rejecting siblings that collapse to one occurrence. */
export function deriveFindingIdentities(manifest: JsonObject, findings: JsonObject): FindingIdentity[] {
  const scan = requireObject(manifest, "scan", "manifest");
  const scanId = requireString(scan, "id", "manifest.scan");
  const targetId = requireString(requireObject(scan, "target", "manifest.scan"), "targetId", "scan.target");
  if (findings.scanId !== scanId) throw new ContractError("findings.scanId: must match manifest scan id");

  const findingIds = new Set<string>();
  const occurrenceIds = new Set<string>();
  const rows: FindingIdentity[] = [];
  requireArray(findings, "findings", "findings").forEach((finding, index) => {
    const context = `findings.findings[${index}]`;
    if (!isJsonObject(finding)) throw new ContractError(`${context}: expected an object`);
    const primary = fingerprint(targetId, finding);
    const row: FindingIdentity = {
      context,
      finding,
      findingId: stableId("csf", primary),
      occurrenceId: stableId("occ", scanId, primary),
      fingerprints: { algorithm: FINGERPRINT_ALGORITHM, primary }
    };
    rows.push(row);
    findingIds.add(row.findingId);
    if (occurrenceIds.has(row.occurrenceId)) {
      throw new ContractError(`${context}: duplicate occurrence identity; use identity.instance to split siblings`);
    }
    occurrenceIds.add(row.occurrenceId);
  });
  if (findingIds.size !== occurrenceIds.size) {
    throw new ContractError("findings: duplicate logical findings in one scan");
  }
  return rows;
}

/** Replace draft-owned identities with the derived values, in place. */
export function populateFindingIdentities(manifest: JsonObject, findings: JsonObject): void {
  for (const { finding, findingId, occurrenceId, fingerprints } of deriveFindingIdentities(manifest, findings)) {
    finding.findingId = findingId;
    finding.occurrenceId = occurrenceId;
    finding.fingerprints = fingerprints;
  }
}

/** Require sealed identities to equal their derived values. */
export function validateFindingIdentities(manifest: JsonObject, findings: JsonObject): void {
  for (const { context, finding, findingId, occurrenceId, fingerprints } of deriveFindingIdentities(manifest, findings)) {
    if (finding.findingId !== findingId) {
      throw new ContractError(`${context}.findingId: does not match derived fingerprint identity`);
    }
    if (finding.occurrenceId !== occurrenceId) {
      throw new ContractError(`${context}.occurrenceId: does not match scan occurrence identity`);
    }
    if (!isDeepStrictEqual(finding.fingerprints, fingerprints)) {
      throw new ContractError(`${context}.fingerprints: does not match derived fingerprint`);
    }
  }
}

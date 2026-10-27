// Patch-risk assessment validation: the schema, then the recommendation and workflow-label gates. Port of
// skills/assess-patch-risk/scripts/validate_patch_risk_assessment.py.
import { readFileSync } from "node:fs";
import { constants } from "node:os";
import { ContractError, isJsonObject, type JsonObject } from "./contract-error.js";
import { JSONDecodeError, pythonJsonLoads } from "./json-loads.js";
import { pythonRepr } from "./python-json.js";
import { validateAgainstSchema } from "./schema.js";

const NON_APPLICABLE = new Set(["no_live_effect", "wrong_owner", "duplicate", "superseded"]);

function rejectDuplicateKeys(pairs: [string, unknown][]): JsonObject {
  const value: JsonObject = {};
  for (const [key, item] of pairs) {
    if (Object.hasOwn(value, key)) throw new Error(`duplicate JSON object key: ${key}`);
    Object.defineProperty(value, key, { value: item, enumerable: true, writable: true, configurable: true });
  }
  return value;
}

/** str(OSError) for a failed read: "[Errno N] <strerror>: '<path>'". */
function osErrorText(error: NodeJS.ErrnoException, path: string): string {
  const messages: Record<string, string> = {
    ENOENT: "No such file or directory",
    EACCES: "Permission denied",
    EISDIR: "Is a directory",
    ENOTDIR: "Not a directory",
    ELOOP: "Too many levels of symbolic links"
  };
  const code = error.code ?? "";
  const errno = (constants.errno as Record<string, number>)[code];
  return errno !== undefined && Object.hasOwn(messages, code) ? `[Errno ${errno}] ${messages[code]}: ${pythonRepr(path)}` : error.message;
}

/** Parse assessment text read in Python's text mode (universal newlines); duplicate keys are rejected. */
export function parsePatchRiskAssessment(text: string): JsonObject {
  let value: unknown;
  try {
    value = pythonJsonLoads(text.replace(/\r\n?/g, "\n"), { objectPairsHook: rejectDuplicateKeys });
  } catch (error) {
    if (error instanceof JSONDecodeError) throw new Error(`cannot read assessment: ${error.message}`);
    throw error;
  }
  if (!isJsonObject(value)) throw new Error("assessment must be a JSON object");
  return value;
}

/** read_object: an assessment from a file, or from `stdin` text when the path is "-". */
export function readPatchRiskAssessment(path: string, stdin?: () => string): JsonObject {
  let text: string;
  try {
    text = path === "-" ? (stdin ?? (() => readFileSync(0, "utf8")))() : new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(readFileSync(path));
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === undefined) throw error;
    throw new Error(`cannot read assessment: ${osErrorText(error as NodeJS.ErrnoException, path)}`);
  }
  return parsePatchRiskAssessment(text);
}

function schemaErrors(value: JsonObject, schemaPath: string): string[] {
  try {
    validateAgainstSchema(value, schemaPath);
  } catch (error) {
    // OSError, ValueError (ContractError), and RecursionError become the error list; anything else is a bug.
    if (error instanceof ContractError || error instanceof RangeError || (error as NodeJS.ErrnoException).code !== undefined) {
      return [(error as Error).message];
    }
    throw error;
  }
  return [];
}

type Item = { [key: string]: any };

function semanticErrors(value: Item): string[] {
  const recommendation: string = value.recommendation;
  const workflowLabel: string = value.workflowLabel;
  const unknowns: Item[] = value.unknowns;
  const evidencePlan: unknown[] = value.evidencePlan;
  const boundaries: Item[] = value.materialBoundaries;
  const validation: Item[] = value.validation;
  const applicability: string = value.applicability.status;
  const criticalUnknown = unknowns.some((item) => item.decisionCritical);
  const failedValidation = validation.some((item) => item.status === "failed");
  const affirmativeFailure =
    value.regressionLikelihood.rating === "critical" || boundaries.some((item) => item.result === "contradicted") || failedValidation;
  const errors: string[] = [];

  if (recommendation === "merge") {
    if (workflowLabel !== "auto_merge_candidate" && workflowLabel !== "human_review_required") {
      errors.push("merge requires an auto-merge or human-review workflow label");
    }
    if (applicability !== "confirmed") errors.push("merge requires confirmed applicability");
    if (criticalUnknown) errors.push("merge cannot retain a decision-critical unknown");
    if (boundaries.some((item) => item.result !== "supported")) errors.push("merge requires every material boundary to be supported");
    if (failedValidation) errors.push("merge cannot retain a failed validation");
    if (evidencePlan.length > 0) errors.push("merge cannot retain an evidence plan");
  } else if (workflowLabel !== recommendation) {
    errors.push("non-merge workflow label must match the recommendation");
  }

  if (recommendation === "hold_for_evidence") {
    if (!criticalUnknown) errors.push("hold_for_evidence requires a decision-critical unknown");
    if (evidencePlan.length === 0) errors.push("hold_for_evidence requires a bounded evidence plan");
    if (affirmativeFailure) errors.push("hold_for_evidence cannot defer an established defect");
  } else if (evidencePlan.length > 0) {
    errors.push("only hold_for_evidence may include an evidence plan");
  }

  if (recommendation === "no_op") {
    if (!NON_APPLICABLE.has(applicability)) errors.push("no_op requires an established non-applicable disposition");
    if (criticalUnknown) errors.push("no_op cannot retain a decision-critical unknown");
  } else if (NON_APPLICABLE.has(applicability)) {
    errors.push("an established non-applicable disposition requires no_op");
  }

  if ((recommendation === "revise" || recommendation === "block") && !affirmativeFailure) {
    errors.push(`${recommendation} requires affirmative failure evidence`);
  }

  if (workflowLabel === "auto_merge_candidate") {
    const requirements: [string, unknown][] = [
      ["impact.rating", value.impact.rating === "low"],
      ["regressionLikelihood.rating", value.regressionLikelihood.rating === "low"],
      ["regressionProtection.rating", value.regressionProtection.rating === "strong"],
      ["regressionProtection.exactHeadChecksPassed", value.regressionProtection.exactHeadChecksPassed],
      ["recoverability.rating", value.recoverability.rating === "easy"],
      ["confidence.rating", value.confidence.rating === "high"],
      ["applicability.status", applicability === "confirmed"],
      ["affectedRuntimeRoots", value.affectedRuntimeRoots.length > 0],
      ["statusQuoRisk.rating", value.statusQuoRisk.rating !== "unknown"],
      ["autoMergeExclusions", value.autoMergeExclusions.length === 0],
      ["unknowns", unknowns.length === 0],
      ["validation", validation.every((item) => item.status === "passed")]
    ];
    for (const [field, passed] of requirements) {
      if (!passed) errors.push(`auto_merge_candidate gate failed: ${field}`);
    }
  }
  return errors;
}

/** Schema errors, or when the schema holds, every recommendation and workflow-label gate that fails. */
export function validatePatchRiskAssessment(value: JsonObject, schemaPath: string): string[] {
  const errors = schemaErrors(value, schemaPath);
  return errors.length > 0 ? errors : semanticErrors(value);
}

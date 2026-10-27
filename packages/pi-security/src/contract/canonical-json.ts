// Canonical contract JSON: parsing, safety checks, and the byte encoding sealed artifacts hash.
// Port of _loads_json, _json_bytes, _contract_json_bytes, and _require_safe_json_value in
// scripts/finalize_scan_contract.py.
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { ContractError, isJsonObject } from "./contract-error.js";
import { dumpsPython, hasLoneSurrogate, parsePythonJson, PyFloat } from "./python-json.js";

export const MAX_JSON_INTEGER = 2 ** 53 - 1;

/** json.loads with non-finite constants rejected. Integral floats stay PyFloat, so they re-encode as Python does. */
export function loadsJson(text: string): unknown {
  return parsePythonJson(text);
}

/** Reject values the contract cannot carry: lone surrogates, unsafe integers, non-finite numbers. */
export function requireSafeJsonValue(value: unknown, context: string, validateStrings = true): void {
  const visit = (item: unknown, location: string): void => {
    if (Array.isArray(item)) {
      item.forEach((child, index) => visit(child, `${location}[${index}]`));
    } else if (item instanceof PyFloat || (typeof item === "number" && !Number.isInteger(item))) {
      const number = item instanceof PyFloat ? item.value : item;
      if (!Number.isFinite(number)) throw new ContractError(`${location}: non-finite JSON numbers are not supported`);
      if (Number.isInteger(number) && Math.abs(number) > MAX_JSON_INTEGER) {
        throw new ContractError(`${location}: unsafe integer-valued JSON numbers are not supported`);
      }
    } else if (isJsonObject(item)) {
      for (const [key, child] of Object.entries(item)) {
        if (validateStrings) requireSafeJsonString(key, location);
        visit(child, `${location}.<property>`);
      }
    } else if (typeof item === "string") {
      if (validateStrings) requireSafeJsonString(item, location);
    } else if (typeof item === "number" || typeof item === "bigint") {
      if ((typeof item === "bigint" ? (item < 0n ? -item : item) : Math.abs(item)) > MAX_JSON_INTEGER) {
        throw new ContractError(`${location}: unsafe integer-valued JSON numbers are not supported`);
      }
    }
  };
  visit(value, context);
}

export function requireSafeJsonString(value: string, context: string): void {
  if (hasLoneSurrogate(value)) throw new ContractError(`${context}: expected well-formed Unicode JSON strings`);
}

/** json.dumps(payload, allow_nan=False, indent=2, sort_keys=True) + "\n", UTF-8 encoded. */
export function jsonBytes(payload: unknown): Buffer {
  let encoded: string;
  try {
    encoded = dumpsPython(payload, { indent: 2, sortKeys: true });
  } catch (error) {
    throw new ContractError(`cannot encode canonical JSON: ${(error as Error).message}`);
  }
  return Buffer.from(`${encoded}\n`, "utf8");
}

export function contractJsonBytes(relativePath: string, payload: unknown): Buffer {
  requireSafeJsonValue(payload, relativePath);
  return jsonBytes(payload);
}

/** SHA-256 of UTF-8 text; lone surrogates cannot be encoded, as in Python. */
export function sha256Text(value: string): string {
  if (hasLoneSurrogate(value)) throw new ContractError("cannot encode text containing a lone surrogate as UTF-8");
  return createHash("sha256").update(value, "utf8").digest("hex");
}

export function sha256Bytes(value: Uint8Array): string {
  return createHash("sha256").update(value).digest("hex");
}

/** _read_json: a contract JSON object from a file. */
export function readContractJsonFile(path: string): Record<string, unknown> {
  let payload: unknown;
  try {
    payload = loadsJson(readFileSync(path, "utf8"));
    requireSafeJsonValue(payload, path);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") throw new ContractError(`missing required contract artifact: ${path}`);
    if (error instanceof ContractError) throw error;
    throw new ContractError(`${path}: invalid JSON: ${(error as Error).message}`);
  }
  if (!isJsonObject(payload)) throw new ContractError(`${path}: expected a JSON object`);
  return payload;
}

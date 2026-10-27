/** A scan contract violation. Messages match scripts/finalize_scan_contract.py ContractError text. */
export class ContractError extends Error {
  override name = "ContractError";
}

export type JsonObject = { [key: string]: unknown };

export function isJsonObject(value: unknown): value is JsonObject {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

// Characters Python's str.strip() removes (str.isspace()); differs from String.prototype.trim().
const PYTHON_WHITESPACE = /^[\t\n\v\f\r\x1c-\x1f \x85\xa0\u1680\u2000-\u200a\u2028\u2029\u202f\u205f\u3000]*$/;

/** Python `not value.strip()`. */
export function isBlank(value: string): boolean {
  return PYTHON_WHITESPACE.test(value);
}

const WHITESPACE_CLASS = PYTHON_WHITESPACE.source.slice(1, -2);
const SURROUNDING_WHITESPACE = new RegExp(`^${WHITESPACE_CLASS}+|${WHITESPACE_CLASS}+$`, "g");

/** Python `value.strip()`. */
export function pythonStrip(value: string): string {
  return value.replace(SURROUNDING_WHITESPACE, "");
}

export function requireObject(payload: JsonObject, key: string, context: string): JsonObject {
  const value = payload[key];
  if (!isJsonObject(value)) throw new ContractError(`${context}.${key}: expected an object`);
  return value;
}

export function requireArray(payload: JsonObject, key: string, context: string): unknown[] {
  const value = payload[key];
  if (!Array.isArray(value)) throw new ContractError(`${context}.${key}: expected an array`);
  return value;
}

export function requireString(payload: JsonObject, key: string, context: string): string {
  const value = payload[key];
  if (typeof value !== "string" || isBlank(value)) {
    throw new ContractError(`${context}.${key}: expected a non-empty string`);
  }
  return value;
}

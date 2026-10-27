// Python json and repr semantics the scan contract depends on byte for byte.
//
// JSON.parse loses the difference between Python's int and float ("3" vs "3.0"), and JSON.stringify writes floats,
// non-ASCII text, and key order differently from json.dumps. These helpers reproduce Python's behavior.

/** A JSON number Python parsed as float. Integral floats keep their Python identity (7.0 is not 7). */
export class PyFloat {
  constructor(readonly value: number) {}
}

const INTEGER_SOURCE = /^-?\d+$/;

/**
 * json.loads: integers become numbers (bigint beyond the safe range), other numbers become PyFloat.
 * NaN and Infinity, which Python also accepts, are rejected here.
 */
export function parsePythonJson(text: string): unknown {
  return JSON.parse(text, function revive(this: unknown, _key: string, value: unknown, context?: { source?: string }) {
    if (typeof value !== "number") return value;
    const source = context?.source;
    if (source === undefined) throw new Error("JSON.parse source access is required");
    if (!INTEGER_SOURCE.test(source)) return new PyFloat(value);
    // Python ints have no negative zero: int("-0") is 0.
    if (Number.isSafeInteger(value)) return value === 0 ? 0 : value;
    return BigInt(source);
  } as (key: string, value: unknown) => unknown);
}

export function isPythonInt(value: unknown): value is number | bigint {
  return (typeof value === "number" && Number.isInteger(value)) || typeof value === "bigint";
}

/** Python's code-point string order; JavaScript's < compares UTF-16 code units. */
export function compareCodePoints(left: string, right: string): number {
  const a = [...left];
  const b = [...right];
  for (let index = 0; index < Math.min(a.length, b.length); index++) {
    const difference = a[index]!.codePointAt(0)! - b[index]!.codePointAt(0)!;
    if (difference !== 0) return difference;
  }
  return a.length - b.length;
}

/** repr() of a finite float. */
export function pythonFloatRepr(value: number): string {
  if (!Number.isFinite(value)) throw new Error("non-finite float");
  if (value === 0) return Object.is(value, -0) ? "-0.0" : "0.0";
  // toExponential() without digits gives the shortest round-trip digits, as Python's repr does.
  const [mantissa, exponentText] = value.toExponential().split("e") as [string, string];
  const negative = mantissa.startsWith("-");
  const digits = mantissa.replace("-", "").replace(".", "");
  const exponent = Number(exponentText);
  const sign = negative ? "-" : "";
  if (exponent < -4 || exponent >= 16) {
    const head = digits.length > 1 ? `${digits[0]}.${digits.slice(1)}` : digits;
    const magnitude = String(Math.abs(exponent)).padStart(2, "0");
    return `${sign}${head}e${exponent < 0 ? "-" : "+"}${magnitude}`;
  }
  if (exponent < 0) return `${sign}0.${"0".repeat(-exponent - 1)}${digits}`;
  const whole = digits.slice(0, exponent + 1).padEnd(exponent + 1, "0");
  const fraction = digits.slice(exponent + 1) || "0";
  return `${sign}${whole}.${fraction}`;
}

// In u-mode a surrogate pair is one code point, so this matches only unpaired surrogates.
const LONE_SURROGATE = /\p{Cs}/u;

export function hasLoneSurrogate(value: string): boolean {
  return LONE_SURROGATE.test(value);
}

const hex4 = (code: number) => code.toString(16).padStart(4, "0");
const U_ESCAPE = "\\" + "u";
const SHORT_ESCAPES: Record<string, string> = {
  '"': '\\"',
  "\\": "\\\\",
  "\n": "\\n",
  "\r": "\\r",
  "\t": "\\t",
  "\b": "\\b",
  "\f": "\\f"
};

function encodeString(value: string, ensureAscii: boolean): string {
  let out = '"';
  for (let index = 0; index < value.length; index++) {
    const character = value[index]!;
    const code = value.charCodeAt(index);
    const short = SHORT_ESCAPES[character];
    if (short !== undefined) out += short;
    else if (code < 0x20 || (ensureAscii && code > 0x7e)) out += U_ESCAPE + hex4(code);
    else out += character;
  }
  return `${out}"`;
}

const nonFiniteRepr = (value: number) => (Number.isNaN(value) ? "nan" : value > 0 ? "inf" : "-inf");

export type DumpsOptions = {
  sortKeys?: boolean;
  /** Python's default is true. */
  ensureAscii?: boolean;
  indent?: number;
  /** [item, key] separators; Python's default is [", ", ": "], or [",", ": "] with indent. */
  separators?: [string, string];
};

/**
 * json.dumps. Integers are numbers or bigints; floats are PyFloat or non-integral numbers. With ensureAscii false,
 * text containing lone surrogates is rejected, as Python's later UTF-8 encoding would be.
 */
export function dumpsPython(value: unknown, options: DumpsOptions = {}): string {
  const ensureAscii = options.ensureAscii ?? true;
  const indent = options.indent;
  const [itemSeparator, keySeparator] = options.separators ?? (indent === undefined ? [", ", ": "] : [",", ": "]);

  const encode = (item: unknown, level: number): string => {
    if (item === null) return "null";
    if (item === true) return "true";
    if (item === false) return "false";
    if (typeof item === "bigint") return item.toString();
    if (item instanceof PyFloat) {
      if (!Number.isFinite(item.value)) throw new Error(`Out of range float values are not JSON compliant: ${nonFiniteRepr(item.value)}`);
      return pythonFloatRepr(item.value);
    }
    if (typeof item === "number") {
      if (!Number.isFinite(item)) throw new Error(`Out of range float values are not JSON compliant: ${nonFiniteRepr(item)}`);
      return Number.isInteger(item) ? String(item) : pythonFloatRepr(item);
    }
    if (typeof item === "string") {
      if (!ensureAscii && hasLoneSurrogate(item)) throw new Error("surrogates not allowed");
      return encodeString(item, ensureAscii);
    }
    const open = indent === undefined ? "" : `\n${" ".repeat(indent * (level + 1))}`;
    const close = indent === undefined ? "" : `\n${" ".repeat(indent * level)}`;
    const separator = indent === undefined ? itemSeparator : `${itemSeparator}${open}`;
    if (Array.isArray(item)) {
      if (item.length === 0) return "[]";
      return `[${open}${item.map((element) => encode(element, level + 1)).join(separator)}${close}]`;
    }
    if (typeof item === "object") {
      const entries = Object.entries(item as Record<string, unknown>);
      if (entries.length === 0) return "{}";
      if (options.sortKeys) entries.sort(([a], [b]) => compareCodePoints(a, b));
      const body = entries.map(([key, element]) => `${encode(key, level + 1)}${keySeparator}${encode(element, level + 1)}`);
      return `{${open}${body.join(separator)}${close}}`;
    }
    throw new Error(`Object of type ${typeof item} is not JSON serializable`);
  };
  return encode(value, 0);
}

// Characters str.isprintable() rejects, except the space.
const NON_PRINTABLE = /[\p{Cc}\p{Cf}\p{Cs}\p{Co}\p{Cn}\p{Zl}\p{Zp}\p{Zs}]/u;

function stringRepr(value: string): string {
  const quote = value.includes("'") && !value.includes('"') ? '"' : "'";
  let out = quote;
  for (const character of value) {
    const code = character.codePointAt(0)!;
    if (character === quote || character === "\\") out += `\\${character}`;
    else if (character === "\t") out += "\\t";
    else if (character === "\n") out += "\\n";
    else if (character === "\r") out += "\\r";
    else if (code < 0x20 || code === 0x7f) out += `\\x${code.toString(16).padStart(2, "0")}`;
    else if (character !== " " && NON_PRINTABLE.test(character)) {
      if (code < 0x100) out += `\\x${code.toString(16).padStart(2, "0")}`;
      else if (code < 0x10000) out += U_ESCAPE + hex4(code);
      else out += "\\" + "U" + code.toString(16).padStart(8, "0");
    } else out += character;
  }
  return out + quote;
}

/** repr() of a JSON value parsed by parsePythonJson, for messages that quote Python's repr. */
export function pythonRepr(value: unknown): string {
  if (value === null || value === undefined) return "None";
  if (value === true) return "True";
  if (value === false) return "False";
  if (typeof value === "bigint") return value.toString();
  if (value instanceof PyFloat) return pythonFloatRepr(value.value);
  if (typeof value === "number") return Number.isInteger(value) ? String(value) : pythonFloatRepr(value);
  if (typeof value === "string") return stringRepr(value);
  if (Array.isArray(value)) return `[${value.map(pythonRepr).join(", ")}]`;
  const entries = Object.entries(value as Record<string, unknown>);
  return `{${entries.map(([key, item]) => `${stringRepr(key)}: ${pythonRepr(item)}`).join(", ")}}`;
}

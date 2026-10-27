// Python's json.loads (CPython 3.13 C scanner, strict mode): the same values, the same JSONDecodeError messages and
// positions, NaN and Infinity, and an object_pairs_hook called as each object closes.
//
// Positions count code points, as Python string indexes do. Values follow python-json.ts: integers are numbers
// (bigint beyond the safe range) and every other number is a PyFloat.
//
// One difference remains, shared by every port that parses into plain objects: JavaScript iterates array-index keys
// ("0", "42") before other keys, so an object mixing them is not iterated in insertion order. It can only change
// which of several errors a validator reports first.
import { PyFloat } from "./python-json.js";

/** json.JSONDecodeError: "<message>: line L column C (char P)". */
export class JSONDecodeError extends Error {
  override name = "JSONDecodeError";
  constructor(
    readonly reason: string,
    readonly position: number,
    points: string[]
  ) {
    let line = 1;
    let lastNewline = -1;
    for (let index = 0; index < position; index++) {
      if (points[index] === "\n") {
        line += 1;
        lastNewline = index;
      }
    }
    super(`${reason}: line ${line} column ${position - lastNewline} (char ${position})`);
  }
}

export type LoadsOptions = {
  /** Receives each object's [key, value] pairs in order when it closes; its return value replaces the object. */
  objectPairsHook?: (pairs: [string, unknown][]) => unknown;
};

const WHITESPACE = new Set([" ", "\t", "\n", "\r"]);
const ESCAPES: Record<string, string> = { '"': '"', "\\": "\\", "/": "/", b: "\b", f: "\f", n: "\n", r: "\r", t: "\t" };
// sys.get_int_max_str_digits() default.
const MAX_INT_DIGITS = 4300;
const HEX = /^[0-9a-fA-F]{4}$/;

/** Raised where Python's scanner raises StopIteration: the caller reports "Expecting value" there. */
class StopIteration {
  constructor(readonly position: number) {}
}

export function pythonJsonLoads(text: string, options: LoadsOptions = {}): unknown {
  const points = Array.from(text);
  const length = points.length;
  const fail = (reason: string, position: number): never => {
    throw new JSONDecodeError(reason, position, points);
  };
  const skipWhitespace = (index: number) => {
    while (index < length && WHITESPACE.has(points[index]!)) index++;
    return index;
  };
  const slice = (start: number, end: number) => points.slice(start, end).join("");

  /** scanstring: `end` is just past the opening quote. Returns the string and the index past its closing quote. */
  function scanString(end: number): [string, number] {
    const begin = end - 1;
    let out = "";
    for (;;) {
      let next = end;
      let character = "";
      for (; next < length; next++) {
        character = points[next]!;
        if (character === '"' || character === "\\") break;
        if (character.codePointAt(0)! <= 0x1f) fail("Invalid control character at", next);
      }
      if (next >= length) fail("Unterminated string starting at", begin);
      out += slice(end, next);
      next++;
      if (character === '"') return [out, next];
      if (next === length) fail("Unterminated string starting at", begin);
      const escape = points[next]!;
      if (escape !== "u") {
        end = next + 1;
        if (!Object.hasOwn(ESCAPES, escape)) fail("Invalid \\escape", end - 2);
        out += ESCAPES[escape];
        continue;
      }
      next++;
      end = next + 4;
      if (end > length) fail("Invalid \\uXXXX escape", next - 1);
      const digits = slice(next, end);
      if (!HEX.test(digits)) fail("Invalid \\uXXXX escape", end - 5);
      let code = Number.parseInt(digits, 16);
      next = end;
      if (code >= 0xd800 && code <= 0xdbff && end + 6 < length && points[next] === "\\" && points[next + 1] === "u") {
        const low = slice(next + 2, end + 6);
        if (!HEX.test(low)) fail("Invalid \\uXXXX escape", end + 1);
        const lowCode = Number.parseInt(low, 16);
        if (lowCode >= 0xdc00 && lowCode <= 0xdfff) {
          code = 0x10000 + ((code - 0xd800) << 10) + (lowCode - 0xdc00);
          end += 6;
        }
      }
      out += String.fromCharCode(...(code > 0xffff ? [0xd800 + ((code - 0x10000) >> 10), 0xdc00 + ((code - 0x10000) & 0x3ff)] : [code]));
    }
  }

  function parseObject(index: number): [unknown, number] {
    const pairs: [string, unknown][] = [];
    index = skipWhitespace(index);
    if (index >= length || points[index] !== "}") {
      for (;;) {
        if (index >= length || points[index] !== '"') fail("Expecting property name enclosed in double quotes", index);
        const [key, afterKey] = scanString(index + 1);
        index = skipWhitespace(afterKey);
        if (index >= length || points[index] !== ":") fail("Expecting ':' delimiter", index);
        index = skipWhitespace(index + 1);
        const [value, afterValue] = scanOnce(index);
        pairs.push([key, value]);
        index = skipWhitespace(afterValue);
        if (index < length && points[index] === "}") break;
        if (index >= length || points[index] !== ",") fail("Expecting ',' delimiter", index);
        const comma = index;
        index = skipWhitespace(index + 1);
        if (index < length && points[index] === "}") fail("Illegal trailing comma before end of object", comma);
      }
    }
    const value = options.objectPairsHook ? options.objectPairsHook(pairs) : Object.fromEntries(pairs);
    return [value, index + 1];
  }

  function parseArray(index: number): [unknown, number] {
    const items: unknown[] = [];
    index = skipWhitespace(index);
    if (index >= length || points[index] !== "]") {
      for (;;) {
        const [value, afterValue] = scanOnce(index);
        items.push(value);
        index = skipWhitespace(afterValue);
        if (index < length && points[index] === "]") break;
        if (index >= length || points[index] !== ",") fail("Expecting ',' delimiter", index);
        const comma = index;
        index = skipWhitespace(index + 1);
        if (index < length && points[index] === "]") fail("Illegal trailing comma before end of array", comma);
      }
    }
    return [items, index + 1];
  }

  function scanOnce(index: number): [unknown, number] {
    if (index >= length) throw new StopIteration(index);
    const character = points[index];
    if (character === '"') return scanString(index + 1);
    if (character === "{") return parseObject(index + 1);
    if (character === "[") return parseArray(index + 1);
    const ahead = (word: string) => slice(index, index + word.length) === word;
    if (character === "n" && ahead("null")) return [null, index + 4];
    if (character === "t" && ahead("true")) return [true, index + 4];
    if (character === "f" && ahead("false")) return [false, index + 5];
    if (character === "N" && ahead("NaN")) return [new PyFloat(Number.NaN), index + 3];
    if (character === "I" && ahead("Infinity")) return [new PyFloat(Number.POSITIVE_INFINITY), index + 8];
    if (character === "-" && ahead("-Infinity")) return [new PyFloat(Number.NEGATIVE_INFINITY), index + 9];
    // _match_number_unicode: ASCII digits only.
    const digit = (at: number) => at < length && points[at]! >= "0" && points[at]! <= "9";
    let end = index;
    if (points[end] === "-") end++;
    if (points[end] === "0") end++;
    else if (digit(end) && points[end] !== "0") while (digit(end)) end++;
    else throw new StopIteration(index);
    let isFloat = false;
    if (points[end] === "." && digit(end + 1)) {
      end += 2;
      while (digit(end)) end++;
      isFloat = true;
    }
    if (points[end] === "e" || points[end] === "E") {
      let exponent = end + 1;
      if (points[exponent] === "+" || points[exponent] === "-") exponent++;
      if (digit(exponent)) {
        while (digit(exponent)) exponent++;
        end = exponent;
        isFloat = true;
      }
    }
    const source = slice(index, end);
    let value: unknown;
    if (isFloat) value = new PyFloat(Number(source));
    else {
      const digits = source.replace("-", "").length;
      if (digits > MAX_INT_DIGITS) {
        throw new Error(
          `Exceeds the limit (${MAX_INT_DIGITS} digits) for integer string conversion: value has ${digits} digits; use sys.set_int_max_str_digits() to increase the limit`
        );
      }
      const number = Number(source);
      value = Number.isSafeInteger(number) ? (number === 0 ? 0 : number) : BigInt(source);
    }
    return [value, end];
  }

  if (points[0] === "\ufeff") fail("Unexpected UTF-8 BOM (decode using utf-8-sig)", 0);
  const start = skipWhitespace(0);
  let value: unknown;
  let end: number;
  try {
    [value, end] = scanOnce(start);
  } catch (error) {
    if (error instanceof StopIteration) fail("Expecting value", error.position);
    throw error;
  }
  end = skipWhitespace(end);
  if (end !== length) fail("Extra data", end);
  return value;
}

// The contract's JSON Schema subset. Port of _validate_schema_node, validate_against_schema, and
// _validate_date_time in scripts/finalize_scan_contract.py.
//
// It implements exactly what the Python validator implements: $ref, type, const, enum, minLength, pattern
// (re.fullmatch), format date-time, minimum, maximum, minItems, maxItems, uniqueItems, contains with
// min/maxContains, items, allOf/if/then (objects only), required, minProperties, properties, and
// additionalProperties. Keywords Python ignores (anyOf, oneOf, maxLength, ...) are ignored here too.
import { basename } from "node:path";
import { readContractJsonFile } from "./canonical-json.js";
import { ContractError, isJsonObject, WHITESPACE_CLASS, type JsonObject } from "./contract-error.js";
import { PyFloat, pythonRepr } from "./python-json.js";

const isNumber = (value: unknown): value is number | bigint | PyFloat =>
  typeof value === "number" || typeof value === "bigint" || value instanceof PyFloat;
const numeric = (value: number | bigint | PyFloat): number | bigint => (value instanceof PyFloat ? value.value : value);

export function schemaTypeMatches(value: unknown, expected: string): boolean {
  switch (expected) {
    case "array":
      return Array.isArray(value);
    case "boolean":
      return typeof value === "boolean";
    case "integer":
      return (typeof value === "number" && Number.isInteger(value)) || typeof value === "bigint";
    case "number":
      return isNumber(value);
    case "object":
      return isJsonObject(value);
    case "string":
      return typeof value === "string";
    case "null":
      return value === null;
    default:
      throw new ContractError(`unsupported schema type ${pythonRepr(expected)}`);
  }
}

function kind(value: unknown): string {
  if (value === null) return "null";
  if (Array.isArray(value)) return "list";
  return typeof value;
}

/** Python equality for schema values: int and float compare by value, bool never equals a number. */
export function schemaValuesEqual(left: unknown, right: unknown): boolean {
  if (isNumber(left) && isNumber(right)) {
    // Loose equality compares a bigint and a number exactly.
    // eslint-disable-next-line eqeqeq
    return numeric(left) == numeric(right);
  }
  if (kind(left) !== kind(right)) return false;
  if (isJsonObject(left) && isJsonObject(right)) {
    const leftKeys = Object.keys(left);
    const rightKeys = new Set(Object.keys(right));
    return (
      leftKeys.length === rightKeys.size &&
      leftKeys.every((key) => rightKeys.has(key)) &&
      leftKeys.every((key) => schemaValuesEqual(left[key], right[key]))
    );
  }
  if (Array.isArray(left) && Array.isArray(right)) {
    return left.length === right.length && left.every((item, index) => schemaValuesEqual(item, right[index]));
  }
  return left === right;
}

export function resolveSchemaReference(rootSchema: JsonObject, reference: string, context: string): JsonObject {
  if (reference === "#") return rootSchema;
  if (!reference.startsWith("#/")) throw new ContractError(`${context}: unsupported schema reference ${pythonRepr(reference)}`);
  let target: unknown = rootSchema;
  for (const rawPart of reference.slice(2).split("/")) {
    const part = rawPart.replaceAll("~1", "/").replaceAll("~0", "~");
    if (!isJsonObject(target) || !Object.hasOwn(target, part)) {
      throw new ContractError(`${context}: unresolved schema reference ${pythonRepr(reference)}`);
    }
    target = target[part];
  }
  if (!isJsonObject(target)) throw new ContractError(`${context}: schema reference ${pythonRepr(reference)} is not an object`);
  return target;
}

const patternCache = new Map<string, RegExp>();

/**
 * A JavaScript RegExp with re.fullmatch semantics for a Python pattern: Python's `.` matches anything but "\n", its
 * `$` also matches before a final "\n", and its `\s` is str.isspace().
 */
export function pythonFullmatchPattern(pattern: string): RegExp {
  const cached = patternCache.get(pattern);
  if (cached !== undefined) return cached;
  let out = "";
  let inClass = false;
  for (let index = 0; index < pattern.length; index++) {
    const character = pattern[index]!;
    if (character === "\\") {
      const next = pattern[index + 1] ?? "";
      index++;
      if (!inClass && next === "s") out += `[${WHITESPACE_CLASS.slice(1, -1)}]`;
      else if (!inClass && next === "S") out += `[^${WHITESPACE_CLASS.slice(1, -1)}]`;
      else if (inClass && (next === "s" || next === "S")) throw new ContractError(`unsupported schema pattern ${pythonRepr(pattern)}`);
      else out += `\\${next}`;
      continue;
    }
    if (inClass) {
      if (character === "]") inClass = false;
      out += character;
    } else if (character === "[") {
      inClass = true;
      out += character;
      // A leading "]" or "^]" is literal.
      if (pattern[index + 1] === "^") out += pattern[++index];
      if (pattern[index + 1] === "]") out += `\\${pattern[++index]}`;
    } else if (character === ".") out += "[^\\n]";
    else if (character === "$") out += "(?=\\n?$)";
    else out += character;
  }
  const compiled = new RegExp(`^(?:${out})$`);
  patternCache.set(pattern, compiled);
  return compiled;
}

const RFC3339 = /^(\d{4})-(\d{2})-(\d{2})[Tt](\d{2}):(\d{2}):(\d{2})(?:\.\d+)?(?:[Zz]|([+-])(\d{2}):(\d{2}))$/;

/** RFC 3339 with an offset, accepted exactly when Python's datetime.fromisoformat accepts it. */
export function validateDateTime(value: string, context: string): void {
  const match = RFC3339.exec(value);
  const fail = () => new ContractError(`${context}: expected an RFC 3339 timestamp`);
  if (match === null) throw fail();
  const [year, month, day, hour, minute, second] = match.slice(1, 7).map(Number) as [number, number, number, number, number, number];
  const leap = year % 4 === 0 && (year % 100 !== 0 || year % 400 === 0);
  const days = [31, leap ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
  if (year < 1 || month < 1 || month > 12 || day < 1 || day > days[month - 1]!) throw fail();
  if (hour > 23 || minute > 59 || second > 59) throw fail();
  // datetime.timezone requires a total offset strictly under 24 hours; minutes alone may exceed 59.
  if (match[7] !== undefined && Number(match[8]) * 60 + Number(match[9]) >= 24 * 60) throw fail();
}

export function validateSchemaNode(value: unknown, schema: JsonObject, context: string, rootSchema: JsonObject = schema): void {
  const reference = schema.$ref;
  if (reference !== undefined) {
    if (typeof reference !== "string") throw new ContractError(`${context}: schema reference must be a string`);
    validateSchemaNode(value, resolveSchemaReference(rootSchema, reference, context), context, rootSchema);
  }
  const expected = schema.type;
  if (Array.isArray(expected)) {
    if (!expected.some((item) => schemaTypeMatches(value, item as string))) {
      throw new ContractError(`${context}: does not match schema type ${pythonRepr(expected)}`);
    }
  } else if (typeof expected === "string" && !schemaTypeMatches(value, expected)) {
    throw new ContractError(`${context}: expected schema type ${expected}`);
  }
  if (Object.hasOwn(schema, "const") && !schemaValuesEqual(value, schema.const)) {
    throw new ContractError(`${context}: expected ${pythonRepr(schema.const)}`);
  }
  if (Object.hasOwn(schema, "enum") && !(schema.enum as unknown[]).some((candidate) => schemaValuesEqual(value, candidate))) {
    throw new ContractError(`${context}: unsupported value ${pythonRepr(value)}`);
  }
  if (typeof value === "string") {
    const minLength = schema.minLength;
    if (minLength && [...value].length < numeric(minLength as number)) throw new ContractError(`${context}: string is too short`);
    if (Object.hasOwn(schema, "pattern") && !pythonFullmatchPattern(schema.pattern as string).test(value)) {
      throw new ContractError(`${context}: string does not match schema pattern`);
    }
    if (schema.format === "date-time") validateDateTime(value, context);
  }
  if (isNumber(value)) {
    if (Object.hasOwn(schema, "minimum") && numeric(value) < numeric(schema.minimum as number)) {
      throw new ContractError(`${context}: value is below schema minimum`);
    }
    if (Object.hasOwn(schema, "maximum") && numeric(value) > numeric(schema.maximum as number)) {
      throw new ContractError(`${context}: value is above schema maximum`);
    }
  }
  if (Array.isArray(value)) {
    if (Object.hasOwn(schema, "minItems") && value.length < numeric(schema.minItems as number)) {
      throw new ContractError(`${context}: array has too few items`);
    }
    if (Object.hasOwn(schema, "maxItems") && value.length > numeric(schema.maxItems as number)) {
      throw new ContractError(`${context}: array has too many items`);
    }
    if (schema.uniqueItems === true) {
      value.forEach((item, index) => {
        if (value.slice(0, index).some((candidate) => schemaValuesEqual(item, candidate))) {
          throw new ContractError(`${context}: array items must be unique`);
        }
      });
    }
    const contains = schema.contains;
    if (isJsonObject(contains)) {
      let matches = 0;
      for (const item of value) {
        try {
          validateSchemaNode(item, contains, context, rootSchema);
          matches += 1;
        } catch (error) {
          if (!(error instanceof ContractError)) throw error;
        }
      }
      if (matches < numeric((schema.minContains as number) ?? 1)) throw new ContractError(`${context}: array contains too few matching items`);
      if (Object.hasOwn(schema, "maxContains") && matches > numeric(schema.maxContains as number)) {
        throw new ContractError(`${context}: array contains too many matching items`);
      }
    }
    const itemSchema = schema.items;
    if (isJsonObject(itemSchema)) {
      value.forEach((item, index) => validateSchemaNode(item, itemSchema, `${context}[${index}]`, rootSchema));
    }
  }
  if (isJsonObject(value)) {
    for (const itemSchema of (schema.allOf as JsonObject[] | undefined) ?? []) validateSchemaNode(value, itemSchema, context, rootSchema);
    const condition = schema.if;
    if (isJsonObject(condition)) {
      let holds = true;
      try {
        validateSchemaNode(value, condition, context, rootSchema);
      } catch (error) {
        if (!(error instanceof ContractError)) throw error;
        holds = false;
      }
      if (holds && isJsonObject(schema.then)) validateSchemaNode(value, schema.then, context, rootSchema);
    }
    for (const key of (schema.required as string[] | undefined) ?? []) {
      if (!Object.hasOwn(value, key)) throw new ContractError(`${context}.${key}: missing required schema property`);
    }
    if (Object.hasOwn(schema, "minProperties") && Object.keys(value).length < numeric(schema.minProperties as number)) {
      throw new ContractError(`${context}: object has too few properties`);
    }
    const properties = isJsonObject(schema.properties) ? schema.properties : {};
    const additionalProperties = Object.hasOwn(schema, "additionalProperties") ? schema.additionalProperties : true;
    for (const [key, item] of Object.entries(value)) {
      const itemSchema = Object.hasOwn(properties, key) ? properties[key] : undefined;
      if (isJsonObject(itemSchema)) validateSchemaNode(item, itemSchema, `${context}.${key}`, rootSchema);
      else if (additionalProperties === false) throw new ContractError(`${context}.${key}: unexpected schema property`);
      else if (isJsonObject(additionalProperties)) validateSchemaNode(item, additionalProperties, `${context}.${key}`, rootSchema);
    }
  }
}

const schemaCache = new Map<string, JsonObject>();

/** Validate a payload against a schema file; the context is the file name without its last extension. */
export function validateAgainstSchema(payload: JsonObject, schemaPath: string): void {
  let schema = schemaCache.get(schemaPath);
  if (schema === undefined) {
    schema = readContractJsonFile(schemaPath) as JsonObject;
    schemaCache.set(schemaPath, schema);
  }
  const name = basename(schemaPath);
  const dot = name.lastIndexOf(".");
  validateSchemaNode(payload, schema, dot > 0 ? name.slice(0, dot) : name, schema);
}

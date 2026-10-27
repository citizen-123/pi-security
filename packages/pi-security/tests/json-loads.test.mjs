// Differential test of src/contract/json-loads.ts against the running Python's json.loads: every prefix of each seed
// document, plus single-character insertions, deletions, and replacements, must give the same value (int and float
// kept apart) or the same exception type and message, with and without a duplicate-rejecting object_pairs_hook.
// Object keys are compared in JavaScript iteration order (array-index keys first), the one known difference.
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { resolve } from "node:path";
import { test } from "node:test";
import { build } from "esbuild";

const packageRoot = resolve(import.meta.dirname, "..");
const bundled = await build({
  bundle: true,
  stdin: {
    contents: 'export * from "./src/contract/json-loads.ts"; export { PyFloat, pythonFloatRepr } from "./src/contract/python-json.ts";',
    resolveDir: packageRoot,
  },
  format: "esm",
  platform: "node",
  write: false,
});
const { pythonJsonLoads, PyFloat, pythonFloatRepr } = await import(
  `data:text/javascript;base64,${Buffer.from(bundled.outputFiles[0].contents).toString("base64")}`
);

const SURROGATE_ESCAPE = "\\" + "ud83d" + "\\" + "ude00";
const SEEDS = [
  '{"a": [1, 2.5, -0, -0.0, 1e3, 1E-2, 10000000000000000000000, true, false, null], "b": {"c": "d"}}',
  ' [ "x\\"y\\\\z\\/\\b\\f\\n\\r\\t", "' + SURROGATE_ESCAPE + '", "\\u00e9\\ud800x" ] ',
  '{"dup": 1, "dup": 2, "n": {"k": 1, "k": {"k": 3}}}',
  '[NaN, Infinity, -Infinity, 0, 0.1, 123456789012345678901234567890.5]',
  '{"key": "caf\u00e9 \u{1F511} \u3000"}\n\n',
  "{}",
  "[]",
  '""',
  "1.5e+400",
];
const ALPHABET = ['"', "\\", "{", "}", "[", "]", ",", ":", " ", "\n", "0", "1", "-", ".", "e", "u", "a", "\x01", "\x1f", "\f", "\v", "\ufeff", "\u{1F511}"];

function corpus() {
  const out = new Set();
  for (const seed of SEEDS) {
    const points = Array.from(seed);
    for (let index = 0; index <= points.length; index++) {
      out.add(points.slice(0, index).join(""));
      if (index < points.length) out.add([...points.slice(0, index), ...points.slice(index + 1)].join(""));
      for (const character of ALPHABET) {
        out.add([...points.slice(0, index), character, ...points.slice(index)].join(""));
        if (index < points.length) out.add([...points.slice(0, index), character, ...points.slice(index + 1)].join(""));
      }
    }
  }
  out.add("1".repeat(4300));
  out.add("-" + "1".repeat(4300));
  out.add("1".repeat(4301));
  out.add("-" + "1".repeat(4301));
  out.add("[" + "1".repeat(4301) + "]");
  out.add("\ufeff[]");
  return [...out];
}

const PYTHON = `
import json, math, sys
def reject(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError(f"duplicate JSON object key: {key}")
        value[key] = item
    return value
def tag(value):
    if isinstance(value, bool) or value is None or isinstance(value, str):
        return value
    if isinstance(value, int):
        return {"$i": str(value)}
    if isinstance(value, float):
        return {"$f": repr(value)}
    if isinstance(value, list):
        return [tag(item) for item in value]
    # JavaScript objects iterate array-index keys first, ascending; see the json-loads.ts header.
    index_keys = sorted((key for key in value if key.isascii() and key.isdigit() and (key == "0" or key[0] != "0") and int(key) < 2**32 - 1), key=int)
    ordered = index_keys + [key for key in value if key not in index_keys]
    return {"$o": [[key, tag(value[key])] for key in ordered]}
results = []
for text in json.load(sys.stdin):
    row = []
    for hook in (None, reject):
        try:
            row.append({"value": tag(json.loads(text, object_pairs_hook=hook))})
        except (ValueError, RecursionError) as error:
            row.append({"error": [type(error).__name__, str(error)]})
    results.append(row)
print(json.dumps(results))
`;

function tag(value) {
  if (value === null || typeof value === "boolean" || typeof value === "string") return value;
  if (typeof value === "number" || typeof value === "bigint") return { $i: String(value) };
  if (value instanceof PyFloat) {
    const number = value.value;
    return { $f: Number.isNaN(number) ? "nan" : number === Infinity ? "inf" : number === -Infinity ? "-inf" : pythonFloatRepr(number) };
  }
  if (Array.isArray(value)) return value.map(tag);
  return { $o: Object.entries(value).map(([key, item]) => [key, tag(item)]) };
}

function reject(pairs) {
  const value = {};
  for (const [key, item] of pairs) {
    if (Object.hasOwn(value, key)) throw new Error(`duplicate JSON object key: ${key}`);
    value[key] = item;
  }
  return value;
}

test("pythonJsonLoads matches json.loads on every prefix and single-character edit of the seeds", () => {
  const texts = corpus();
  const python = spawnSync(process.env.PYTHON ?? "python3", ["-I", "-c", PYTHON], {
    input: JSON.stringify(texts),
    encoding: "utf8",
    maxBuffer: 1 << 30,
  });
  assert.equal(python.status, 0, python.stderr);
  const expected = JSON.parse(python.stdout);
  texts.forEach((text, index) => {
    const actual = [undefined, reject].map((hook) => {
      try {
        return { value: tag(pythonJsonLoads(text, hook ? { objectPairsHook: hook } : {})) };
      } catch (error) {
        const type = error.name === "JSONDecodeError" ? "JSONDecodeError" : "ValueError";
        return { error: [type, error.message] };
      }
    });
    assert.deepEqual(actual, expected[index], `input ${JSON.stringify(text).slice(0, 200)}`);
  });
  assert.ok(texts.length > 5000, `corpus has ${texts.length} inputs`);
});

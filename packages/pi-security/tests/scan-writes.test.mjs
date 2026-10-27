// Differential test of src/contract/scan-writes.ts: each scenario builds the same synthetic directory twice, runs the
// Python function from scripts/finalize_scan_contract.py on one copy and the TypeScript port on the other, and
// requires the same outcome (ContractError message, or success) and the same resulting tree, modes included.
// Swaps during a write are covered by tests/test_finalize_scan_contract.py on the Python side; the port's held
// directories rely on /proc/self/fd on Linux (see the module header).
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { lstatSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, readlinkSync, realpathSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { test } from "node:test";
import { build } from "esbuild";

const packageRoot = resolve(import.meta.dirname, "..");
const bundled = await build({
  bundle: true,
  stdin: { contents: 'export * from "./src/contract/scan-writes.ts";', resolveDir: packageRoot },
  format: "esm",
  platform: "node",
  write: false,
});
const writes = await import(`data:text/javascript;base64,${Buffer.from(bundled.outputFiles[0].contents).toString("base64")}`);

const PYTHON_RUNNER = `
import importlib.util, json, sys
from pathlib import Path
spec = importlib.util.spec_from_file_location("finalize_scan_contract", sys.argv[1])
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
call = json.loads(sys.argv[2])
args = [bytes(arg["bytes"], "utf-8") if isinstance(arg, dict) else arg for arg in call["args"]]
args = [Path(arg) if index in call["paths"] else arg for index, arg in enumerate(args)]
try:
    getattr(module, call["function"])(*args, **call.get("kwargs", {}))
    print(json.dumps({"ok": True}))
except module.ContractError as error:
    print(json.dumps({"error": str(error)}))
except OSError as error:
    print(json.dumps({"error": type(error).__name__}))
`;

function runPython(call) {
  const python = process.env.PYTHON ?? "python3";
  const result = spawnSync(python, ["-I", "-c", PYTHON_RUNNER, join(packageRoot, "scripts/finalize_scan_contract.py"), JSON.stringify(call)], {
    encoding: "utf8",
  });
  assert.equal(result.status, 0, result.stderr);
  return JSON.parse(result.stdout);
}

const PORTS = {
  write_scan_local_bytes: (scanDir, relativePath, payload, kwargs) =>
    writes.writeScanLocalBytes(scanDir, relativePath, payload, { externalName: kwargs?.external_name ?? false }),
  write_external_output_bytes: (output, payload) => writes.writeExternalOutputBytes(output, payload),
  _remove_scan_local_file_if_exists: (scanDir, relativePath) => writes.removeScanLocalFileIfExists(scanDir, relativePath),
};

function runPort(call) {
  const args = call.args.map((arg) => (typeof arg === "object" ? Buffer.from(arg.bytes, "utf8") : arg));
  try {
    PORTS[call.function](...args, call.kwargs);
    return { ok: true };
  } catch (error) {
    if (error.name === "ContractError") return { error: error.message };
    return { error: { ENOENT: "FileNotFoundError", ENOTDIR: "NotADirectoryError", ELOOP: "OSError" }[error.code] ?? error.code };
  }
}

function tree(root, prefix = "") {
  const entries = {};
  for (const name of readdirSync(join(root, prefix)).sort()) {
    const relative = prefix ? `${prefix}/${name}` : name;
    const full = join(root, relative);
    const metadata = lstatSync(full);
    const mode = (metadata.mode & 0o777).toString(8);
    if (metadata.isSymbolicLink()) entries[relative] = { link: readlinkSync(full) };
    else if (metadata.isDirectory()) Object.assign(entries, { [relative]: { dir: mode } }, tree(root, relative));
    else entries[relative] = { file: readFileSync(full, "utf8"), mode };
  }
  return entries;
}

// Each scenario lays out a sandbox holding scan/ and outside/, then names the call; "$scan" and "$sandbox" are
// replaced with absolute paths.
const SCENARIOS = {
  "writes a new file": [() => {}, ["write_scan_local_bytes", "$scan", "a.json", "{}"]],
  "creates missing parent directories": [() => {}, ["write_scan_local_bytes", "$scan", "nested/deep/a.json", "{}"]],
  "replaces an existing regular file": [(s) => writeFileSync(join(s, "scan/a.json"), "old"), ["write_scan_local_bytes", "$scan", "a.json", "new"]],
  "refuses a symlink target": [
    (s) => {
      writeFileSync(join(s, "scan/real.json"), "real");
      symlinkSync("real.json", join(s, "scan/a.json"));
    },
    ["write_scan_local_bytes", "$scan", "a.json", "new"],
  ],
  "refuses a dangling symlink target": [(s) => symlinkSync("../outside/new.json", join(s, "scan/a.json")), ["write_scan_local_bytes", "$scan", "a.json", "x"]],
  "refuses a directory target": [(s) => mkdirSync(join(s, "scan/a.json")), ["write_scan_local_bytes", "$scan", "a.json", "x"]],
  "refuses a symlinked parent": [(s) => symlinkSync("../outside", join(s, "scan/exports"), "dir"), ["write_scan_local_bytes", "$scan", "exports/results.sarif", "x"]],
  "refuses a file as a parent": [(s) => writeFileSync(join(s, "scan/exports"), "file"), ["write_scan_local_bytes", "$scan", "exports/results.sarif", "x"]],
  "refuses an escaping path": [() => {}, ["write_scan_local_bytes", "$scan", "../outside/a.json", "x"]],
  "refuses a dot-dot component": [() => {}, ["write_scan_local_bytes", "$scan", "a/../b.json", "x"]],
  "refuses a Windows device name": [() => {}, ["write_scan_local_bytes", "$scan", "con.json", "x"]],
  "refuses an absolute path": [() => {}, ["write_scan_local_bytes", "$scan", "/tmp/a.json", "x"]],
  "refuses a symlinked scan directory": [(s) => symlinkSync("scan", join(s, "alias"), "dir"), ["write_scan_local_bytes", "$sandbox/alias", "a.json", "x"]],
  "refuses a missing scan directory": [() => {}, ["write_scan_local_bytes", "$sandbox/missing", "a.json", "x"]],
  "checks the scan directory before the path": [() => {}, ["write_scan_local_bytes", "$sandbox/missing", "../a.json", "x"]],
  "external name with dot components": [() => {}, ["write_scan_local_bytes", "$scan", "./out/./a.json", "x", { external_name: true }]],
  "external name with dot-dot": [() => {}, ["write_scan_local_bytes", "$scan", "out/../a.json", "x", { external_name: true }]],
  "external name that is only a dot": [() => {}, ["write_scan_local_bytes", "$scan", ".", "x", { external_name: true }]],
  "external output in an existing directory": [() => {}, ["write_external_output_bytes", "$sandbox/outside/out.sarif", "x"]],
  "external output with missing parents": [() => {}, ["write_external_output_bytes", "$sandbox/outside/a/b/out.sarif", "x"]],
  "external output normalizes dot-dot lexically": [() => {}, ["write_external_output_bytes", "$sandbox/outside/a/../out.csv", "x"]],
  "external output through a symlinked parent": [
    (s) => symlinkSync("outside", join(s, "linked"), "dir"),
    ["write_external_output_bytes", "$sandbox/linked/out.sarif", "x"],
  ],
  "external output under a file": [(s) => writeFileSync(join(s, "outside/file"), "f"), ["write_external_output_bytes", "$sandbox/outside/file/out.sarif", "x"]],
  "external output onto a symlink": [(s) => symlinkSync("target", join(s, "outside/out.sarif")), ["write_external_output_bytes", "$sandbox/outside/out.sarif", "x"]],
  "removes a regular file": [(s) => writeFileSync(join(s, "scan/report.html"), "<p>"), ["_remove_scan_local_file_if_exists", "$scan", "report.html"]],
  "removes a symlink without following it": [
    (s) => {
      writeFileSync(join(s, "outside/keep.html"), "keep");
      symlinkSync("../outside/keep.html", join(s, "scan/report.html"));
    },
    ["_remove_scan_local_file_if_exists", "$scan", "report.html"],
  ],
  "ignores a missing file": [() => {}, ["_remove_scan_local_file_if_exists", "$scan", "report.html"]],
  "refuses to remove a directory": [(s) => mkdirSync(join(s, "scan/report.html")), ["_remove_scan_local_file_if_exists", "$scan", "report.html"]],
  "fails on a missing parent": [() => {}, ["_remove_scan_local_file_if_exists", "$scan", "missing/report.html"]],
  "fails on a symlinked parent": [(s) => symlinkSync("../outside", join(s, "scan/dir"), "dir"), ["_remove_scan_local_file_if_exists", "$scan", "dir/report.html"]],
};

const PATH_ARGS = { write_scan_local_bytes: [0], write_external_output_bytes: [0], _remove_scan_local_file_if_exists: [0] };

function sandbox(setup) {
  const root = realpathSync(mkdtempSync(join(tmpdir(), "pi-security-scan-writes-")));
  mkdirSync(join(root, "scan"));
  mkdirSync(join(root, "outside"));
  setup(root);
  return root;
}

for (const [name, [setup, [fn, ...rawArgs]]] of Object.entries(SCENARIOS)) {
  test(`scan-local writes match Python: ${name}`, { skip: process.platform === "win32" ? "POSIX symlink fixtures" : false }, () => {
    const outcomes = [];
    for (const run of [runPython, runPort]) {
      const root = sandbox(setup);
      try {
        const kwargs = typeof rawArgs.at(-1) === "object" ? rawArgs.at(-1) : undefined;
        const positional = (kwargs ? rawArgs.slice(0, -1) : rawArgs).map((arg, index) => {
          const text = arg.replace("$scan", join(root, "scan")).replace("$sandbox", root);
          return index === 2 || (fn === "write_external_output_bytes" && index === 1) ? { bytes: text } : text;
        });
        const outcome = run({ function: fn, args: positional, paths: PATH_ARGS[fn], kwargs });
        outcomes.push({ outcome, tree: tree(root) });
      } finally {
        rmSync(root, { recursive: true, force: true });
      }
    }
    assert.deepEqual(outcomes[1], outcomes[0]);
  });
}

// Read helpers, through the same differential runner: outcome only (Python's parser detail after "invalid JSON:"
// is not reproduced, so those messages compare by prefix).
const reads = await import(
  `data:text/javascript;base64,${Buffer.from(
    (
      await build({
        bundle: true,
        stdin: { contents: 'export * from "./src/contract/scan-files.ts";', resolveDir: packageRoot },
        format: "esm",
        platform: "node",
        write: false,
      })
    ).outputFiles[0].contents,
  ).toString("base64")}`
);

const READ_SCENARIOS = {
  "an object": '{"a": 1.0, "b": [1, 2]}',
  "a byte order mark": "\ufeff{}",
  "an array": "[1]",
  "invalid UTF-8": Buffer.from([0x7b, 0xff, 0x7d]),
  "NaN": '{"a": NaN}',
  "a lone surrogate (strings are not checked)": '{"a": "\\ud800"}',
  "an unsafe integer": '{"a": 9007199254740993}',
};

for (const [name, content] of Object.entries(READ_SCENARIOS)) {
  test(`scan-local JSON reads match Python: ${name}`, () => {
    const root = sandbox((s) => writeFileSync(join(s, "scan/doc.json"), content));
    try {
      const script = `
import importlib.util, hashlib, json, sys
from pathlib import Path
spec = importlib.util.spec_from_file_location("f", sys.argv[1]); m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
try:
    payload, raw = m._read_scan_local_json_bytes(Path(sys.argv[2]), "doc.json", "doc.json")
    print(json.dumps({"payload": json.dumps(payload, sort_keys=True), "sha": m._sha256_scan_local_file(Path(sys.argv[2]), "doc.json", "doc.json")}))
except m.ContractError as error:
    print(json.dumps({"error": str(error)}))
`;
      const python = spawnSync(process.env.PYTHON ?? "python3", ["-I", "-c", script, join(packageRoot, "scripts/finalize_scan_contract.py"), join(root, "scan")], { encoding: "utf8" });
      assert.equal(python.status, 0, python.stderr);
      const expected = JSON.parse(python.stdout);
      let actual;
      try {
        const { payload } = reads.readScanLocalJsonBytes(join(root, "scan"), "doc.json", "doc.json");
        actual = { sha: reads.sha256ScanLocalFile(join(root, "scan"), "doc.json", "doc.json"), keys: Object.keys(payload).sort() };
      } catch (error) {
        actual = { error: error.message };
      }
      if (expected.error !== undefined) {
        assert.equal(actual.error?.startsWith(expected.error.split(": invalid JSON:")[0]), true, `${actual.error} vs ${expected.error}`);
        assert.equal(actual.error.includes(": invalid JSON:"), expected.error.includes(": invalid JSON:"));
      } else {
        assert.equal(actual.sha, expected.sha);
        assert.deepEqual(actual.keys, Object.keys(JSON.parse(expected.payload)).sort());
      }
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });
}

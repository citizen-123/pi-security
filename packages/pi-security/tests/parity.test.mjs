// Holds TypeScript ports of the Python scripts to the goldens recorded by tests/parity/oracle.py and the vectors
// recorded by tests/parity/record_vectors.py. See tests/parity/README.md.
//
// PI_SECURITY_PARITY_SELF_TEST=python routes every tool to its Python script instead, which checks this harness
// (work directory layout, Git fixtures, symlinks, normalization) against the goldens without any port.
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { cpSync, existsSync, lstatSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, readlinkSync, rmSync, symlinkSync, unlinkSync, writeFileSync, appendFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, relative, resolve, sep } from "node:path";
import { test } from "node:test";
import { functions, parseVectorLine, tools } from "./parity/ports.mjs";

const parityDir = resolve(import.meta.dirname, "parity");
const packageRoot = resolve(import.meta.dirname, "..");
const casesDir = join(parityDir, "cases");
const goldensDir = join(parityDir, "goldens");
const vectorsDir = join(parityDir, "vectors");

const PYTHON_SCRIPTS = {
  finalize_scan_contract: "scripts/finalize_scan_contract.py",
  validate_scan_contract: "scripts/validate_scan_contract.py",
  normalize_candidates: "scripts/normalize_candidates.py",
  generate_in_scope_files: "scripts/generate_in_scope_files.py",
  config_preflight: "scripts/config_preflight.py",
  validate_patch_risk_assessment: "skills/assess-patch-risk/scripts/validate_patch_risk_assessment.py",
};

const selfTest = process.env.PI_SECURITY_PARITY_SELF_TEST === "python";
const activeTools = selfTest
  ? Object.fromEntries(
      Object.entries(PYTHON_SCRIPTS).map(([name, script]) => [
        name,
        async (args, { cwd }) => {
          const python = process.env.PYTHON ?? "python3";
          const result = spawnSync(python, ["-I", join(packageRoot, script), ...args], {
            cwd,
            env: { ...process.env, PYTHONDONTWRITEBYTECODE: "1", PYTHONUTF8: "1", TZ: "UTC", LC_ALL: "C.UTF-8" },
          });
          return { status: result.status === 0 ? "ok" : "rejected", stdout: result.stdout };
        },
      ]),
    )
  : tools;

// Must match GIT_ENV and build_git in tests/parity/oracle.py.
const GIT_ENV = {
  GIT_AUTHOR_NAME: "Parity Author",
  GIT_AUTHOR_EMAIL: "parity@example.invalid",
  GIT_COMMITTER_NAME: "Parity Author",
  GIT_COMMITTER_EMAIL: "parity@example.invalid",
  GIT_CONFIG_NOSYSTEM: "1",
  GIT_CONFIG_GLOBAL: process.platform === "win32" ? "NUL" : "/dev/null",
};

function git(repo, args, date) {
  const env = { ...process.env, ...GIT_ENV };
  if (date !== undefined) env.GIT_AUTHOR_DATE = env.GIT_COMMITTER_DATE = date;
  const result = spawnSync("git", ["-C", repo, ...args], { env, encoding: "utf8" });
  if (result.status !== 0) throw new Error(`git ${args.join(" ")}: ${result.stderr}`);
}

function applyFiles(repo, change) {
  for (const [path, text] of Object.entries(change.write ?? {})) {
    mkdirSync(dirname(join(repo, path)), { recursive: true });
    writeFileSync(join(repo, path), text, "utf8");
  }
  for (const [encoded, text] of Object.entries(change.write_raw ?? {})) {
    const path = Buffer.concat([Buffer.from(repo), Buffer.from("/"), Buffer.from(encoded, "base64")]);
    mkdirSync(dirname(path.toString("latin1")) === "." ? repo : Buffer.from(dirname(path.toString("latin1")), "latin1"), { recursive: true });
    writeFileSync(path, text, "utf8");
  }
  for (const [path, encoded] of Object.entries(change.write_bytes ?? {})) {
    mkdirSync(dirname(join(repo, path)), { recursive: true });
    writeFileSync(join(repo, path), Buffer.from(encoded, "base64"));
  }
  for (const path of change.delete ?? []) unlinkSync(join(repo, path));
}

function buildGit(work, spec) {
  const repo = join(work, spec.path);
  mkdirSync(repo, { recursive: true });
  git(repo, ["init", "-q", "-b", "main"]);
  (spec.commits ?? []).forEach((commit, index) => {
    applyFiles(repo, commit);
    git(repo, ["add", "-A"]);
    git(repo, ["commit", "-q", "-m", commit.message ?? `commit ${index}`], `2026-01-01T00:00:${String(index).padStart(2, "0")}Z`);
  });
  if (spec.worktree) {
    applyFiles(repo, spec.worktree);
    for (const path of spec.worktree.stage ?? []) git(repo, ["add", "--", path]);
  }
}

const normalize = (data, work) => Buffer.from(Buffer.from(data).toString("latin1").split(work).join("<WORK>"), "latin1");

// Must match golden_name in tests/parity/oracle.py.
function goldenName(relativeBytes) {
  try {
    return new TextDecoder("utf-8", { fatal: true }).decode(relativeBytes);
  } catch {
    let escaped = "";
    for (const byte of relativeBytes) escaped += byte < 0x80 && byte !== 0x25 ? String.fromCharCode(byte) : `%${byte.toString(16).toUpperCase().padStart(2, "0")}`;
    return `${escaped}.rawpath`;
  }
}

function captureTree(work) {
  const files = new Map();
  const walk = (directory, prefix) => {
    const entries = readdirSync(directory, { encoding: "buffer" }).sort(Buffer.compare);
    for (const name of entries) {
      if (name.equals(Buffer.from(".git"))) continue;
      const path = Buffer.concat([directory, Buffer.from(sep), name]);
      const rel = prefix.length === 0 ? name : Buffer.concat([prefix, Buffer.from("/"), name]);
      const stat = lstatSync(path);
      if (stat.isSymbolicLink()) files.set(`tree/${goldenName(rel)}.symlink`, readlinkSync(path, { encoding: "buffer" }));
      else if (stat.isDirectory()) walk(path, rel);
      else if (stat.isFile()) files.set(`tree/${goldenName(rel)}`, normalize(readFileSync(path), work));
    }
  };
  walk(Buffer.from(work), Buffer.alloc(0));
  return new Map([...files].sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0)));
}

function readGolden(directory) {
  const files = new Map();
  const walk = (current) => {
    for (const name of readdirSync(current).sort()) {
      const path = join(current, name);
      if (lstatSync(path).isDirectory()) walk(path);
      else files.set(relative(directory, path).split(sep).join("/"), readFileSync(path));
    }
  };
  if (existsSync(directory)) walk(directory);
  return files;
}

function listCases() {
  const found = [];
  const walk = (directory) => {
    if (existsSync(join(directory, "case.json"))) {
      found.push(relative(casesDir, directory).split(sep).join("/"));
      return;
    }
    for (const name of readdirSync(directory).sort()) {
      if (lstatSync(join(directory, name)).isDirectory()) walk(join(directory, name));
    }
  };
  walk(casesDir);
  return found;
}

const caseNames = listCases();

test("parity: every case has goldens and every golden has a case", () => {
  const goldenNames = existsSync(goldensDir) ? listGoldenNames() : [];
  assert.deepEqual(goldenNames, caseNames);
});

function listGoldenNames() {
  const found = [];
  const walk = (directory) => {
    if (existsSync(join(directory, "result.json"))) {
      found.push(relative(goldensDir, directory).split(sep).join("/"));
      return;
    }
    for (const name of readdirSync(directory).sort()) {
      if (lstatSync(join(directory, name)).isDirectory()) walk(join(directory, name));
    }
  };
  walk(goldensDir);
  return found;
}

for (const name of caseNames) {
  const caseDir = join(casesDir, name);
  const spec = JSON.parse(readFileSync(join(caseDir, "case.json"), "utf8"));
  const needed = [...new Set(spec.steps.map((step) => step.argv[0]).filter((tool) => tool !== "parity_append"))];
  const missing = needed.filter((tool) => !(tool in activeTools));
  test(`parity case ${name}`, { skip: missing.length > 0 ? `no TypeScript port for ${missing.join(", ")}` : false }, async () => {
    const temporary = mkdtempSync(join(tmpdir(), "pi-security-parity-"));
    try {
      const work = join(temporary, "work");
      cpSync(join(caseDir, "input"), work, { recursive: true });
      mkdirSync(work, { recursive: true });
      if (spec.git) buildGit(work, spec.git);
      for (const [path, target] of Object.entries(spec.symlinks ?? {})) {
        mkdirSync(dirname(join(work, path)), { recursive: true });
        symlinkSync(target, join(work, path));
      }
      const substitute = (value) => value.replaceAll("{work}", work).replaceAll("{schemas}", join(packageRoot, "schemas"));
      const steps = [];
      for (const step of spec.steps) {
        const [tool, ...args] = step.argv.map(substitute);
        if (tool === "parity_append") {
          appendFileSync(args[0], args[1], "utf8");
          steps.push({ status: "ok" });
          continue;
        }
        const outcome = await activeTools[tool](args, { cwd: work });
        const record = { status: outcome.status };
        if (step.stdout === "compare") record.stdout = normalize(outcome.stdout ?? "", work).toString("utf8");
        steps.push(record);
        if (outcome.status !== "ok") break;
      }
      const golden = readGolden(join(goldensDir, name));
      const expected = JSON.parse(golden.get("result.json").toString("utf8"));
      // Error text is recorded for reference only; ports reproduce status and compared stdout.
      assert.deepEqual(steps, expected.steps.map(({ stderr, ...rest }) => rest), "step results");
      const actualTree = captureTree(work);
      const expectedTree = new Map([...golden].filter(([key]) => key.startsWith("tree/")));
      assert.deepEqual([...actualTree.keys()].sort(), [...expectedTree.keys()].sort(), "files left in the work directory");
      for (const [key, bytes] of expectedTree) {
        assert.ok(actualTree.get(key).equals(bytes), `${key} differs from the golden`);
      }
    } finally {
      rmSync(temporary, { recursive: true, force: true });
    }
  });
}

// ─── Recorded vectors ────────────────────────────────────────────────────────

// Plain JSON objects only: PyFloat values from parseVectorLine pass through untouched.
const isPlainObject = (value) => value !== null && typeof value === "object" && Object.getPrototypeOf(value) === Object.prototype;

const decode = (value) => {
  if (Array.isArray(value)) return value.map(decode);
  if (isPlainObject(value)) {
    if (Object.keys(value).length === 1 && typeof value.$bytes === "string") return Buffer.from(value.$bytes, "base64");
    return Object.fromEntries(Object.entries(value).map(([key, item]) => [key, decode(item)]));
  }
  return value;
};

const encode = (value) => {
  if (value instanceof Uint8Array) return { $bytes: Buffer.from(value).toString("base64") };
  if (Array.isArray(value)) return value.map(encode);
  if (isPlainObject(value)) return Object.fromEntries(Object.entries(value).map(([key, item]) => [key, encode(item)]));
  return value;
};

const vectorFiles = existsSync(vectorsDir) ? readdirSync(vectorsDir).filter((name) => name.endsWith(".jsonl")).sort() : [];
for (const file of vectorFiles) {
  const name = file.slice(0, -".jsonl".length);
  const port = functions[name];
  test(`parity vectors ${name}`, { skip: port === undefined ? "no TypeScript port" : false }, () => {
    const vectors = readFileSync(join(vectorsDir, file), "utf8").split("\n").filter(Boolean).map(parseVectorLine);
    for (const [index, vector] of vectors.entries()) {
      const args = decode(vector.args);
      if (vector.error !== undefined) {
        assert.throws(
          () => port(args),
          (error) => vector.error.type !== "ContractError" || error.message === vector.error.message,
          `vector ${index} must throw ${vector.error.type}: ${vector.error.message}`,
        );
      } else {
        assert.deepEqual(encode(port(args)), vector.result, `vector ${index}`);
      }
    }
  });
}

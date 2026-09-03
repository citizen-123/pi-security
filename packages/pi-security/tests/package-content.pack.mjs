import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { mkdir, mkdtemp, readFile, readdir, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { basename, dirname, extname, join, posix, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import test from "node:test";
import { gunzipSync } from "node:zlib";

const execFileAsync = promisify(execFile);
const packageRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const repositoryRoot = resolve(packageRoot, "../..");
const repositoryPackagePrefix = "packages/pi-security/";

const nestedFiles = [
  "dist/pi-security-extension.mjs",
  "agents/*.md",
  "skills/**/*.md",
  "skills/**/*.py",
  "scripts/*.py",
  "scripts/**/*.py",
  "schemas/*.json",
  "schemas/**/*.json",
  "references/*.md",
  "references/**/*.md",
  "templates/**/*.md",
  "README.md",
];
const rootFiles = [
  `${repositoryPackagePrefix}dist/pi-security-extension.mjs`,
  `${repositoryPackagePrefix}package.json`,
  ...nestedFiles.slice(1, -1).map((path) => `${repositoryPackagePrefix}${path}`),
  `${repositoryPackagePrefix}README.md`,
  "README.md",
  "LICENSE",
];
const runtimeTrees = [
  ["agents", new Set([".md"])],
  ["skills", new Set([".md", ".py"])],
  ["scripts", new Set([".py"])],
  ["schemas", new Set([".json"])],
  ["references", new Set([".md"])],
  ["templates", new Set([".md"])],
];
const requiredPackageSentinels = [
  "package.json",
  "README.md",
  "dist/pi-security-extension.mjs",
  "agents/pi-security-scout.md",
  "agents/pi-security-auditor.md",
  "agents/pi-security-validator.md",
  "agents/pi-security-reviewer.md",
  "skills/security-scan/SKILL.md",
  "skills/security-diff-scan/SKILL.md",
  "skills/deep-security-scan/SKILL.md",
  "scripts/workbench_db.py",
  "scripts/deep_scan_workbench.py",
  "scripts/finalize_scan_contract.py",
  "scripts/workbench/__init__.py",
  "scripts/workbench/handoff.py",
  "schemas/scan-manifest.schema.json",
  "schemas/definitions/artifact-common.schema.json",
  "schemas/tools/scan-draft.schema.json",
  "references/core-scan.md",
  "references/final-report.md",
  "templates/deep-scan/discovery.md",
  "templates/deep-scan/dedup.md",
];
const bundledSubagentSentinels = [
  "node_modules/pi-subagents/package.json",
  "node_modules/pi-subagents/index.ts",
  "node_modules/pi-subagents/agents/worker.md",
  "node_modules/pi-subagents/agents/scout.md",
  "node_modules/pi-subagents/agents/reviewer.md",
];
const expectedRuntimeDependencies = {
  "pi-subagents": "0.62.0",
  "zod": "^4.3.6",
};
const bundledRuntimeTrees = new Set([
  "pi-subagents",
  ...Object.keys(
    (await readJson(resolve(repositoryRoot, "node_modules/pi-subagents/package.json"))).dependencies,
  ),
]);
const requiredPolicyRuntimeMarkers = [
  "security-readonly",
  "security-delegating-readonly",
  "security-artifact-writer",
  "PI_SECURITY_POLICY_DENIED",
  "PI_SECURITY_ENFORCEMENT_UNSUPPORTED",
  "PI_SECURITY_POLICY_RECOVERY_REJECTED",
  "continuation.exact-policy-reissue",
  "pi.worker-session.tools",
];
const forbiddenPackPaths = [
  ["Python cache directory", /(?:^|\/)__pycache__(?:\/|$)/u],
  ["Python bytecode", /\.py[co]$/iu],
  ["tool cache directory", /(?:^|\/)\.(?:cache|mypy_cache|pytest_cache|ruff_cache)(?:\/|$)/u],
  ["temporary cache directory", /(?:^|\/)(?:config-cache|eval-cache|scan-cache)(?:\/|$)/u],
  ["local database", /\.(?:db|sqlite|sqlite3)(?:-(?:journal|shm|wal))?$/iu],
  ["temporary file", /\.(?:tmp|temp)$/iu],
  ["local state directory", /(?:^|\/)(?:scans|security-scans|state|temp|tmp)(?:\/|$)/u],
  ["evaluation artifact", /^(?:packages\/pi-security\/)?evals(?:\/|$)/u],
  ["package test", /^(?:packages\/pi-security\/)?tests(?:\/|$)/u],
  ["unbundled TypeScript source", /^(?:packages\/pi-security\/)?(?:extensions|src)(?:\/|$)/u],
  ["development input", /^(?:packages\/pi-security\/)?(?:lifecycle\.ts|requirements-test\.txt|scripts-build\.mjs|tsconfig\.json)$/u],
];

async function readJson(path) {
  return JSON.parse(await readFile(path, "utf8"));
}

async function collectRuntimeAssets() {
  const assets = [];
  for (const [directory, extensions] of runtimeTrees) {
    await walkRuntimeTree(resolve(packageRoot, directory), directory, extensions, assets);
  }
  return assets.sort();
}

async function walkRuntimeTree(directory, relativeDirectory, extensions, assets) {
  const entries = await readdir(directory, { withFileTypes: true });
  entries.sort((left, right) => left.name.localeCompare(right.name));
  for (const entry of entries) {
    const relative = posix.join(relativeDirectory, entry.name);
    if (entry.isDirectory()) {
      await walkRuntimeTree(join(directory, entry.name), relative, extensions, assets);
    } else if (entry.isFile() && extensions.has(extname(entry.name))) {
      assets.push(relative);
    } else if (!entry.isFile()) {
      assert.fail(`Publishable runtime tree contains a non-file entry: ${relative}`);
    }
  }
}

function requiredPublicationPaths(packagePrefix, runtimeAssets) {
  return new Set([
    "package.json",
    "README.md",
    "LICENSE",
    ...requiredPackageSentinels.map((path) => `${packagePrefix}${path}`),
    ...runtimeAssets.map((path) => `${packagePrefix}${path}`),
    ...bundledSubagentSentinels,
  ]);
}

function assertPackContents(files, requiredPaths, packagePrefix) {
  const normalized = files.map((path) => path.replaceAll("\\", "/")).sort();
  assert.equal(new Set(normalized).size, normalized.length, "npm pack returned duplicate paths");

  const present = new Set(normalized);
  const missing = [...requiredPaths].filter((path) => !present.has(path)).sort();
  assert.deepEqual(missing, [], "npm pack is missing required runtime assets");

  const forbidden = [];
  for (const path of normalized) {
    for (const [label, pattern] of forbiddenPackPaths) {
      if (pattern.test(path)) forbidden.push(`${label}: ${path}`);
    }
  }
  assert.deepEqual(forbidden, [], "npm pack contains forbidden cache, state, or development artifacts");

  const unexpected = normalized.filter((path) => !isAllowedPackPath(path, packagePrefix));
  assert.deepEqual(unexpected, [], "npm pack contains paths outside the runtime allowlist");
}

function isAllowedPackPath(path, packagePrefix) {
  if (path === "package.json" || path === "README.md" || path === "LICENSE") return true;
  const dependency = path.match(/^node_modules\/((?:@[^/]+\/)?[^/]+)\//u)?.[1];
  if (dependency && bundledRuntimeTrees.has(dependency)) return true;
  if (packagePrefix && !path.startsWith(packagePrefix)) return false;
  const relative = packagePrefix ? path.slice(packagePrefix.length) : path;
  if (relative === "README.md" || relative === "package.json" || relative === "LICENSE") {
    return true;
  }
  if (relative === "dist/pi-security-extension.mjs") return true;
  return [
    /^agents\/[^/]+\.md$/u,
    /^skills\/.+\.(?:md|py)$/u,
    /^scripts\/.+\.py$/u,
    /^schemas\/.+\.json$/u,
    /^references\/.+\.md$/u,
    /^templates\/.+\.md$/u,
  ].some((pattern) => pattern.test(relative));
}

function tarText(buffer, offset, length) {
  const field = buffer.subarray(offset, offset + length);
  const terminator = field.indexOf(0);
  return field.subarray(0, terminator < 0 ? field.length : terminator).toString("utf8");
}

function tarSize(header, label) {
  const field = header.subarray(124, 136);
  if ((field[0] & 0x80) !== 0) {
    let value = BigInt(field[0] & 0x7f);
    for (const byte of field.subarray(1)) value = (value << 8n) | BigInt(byte);
    assert.ok(value <= BigInt(Number.MAX_SAFE_INTEGER), `${label} tar entry is too large`);
    return Number(value);
  }
  const encoded = tarText(header, 124, 12).trim();
  const value = encoded === "" ? 0 : Number.parseInt(encoded, 8);
  assert.equal(Number.isSafeInteger(value) && value >= 0, true, `${label} has an invalid tar size`);
  return value;
}

function paxFields(data, label) {
  const fields = Object.create(null);
  let offset = 0;
  while (offset < data.length) {
    const separator = data.indexOf(0x20, offset);
    assert.notEqual(separator, -1, `${label} has an invalid PAX record`);
    const length = Number(data.subarray(offset, separator).toString("ascii"));
    assert.equal(Number.isSafeInteger(length) && length > 0, true, `${label} has an invalid PAX length`);
    const end = offset + length;
    assert.ok(end <= data.length, `${label} has a truncated PAX record`);
    assert.equal(data[end - 1], 0x0a, `${label} has an unterminated PAX record`);
    const record = data.subarray(separator + 1, end - 1).toString("utf8");
    const equals = record.indexOf("=");
    assert.ok(equals > 0, `${label} has an invalid PAX field`);
    fields[record.slice(0, equals)] = record.slice(equals + 1);
    offset = end;
  }
  return fields;
}

async function npmArchiveFiles(archivePath, label) {
  const archive = gunzipSync(await readFile(archivePath));
  const files = [];
  let offset = 0;
  let localPax;
  let longPath;
  while (offset + 512 <= archive.length) {
    const header = archive.subarray(offset, offset + 512);
    if (header.every((byte) => byte === 0)) break;
    const size = tarSize(header, label);
    const dataStart = offset + 512;
    const dataEnd = dataStart + size;
    assert.ok(dataEnd <= archive.length, `${label} npm archive is truncated`);
    const data = archive.subarray(dataStart, dataEnd);
    const type = tarText(header, 156, 1);
    const name = tarText(header, 0, 100);
    const prefix = tarText(header, 345, 155);
    const headerPath = prefix ? `${prefix}/${name}` : name;

    if (type === "x") {
      localPax = paxFields(data, label);
    } else if (type === "g") {
      paxFields(data, label);
    } else if (type === "L") {
      longPath = tarText(data, 0, data.length).replace(/\n$/u, "");
    } else {
      const entryPath = localPax?.path ?? longPath ?? headerPath;
      localPax = undefined;
      longPath = undefined;
      if (type !== "5") {
        assert.ok(
          type === "" || type === "0" || type === "7",
          `${label} npm archive contains unsupported tar entry type ${JSON.stringify(type)}`,
        );
        assert.match(entryPath, /^package\/[^/]/u, `${label} npm archive entry is outside package/`);
        files.push(entryPath.slice("package/".length));
      }
    }
    offset = dataStart + Math.ceil(size / 512) * 512;
  }
  assert.ok(files.length > 0, `${label} npm archive contains no files`);
  return files;
}

async function npmPackFiles(cwd, label) {
  const staging = await mkdtemp(join(tmpdir(), `pi-security-${label}-npm-pack-`));
  const cache = join(staging, "cache");
  const destination = join(staging, "archive");
  const npm = process.platform === "win32" ? "npm.cmd" : "npm";
  try {
    await Promise.all([
      mkdir(cache, { recursive: true }),
      mkdir(destination, { recursive: true }),
    ]);
    const { stdout } = await execFileAsync(
      npm,
      [
        "pack",
        "--json",
        "--ignore-scripts",
        "--loglevel=error",
        "--pack-destination",
        destination,
      ],
      {
        cwd,
        env: {
          ...process.env,
          npm_config_audit: "false",
          npm_config_cache: cache,
          npm_config_fund: "false",
          npm_config_update_notifier: "false",
        },
        maxBuffer: 16 * 1024 * 1024,
        windowsHide: true,
      },
    );
    const report = JSON.parse(stdout);
    const entries = Array.isArray(report) ? report : Object.values(report);
    assert.equal(entries.length, 1, `${label} npm pack must describe exactly one package`);
    assert.ok(Array.isArray(entries[0]?.files), `${label} npm pack did not return a file manifest`);
    assert.equal(typeof entries[0]?.filename, "string", `${label} npm pack did not return an archive name`);
    assert.equal(
      basename(entries[0].filename),
      entries[0].filename,
      `${label} npm pack returned an unsafe archive name`,
    );
    const archived = await npmArchiveFiles(
      join(destination, entries[0].filename),
      label,
    );
    const reported = entries[0].files.map((entry) => entry.path);
    assert.deepEqual(
      archived.toSorted(),
      reported.toSorted(),
      `${label} npm archive entries differ from the reported manifest`,
    );
    return archived;
  } finally {
    await rm(staging, { recursive: true, force: true });
  }
}

test("package manifests pin bundled subagents and load its extension first", async () => {
  const [rootManifest, nestedManifest] = await Promise.all([
    readJson(resolve(repositoryRoot, "package.json")),
    readJson(resolve(packageRoot, "package.json")),
  ]);

  assert.deepEqual(rootManifest.files, rootFiles);
  assert.deepEqual(nestedManifest.files, nestedFiles);
  for (const manifest of [rootManifest, nestedManifest]) {
    assert.deepEqual(manifest.dependencies, expectedRuntimeDependencies);
    assert.deepEqual(manifest.bundleDependencies, ["pi-subagents"]);
  }
  assert.deepEqual(rootManifest.pi.extensions, [
    "./node_modules/pi-subagents/index.ts",
    "./packages/pi-security/dist/pi-security-extension.mjs",
  ]);
  assert.deepEqual(nestedManifest.pi.extensions, [
    "./node_modules/pi-subagents/index.ts",
    "./dist/pi-security-extension.mjs",
  ]);
});

test("built runtime bundles include the complete permission-profile layer", async () => {
  for (const relativePath of ["dist/pi-security-extension.mjs"]) {
    const bundle = await readFile(resolve(packageRoot, relativePath), "utf8");
    for (const marker of requiredPolicyRuntimeMarkers) {
      assert.equal(
        bundle.includes(marker),
        true,
        `${relativePath} is missing permission-profile runtime marker ${marker}`,
      );
    }
  }
});

test("repository and nested npm packs contain runtime assets and no local artifacts", async () => {
  const runtimeAssets = await collectRuntimeAssets();
  for (const publication of [
    { cwd: repositoryRoot, label: "repository", packagePrefix: repositoryPackagePrefix },
    { cwd: packageRoot, label: "nested", packagePrefix: "" },
  ]) {
    const files = await npmPackFiles(publication.cwd, publication.label);
    if (publication.packagePrefix) {
      assert.equal(
        files.includes(`${publication.packagePrefix}package.json`),
        true,
        "the root pack must retain the nested manifest consumed by scan completion",
      );
    }
    assertPackContents(
      files,
      requiredPublicationPaths(publication.packagePrefix, runtimeAssets),
      publication.packagePrefix,
    );
  }
});

test("pack-content assertion rejects missing and forbidden paths", () => {
  const required = ["package.json", `${repositoryPackagePrefix}dist/pi-security-extension.mjs`];
  assert.throws(
    () => assertPackContents(["package.json"], required, repositoryPackagePrefix),
    /missing required runtime assets/u,
  );
  assert.throws(
    () => assertPackContents([
      ...required,
      `${repositoryPackagePrefix}scripts/__pycache__/workbench.cpython-312.pyc`,
    ], required, repositoryPackagePrefix),
    /forbidden cache, state, or development artifacts/u,
  );
});

// populateFindingIdentities and validateFindingIdentities against the sealed outputs in the parity goldens.
// fingerprint, stableId, and deriveFindingIdentities are held to recorded vectors in tests/parity.test.mjs.
import assert from "node:assert/strict";
import { existsSync, readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { test } from "node:test";
import { build } from "esbuild";

const bundled = await build({
  bundle: true,
  stdin: {
    contents: 'export * from "./src/contract/finding-identity.ts";',
    resolveDir: new URL("..", import.meta.url).pathname,
  },
  format: "esm",
  platform: "node",
  write: false,
});
const { populateFindingIdentities, validateFindingIdentities } = await import(
  `data:text/javascript;base64,${Buffer.from(bundled.outputFiles[0].contents).toString("base64")}`
);

const goldens = new URL("parity/goldens/finalize/", import.meta.url).pathname;
const sealedScans = readdirSync(goldens)
  .map((name) => join(goldens, name, "tree", "scan"))
  .filter((dir) => existsSync(join(dir, "findings.json")) && existsSync(join(dir, "exports")));
const read = (dir, name) => JSON.parse(readFileSync(join(dir, name), "utf8"));

test("finalize goldens include sealed scans", () => {
  assert.ok(sealedScans.length >= 8, `found ${sealedScans.length}`);
});

for (const dir of sealedScans) {
  const label = dir.split("/").at(-3);

  test(`sealed identities validate: ${label}`, () => {
    validateFindingIdentities(read(dir, "scan-manifest.json"), read(dir, "findings.json"));
  });

  test(`populating stripped identities reproduces the seal: ${label}`, () => {
    const manifest = read(dir, "scan-manifest.json");
    const sealed = read(dir, "findings.json");
    const draft = structuredClone(sealed);
    for (const finding of draft.findings) {
      delete finding.findingId;
      delete finding.occurrenceId;
      finding.fingerprints = { algorithm: "pi-security/v1", primary: "draft" };
    }
    populateFindingIdentities(manifest, draft);
    assert.deepEqual(draft, sealed);
  });
}

test("tampered identities are rejected with the finalizer's messages", () => {
  const dir = sealedScans.find((scan) => read(scan, "findings.json").findings.length > 0);
  const manifest = read(dir, "scan-manifest.json");
  const cases = [
    ["findingId", "csf_000000000000000000000000", "findings.findings[0].findingId: does not match derived fingerprint identity"],
    ["occurrenceId", "occ_000000000000000000000000", "findings.findings[0].occurrenceId: does not match scan occurrence identity"],
    ["fingerprints", { algorithm: "pi-security/v1", primary: "x" }, "findings.findings[0].fingerprints: does not match derived fingerprint"],
  ];
  for (const [field, value, message] of cases) {
    const findings = read(dir, "findings.json");
    findings.findings[0][field] = value;
    assert.throws(() => validateFindingIdentities(manifest, findings), { name: "ContractError", message });
  }
  const renamed = read(dir, "findings.json");
  renamed.findings[0].identity.anchor = "a-different-anchor";
  assert.throws(() => validateFindingIdentities(manifest, renamed), { name: "ContractError" });
});

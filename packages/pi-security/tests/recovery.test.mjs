// populateUnsealedManifestEnvelope with PI_SECURITY_STARTED_AT and no completion binding stamps completedAt from the
// clock, which recorded vectors cannot hold; the rest of src/contract/recovery.ts is held to vectors in
// tests/parity.test.mjs.
import assert from "node:assert/strict";
import { test } from "node:test";
import { build } from "esbuild";

const bundled = await build({
  bundle: true,
  stdin: {
    contents: 'export * from "./src/contract/recovery.ts";',
    resolveDir: new URL("..", import.meta.url).pathname,
  },
  format: "esm",
  platform: "node",
  write: false,
});
const { populateUnsealedManifestEnvelope } = await import(
  `data:text/javascript;base64,${Buffer.from(bundled.outputFiles[0].contents).toString("base64")}`
);

function stamp(startedAt, now) {
  const manifest = { scan: { id: "scan_clock" } };
  populateUnsealedManifestEnvelope(manifest, manifest.scan, null, {
    env: { PI_SECURITY_STARTED_AT: startedAt },
    now: () => now,
  });
  return manifest.scan;
}

test("completedAt uses Python's isoformat: microseconds, omitted when zero", () => {
  assert.equal(stamp("2026-06-01T10:00:00Z", new Date("2026-06-01T10:30:00.123Z")).completedAt, "2026-06-01T10:30:00.123000Z");
  assert.equal(stamp("2026-06-01T10:00:00Z", new Date("2026-06-01T10:30:00.007Z")).completedAt, "2026-06-01T10:30:00.007000Z");
  assert.equal(stamp("2026-06-01T10:00:00Z", new Date("2026-06-01T10:30:00.000Z")).completedAt, "2026-06-01T10:30:00Z");
});

test("PI_SECURITY_STARTED_AT is copied when valid and leaves the times alone when unset", () => {
  const scan = stamp("2026-06-01T10:00:00+02:00", new Date("2026-06-01T10:30:00Z"));
  assert.equal(scan.startedAt, "2026-06-01T10:00:00+02:00");
  assert.equal(scan.status, "completed");
  const unset = stamp(undefined, new Date("2026-06-01T10:30:00Z"));
  assert.equal(Object.hasOwn(unset, "startedAt") || Object.hasOwn(unset, "completedAt"), false);
  assert.throws(() => stamp("yesterday", new Date()), { message: "PI_SECURITY_STARTED_AT: expected an RFC 3339 timestamp" });
});

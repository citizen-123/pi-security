import assert from "node:assert/strict";
import test from "node:test";
import { build } from "esbuild";

const bundle = await build({
  bundle: true,
  entryPoints: [new URL("../src/enforcement-capabilities.ts", import.meta.url).pathname],
  format: "esm",
  platform: "node",
  write: false,
});
const enforcement = await import(
  `data:text/javascript;base64,${Buffer.from(bundle.outputFiles[0].contents).toString("base64")}`,
);

test("enforcement capability reports fail closed for malformed host observations", () => {
  for (const input of [
    {
      kind: "effective",
      piTools: "true",
      targetHandles: true,
      artifactRoots: true,
    },
    {
      kind: "availability",
      piTools: true,
      targetHandles: 1,
    },
    {
      kind: "effective",
      piTools: true,
      platformMechanisms: ["unrecognized-host-mechanism"],
    },
  ]) {
    const report = enforcement.describePiEnforcementCapabilities(input);
    assert.equal(report.supported, false);
    assert.deepEqual(report.mechanisms, []);
    assert.match(report.unsupportedReason, /invalid host enforcement capability report/u);
    assert.throws(
      () => enforcement.assertPiEnforcementSupported(report),
      (error) => error.code === "PI_SECURITY_ENFORCEMENT_UNSUPPORTED",
    );
  }
});

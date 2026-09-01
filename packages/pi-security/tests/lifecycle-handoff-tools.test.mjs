import assert from "node:assert/strict";
import test from "node:test";
import { build } from "esbuild";

const bundle = await build({
  bundle: true,
  stdin: {
    contents: [
      'export { handoffClaimTokenSchema, recoveryHandoffClaimTokenSchema } from "./src/lifecycle/handoff-tools.ts";',
      'export { lifecycleToolJsonSchema, parseLifecycleToolInput } from "./src/lifecycle/catalog.ts";'
    ].join("\n"),
    loader: "ts",
    resolveDir: new URL("..", import.meta.url).pathname
  },
  format: "esm",
  platform: "node",
  write: false
});
const {
  handoffClaimTokenSchema,
  lifecycleToolJsonSchema,
  parseLifecycleToolInput,
  recoveryHandoffClaimTokenSchema
} = await import(
  `data:text/javascript;base64,${Buffer.from(bundle.outputFiles[0].contents).toString("base64")}`
);

const lowercaseToken = "a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d";
const uppercaseToken = lowercaseToken.toUpperCase();
const lowercaseRecoveryToken = `recovery_${lowercaseToken}`;
const uppercaseRecoveryToken = `recovery_${uppercaseToken}`;

test("handoff token schemas normalize UUID casing before lifecycle command invocation", () => {
  assert.equal(handoffClaimTokenSchema.parse(uppercaseToken), lowercaseToken);
  assert.equal(
    recoveryHandoffClaimTokenSchema.parse(uppercaseRecoveryToken),
    lowercaseRecoveryToken
  );
  assert.equal(
    parseLifecycleToolInput(handoffClaimTokenSchema, uppercaseRecoveryToken),
    lowercaseRecoveryToken
  );

  const jsonSchema = lifecycleToolJsonSchema(handoffClaimTokenSchema);
  assert.match(JSON.stringify(jsonSchema), /recovery_\[0-9a-fA-F\]/u);
});

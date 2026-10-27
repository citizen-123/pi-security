// TypeScript ports checked by tests/parity.test.mjs.
//
// tools: case tool name (argv[0] in tests/parity/cases/*/case.json) ->
//   async (args, { cwd }) => ({ status: "ok" | "rejected", stdout?: string | Buffer })
//   args are argv[1:] with placeholders already substituted. A port reports rejection instead of throwing.
//
// functions: recorded vector function name (tests/parity/vectors/<name>.jsonl) ->
//   (args) => result, where args is the recorded parameter object; throw to reproduce a recorded error.
//   Where Python raised ContractError, the port must throw an error with the same message.
//   Bytes are passed and returned as Buffer/Uint8Array.
//
// Register a port here as part of the change that adds it. Until then its cases and vectors are skipped.
import { build } from "esbuild";

const bundled = await build({
  bundle: true,
  stdin: {
    contents: 'export * from "./src/contract/finding-identity.ts";',
    resolveDir: new URL("../..", import.meta.url).pathname,
  },
  format: "esm",
  platform: "node",
  write: false,
});
const identity = await import(
  `data:text/javascript;base64,${Buffer.from(bundled.outputFiles[0].contents).toString("base64")}`
);

export const tools = {};

export const functions = {
  "finalize_scan_contract._fingerprint": ({ target_id, finding }) => identity.fingerprint(target_id, finding),
  "finalize_scan_contract._stable_id": ({ prefix, parts }) => identity.stableId(prefix, ...parts),
  "finalize_scan_contract._derived_finding_identity_rows": ({ manifest, findings }) =>
    identity
      .deriveFindingIdentities(manifest, findings)
      .map((row) => [row.context, row.finding, row.findingId, row.occurrenceId, row.fingerprints]),
};

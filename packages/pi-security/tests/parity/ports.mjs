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

import { mkdirSync, realpathSync, renameSync, statSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";

async function load(entry) {
  const bundled = await build({
    bundle: true,
    stdin: { contents: `export * from "./${entry}";`, resolveDir: new URL("../..", import.meta.url).pathname },
    format: "esm",
    platform: "node",
    write: false,
  });
  return import(`data:text/javascript;base64,${Buffer.from(bundled.outputFiles[0].contents).toString("base64")}`);
}

const identity = await load("src/contract/finding-identity.ts");
const candidates = await load("src/contract/candidates.ts");

/** Minimal argparse: options with one value, or every value up to the next option for multi-value options. */
function parseOptions(args, multi = new Set(), flags = new Set()) {
  const options = {};
  for (let index = 0; index < args.length; index++) {
    const name = args[index].replace(/^--/, "");
    if (flags.has(name)) options[name] = true;
    else if (multi.has(name)) {
      options[name] = [];
      while (index + 1 < args.length && !args[index + 1].startsWith("--")) options[name].push(args[++index]);
    } else options[name] = args[++index];
  }
  return options;
}

function atomicWrite(path, bytes) {
  mkdirSync(dirname(path), { recursive: true });
  const temporary = `${path}.tmp-${process.pid}`;
  writeFileSync(temporary, bytes);
  renameSync(temporary, path);
}

export const tools = {
  // CLI shim over normalizeCandidateFiles, mirroring normalize_candidates.py main().
  normalize_candidates: async (args) => {
    try {
      const options = parseOptions(args, new Set(["input"]), new Set(["allow-missing-in-scope"]));
      const repoRoot = realpathSync(options["repo-root"]);
      if (!statSync(repoRoot).isDirectory()) return { status: "rejected" };
      const output = resolve(options.out);
      const scopePath = realpathSync(options["in-scope-files"]);
      const inputs = options.input.map((input) => realpathSync(input));
      if (inputs.includes(output) || output === scopePath) return { status: "rejected" };
      const result = candidates.normalizeCandidateFiles({
        inputs,
        repoRoot,
        scopePath,
        allowMissingInScope: options["allow-missing-in-scope"] === true,
      });
      atomicWrite(output, result.jsonl);
      return { status: "ok" };
    } catch {
      return { status: "rejected" };
    }
  },
};

export const functions = {
  "finalize_scan_contract._fingerprint": ({ target_id, finding }) => identity.fingerprint(target_id, finding),
  "finalize_scan_contract._stable_id": ({ prefix, parts }) => identity.stableId(prefix, ...parts),
  "finalize_scan_contract._derived_finding_identity_rows": ({ manifest, findings }) =>
    identity
      .deriveFindingIdentities(manifest, findings)
      .map((row) => [row.context, row.finding, row.findingId, row.occurrenceId, row.fingerprints]),
};

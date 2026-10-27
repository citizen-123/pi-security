// TypeScript ports checked by tests/parity.test.mjs.
//
// tools: case tool name (argv[0] in tests/parity/cases/*/case.json) ->
//   async (args, { cwd }) => ({ status: "ok" | "rejected", stdout?: string | Buffer })
//   args are argv[1:] with placeholders already substituted. A port reports rejection instead of throwing.
//
// functions: recorded vector function name (tests/parity/vectors/<name>.jsonl) ->
//   (args) => result, where args is the recorded parameter object; throw to reproduce a recorded error.
//   Bytes are passed and returned as Buffer/Uint8Array.
//
// Register a port here as part of the change that adds it. Until then its cases and vectors are skipped.

export const tools = {};

export const functions = {};

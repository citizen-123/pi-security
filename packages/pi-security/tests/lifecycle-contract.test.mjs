import assert from "node:assert/strict";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { createRequire } from "node:module";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import test from "node:test";
import { build } from "esbuild";

const packageRoot = resolve(import.meta.dirname, "..");
const repositoryRoot = resolve(packageRoot, "../..");
const originalRoot = resolve(repositoryRoot, "plugins/codex-security");
const contract = JSON.parse(
  await readFile(resolve(import.meta.dirname, "fixtures/lifecycle-tools.json"), "utf8")
);

const brandReplacements = [
  ["CODEX_SECURITY", "PI_SECURITY"],
  ["CodexSecurity", "PiSecurity"],
  ["codexSecurity", "piSecurity"],
  ["codex_security", "pi_security"],
  ["codex-security", "pi-security"],
  ["Codex Security", "Pi Security"],
  ["Codex", "Pi"],
  ["codex", "pi"],
  ["local_plugin", "local_package"],
  ["plugin", "package"]
];

function normalizeBrand(value) {
  for (const [from, to] of brandReplacements) value = value.replaceAll(from, to);
  return value;
}

function parseAnnotations(source) {
  return Object.fromEntries(
    [...source.matchAll(/(\w+Hint):\s*(true|false)/g)]
      .map((entry) => [entry[1], entry[2] === "true"])
  );
}

function parseDirectRegistrations(source, original) {
  const registrations = [];
  const pattern = /server\.registerTool\("([^"]+)",\s*\{([\s\S]*?)\}\s*,\s*async/g;
  for (const match of source.matchAll(pattern)) {
    const [, sourceName, config] = match;
    const annotationsSource = /annotations:\s*\{([^}]+)\}/s.exec(config)?.[1];
    const meta = /_meta:\s*(\w+)/.exec(config)?.[1];
    assert.ok(/inputSchema:\s*\w+/.test(config), `missing schema for ${sourceName}`);
    assert.ok(annotationsSource && meta, `incomplete registration for ${sourceName}`);
    registrations.push({
      name: normalizeBrand(sourceName),
      ...(original ? { originalName: sourceName } : {}),
      audience: meta === "appMeta" ? "app" : "model",
      annotations: parseAnnotations(annotationsSource)
    });
  }
  return registrations;
}

function parseCompactBlock(source, original) {
  const registrations = [];
  const pattern = /registerCompactTool\(server,\s*\{([\s\S]*?)\n\s*\}\);/g;
  for (const match of source.matchAll(pattern)) {
    const config = match[1];
    const sourceName = /name:\s*"([^"]+)"/.exec(config)?.[1];
    const readOnly = /readOnly:\s*(true|false)/.exec(config)?.[1];
    assert.ok(sourceName && readOnly && /inputSchema:\s*\w+/.test(config), "incomplete compact registration");
    registrations.push({
      name: normalizeBrand(sourceName),
      ...(original ? { originalName: sourceName } : {}),
      audience: "model",
      annotations: {
        readOnlyHint: readOnly === "true",
        destructiveHint: false,
        idempotentHint: true,
        openWorldHint: false
      }
    });
  }
  return registrations;
}

function compactSurfaceBlocks(source) {
  const workerMarker = "/** Expose only the operations appropriate to the inherited worker phase. */";
  const workerStart = source.indexOf('if (context.layout === "worker")');
  const reducerGuard = source.indexOf('if (context.layout !== "reducer")', workerStart);
  const reducerStart = source.indexOf("registerCompactTool(server, {", reducerGuard);
  const reducerEnd = source.indexOf("\n}\n\ninterface CompactToolRegistration", reducerStart);
  assert.ok(workerStart > 0 && reducerGuard > workerStart && reducerStart > reducerGuard && reducerEnd > reducerStart);
  return {
    standalone: source.slice(0, source.indexOf(workerMarker)),
    worker: source.slice(workerStart, reducerGuard),
    reducer: source.slice(reducerStart, reducerEnd)
  };
}

async function readSurfaces(root, original) {
  const base = original ? resolve(root, "mcp-app") : root;
  const [server, handoff, compact] = await Promise.all([
    readFile(resolve(base, "server.ts"), "utf8"),
    readFile(resolve(base, "src/server/handoff-tools.ts"), "utf8"),
    readFile(resolve(base, "src/server/compact-artifact-tools.ts"), "utf8")
  ]);
  const blocks = compactSurfaceBlocks(compact);
  return {
    standalone: [
      ...parseDirectRegistrations(server, original),
      ...parseDirectRegistrations(handoff, original),
      ...parseCompactBlock(blocks.standalone, original)
    ],
    worker: parseCompactBlock(blocks.worker, original),
    reducer: parseCompactBlock(blocks.reducer, original)
  };
}

function expectedSurface(surface, original) {
  const byName = new Map(contract.tools.map((tool) => [tool.name, tool]));
  return contract.surfaces[surface].map((name) => {
    const tool = byName.get(name);
    return {
      name,
      ...(original ? { originalName: tool.originalName } : {}),
      audience: tool.audience,
      annotations: tool.annotations
    };
  });
}

function sortRecords(records) {
  return records.toSorted((left, right) => left.name.localeCompare(right.name));
}

function normalizeInputSchema(value, parentKey = "") {
  if (typeof value === "string") return normalizeBrand(value);
  if (Array.isArray(value)) {
    const normalized = value.map((item) => normalizeInputSchema(item));
    return parentKey === "required" && normalized.every((item) => typeof item === "string")
      ? normalized.sort()
      : normalized;
  }
  if (!value || typeof value !== "object") return value;
  return Object.fromEntries(
    Object.entries(value)
      .map(([key, child]) => [normalizeBrand(key), normalizeInputSchema(child, key)])
      .sort(([left], [right]) => left.localeCompare(right))
  );
}


function captureServer() {
  return {
    registrations: [],
    registerTool(name, config, handler) {
      this.registrations.push({ name, ...config, handler });
    }
  };
}

function emittedRecords(registrations, emitInputSchema) {
  return registrations
    .map((registration) => ({
      name: normalizeBrand(registration.name),
      inputSchema: normalizeInputSchema(emitInputSchema(registration.inputSchema))
    }))
    .sort((left, right) => left.name.localeCompare(right.name));
}

async function readOriginalEmittedSurfaces() {
  const temporaryDirectory = await mkdtemp(join(tmpdir(), "pi-security-lifecycle-contract-"));
  const output = resolve(temporaryDirectory, "original-contract.cjs");
  const mcpAppRoot = resolve(originalRoot, "mcp-app");
  try {
    await build({
      bundle: true,
      format: "cjs",
      loader: { ".md": "text" },
      logLevel: "silent",
      outfile: output,
      platform: "node",
      stdin: {
        contents: [
          'import * as z4mini from "zod/v4-mini";',
          'export { createCodexSecurityServer } from "./server.ts";',
          'export { registerCompactWorkerArtifactTools } from "./src/server/compact-artifact-tools.ts";',
          "export function emitInputSchema(schema) {",
          "  let objectSchema = schema;",
          "  if (schema && typeof schema === 'object' && !schema._def && !schema._zod) {",
          "    const values = Object.values(schema);",
          "    if (values.length > 0 && values.every((value) => value && typeof value === 'object' && (value._def || value._zod || typeof value.parse === 'function'))) {",
          "      objectSchema = z4mini.object(schema);",
          "    }",
          "  }",
          "  return z4mini.toJSONSchema(objectSchema, { target: 'draft-7', io: 'input' });",
          "}"
        ].join("\n"),
        loader: "ts",
        resolveDir: mcpAppRoot,
        sourcefile: "lifecycle-contract-entry.ts"
      },
      plugins: [{
        name: "lifecycle-contract-dependencies",
        setup(builder) {
          builder.onResolve(
            { filter: /^@modelcontextprotocol\/sdk\/server\/mcp\.js$/ },
            () => ({ path: "mcp-server-stub", namespace: "contract" })
          );
          builder.onLoad(
            { filter: /^mcp-server-stub$/, namespace: "contract" },
            () => ({
              loader: "js",
              contents: `
                export class McpServer {
                  constructor() {
                    this.registrations = [];
                    this.server = {
                      onclose: undefined,
                      getClientCapabilities: () => ({ sampling: {} }),
                      createMessage: async () => ({})
                    };
                  }
                  registerTool(name, config, handler) {
                    this.registrations.push({ name, ...config, handler });
                  }
                }
              `
            })
          );
          builder.onResolve(
            { filter: /^@openai\/codex-sdk$/ },
            () => ({ path: "codex-sdk-stub", namespace: "contract" })
          );
          builder.onLoad(
            { filter: /^codex-sdk-stub$/, namespace: "contract" },
            () => ({ loader: "js", contents: "export class Codex {}" })
          );
        }
      }],
      target: "node20"
    });

    const require = createRequire(import.meta.url);
    const bundled = require(output);
    const standalone = bundled.createCodexSecurityServer();
    const worker = captureServer();
    const reducer = captureServer();
    bundled.registerCompactWorkerArtifactTools(worker, { layout: "worker" });
    bundled.registerCompactWorkerArtifactTools(reducer, { layout: "reducer" });
    return {
      standalone: emittedRecords(standalone.registrations, bundled.emitInputSchema),
      worker: emittedRecords(worker.registrations, bundled.emitInputSchema),
      reducer: emittedRecords(reducer.registrations, bundled.emitInputSchema)
    };
  } finally {
    await rm(temporaryDirectory, { recursive: true, force: true });
  }
}

test("the contract projects every original registration on each port surface", async () => {
  const [original, port] = await Promise.all([
    readSurfaces(originalRoot, true),
    readSurfaces(packageRoot, false)
  ]);
  for (const surface of ["standalone", "worker", "reducer"]) {
    assert.deepEqual(sortRecords(original[surface]), expectedSurface(surface, true));
    assert.deepEqual(sortRecords(port[surface]), expectedSurface(surface, false));
  }

  const representedNames = new Set(Object.values(contract.surfaces).flat());
  assert.equal(representedNames.size, 46);
  assert.deepEqual([...representedNames].sort(), contract.tools.map((tool) => tool.name));
  for (const tool of contract.tools) {
    assert.deepEqual(
      tool.surfaces,
      Object.entries(contract.surfaces)
        .filter(([, names]) => names.includes(tool.name))
        .map(([surface]) => surface)
    );
    assert.equal(tool.inputSchema?.type, "object", `${tool.name} frozen input schema`);
  }
});

test("normalized original emitted schemas match the frozen port contract", async () => {
  const surfaces = await readOriginalEmittedSurfaces();
  const byName = new Map(contract.tools.map((tool) => [tool.name, tool]));
  for (const surface of ["standalone", "worker", "reducer"]) {
    assert.deepEqual(
      surfaces[surface],
      contract.surfaces[surface].map((name) => ({
        name,
        inputSchema: byName.get(name).inputSchema
      })),
      `${surface} original emitted schemas`
    );
  }
});

test("every checked schema artifact named by the contract exists in both trees", async () => {
  assert.ok(contract.schemaArtifacts.includes("schemas/tools/deep-reducer.schema.json"));
  await Promise.all(contract.schemaArtifacts.flatMap((path) => [
    readFile(resolve(originalRoot, path)),
    readFile(resolve(packageRoot, path))
  ]));
});

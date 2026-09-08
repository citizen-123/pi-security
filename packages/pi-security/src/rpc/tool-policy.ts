import { basename, extname, isAbsolute, join, matchesGlob, relative, resolve } from "node:path";
import {
  createFindToolDefinition,
  createGrepToolDefinition,
  createLsToolDefinition,
  createReadToolDefinition,
  truncateHead,
  type ExtensionAPI,
} from "@earendil-works/pi-coding-agent";
import {
  assertPathInside,
  openExecutionTargetPath,
  readOpenedDirectory,
  type BoundPathKind,
} from "../execution-boundary.js";
import { createExecutionPolicyContext } from "../execution-policy.js";

interface PhaseToolAuthority {
  artifactRoot: string;
  runId: string;
  targetPath: string;
  tools: string[];
}

const TOOL_NAMES: Record<string, true> = { read: true, grep: true, find: true, ls: true };

/** Loaded explicitly by the host; repository extensions and built-in tools stay disabled. */
export default function phaseToolPolicy(pi: ExtensionAPI): void {
  const authority: PhaseToolAuthority = JSON.parse(process.env.PI_SECURITY_RPC_AUTHORITY ?? "null");
  if (
    !authority || typeof authority.targetPath !== "string" || !isAbsolute(authority.targetPath)
    || typeof authority.artifactRoot !== "string" || !isAbsolute(authority.artifactRoot)
    || typeof authority.runId !== "string" || !authority.runId
    || !Array.isArray(authority.tools) || authority.tools.some((name) => !Object.hasOwn(TOOL_NAMES, name))
  ) {
    throw new Error("RPC tool authority is missing or invalid.");
  }
  const allowed = new Set(authority.tools);
  const contexts = [...new Set([authority.targetPath, authority.artifactRoot])].map((root) => (
    createExecutionPolicyContext({
      profile: "security-readonly",
      target: { root },
      scan: { id: authority.runId, artifactRoot: authority.artifactRoot },
    })
  ));

  async function open(input: string, expected: BoundPathKind = "any") {
    const absolute = resolve(authority.targetPath, input);
    const context = contexts.find((candidate) => {
      const path = relative(candidate.target.root, absolute);
      return path === "" || (!isAbsolute(path) && path !== ".." && !path.startsWith("../") && !path.startsWith("..\\"));
    });
    if (!context) throw new Error("RPC tool path is outside the issued target and artifact roots.");
    assertPathInside(context.target.root, absolute, "RPC tool path", true);
    return await openExecutionTargetPath(context, relative(context.target.root, absolute).replaceAll("\\", "/") || ".", {
      capability: "target.read",
      expected,
    });
  }

  async function readFile(input: string): Promise<Buffer> {
    const opened = await open(input, "file");
    try {
      return await opened.handle.readFile();
    } finally {
      await opened.handle.close();
    }
  }

  async function stat(input: string) {
    const opened = await open(input);
    try {
      return opened.metadata;
    } finally {
      await opened.handle.close();
    }
  }

  async function entries(input: string) {
    const opened = await open(input, "directory");
    try {
      return await readOpenedDirectory(opened, "RPC tool directory", async (entry) => {
        // Directory listings may name links, but never follow them or read their targets.
        if (entry.isSymbolicLink()) return;
        const child = await open(join(opened.absolute, entry.name));
        await child.handle.close();
      });
    } finally {
      await opened.handle.close();
    }
  }

  async function* files(input: string, signal?: AbortSignal): AsyncGenerator<string> {
    signal?.throwIfAborted();
    if ((await stat(input)).isFile()) {
      yield input;
      return;
    }
    const children = await entries(input);
    children.sort((left, right) => left.name.localeCompare(right.name));
    for (const entry of children) {
      signal?.throwIfAborted();
      if (entry.isSymbolicLink() || entry.name === ".git" || entry.name === "node_modules") continue;
      const child = join(input, entry.name);
      const metadata = await stat(child);
      if (metadata.isDirectory()) yield* files(child, signal);
      else if (metadata.isFile()) yield child;
    }
  }

  const read = createReadToolDefinition(authority.targetPath, {
    operations: {
      access: async (input) => {
        const opened = await open(input, "file");
        await opened.handle.close();
      },
      readFile,
      detectImageMimeType: async (input) => {
        const mimeTypes: Record<string, string> = {
          ".png": "image/png", ".jpg": "image/jpeg", ".jpeg": "image/jpeg",
          ".gif": "image/gif", ".webp": "image/webp", ".bmp": "image/bmp",
        };
        return mimeTypes[extname(input).toLowerCase()];
      },
    },
  });
  const ls = createLsToolDefinition(authority.targetPath, {
    operations: {
      exists: async (input) => { await stat(input); return true; },
      stat,
      readdir: async (input) => (await entries(input)).map((entry) => entry.name),
    },
  });
  const find = createFindToolDefinition(authority.targetPath);
  find.description = "Find files by glob within the issued target or artifact roots. Does not follow symlinks; skips .git and node_modules.";
  find.promptSnippet = "Find approved source files by glob";
  find.execute = async (id, args, signal, onUpdate, ctx) => {
    const guarded = createFindToolDefinition(authority.targetPath, {
      operations: {
        exists: async (input) => { await stat(input); return true; },
        glob: async (pattern, input, options) => {
          const found: string[] = [];
          for await (const file of files(input, signal)) {
            const candidate = pattern.includes("/") ? relative(input, file).replaceAll("\\", "/") : basename(file);
            if (!matchesGlob(candidate, pattern)) continue;
            found.push(file);
            if (found.length >= options.limit) break;
          }
          return found;
        },
      },
    });
    return await guarded.execute(id, args, signal, onUpdate, ctx);
  };
  // Keep the native schema and rendering; the implementation must never spawn a path-based search.
  const grep = createGrepToolDefinition(authority.targetPath);
  grep.description = "Search approved source files for literal text. Does not follow symlinks; skips .git and node_modules. Regular expressions are not accepted.";
  grep.promptSnippet = "Search approved source contents";
  const literalParameter = {
    ...grep.parameters.properties.literal,
    const: true,
    default: true,
    description: "Search is always literal; must be true when supplied.",
  };
  grep.parameters = {
    ...grep.parameters,
    properties: {
      ...grep.parameters.properties,
      literal: literalParameter,
    },
  };
  grep.execute = async (_id, args, signal) => {
    if (args.literal === false) throw new Error("Bound phase grep supports literal search only.");
    const input = resolve(authority.targetPath, args.path || ".");
    const directory = (await stat(input)).isDirectory();
    const literal = args.ignoreCase ? args.pattern.toLowerCase() : args.pattern;
    const output: string[] = [];
    const maximum = Math.max(1, args.limit ?? 100);
    const context = Math.max(0, Math.floor(args.context ?? 0));
    let matches = 0;
    for await (const file of files(input, signal)) {
      const name = directory ? relative(input, file).replaceAll("\\", "/") : basename(file);
      if (args.glob && !matchesGlob(args.glob.includes("/") ? name : basename(file), args.glob)) continue;
      const text = (await readFile(file)).toString("utf8");
      if (text.includes("\0")) continue;
      const lines = text.split(/\r?\n/u);
      for (let index = 0; index < lines.length; index += 1) {
        signal?.throwIfAborted();
        const line = lines[index]!;
        if (!(args.ignoreCase ? line.toLowerCase() : line).includes(literal)) continue;
        for (let row = Math.max(0, index - context); row <= Math.min(lines.length - 1, index + context); row += 1) {
          output.push(`${name}${row === index ? ":" : "-"}${row + 1}:${lines[row]}`);
        }
        matches += 1;
        if (matches >= maximum) break;
      }
      if (matches >= maximum) break;
    }
    const truncation = truncateHead(output.join("\n") || "No matches found");
    return {
      content: [{ type: "text", text: truncation.content }],
      details: {
        ...(truncation.truncated ? { truncation } : {}),
        ...(matches >= maximum ? { matchLimitReached: maximum } : {}),
      },
    };
  };
  if (allowed.has("read")) pi.registerTool(read);
  if (allowed.has("grep")) pi.registerTool(grep);
  if (allowed.has("find")) pi.registerTool(find);
  if (allowed.has("ls")) pi.registerTool(ls);
  pi.on("session_start", () => { pi.setActiveTools([...allowed]); });
  pi.on("tool_call", (event) => {
    if (!allowed.has(event.toolName)) return { block: true, reason: "Tool is outside the issued phase capability profile." };
  });
  pi.on("user_bash", () => ({ result: { output: "Shell execution is outside the issued phase capability profile.", exitCode: 1, cancelled: false, truncated: false } }));
  pi.registerCommand("pi-security-policy-ready", { description: "Host RPC tool authority is installed.", handler: async () => undefined });
}

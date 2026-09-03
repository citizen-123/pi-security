#!/usr/bin/env node
import { mkdir, rm } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { build } from "esbuild";

const root = dirname(fileURLToPath(import.meta.url));
await rm(resolve(root, "dist"), { recursive: true, force: true });
await mkdir(resolve(root, "dist"), { recursive: true });
await Promise.all([
  build({
    bundle: true,
    entryPoints: [resolve(root, "extensions/pi-security.ts")],
    external: ["@earendil-works/pi-coding-agent", "fsevents"],
    format: "esm",
    logLevel: "info",
    loader: { ".md": "text" },
    outfile: resolve(root, "dist/pi-security-extension.mjs"),
    platform: "node",
    target: "node20"
  }),
  build({
    banner: { js: "#!/usr/bin/env node" },
    bundle: true,
    entryPoints: [resolve(root, "src/cli/main.ts")],
    external: ["fsevents"],
    format: "esm",
    logLevel: "info",
    outfile: resolve(root, "dist/pi-security-cli.mjs"),
    platform: "node",
    target: "node20"
  })
]);

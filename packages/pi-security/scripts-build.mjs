#!/usr/bin/env node
import { chmod, mkdir, rm } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { build } from "esbuild";

const root = dirname(fileURLToPath(import.meta.url));
const output = resolve(root, "dist/server.cjs");
await rm(resolve(root, "dist"), { recursive: true, force: true });
await mkdir(resolve(root, "dist"), { recursive: true });
await build({
  banner: { js: "#!/usr/bin/env node" },
  bundle: true,
  entryPoints: [resolve(root, "main.ts")],
  external: ["fsevents"],
  format: "cjs",
  loader: { ".md": "text" },
  logLevel: "info",
  outfile: output,
  platform: "node",
  target: "node20"
});
await build({
  bundle: true,
  entryPoints: [resolve(root, "extensions/pi-security.ts")],
  external: ["@earendil-works/pi-coding-agent", "fsevents"],
  format: "esm",
  logLevel: "info",
  loader: { ".md": "text" },
  outfile: resolve(root, "dist/pi-security-extension.mjs"),
  platform: "node",
  target: "node20"
});
await chmod(output, 0o755);

import assert from "node:assert/strict";
import test from "node:test";
import { build } from "esbuild";

const packageRoot = new URL("..", import.meta.url).pathname;
const bundle = await build({
  bundle: true,
  format: "esm",
  platform: "node",
  stdin: {
    contents: [
      'export { registerPiSecurityLifecycleTools } from "./extensions/lifecycle-tools.ts";',
      'export { issuePiLifecycleContext } from "./src/pi-permission-profile.ts";'
    ].join("\n"),
    loader: "ts",
    resolveDir: packageRoot
  },
  write: false
});
const { issuePiLifecycleContext, registerPiSecurityLifecycleTools } = await import(
  `data:text/javascript;base64,${Buffer.from(bundle.outputFiles[0].contents).toString("base64")}`
);

test("the Deep Scan tool renders structured progress instead of a generic spinner", () => {
  const tools = new Map();
  registerPiSecurityLifecycleTools({
    on() {},
    registerTool(tool) {
      tools.set(tool.name, tool);
    }
  }, issuePiLifecycleContext({
    targetRoot: "/target",
    scanId: "scan",
    artifactRoot: "/artifacts"
  }));

  const deepScan = tools.get("start_pi_security_deep_scan");
  assert.ok(deepScan);
  assert.match(
    deepScan.renderCall().render(160).join("\n"),
    /preparing independent reviews/u
  );
  assert.match(
    deepScan.renderResult({
      content: [{ type: "text", text: "fallback" }],
      details: { statusText: "Deep Scan: 2 independent Standard reviews completed." }
    }, { isPartial: true }).render(160).join("\n"),
    /2 independent Standard reviews completed/u
  );
});

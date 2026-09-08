import assert from "node:assert/strict";
import { mkdtemp, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import test from "node:test";

const packageRoot = resolve(import.meta.dirname, "..");
const contract = JSON.parse(
  await readFile(resolve(import.meta.dirname, "fixtures/native-lifecycle-tools.json"), "utf8")
);

function normalizeSchema(value, parentKey = "") {
  if (Array.isArray(value)) {
    const normalized = value.map((item) => normalizeSchema(item));
    return parentKey === "required" && normalized.every((item) => typeof item === "string")
      ? normalized.sort()
      : normalized;
  }
  if (!value || typeof value !== "object") return value;
  return Object.fromEntries(
    Object.entries(value)
      .filter(([key]) => !key.startsWith("~"))
      .map(([key, child]) => [key, normalizeSchema(child, key)])
      .sort(([left], [right]) => left.localeCompare(right))
  );
}

function extensionHarness() {
  const commands = new Map();
  const events = new Map();
  const tools = new Map();
  const sentMessages = [];
  return {
    commands,
    events,
    sentMessages,
    tools,
    api: {
      on(name, handler) {
        const handlers = events.get(name) ?? [];
        handlers.push(handler);
        events.set(name, handlers);
      },
      registerCommand(name, command) {
        commands.set(name, command);
      },
      registerTool(tool) {
        assert.equal(tools.has(tool.name), false, `duplicate Pi tool ${tool.name}`);
        tools.set(tool.name, tool);
      },
      sendUserMessage(message, options) {
        sentMessages.push({ message, options });
      }
    }
  };
}

function successfulDetails(result, name) {
  assert.equal(result.isError, undefined, `${name}: ${result.content?.[0]?.text ?? "tool error"}`);
  return result.details;
}

test("the Pi extension exposes and executes the managed lifecycle catalog", async () => {
  const fixtureRoot = await mkdtemp(join(tmpdir(), "pi-security-extension-lifecycle-"));
  const target = join(fixtureRoot, "target");
  const state = join(fixtureRoot, "state");
  const scans = join(fixtureRoot, "scans");
  const previousState = process.env.PI_SECURITY_STATE_DIR;
  const previousScanRoot = process.env.PI_SECURITY_SCAN_ROOT;
  process.env.PI_SECURITY_STATE_DIR = state;
  process.env.PI_SECURITY_SCAN_ROOT = scans;

  try {
    await mkdir(target, { recursive: true });
    await writeFile(join(target, "fixture.py"), "print('fixture')\n");
    const extensionUrl = pathToFileURL(
      resolve(packageRoot, "dist/pi-security-extension.mjs")
    );
    extensionUrl.searchParams.set("lifecycle-test", fixtureRoot);
    const { default: loadExtension } = await import(extensionUrl.href);
    const harness = extensionHarness();
    loadExtension(harness.api);

    const expectedNames = [
      ...contract.surfaces.standalone,
      "inspect_pi_security_canonical_run",
      "start_pi_security_canonical_scan",
      "pi_security_control_agents",
      "pi_security_spawn_agents",
      "pi_security_workbench"
    ].sort();
    assert.equal(contract.surfaces.standalone.length, 44);
    assert.deepEqual([...harness.tools.keys()].sort(), expectedNames);
    assert.deepEqual(
      [...harness.commands.keys()].sort(),
      ["deep-security-scan", "security-diff-scan", "security-scan"],
    );
    await harness.commands.get("deep-security-scan").handler("focus on auth");
    assert.deepEqual(harness.sentMessages.at(-1), {
      message: "/deep-security-scan focus on auth",
      options: { deliverAs: "followUp" },
    });

    const contractByName = new Map(contract.tools.map((tool) => [tool.name, tool]));
    for (const name of contract.surfaces.standalone) {
      const registration = harness.tools.get(name);
      assert.ok(registration, name);
      assert.deepEqual(
        normalizeSchema(registration.parameters),
        contractByName.get(name).inputSchema,
        `${name} Pi input schema`
      );
    }

    const selectedOptions = [];
    const sessionId = "native-lifecycle-session";
    const context = {
      hasUI: true,
      model: undefined,
      modelRegistry: { getAvailable: () => [] },
      sessionManager: {
        getEntries: () => [],
        getSessionId: () => sessionId,
      },
      ui: {
        async select(_title, options) {
          selectedOptions.push(options);
          return options[0];
        },
      },
    };
    const execute = async (name, params) => {
      const registration = harness.tools.get(name);
      assert.ok(registration, name);
      return registration.execute(
        `call-${name}`,
        params,
        undefined,
        undefined,
        context
      );
    };
    const call = async (name, params) =>
      successfulDetails(await execute(name, params), name);

    const duplicateQuestion = {
      header: "First choice",
      id: "duplicate_id",
      question: "Choose the first option.",
      options: [
        { label: "One", description: "Choose one." },
        { label: "Two", description: "Choose two." }
      ]
    };
    await assert.rejects(
      execute("request_pi_security_user_input", {
        questions: [
          duplicateQuestion,
          {
            ...duplicateQuestion,
            header: "Second choice",
            question: "Choose the second option."
          }
        ]
      }),
      /Question IDs must be unique/u
    );
    const input = await call("request_pi_security_user_input", {
      questions: [duplicateQuestion],
    });
    assert.equal(input.status, "accepted");
    assert.deepEqual(input.answers, { duplicate_id: "One" });
    assert.match(selectedOptions[0][0], /^One — Choose one\./u);
    await assert.rejects(
      execute("start_pi_security_prompt_only_scan", {
        mode: "diff",
        targetPath: target,
        scope: "."
      }),
      /Review changes prompt-only scans require diffTarget/u
    );

    const started = await call("start_pi_security_standard_scan", {
      targetPath: `  ${target}  `,
      scope: ".",
      targetSummary: "Temporary Pi extension lifecycle fixture"
    });
    assert.equal(started.startDisposition, "created");
    assert.equal(started.scan.progress.status, "running");
    assert.equal(started.scan.continuationThreadId, sessionId);
    assert.equal(started.scan.targetPath, target);
    assert.match(started.scanId, /^[0-9a-f-]{36}$/u);
    assert.match(started.handoffClaimToken, /^[0-9a-f-]{36}$/u);

    await call("update_pi_security_scan_progress", {
      scanId: started.scanId,
      handoffClaimToken: started.handoffClaimToken,
      preflightChecks: []
    });
    const progressed = await call("update_pi_security_scan_progress", {
      scanId: started.scanId,
      handoffClaimToken: started.handoffClaimToken,
      phase: "threat_model"
    });
    assert.equal(progressed.scan.progress.phase, "threat_model");

    const draft = await call("record_pi_security_scan_draft", {
      scanId: started.scanId,
      handoffClaimToken: started.handoffClaimToken,
      findings: [],
      coverage: {
        completeness: "complete",
        surfaces: [],
        explicitExclusions: [],
        deferred: []
      }
    });
    assert.equal(draft.status, "draft_written");

    const completed = await call("complete_pi_security_scan", {
      scanId: started.scanId,
      handoffClaimToken: started.handoffClaimToken
    });
    assert.equal(completed.scan.progress.status, "complete");

    const retrieved = await call("get_pi_security_completed_scan", {
      scanId: started.scanId,
      handoffClaimToken: started.handoffClaimToken
    });
    assert.deepEqual(retrieved.findings.findings, []);
    assert.equal(retrieved.coverage.completeness, "complete");
    assert.equal(retrieved.manifest.scan.sealedAt.length > 0, true);
  } finally {
    if (previousState === undefined) delete process.env.PI_SECURITY_STATE_DIR;
    else process.env.PI_SECURITY_STATE_DIR = previousState;
    if (previousScanRoot === undefined) delete process.env.PI_SECURITY_SCAN_ROOT;
    else process.env.PI_SECURITY_SCAN_ROOT = previousScanRoot;
    await rm(fixtureRoot, { recursive: true, force: true });
  }
});

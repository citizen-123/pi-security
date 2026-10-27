// Differential test of src/contract/finalize.ts for the paths the curated parity cases do not reach: export output
// aliasing, sealed-artifact protection, report output checks, re-finalization, receipts, and tampering. Each scenario
// starts from the curated finalize/standard-single input, runs the same calls through Python
// (scripts/finalize_scan_contract.py, scripts/validate_scan_contract.py) and through the port, and requires the same
// outcomes (ContractError messages included) and the same resulting tree.
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { cpSync, linkSync, lstatSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, readlinkSync, realpathSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { createHash } from "node:crypto";
import { join, resolve } from "node:path";
import { test } from "node:test";
import { build } from "esbuild";

const packageRoot = resolve(import.meta.dirname, "..");
const schemaDir = join(packageRoot, "schemas");
const input = join(packageRoot, "tests/parity/cases/finalize/standard-single/input/scan");
const bundled = await build({
  bundle: true,
  stdin: { contents: 'export * from "./src/contract/finalize.ts";', resolveDir: packageRoot },
  format: "esm",
  platform: "node",
  write: false,
});
const finalize = await import(`data:text/javascript;base64,${Buffer.from(bundled.outputFiles[0].contents).toString("base64")}`);

// Calls are [function, ...args]; "$scan" and "$sandbox" become absolute paths.
const PYTHON_RUNNER = `
import base64, importlib.util, json, sys
from pathlib import Path
def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module
finalizer = load("finalize_scan_contract", sys.argv[1])
validator = load("validate_scan_contract", sys.argv[2])
outcomes = []
for call in json.loads(sys.argv[3]):
    name, args = call[0], call[1:]
    try:
        if name == "finalize":
            finalizer.finalize_scan(Path(args[0]))
            result = None
        elif name == "export":
            result = base64.b64encode(finalizer.build_findings_export(Path(args[0]), args[1])).decode()
        elif name == "write_export":
            finalizer.write_export_output(Path(args[0]), Path(args[1]), args[2], args[3].encode())
            result = None
        elif name == "validate":
            result = validator.receipt(validator.validate_contract(Path(args[0])))["status"]
        outcomes.append({"ok": result})
    except ValueError as error:
        # validate_scan_contract loads its own finalizer copy, so match ContractError by name.
        outcomes.append({"error": str(error) if type(error).__name__ == "ContractError" else type(error).__name__})
    except OSError as error:
        outcomes.append({"error": type(error).__name__})
print(json.dumps(outcomes))
`;

function runPython(calls) {
  const result = spawnSync(
    process.env.PYTHON ?? "python3",
    ["-I", "-c", PYTHON_RUNNER, join(packageRoot, "scripts/finalize_scan_contract.py"), join(packageRoot, "scripts/validate_scan_contract.py"), JSON.stringify(calls)],
    { encoding: "utf8" },
  );
  assert.equal(result.status, 0, result.stderr);
  return JSON.parse(result.stdout);
}

function runPort(calls) {
  return calls.map(([name, ...args]) => {
    try {
      if (name === "finalize") finalize.finalizeScan(args[0], { schemaDir, warn: () => {} });
      if (name === "export") return { ok: finalize.buildFindingsExport(args[0], args[1], schemaDir).toString("base64") };
      if (name === "write_export") finalize.writeExportOutput(args[0], args[1], args[2], Buffer.from(args[3]));
      if (name === "validate") return { ok: finalize.contractReceipt(finalize.validateContract(args[0], schemaDir)).status };
      return { ok: null };
    } catch (error) {
      if (error.name === "ContractError") return { error: error.message };
      return { error: { ENOENT: "FileNotFoundError", ENOTDIR: "NotADirectoryError", EISDIR: "IsADirectoryError" }[error.code] ?? error.code ?? String(error) };
    }
  });
}

function tree(root, prefix = "") {
  const entries = {};
  for (const name of readdirSync(join(root, prefix)).sort()) {
    const relative = prefix ? `${prefix}/${name}` : name;
    const full = join(root, relative);
    const metadata = lstatSync(full);
    if (metadata.isSymbolicLink()) entries[relative] = { link: readlinkSync(full) };
    else if (metadata.isDirectory()) Object.assign(entries, { [relative]: { dir: (metadata.mode & 0o777).toString(8) } }, tree(root, relative));
    else entries[relative] = { file: readFileSync(full).toString("base64"), mode: (metadata.mode & 0o777).toString(8), links: metadata.nlink };
  }
  return entries;
}

const editJson = (path, edit) => {
  const value = JSON.parse(readFileSync(path, "utf8"));
  edit(value);
  writeFileSync(path, `${JSON.stringify(value, null, 2)}\n`);
};

const F = ["finalize", "$scan"];
const SCENARIOS = {
  "finalizes, re-finalizes, and validates": [() => {}, [F, F, ["validate", "$scan"]]],
  "removes a stale report.html": [(s) => writeFileSync(join(s, "scan/report.html"), "<p>stale</p>"), [F]],
  "refuses a symlinked report.md": [(s) => symlinkSync("../outside/report.md", join(s, "scan/report.md")), [F]],
  "refuses a directory at report.md": [(s) => mkdirSync(join(s, "scan/report.md")), [F]],
  "refuses a directory at report.html": [(s) => mkdirSync(join(s, "scan/report.html")), [F]],
  "seals coverage receipts": [
    (s) => {
      mkdirSync(join(s, "scan/artifacts"));
      writeFileSync(join(s, "scan/artifacts/receipt.txt"), "reviewed\n");
      editJson(join(s, "scan/coverage.json"), (coverage) => {
        coverage.surfaces[0].receiptRefs = ["artifacts/receipt.txt"];
      });
    },
    [F, ["validate", "$scan"]],
  ],
  "rejects a symlinked receipt": [
    (s) => {
      mkdirSync(join(s, "scan/artifacts"));
      writeFileSync(join(s, "outside/receipt.txt"), "elsewhere\n");
      symlinkSync("../../outside/receipt.txt", join(s, "scan/artifacts/receipt.txt"));
      editJson(join(s, "scan/coverage.json"), (coverage) => {
        coverage.surfaces[0].receiptRefs = ["artifacts/receipt.txt"];
      });
    },
    [F],
  ],
  "detects tampering after sealing": [() => {}, [F, ["tamper"], ["validate", "$scan"], ["export", "$scan", "csv"], F]],
  "rejects an unsealed scan for exports and validation": [() => {}, [["export", "$scan", "json"], ["validate", "$scan"]]],
  "exports every format": [() => {}, [F, ["export", "$scan", "json"], ["export", "$scan", "csv"], ["export", "$scan", "sarif"], ["export", "$scan", "xml"]]],
  "writes exports to their scan paths": [
    () => {},
    [F, ["write_export", "$scan", "$scan/exports/findings.csv", "csv", "a,b\r\n"], ["write_export", "$scan", "$scan/exports/findings.json", "json", "{}"]],
  ],
  "refuses other scan paths": [
    () => {},
    [
      F,
      ["write_export", "$scan", "$scan/findings.json", "json", "{}"],
      ["write_export", "$scan", "$scan/exports/findings.json", "csv", "x"],
      ["write_export", "$scan", "$scan/exports/../coverage.json", "json", "{}"],
      ["write_export", "$scan", "$scan", "json", "{}"],
    ],
  ],
  "writes outside the scan directory": [
    () => {},
    [F, ["write_export", "$scan", "$sandbox/outside/findings.csv", "csv", "x"], ["write_export", "$scan", "$sandbox/outside/missing/findings.csv", "csv", "x"]],
  ],
  "refuses an export through a symlinked scan alias": [
    (s) => symlinkSync("scan", join(s, "alias"), "dir"),
    [F, ["write_export", "$scan", "$sandbox/alias/exports/findings.csv", "csv", "x"]],
  ],
  "refuses an export path hard-linked to a sealed artifact": [
    () => {},
    [F, ["hardlink"], ["write_export", "$scan", "$scan/exports/findings.json", "json", "{}"]],
  ],
  "refuses an unsupported export format": [() => {}, [F, ["write_export", "$scan", "$sandbox/outside/out.xml", "xml", "x"]]],
  "rejects a case-colliding artifact record": [() => {}, [F, ["duplicate_artifact"], ["export", "$scan", "csv"]]],
  "rejects sealedAt that differs from completedAt": [() => {}, [F, ["move_seal"], ["export", "$scan", "csv"]]],
  "exports the sealed findings bytes as they are": [() => {}, [F, ["reformat_findings"], ["export", "$scan", "json"]]],
  "rejects a receipt missing from the seal": [
    (s) => {
      mkdirSync(join(s, "scan/artifacts"));
      for (const name of ["b.txt", "a.txt"]) writeFileSync(join(s, "scan/artifacts", name), `${name}\n`);
      editJson(join(s, "scan/coverage.json"), (coverage) => {
        coverage.surfaces[0].receiptRefs = ["artifacts/b.txt", "artifacts/a.txt"];
      });
    },
    [F, ["drop_receipt"], ["export", "$scan", "csv"]],
  ],
  "seals receipts in sorted order": [
    (s) => {
      mkdirSync(join(s, "scan/artifacts"));
      for (const name of ["b.txt", "a.txt"]) writeFileSync(join(s, "scan/artifacts", name), `${name}\n`);
      editJson(join(s, "scan/coverage.json"), (coverage) => {
        coverage.surfaces[0].receiptRefs = ["artifacts/b.txt", "artifacts/a.txt"];
      });
    },
    [F],
  ],
  "rejects a sealed finding identity that was changed": [() => {}, [F, ["change_identity"], ["export", "$scan", "csv"], ["validate", "$scan"]]],
  "validation requires the report": [() => {}, [F, ["remove_report"], ["validate", "$scan"]]],
  "normalizes open questions": [
    (s) =>
      editJson(join(s, "scan/coverage.json"), (coverage) => {
        coverage.openQuestions = ["  Is the parser reachable?  ", { question: "Who calls it?", followUpPrompt: " " }, 5];
      }),
    [F],
  ],
};

const sha256 = (path) => createHash("sha256").update(readFileSync(path)).digest("hex");

/** Edit the sealed manifest; with `resealFindings`, refresh the findings.json digest after editing that file. */
function editSealed(s, edit, resealFindings = false) {
  editJson(join(s, "scan/scan-manifest.json"), (manifest) => {
    edit(manifest.scan);
    if (resealFindings) manifest.scan.artifacts.find((artifact) => artifact.path === "findings.json").sha256 = sha256(join(s, "scan/findings.json"));
  });
}

// Steps that change the sandbox between calls, identically for both runs.
const ACTIONS = {
  duplicate_artifact: (s) => editSealed(s, (scan) => scan.artifacts.push({ ...scan.artifacts[0], path: "FINDINGS.json" })),
  move_seal: (s) => editSealed(s, (scan) => {
    scan.sealedAt = "2030-01-01T00:00:00Z";
  }),
  reformat_findings: (s) => {
    writeFileSync(join(s, "scan/findings.json"), JSON.stringify(JSON.parse(readFileSync(join(s, "scan/findings.json"), "utf8"))));
    editSealed(s, () => {}, true);
  },
  drop_receipt: (s) => editSealed(s, (scan) => {
    scan.artifacts = scan.artifacts.filter((artifact) => artifact.path !== "artifacts/a.txt");
  }),
  change_identity: (s) => {
    editJson(join(s, "scan/findings.json"), (findings) => {
      // Same format, different value: only the derived-identity check can tell.
      const id = findings.findings[0].findingId;
      findings.findings[0].findingId = id.slice(0, -1) + (id.endsWith("0") ? "1" : "0");
    });
    editSealed(s, () => {}, true);
  },
  remove_report: (s) => rmSync(join(s, "scan/report.md")),
  tamper: (s) => editJson(join(s, "scan/findings.json"), (findings) => {
    findings.findings[0].title = "Changed after sealing";
  }),
  hardlink: (s) => {
    mkdirSync(join(s, "scan/exports"), { recursive: true });
    rmSync(join(s, "scan/exports/findings.json"), { force: true });
    linkSync(join(s, "scan/findings.json"), join(s, "scan/exports/findings.json"));
  },
};

function sandbox(setup) {
  const root = realpathSync(mkdtempSync(join(tmpdir(), "pi-security-finalize-")));
  cpSync(input, join(root, "scan"), { recursive: true });
  mkdirSync(join(root, "outside"));
  setup(root);
  return root;
}

/** Run calls in order, splitting at sandbox actions so both implementations see the same changes. */
function runAll(run, root, calls) {
  const outcomes = [];
  let batch = [];
  const flush = () => {
    if (batch.length > 0) outcomes.push(...run(batch));
    batch = [];
  };
  for (const [name, ...args] of calls) {
    if (Object.hasOwn(ACTIONS, name)) {
      flush();
      ACTIONS[name](root);
      outcomes.push({ action: name });
    } else {
      batch.push([name, ...args.map((arg) => arg.replace("$scan", join(root, "scan")).replace("$sandbox", root))]);
    }
  }
  flush();
  return outcomes;
}

for (const [name, [setup, calls]] of Object.entries(SCENARIOS)) {
  test(`finalization matches Python: ${name}`, { skip: process.platform === "win32" ? "POSIX symlink fixtures" : false }, () => {
    const results = [];
    for (const run of [runPython, runPort]) {
      const root = sandbox(setup);
      try {
        const outcomes = runAll(run, root, calls);
        results.push({ outcomes, tree: tree(root) });
      } finally {
        rmSync(root, { recursive: true, force: true });
      }
    }
    assert.deepEqual(results[1], results[0]);
  });
}

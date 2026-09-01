import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import test from "node:test";
import {
  defaultCasesPath,
  defaultResultsPath,
  evaluateFixture,
} from "../evals/triage-sastbench/evaluate.mjs";

async function documents() {
  return {
    casesDocument: JSON.parse(await readFile(defaultCasesPath, "utf8")),
    resultsDocument: JSON.parse(await readFile(defaultResultsPath, "utf8")),
    fixtureDirectory: resolve(defaultCasesPath, ".."),
  };
}

test("synthetic triage fixtures grade every source anchor, verdict, severity, dedup, and report", async () => {
  const outcome = await evaluateFixture(await documents());
  assert.equal(outcome.pass, true, outcome.failures.join("\n"));
  assert.deepEqual(outcome.metrics, {
    caseCount: 7,
    resultCount: 7,
    exactCaseCount: 7,
    expectedVerdicts: { confirmed: 5, not_actionable: 1, needs_review: 1 },
    observedVerdicts: { confirmed: 5, not_actionable: 1, needs_review: 1 },
    uniqueFindingCount: 5,
  });
});

test("fixture evaluator rejects split dedup groups and weakened severity or reports", async () => {
  const input = await documents();
  const duplicate = input.resultsDocument.results.find(
    (entry) => entry.caseId === "sql-search-duplicate",
  );
  duplicate.dedupKey = "CWE-89|src/server.js|different-root";
  const traversal = input.resultsDocument.results.find(
    (entry) => entry.caseId === "download-traversal",
  );
  traversal.severity = "low";
  traversal.report = "Path traversal without an evidence location.";

  const outcome = await evaluateFixture(input);
  assert.equal(outcome.pass, false);
  assert.ok(outcome.failures.some((failure) => /dedup group sql-search split/u.test(failure)));
  assert.ok(outcome.failures.some((failure) => /download-traversal: severity expected "high"/u.test(failure)));
  assert.ok(outcome.failures.some((failure) => /report is missing "src\/server\.js:27-30"/u.test(failure)));
});

test("fixture evaluator refuses source anchors outside the synthetic repository", async () => {
  const input = await documents();
  input.casesDocument.cases[0].source.path = "../../expected-results.json";
  const outcome = await evaluateFixture(input);
  assert.equal(outcome.pass, false);
  assert.ok(outcome.failures.some((failure) => /source path escapes the fixture repository/u.test(failure)));
});

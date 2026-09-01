import { readFile } from "node:fs/promises";
import { dirname, isAbsolute, relative, resolve, sep } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const evaluationRoot = dirname(fileURLToPath(import.meta.url));
export const defaultCasesPath = resolve(evaluationRoot, "fixtures/cases.json");
export const defaultResultsPath = resolve(evaluationRoot, "fixtures/expected-results.json");

async function readJson(path) {
  return JSON.parse(await readFile(path, "utf8"));
}

function inside(root, candidate) {
  const local = relative(root, candidate);
  return local === "" || (!local.startsWith(`..${sep}`) && local !== ".." && !isAbsolute(local));
}

function countByVerdict(rows) {
  const counts = { confirmed: 0, not_actionable: 0, needs_review: 0 };
  for (const row of rows) {
    if (Object.hasOwn(counts, row.verdict)) counts[row.verdict] += 1;
  }
  return counts;
}

export async function evaluateFixture({
  casesDocument,
  resultsDocument,
  fixtureDirectory = resolve(evaluationRoot, "fixtures"),
}) {
  const failures = [];
  if (casesDocument?.schemaVersion !== "pi-security.synthetic-triage-cases/v1") {
    failures.push("unsupported cases schemaVersion");
  }
  if (resultsDocument?.schemaVersion !== "pi-security.synthetic-triage-results/v1") {
    failures.push("unsupported results schemaVersion");
  }
  const cases = Array.isArray(casesDocument?.cases) ? casesDocument.cases : [];
  const results = Array.isArray(resultsDocument?.results) ? resultsDocument.results : [];
  const caseIds = new Set();
  const resultById = new Map();
  for (const entry of cases) {
    if (typeof entry?.caseId !== "string" || !entry.caseId || caseIds.has(entry.caseId)) {
      failures.push(`invalid or duplicate case id ${JSON.stringify(entry?.caseId)}`);
    } else {
      caseIds.add(entry.caseId);
    }
  }
  for (const result of results) {
    if (typeof result?.caseId !== "string" || !result.caseId || resultById.has(result.caseId)) {
      failures.push(`invalid or duplicate result id ${JSON.stringify(result?.caseId)}`);
    } else {
      resultById.set(result.caseId, result);
    }
  }
  for (const resultId of resultById.keys()) {
    if (!caseIds.has(resultId)) failures.push(`unexpected result ${resultId}`);
  }

  const repositoryRoot = resolve(fixtureDirectory, String(casesDocument?.repository ?? ""));
  const directFailures = new Set();
  const dedupGroups = new Map();
  const dedupOwners = new Map();
  for (const entry of cases) {
    const id = entry.caseId;
    const result = resultById.get(id);
    const expected = entry.expected ?? {};
    const source = entry.source ?? {};
    const sourcePath = resolve(repositoryRoot, String(source.path ?? ""));
    if (!inside(repositoryRoot, sourcePath)) {
      failures.push(`${id}: source path escapes the fixture repository`);
      directFailures.add(id);
    } else {
      try {
        const lines = (await readFile(sourcePath, "utf8")).split(/\r?\n/u);
        const line = lines[Number(source.line) - 1];
        if (!line || !line.includes(String(source.contains ?? ""))) {
          failures.push(`${id}: source anchor no longer matches ${source.path}:${source.line}`);
          directFailures.add(id);
        }
      } catch (error) {
        failures.push(`${id}: source fixture is unreadable: ${error.message}`);
        directFailures.add(id);
      }
    }
    if (!result) {
      failures.push(`${id}: missing result`);
      directFailures.add(id);
      continue;
    }
    for (const field of ["verdict", "severity"]) {
      if (result[field] !== expected[field]) {
        failures.push(`${id}: ${field} expected ${JSON.stringify(expected[field])}, got ${JSON.stringify(result[field])}`);
        directFailures.add(id);
      }
    }
    if (expected.dedupGroup === null) {
      if (result.dedupKey !== null) {
        failures.push(`${id}: non-actionable case must not have a dedup key`);
        directFailures.add(id);
      }
    } else if (typeof result.dedupKey !== "string" || !result.dedupKey) {
      failures.push(`${id}: expected a nonempty dedup key`);
      directFailures.add(id);
    } else {
      const prior = dedupGroups.get(expected.dedupGroup);
      if (prior !== undefined && prior !== result.dedupKey) {
        failures.push(`${id}: dedup group ${expected.dedupGroup} split across keys`);
        directFailures.add(id);
      }
      dedupGroups.set(expected.dedupGroup, result.dedupKey);
      const owner = dedupOwners.get(result.dedupKey);
      if (owner !== undefined && owner !== expected.dedupGroup) {
        failures.push(`${id}: unrelated groups ${owner} and ${expected.dedupGroup} share a dedup key`);
        directFailures.add(id);
      }
      dedupOwners.set(result.dedupKey, expected.dedupGroup);
    }
    if (typeof result.report !== "string") {
      failures.push(`${id}: report is missing`);
      directFailures.add(id);
    } else {
      for (const fragment of expected.reportIncludes ?? []) {
        if (!result.report.toLowerCase().includes(String(fragment).toLowerCase())) {
          failures.push(`${id}: report is missing ${JSON.stringify(fragment)}`);
          directFailures.add(id);
        }
      }
    }
  }

  return {
    pass: failures.length === 0,
    failures,
    metrics: {
      caseCount: cases.length,
      resultCount: results.length,
      exactCaseCount: cases.length - directFailures.size,
      expectedVerdicts: countByVerdict(cases.map((entry) => entry.expected ?? {})),
      observedVerdicts: countByVerdict(results),
      uniqueFindingCount: new Set(
        results.map((entry) => entry.dedupKey).filter((value) => typeof value === "string" && value),
      ).size,
    },
  };
}

export async function evaluateFiles(resultsPath = defaultResultsPath, casesPath = defaultCasesPath) {
  return evaluateFixture({
    casesDocument: await readJson(casesPath),
    resultsDocument: await readJson(resultsPath),
    fixtureDirectory: resolve(dirname(casesPath)),
  });
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  const outcome = await evaluateFiles(process.argv[2] ? resolve(process.argv[2]) : defaultResultsPath);
  process.stdout.write(`${JSON.stringify(outcome, null, 2)}\n`);
  if (!outcome.pass) process.exitCode = 1;
}

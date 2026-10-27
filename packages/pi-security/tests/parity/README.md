# Parity oracle

Contract for porting the Python scripts to TypeScript (`openspec/changes/durable-runtime`, design D9). The Python implementation produces the expected outputs; TypeScript ports must reproduce them byte for byte. The goldens and vectors stay after the Python code is deleted, so they remain the contract.

## Two tiers

**Curated cases** (`cases/`, `goldens/`). End-to-end runs of each script. Each case is an `input/` tree plus `case.json`: optional Git repository spec (`git`), symlinks (`symlinks`), and `steps` run in order in one work directory. A golden records each step's status (`ok` or `rejected`), stdout where the step's output is the product (`"stdout": "compare"`), and every file left in the work directory. Absolute work paths are recorded as `<WORK>`.

| Suite | Script | Covers |
|---|---|---|
| `finalize`, `export-{json,csv,sarif}` | `finalize_scan_contract.py` | Sealing, fingerprints, IDs, report, SARIF and exports for standard, diff, deep, partial, empty, unicode, and number/ordering-trap scans; rejections |
| `validate` | `validate_scan_contract.py` | Receipts; unsealed and tampered scans |
| `normalize` | `normalize_candidates.py` | Merging, location ordering, CWE forms, code-point ordering, CRLF scope lists, symlinks, deleted scope paths; rejections |
| `inventory` | `generate_in_scope_files.py` | Git and directory inventories, revision and local-patch diffs, exclusions, binaries, renames, deletes; rejections |
| `preflight` | `config_preflight.py` | Ready, blocked, malformed checks |
| `patch-risk` | `skills/assess-patch-risk/scripts/validate_patch_risk_assessment.py` | Every workflow gate; malformed JSON |

**Recorded vectors** (`vectors/`). Input/output pairs of pure functions (report rendering, SARIF, fingerprints, stable IDs, canonical JSON), captured from every call made by the fixed-fixture test modules of the existing pytest suite (`SOURCE_TESTS` in `record_vectors.py`). This reaches many more edge cases than the curated tier, including hostile strings with lone surrogates. Calls from workbench-flow tests are excluded because they carry wall-clock timestamps and random UUIDs, as are vectors over 256 KB (size-limit tests). CSV export and candidate merging only run through subprocesses in the suite, so the curated cases cover them.

Ports must reproduce statuses, compared stdout, files, and vector results. Python's error text is kept in goldens for reference only.

## Traps the goldens pin

- Canonical JSON is `json.dumps(indent=2, sort_keys=True)` with `ensure_ascii=True`: non-ASCII is written as `\uXXXX`, characters above U+FFFF as surrogate pairs. `JSON.stringify` writes raw UTF-8.
- Python writes `7.0` for an integral float; `JSON.stringify` writes `7`.
- Python sorts strings by code point; JavaScript's default sort uses UTF-16 code units, which disagree above U+FFFF.
- CSV exports use CRLF line endings.
- Diff inventories list deleted files and record renames under the new path.

## Commands

From `packages/pi-security`:

```bash
python3 tests/parity/build_cases.py            # regenerate cases/ from the builder
python3 tests/parity/build_cases.py --check    # fail if cases/ is stale
python3 tests/parity/oracle.py --write         # regenerate goldens/ from Python
python3 tests/parity/oracle.py                 # fail if Python output differs from goldens/
python3 tests/parity/record_vectors.py         # rerun the source test modules and regenerate vectors/ (Python 3.12+, pytest)
python3 tests/parity/record_vectors.py --check # fail if vectors/ differs from a fresh recording
node --test tests/parity.test.mjs              # check registered TypeScript ports
PI_SECURITY_PARITY_SELF_TEST=python node --test tests/parity.test.mjs   # check this harness via Python
```

`tests/test_parity_oracle.py` runs all three checks with the Python suite (`npm run test:python`); the vector check is skipped below Python 3.12. Run the recorder with `PYTHONPATH=tests`, as the suite does.

## Adding a port

Register it in `ports.mjs` in the change that adds it. A case runs once every tool its steps name is registered, and a vector file runs once its function is registered. Until then they are skipped with the reason shown.

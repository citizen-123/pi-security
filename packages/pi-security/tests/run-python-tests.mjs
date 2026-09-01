import { spawn } from "node:child_process";
import { delimiter, resolve } from "node:path";
import { build } from "esbuild";

const packageRoot = resolve(import.meta.dirname, "..");
const resolverBundle = await build({
  bundle: true,
  entryPoints: [resolve(packageRoot, "src/python_command.ts")],
  format: "esm",
  platform: "node",
  write: false,
});
const { resolvePythonCommand } = await import(
  `data:text/javascript;base64,${Buffer.from(resolverBundle.outputFiles[0].contents).toString("base64")}`
);
const pythonCommand = await resolvePythonCommand();
const requirementsPath = resolve(packageRoot, "requirements-test.txt");
const testEnvironment = {
  ...process.env,
  PYTHONDONTWRITEBYTECODE: "1",
  PYTHONUTF8: "1",
  PYTHONPATH: [resolve(packageRoot, "tests"), process.env.PYTHONPATH]
    .filter(Boolean)
    .join(delimiter),
};

function runPython(arguments_) {
  return new Promise((resolveRun, rejectRun) => {
    const child = spawn(pythonCommand, arguments_, {
      cwd: packageRoot,
      env: testEnvironment,
      stdio: "inherit",
    });
    child.once("error", rejectRun);
    child.once("exit", (code, signal) => {
      if (signal) {
        rejectRun(new Error(`Python test process stopped by ${signal}.`));
      } else {
        resolveRun(code ?? 1);
      }
    });
  });
}

const dependencyStatus = await runPython([
  "-c",
  "import jsonschema, pytest, referencing",
]);
if (dependencyStatus !== 0) {
  process.stderr.write(
    `Install the declared Python test environment with ${pythonCommand} -m pip install -r ${requirementsPath}\n`,
  );
  process.exitCode = dependencyStatus;
} else {
  process.exitCode = await runPython(["-m", "pytest", "tests"]);
}

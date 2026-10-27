// Host capability preflight: whether the scan working directory is reachable, plus the runtime capabilities the host
// reports. Port of scripts/config_preflight.py.
import { lstatSync, readlinkSync, statSync } from "node:fs";
import { homedir } from "node:os";
import { compareCodePoints, dumpsPython, pythonRepr } from "../contract/python-json.js";

export const PREFLIGHT_PROFILES = ["deep_security_scan", "security_diff_scan", "security_scan"] as const;
export type PreflightProfile = (typeof PREFLIGHT_PROFILES)[number];

export type PreflightResult = { capability: string; reason: string; severity: "block" | "suggest"; status: "pass" | "fail" | "unknown" };
export type PreflightReport = { profile: PreflightProfile; status: "ready" | "blocked"; results: PreflightResult[] };

export class PreflightError extends Error {
  override name = "PreflightError";
}

/** posixpath.realpath(path, strict=False) as of Python 3.13: missing components are kept and walking continues. */
export function pythonRealpath(path: string, cwd = process.cwd()): string {
  const rest: (string | null)[] = path.split("/").reverse();
  let partCount = rest.length;
  let resolved = path.startsWith("/") ? "/" : cwd;
  const seen = new Map<string, string | null>();
  while (partCount > 0) {
    const name = rest.pop()!;
    if (name === null) {
      seen.set(rest.pop()!, resolved);
      continue;
    }
    partCount -= 1;
    if (name === "" || name === ".") continue;
    if (name === "..") {
      resolved = resolved.slice(0, resolved.lastIndexOf("/")) || "/";
      continue;
    }
    const next = resolved === "/" ? `/${name}` : `${resolved}/${name}`;
    let target: string;
    try {
      if (!lstatSync(next).isSymbolicLink()) {
        resolved = next;
        continue;
      }
      if (seen.has(next)) {
        const known = seen.get(next)!;
        // A loop keeps the link path itself.
        resolved = known ?? next;
        continue;
      }
      target = readlinkSync(next);
    } catch {
      resolved = next;
      continue;
    }
    if (target.startsWith("/")) resolved = "/";
    seen.set(next, null);
    rest.push(next, null);
    const targetParts = target.split("/").reverse();
    rest.push(...targetParts);
    partCount += targetParts.length;
  }
  return resolved;
}

/** Path(value).expanduser().resolve() */
function resolveWorkingDirectory(value: string): string {
  const expanded = value === "~" || value.startsWith("~/") ? homedir() + value.slice(1) : value;
  return pythonRealpath(expanded);
}

/** NAME=true or NAME=false (any case); a repeated name keeps its last value. */
export function parseRuntimeChecks(values: string[]): Map<string, boolean> {
  const checks = new Map<string, boolean>();
  for (const value of values) {
    const separator = value.indexOf("=");
    const name = separator < 0 ? value : value.slice(0, separator);
    const raw = separator < 0 ? "" : value.slice(separator + 1).toLowerCase();
    if (separator < 0 || !name || (raw !== "true" && raw !== "false")) {
      throw new PreflightError(`Invalid --runtime-check ${pythonRepr(value)}; expected NAME=true or NAME=false.`);
    }
    checks.set(name, raw === "true");
  }
  return checks;
}

export function evaluatePreflight(profile: PreflightProfile, cwd: string, runtimeChecks: string[]): PreflightReport {
  const directory = resolveWorkingDirectory(cwd);
  let accessible = false;
  try {
    accessible = statSync(directory).isDirectory();
  } catch {
    // Path.is_dir() is False when the path cannot be inspected.
  }
  const results: PreflightResult[] = [
    {
      capability: "target_access",
      reason: accessible ? `Scan working directory is available: ${directory}` : `Scan working directory is not an accessible directory: ${directory}`,
      severity: "block",
      status: accessible ? "pass" : "fail"
    }
  ];
  const checks = [...parseRuntimeChecks(runtimeChecks)].sort(([left], [right]) => compareCodePoints(left, right));
  for (const [name, available] of checks) {
    results.push({
      capability: name,
      reason: available
        ? `The active host reports ${name} is available.`
        : `The active host reports ${name} is unavailable; use the documented single-agent fallback.`,
      severity: "suggest",
      status: available ? "pass" : "unknown"
    });
  }
  const blocked = results.some((result) => result.severity === "block" && result.status === "fail");
  return { profile, status: blocked ? "blocked" : "ready", results };
}

/** The report as config_preflight.py prints it: compact JSON, non-ASCII escaped, then a newline. */
export function formatPreflightReport(report: PreflightReport): string {
  return `${dumpsPython(report, { separators: [",", ":"] })}\n`;
}

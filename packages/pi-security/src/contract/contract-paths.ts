// Repository- and scan-relative path checks. Port of _require_safe_relative_path,
// _require_portable_relative_path, and _windows_unsafe_path_component in scripts/finalize_scan_contract.py.
import { ContractError, isBlank } from "./contract-error.js";
import { hasLoneSurrogate } from "./python-json.js";

const WINDOWS_UNSAFE_COMPONENT =
  /[<>:"|?*\x00-\x1f]|[ .]$|^(?:con|prn|aux|nul|conin\$|conout\$|com[1-9\xb9\xb2\xb3]|lpt[1-9\xb9\xb2\xb3])(?:\..*)?$/iu;
const LETTER = /^\p{L}$/u;

/** PurePosixPath(value).as_posix() for a relative path: empty and "." components dropped. */
export function normalizePosixPath(value: string): string {
  const parts = value.split("/").filter((part) => part !== "" && part !== ".");
  return parts.length === 0 ? "." : parts.join("/");
}

export function requireSafeRelativePath(value: string, context: string, allowDot = false): string {
  const fail = () => new ContractError(`${context}: expected a safe repository-relative POSIX path`);
  if (hasLoneSurrogate(value)) throw fail();
  const normalized = normalizePosixPath(value);
  const characters = [...value];
  if (
    isBlank(value) ||
    (normalized === "." && !allowDot) ||
    (characters.length >= 2 && LETTER.test(characters[0]!) && characters[1] === ":") ||
    value.includes("\\") ||
    value.includes("\0") ||
    characters.some((character) => character.codePointAt(0)! < 32) ||
    value.startsWith("/") ||
    value.split("/").includes("..")
  ) {
    throw fail();
  }
  return normalized;
}

export function windowsUnsafePathComponent(value: string): boolean {
  if (value === "" || value === ".") return false;
  return WINDOWS_UNSAFE_COMPONENT.test(value);
}

/** A safe relative path that is also valid on Windows. */
export function requirePortableRelativePath(value: string, context: string, allowDot = false): string {
  const normalized = requireSafeRelativePath(value, context, allowDot);
  if (value.split("/").some(windowsUnsafePathComponent)) {
    throw new ContractError(`${context}: expected a safe scan-relative POSIX path`);
  }
  return normalized;
}

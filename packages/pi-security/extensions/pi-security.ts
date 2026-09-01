import { execFile } from "node:child_process";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";
import { promisify } from "node:util";
import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";
import { Type } from "typebox";
import { executeTrustedWorkbench } from "../src/execution-boundary.js";
import {
  assertPiPermissionSurface,
  issuePiDelegatingAgentContext,
  issuePiLifecycleContext,
  issuePiWorkbenchContext,
  piPermissionSurfaceAllowed
} from "../src/pi-permission-profile.js";
import { resolvePythonCommand } from "../src/python_command.js";
import { registerSecuritySubagentTools } from "./subagent-tools.js";
import { registerPiSecurityLifecycleTools } from "./lifecycle-tools.js";

const execFileAsync = promisify(execFile);
const packageRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const workbench = resolve(packageRoot, "scripts/workbench_db.py");


export default function piSecurity(pi: ExtensionAPI): void {
  const permissionBindings = {
    targetRoot: packageRoot,
    scanId: "pi-security-extension",
    artifactRoot: packageRoot
  };
  const lifecycleContext = issuePiLifecycleContext(permissionBindings);
  const workbenchContext = issuePiWorkbenchContext(permissionBindings);
  const delegationRegistrationContext = issuePiDelegatingAgentContext(permissionBindings, 1);
  registerSecuritySubagentTools(pi, delegationRegistrationContext);
  registerPiSecurityLifecycleTools(pi, lifecycleContext);
  if (piPermissionSurfaceAllowed(workbenchContext, "workbench")) {
    pi.registerTool({
    name: "pi_security_workbench",
    label: "Pi Security Workbench",
    description: "Run a Pi Security lifecycle, finding, export, triage, remediation, or scan-artifact workbench operation. Arguments match workbench_db.py.",
    parameters: Type.Object({
      command: Type.String({ description: "Workbench subcommand, such as inspect-target, start-prompt-only-scan, get-scan, list-findings, or complete-scan." }),
      args: Type.Optional(Type.Array(Type.String(), { description: "Arguments following the subcommand, without a shell." })),
      stdin: Type.Optional(Type.String({ description: "Optional standard input for operations accepting JSON or user context." }))
    }),
    async execute(_toolCallId, params, signal) {
      assertPiPermissionSurface(workbenchContext, "workbench", "pi_security_workbench");
      const pythonCommand = await resolvePythonCommand();
      const child = executeTrustedWorkbench(workbenchContext, () => execFileAsync(
        pythonCommand,
        [workbench, params.command, ...(params.args ?? [])],
        {
          cwd: packageRoot,
          encoding: "utf8",
          env: process.env,
          maxBuffer: 4 * 1024 * 1024,
          signal
        }
      ));
      if (params.stdin !== undefined) {
        child.child.stdin?.end(params.stdin);
      }
      const { stdout } = await child;
      const value = JSON.parse(stdout) as unknown;
      return {
        content: [{ type: "text", text: JSON.stringify(value) }],
        details: value
      };
    }
  });
  }

  pi.registerCommand("security-scan", {
    description: "Run a Pi Security scan in the current repository",
    handler: async (args) => {
      const focus = args.trim() ? ` Focus: ${args.trim()}` : "";
      pi.sendUserMessage(
        `Use the security-scan skill to audit the current repository.${focus}`,
        { deliverAs: "followUp" }
      );
    }
  });

  pi.registerCommand("security-diff-scan", {
    description: "Review the current changes for security vulnerabilities",
    handler: async (args) => {
      const focus = args.trim() ? ` Focus: ${args.trim()}` : "";
      pi.sendUserMessage(
        `Use the security-diff-scan skill to review the current changes.${focus}`,
        { deliverAs: "followUp" }
      );
    }
  });
}

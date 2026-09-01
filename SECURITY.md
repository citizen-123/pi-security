# Security policy

Pi Security is a local tool for reviewing repositories you trust and have
permission to assess.

## Reporting a vulnerability

Report vulnerabilities privately through this repository's
[security advisory form](https://github.com/citizen-123/pi-security/security/advisories/new).
Do not publish unpatched vulnerabilities, exploits, credentials, private source,
or sensitive scan results in GitHub issues or pull requests.

Include the affected version or commit, platform, attacker prerequisites,
security boundary crossed, minimal reproduction, expected and actual behavior,
impact, and any known mitigation. Use synthetic data where possible and never
include a live credential.

## Scope

This policy covers the Pi extension, Python workbench, scan orchestration,
schemas, generated artifacts, package contents, and build process
on the current default branch.

Examples of in-scope issues include:

- credentials, private source, or scan results sent to an unauthorized model,
  process, path, or network destination;
- a scan, patch, or file write outside the target or output path the operator
  authorized;
- path traversal, symlink handling, or file replacement that crosses an enforced
  filesystem boundary;
- bypass of a selected execution capability, credential, target, or scan scope;
- incomplete, forged, or incorrectly scoped results accepted as a completed or
  passing scan; and
- a reachable vulnerability in the distributed package or build process.

## Threat model

Pi Security runs with the permissions of the current operating-system account.
It is not a multi-user isolation boundary. The selected repository, local Git
configuration, executables on `PATH`, environment, Pi installation, and local
scan state are trusted to the extent that the operator grants them authority.

Repository contents, filenames, symlinks, model output, patches, service
responses, and imported artifacts are data. They do not authorize another
target, broader scope, different credential, unrelated read or write, or an
incomplete result.

Reports that assume prior control of the user's account or trusted local state
must show how an attacker-controlled input reaches that state through a
supported Pi Security workflow and crosses an actual boundary. Prompt injection,
missed findings, false positives, dependency advisories without reachable
impact, and vulnerabilities in a repository being scanned are not Pi Security
vulnerabilities by themselves.

## Safe operation

- Scan only repositories you own or have explicit permission to assess.
- Review repository instructions and generated patches before applying them.
- Provide only the credentials and environment variables the scan needs.
- Keep scan state and results private, restrict access, and review artifacts
  before sharing or uploading them.
- Keep Pi Security and its dependencies up to date.

If a scan finds a vulnerability in another project, follow that project's
security policy and disclose the finding only to authorized maintainers.

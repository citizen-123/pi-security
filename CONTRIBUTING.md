# Contributing

Thanks for helping improve Pi Security. Bug reports, feature requests,
documentation corrections, and pull requests are welcome.

## Development

Pi Security is implemented in `packages/pi-security/`. The package contains the
Pi extension, MCP server, scan workbench, schemas, skills, and tests.

Install dependencies and run the project checks from the repository root:

```bash
npm install
npm run typecheck
npm test
npm run test:pack
```

Use Node.js 20 or newer, npm 10 or newer, and Python 3.11 or newer. Keep changes
focused, follow the existing implementation patterns, and add tests for new or
changed observable behavior.

## Reporting bugs and proposing changes

Search the existing issues before opening a new one. For a bug, include the Pi
Security version, operating system, reproduction steps, and expected and actual
behavior. Remove credentials, private source, repository identities, and scan
findings before posting.

For a feature request, describe the user problem and desired workflow. Commands,
arguments, environment variables, accepted values, and defaults are public API;
changes to them must update help, documentation, schemas, and tests together.

## Security issues

Report vulnerabilities privately as described in [SECURITY.md](SECURITY.md).
Do not publish exploits, credentials, private source, or sensitive scan results
in an issue or pull request.

If Pi Security finds a vulnerability in another project, follow that project's
security policy and disclose it only to authorized maintainers.

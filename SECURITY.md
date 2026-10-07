# Security Policy

## Supported versions

VulnProcessing is maintained as a portfolio reference rather than a production
service. Security fixes are applied to the latest public release and the current
`main` branch.

| Version | Supported |
|---|---|
| `0.2.x` / `main` | Yes |
| `< 0.2` | No |

## Reporting a vulnerability

Please use GitHub's private vulnerability reporting for security-sensitive reports:

1. Open the repository's **Security** tab.
2. Select **Advisories** and **Report a vulnerability**.
3. Include the affected revision, reproduction steps, impact and any suggested
   mitigation.

Do not disclose exploit details in a public issue before a fix is available. Ordinary
correctness bugs that do not cross a security boundary can be reported as public
issues.

## Scope

Useful reports include vulnerabilities in:

- management authentication, operation scopes or tenant isolation;
- import validation, request limits and resource-consumption boundaries;
- webhook authentication, replay protection and dispatch state transitions;
- handling of credentials and transport security in external connectors;
- public error responses, local data exposure or the public-snapshot checks;
- CI workflow permissions and dependency or build integrity.

The repository is not deployed as a public service. Historical Azure plans and other
limitations explicitly documented in `docs/architecture.md` are not vulnerabilities by
themselves. A report is still welcome when the implementation contradicts those stated
boundaries or creates an exploitable path in a supported local setup.

## Response expectations

This project has no bug-bounty program or production-response SLA. Reports will be
acknowledged and assessed on a best-effort basis. Please allow time for a coordinated
fix before publishing details.

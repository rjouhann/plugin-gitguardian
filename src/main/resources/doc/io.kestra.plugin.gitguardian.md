GitGuardian detects hardcoded secrets in source code, files, and messages, and manages the resulting incidents. This plugin brings the [GitGuardian public API](https://api.gitguardian.com/docs) into Kestra flows.

## Authentication

Every task and trigger authenticates with an `apiKey`: a GitGuardian personal access token or service account token created in the dashboard under **API > Personal access tokens** or **Service accounts**. Store it as a Kestra secret and reference it as `{{ secret('GITGUARDIAN_API_KEY') }}`.

`apiUrl` defaults to the US region `https://api.gitguardian.com`. Use `https://api.eu1.gitguardian.com` for EU workspaces and `https://<instance>/exposed` for self-hosted GitGuardian.

## Sub-groups

- **Secrets scanning** (`io.kestra.plugin.gitguardian.scan`): scan inline content or files from internal storage and fail the flow when a secret is found. Requires the `scan` scope.
- **Secret incidents** (`io.kestra.plugin.gitguardian.incidents`): react to new incidents with a polling trigger, list and fetch incidents, and triage them (assign, update severity and custom tags, add notes, ignore, reopen, resolve). Requires `incidents:read`, plus `incidents:write` for the triage tasks.

- **Public Monitoring incidents** (`io.kestra.plugin.gitguardian.publicincidents`): same trigger, read and triage tasks for secrets leaked on the public perimeter. Scopes `incidents:read`, `incidents:write`.
- **Webhooks** (`io.kestra.plugin.gitguardian.webhooks`): `Receive` verifies and parses custom webhook events delivered through Kestra's core `Webhook` trigger. No scope.
- **Sources** (`io.kestra.plugin.gitguardian.sources`): list and fetch monitored sources, launch historical scans, create custom sources. Scopes `sources:read`, `sources:scan`, `sources:write`.
- **Honeytokens** (`io.kestra.plugin.gitguardian.honeytokens`): create (value returned encrypted), list, get, revoke, and a trigger on honeytoken events. Scopes `honeytokens:read`, `honeytokens:write`.
- **Audit logs** (`io.kestra.plugin.gitguardian.auditlogs`): export entries and react to sensitive actions. Scope `audit_logs:read`.
- **Health checks** (`io.kestra.plugin.gitguardian.healthchecks`): list, re-run, and react when an integration starts failing. Scopes `health_checks:read`, `health_checks:write`.
- **Teams and members** (`io.kestra.plugin.gitguardian.teams`, `.members`): read-only lookups for routing and audits. Scopes `teams:read`, `members:read`.

## Typical flows

1. **Pre-flight scan**: a flow renders a file or dataset, `scan.Scan` checks it, and the flow fails before publishing if a secret is present.
2. **Incident response**: `incidents.Trigger` starts a flow per new incident that notifies a channel, assigns an owner, opens a ticket, and records a note; a rotation flow ends with `incidents.Resolve` and `secretRevoked: true`.
3. **Real-time alternative**: point a GitGuardian custom webhook at Kestra's webhook endpoint, use the core `Webhook` trigger, and pass `trigger.body` and `trigger.headers` to `webhooks.Receive` for signature verification and a typed `incident`.
4. **Reporting**: `incidents.List` or `auditlogs.List` with `fetchType: STORE` export data for dashboards, SIEMs and compliance.
5. **Non-VCS data**: `sources.CreateCustomSource` once, then `scan.CreateIncidents` on every export to record real incidents for data GitGuardian does not monitor natively.
6. **Tripwires**: `honeytokens.Create` in deployment flows, `honeytokens.Trigger` into the incident response flow.
7. **Perimeter health**: `healthchecks.Trigger` when an integration breaks, `sources.Scan` after onboarding repositories.

## Required scopes

| Task | Scope |
|---|---|
| `scan.Scan` | `scan` |
| `incidents.Trigger`, `incidents.List`, `incidents.Get` | `incidents:read` |
| `incidents.Assign`, `incidents.Update`, `incidents.AddNote`, `incidents.Ignore`, `incidents.Reopen`, `incidents.Resolve` | `incidents:write` |
| `publicincidents.Trigger`, `publicincidents.List`, `publicincidents.Get` | `incidents:read` |
| `publicincidents.Assign`, `Update`, `AddNote`, `Ignore`, `Reopen`, `Resolve` | `incidents:write` |
| `webhooks.Receive` | none |
| `scan.CreateIncidents` | `scan:create-incidents` |
| `sources.List`, `sources.Get` | `sources:read` |
| `sources.Scan` | `sources:scan` |
| `sources.CreateCustomSource` | `sources:write` |
| `honeytokens.Trigger`, `honeytokens.List`, `honeytokens.Get` | `honeytokens:read` |
| `honeytokens.Create`, `honeytokens.Reset`, `honeytokens.Revoke` | `honeytokens:write` |
| `auditlogs.Trigger`, `auditlogs.List` | `audit_logs:read` |
| `healthchecks.Trigger`, `healthchecks.List` | `health_checks:read` |
| `healthchecks.Run` | `health_checks:write` |
| `teams.List` | `teams:read` |
| `members.List` | `members:read` |

## Quotas and rate limits

Only the `scan` scope consumes the workspace API quota: one call per `scan.Scan` request (up to 20 documents) and per `scan.CreateIncidents` request. Other tasks are rate limited per token (for example 1000 requests per minute for a Business plan service account); the plugin retries `429` responses up to three times honoring `Retry-After`.

## Safety

Scanning is stateless on the GitGuardian side, and the plugin never writes matched secret strings to task outputs or logs, only the detector, validity, and match positions.

<p align="center">
  <a href="https://www.kestra.io">
    <img src="https://kestra.io/banner.png"  alt="Kestra workflow orchestrator" />
  </a>
</p>

<h1 align="center" style="border-bottom: none">
    Event-Driven Declarative Orchestrator
</h1>

<div align="center">
 <a href="https://github.com/kestra-io/kestra/releases"><img src="https://img.shields.io/github/tag-pre/kestra-io/kestra.svg?color=blueviolet" alt="Last Version" /></a>
  <a href="https://github.com/kestra-io/kestra/blob/develop/LICENSE"><img src="https://img.shields.io/github/license/kestra-io/kestra?color=blueviolet" alt="License" /></a>
  <a href="https://github.com/kestra-io/kestra/stargazers"><img src="https://img.shields.io/github/stars/kestra-io/kestra?color=blueviolet&logo=github" alt="Github star" /></a> <br>
<a href="https://kestra.io"><img src="https://img.shields.io/badge/Website-kestra.io-192A4E?color=blueviolet" alt="Kestra infinitely scalable orchestration and scheduling platform"></a>
<a href="https://kestra.io/slack"><img src="https://img.shields.io/badge/Slack-Join%20Community-blueviolet?logo=slack" alt="Slack"></a>
</div>

<br />

<p align="center">
  <a href="https://twitter.com/kestra_io" style="margin: 0 10px;">
        <img src="https://kestra.io/twitter.svg" alt="twitter" width="35" height="25" /></a>
  <a href="https://www.linkedin.com/company/kestra/" style="margin: 0 10px;">
        <img src="https://kestra.io/linkedin.svg" alt="linkedin" width="35" height="25" /></a>
  <a href="https://www.youtube.com/@kestra-io" style="margin: 0 10px;">
        <img src="https://kestra.io/youtube.svg" alt="youtube" width="35" height="25" /></a>
</p>

<br />
<p align="center">
    <a href="https://go.kestra.io/video/product-overview" target="_blank">
        <img src="https://kestra.io/startvideo.png" alt="Get started in 3 minutes with Kestra" width="640px" />
    </a>
</p>
<p align="center" style="color:grey;"><i>Get started with Kestra in 3 minutes.</i></p>

# Kestra GitGuardian Plugin

Bring [GitGuardian](https://www.gitguardian.com) secrets detection and incident management into your Kestra flows.

## Use cases

### 1. Scan before data leaves the flow

Kestra flows generate configuration files, export datasets, render templates, and push artifacts to other systems. `scan.Scan` sends that content to GitGuardian's detection engine (500+ detectors, validity checks) and fails the flow before a hardcoded credential propagates downstream.

```yaml
id: scan_before_publish
namespace: company.data

tasks:
  - id: render
    type: io.kestra.plugin.core.storage.Write
    content: "{{ render(inputs.template) }}"
    extension: .yml

  - id: scan
    type: io.kestra.plugin.gitguardian.scan.Scan
    apiKey: "{{ secret('GITGUARDIAN_API_KEY') }}"
    files:
      - "{{ outputs.render.uri }}"
    # fails the flow on the first policy break (default); set failOnPolicyBreak: false to branch instead

  - id: publish
    type: io.kestra.plugin.core.log.Log
    message: "Clean, publishing {{ outputs.render.uri }}"
```

Outputs: `policyBreakCount`, `documentCount`, per-document `results` (detector, validity, known incident URL, match positions) and an Ion file `uri`. Matched secret strings are never written to outputs or logs.

### 2. Orchestrate the response when GitGuardian detects a secret

Two ways to start a flow from an incident, use either or both:

**Polling trigger** (`incidents.Trigger`): polls `GET /v1/incidents/secrets` and starts one execution per new incident, oldest first, with server-side filters. State lives in the namespace KV store, so restarts never re-fire or skip an incident.

```yaml
id: incident_response
namespace: company.security

tasks:
  - id: notify
    type: io.kestra.plugin.slack.SlackIncomingWebhook
    url: "{{ secret('SLACK_WEBHOOK') }}"
    payload: |
      {"text": ":rotating_light: {{ trigger.incident.incidentName }} ({{ trigger.incident.severity }}) {{ trigger.incident.gitguardianUrl }}"}

  - id: assign
    type: io.kestra.plugin.gitguardian.incidents.Assign
    apiKey: "{{ secret('GITGUARDIAN_API_KEY') }}"
    incidentId: "{{ trigger.incident.id }}"
    assigneeEmail: security-oncall@company.com

  - id: note
    type: io.kestra.plugin.gitguardian.incidents.AddNote
    apiKey: "{{ secret('GITGUARDIAN_API_KEY') }}"
    incidentId: "{{ trigger.incident.id }}"
    comment: "Triage started by Kestra execution {{ execution.id }}"

triggers:
  - id: on_incident
    type: io.kestra.plugin.gitguardian.incidents.Trigger
    apiKey: "{{ secret('GITGUARDIAN_API_KEY') }}"
    interval: PT1M
    severity: CRITICAL
    validity: VALID
```

**Real-time webhook** (no polling): create a [custom webhook](https://docs.gitguardian.com/platform/configure-alerting/notifiers-integrations/custom-webhook) in GitGuardian pointing at Kestra's webhook endpoint `https://<kestra>/api/v1/main/executions/webhook/company.security/incident_webhook/<key>`, enable its signature token, and pair the core `Webhook` trigger with `webhooks.Receive`. The task verifies the `Gitguardian-Signature` HMAC and the `Timestamp` header, then exposes the typed event and incident.

```yaml
id: incident_webhook
namespace: company.security

tasks:
  - id: event
    type: io.kestra.plugin.gitguardian.webhooks.Receive
    body: "{{ trigger.body }}"
    headers: "{{ trigger.headers }}"
    signatureToken: "{{ secret('GITGUARDIAN_WEBHOOK_SIGNATURE_TOKEN') }}"

  - id: escalate
    type: io.kestra.plugin.gitguardian.incidents.Update
    runIf: "{{ outputs.event.action == 'incident_triggered' and outputs.event.incident.validity == 'valid' }}"
    apiKey: "{{ secret('GITGUARDIAN_API_KEY') }}"
    incidentId: "{{ outputs.event.incident.id }}"
    severity: CRITICAL
    customTags:
      source: kestra

triggers:
  - id: webhook
    type: io.kestra.plugin.core.trigger.Webhook
    key: "{{ secret('GITGUARDIAN_WEBHOOK_KEY') }}"
```

Webhook events cover new incidents and occurrences, validity, status, severity and risk score changes, assignments, sharing, comments, and honeytoken events, for both internal and Public Monitoring incidents. Delivery is best effort on GitGuardian's side, so keep the polling trigger as a safety net when completeness matters.

**Public Monitoring**: secrets of yours leaked on public GitHub, gists or Docker Hub are a separate incident set (`/v1/public-incidents/secrets`). `publicincidents.Trigger`, `List`, `Get`, `Assign`, `Update`, `AddNote`, `Ignore`, `Reopen` and `Resolve` mirror the internal incident tasks for that perimeter.

Triage and remediation building blocks: `Assign`, `Update` (severity, custom tags), `AddNote`, `Ignore` (test credential, false positive, low risk, invalid), `Reopen`, and `Resolve` with `secretRevoked: true` as the last step of an automated rotation flow.

### 3. Bring non-VCS data into GitGuardian

Kestra moves data GitGuardian cannot monitor natively: warehouse tables, ticket exports, object storage dumps. This is GitGuardian's [Bring Your Own Sources](https://docs.gitguardian.com/internal-monitoring/integrate-sources/bring-your-own-sources) done from Kestra: `sources.CreateCustomSource` creates the custom source once (token scopes `scan` and `scan:create-incidents`, GitGuardian recommends a dedicated service account per source); `scan.CreateIncidents` then scans each export in requests under the 1 MB body limit and records findings as real incidents on the dashboard, with a `locationUrl` pointing back at the data.

```yaml
id: warehouse_export_scan
namespace: company.data

tasks:
  - id: export
    type: io.kestra.plugin.jdbc.postgresql.CopyOut
    url: jdbc:postgresql://warehouse:5432/analytics
    username: "{{ secret('PG_USER') }}"
    password: "{{ secret('PG_PASSWORD') }}"
    sql: SELECT id, notes FROM support_tickets WHERE updated_at > now() - interval '1 day'
    format: CSV

  - id: create_incidents
    type: io.kestra.plugin.gitguardian.scan.CreateIncidents
    apiKey: "{{ secret('GITGUARDIAN_API_KEY') }}"
    sourceUuid: "{{ kv('GITGUARDIAN_WAREHOUSE_SOURCE_UUID') }}"
    files:
      - "{{ outputs.export.uri }}"
    locationUrl: https://warehouse.company.com/tables/support_tickets
```

### 4. Honeytokens as intrusion tripwires

`honeytokens.Create` mints a decoy AWS credential from a deployment flow and returns it encrypted (`{{ decrypt(outputs.create.encryptedToken) }}`) so it can be placed in a config file or repository without ever appearing in clear in Kestra. `honeytokens.Trigger` starts a response flow the moment the decoy is used, with the source IP, action, and honeytoken description. Close the loop with `honeytokens.Reset` once the investigation is over, or `honeytokens.Revoke` if the decoy is burned. Honeytoken webhook events (`honeytoken_triggered`, `new_honeytoken_event`) are also typed by `webhooks.Receive`.

### 5. Audit logs to your SIEM

`auditlogs.List` with `fetchType: STORE` exports a period of workspace activity to internal storage for S3, Splunk, Elasticsearch or a warehouse. `auditlogs.Trigger` fires one execution per poll with every new event, optionally restricted to sensitive `eventNames` such as `incident.ignored` or `api_token.created`.

### 6. Keep the perimeter healthy

`healthchecks.Trigger` fires when a GitHub, GitLab, Jira, Slack or registry integration starts failing (once per failure streak, not on every run), `healthchecks.Run` re-checks on demand, and `sources.List` + `sources.Scan` launch historical scans on at-risk or newly onboarded repositories.

### 7. Report and export

`incidents.List` with `fetchType: STORE` streams every matching incident to internal storage for weekly reports, CSV exports, or loading into a warehouse with Kestra's serdes and storage plugins. `teams.List` and `members.List` resolve owners for routing and access audits.

## Components

| Component | Type | Scope | Description |
|---|---|---|---|
| `scan.Scan` | task | `scan` | Scan inline content and/or internal storage files (`/v1/scan`, `/v1/multiscan`, batches of 20, 1 MB per document). |
| `incidents.Trigger` | trigger | `incidents:read` | Start a flow per new (or re-triggered) secret incident, with status / severity / validity / detector / tag / risk score filters. |
| `incidents.List` | task | `incidents:read` | List incidents with server-side filters, cursor pagination, `maxResults`, and `fetchType` FETCH / FETCH_ONE / STORE / NONE. |
| `incidents.Get` | task | `incidents:read` | Fetch one incident by ID. |
| `incidents.Assign` | task | `incidents:write` | Assign to a member by email or ID. |
| `incidents.Update` | task | `incidents:write` | Set severity and/or custom tags. |
| `incidents.AddNote` | task | `incidents:write` | Add a note. |
| `incidents.Ignore` / `Reopen` / `Resolve` | task | `incidents:write` | Change the incident status. |
| `publicincidents.Trigger` | trigger | `incidents:read` | Start a flow per new Public Monitoring incident. |
| `publicincidents.List` / `Get` | task | `incidents:read` | Read Public Monitoring incidents with the same filters plus `declarativeSecretStatus`. |
| `publicincidents.Assign` / `Update` / `AddNote` / `Ignore` / `Reopen` / `Resolve` | task | `incidents:write` | Triage Public Monitoring incidents. |
| `webhooks.Receive` | task | none | Verify (HMAC + timestamp) and parse a GitGuardian custom webhook event received by the core Webhook trigger. |
| `scan.CreateIncidents` | task | `scan:create-incidents` | Scan content and create incidents on a custom source (beta endpoint). |
| `sources.CreateCustomSource` | task | `sources:write` | Create the custom source that `CreateIncidents` needs (beta). |
| `sources.List` / `sources.Get` | task | `sources:read` | List monitored sources with filters; fetch one with its `lastScan`. |
| `sources.Scan` | task | `sources:scan` | Launch historical scans on source IDs (beta). |
| `honeytokens.Create` | task | `honeytokens:write` | Create a honeytoken, value returned encrypted. Needs `kestra.encryption.secret-key`. |
| `honeytokens.Get` / `List` | task | `honeytokens:read` | Read honeytokens, never their values. |
| `honeytokens.Reset` / `Revoke` | task | `honeytokens:write` | Reset a triggered honeytoken after investigation, or revoke it for good. |
| `honeytokens.Trigger` | trigger | `honeytokens:read` | Start a flow per honeytoken event, with the honeytoken details. |
| `auditlogs.List` | task | `audit_logs:read` | List or export audit log entries with filters. |
| `auditlogs.Trigger` | trigger | `audit_logs:read` | Start a flow per poll with all new events, optional `eventNames` filter. |
| `healthchecks.List` | task | `health_checks:read` | Latest health check per integration instance. |
| `healthchecks.Run` | task | `health_checks:write` | Re-run the health check of one integration instance. |
| `healthchecks.Trigger` | trigger | `health_checks:read` | Start a flow when integrations enter `FAIL` (or other statuses), once per streak. |
| `teams.List` | task | `teams:read` | List workspace teams. |
| `members.List` | task | `members:read` | List workspace members. |

All types live under `io.kestra.plugin.gitguardian`.

## Setup

1. Create a [service account token or personal access token](https://docs.gitguardian.com/api-docs/authentication) in the GitGuardian dashboard with the scopes from the table above.
2. Store it as a Kestra secret, for example `GITGUARDIAN_API_KEY`.
3. Reference it in your flows as `apiKey: "{{ secret('GITGUARDIAN_API_KEY') }}"`.

`apiUrl` defaults to the US region `https://api.gitguardian.com`. Use `https://api.eu1.gitguardian.com` for EU workspaces, or `https://<your-instance>/exposed` for self-hosted GitGuardian.

## Development

Requires JDK 25 (Kestra 2.0 baseline).

```bash
JAVA_HOME=/opt/homebrew/opt/openjdk@25 ./gradlew test        # unit tests (WireMock) and sanity-check flows
GITGUARDIAN_API_KEY=... ./gradlew test --tests '*LiveApiTest'  # optional, read-only against the real API
GITGUARDIAN_API_KEY=... GITGUARDIAN_LIVE_WRITE=true ./gradlew test --tests '*LiveWriteApiTest'  # optional, creates and triages a test incident and honeytoken
./gradlew shadowJar                                            # build/libs/plugin-gitguardian-<version>.jar
docker compose up -d                                           # local Kestra v2.0.8 with the plugin mounted in /app/plugins
```

For local QA, put the base64-encoded token in a git-ignored `.env` as `SECRET_GITGUARDIAN_API_KEY` so flows can use `{{ secret('GITGUARDIAN_API_KEY') }}`.

Run `./gradlew lintPluginDocs` before pushing to validate the plugin documentation.

## License

Apache 2.0, see [LICENSE](LICENSE).

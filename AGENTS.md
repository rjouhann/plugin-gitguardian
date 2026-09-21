# Kestra GitGuardian Plugin

## What

- Provides plugin components under `io.kestra.plugin.gitguardian`.
- `scan.Scan` scans inline content and internal storage files for secrets via `POST /v1/scan` and `POST /v1/multiscan`.
- `incidents.Trigger` polls `GET /v1/incidents/secrets` and fires one execution per new incident (KV watermark); `incidents.List` / `Get` read incidents; `Assign`, `Update`, `AddNote`, `Ignore`, `Reopen`, `Resolve` write them.
- `scan.CreateIncidents` + `sources.CreateCustomSource` register incidents for non-VCS data; `sources.List` / `Get` / `Scan` manage the perimeter.
- `honeytokens.Create` (value returned as `EncryptedString`) / `Get` / `List` / `Revoke` / `Reset` and `honeytokens.Trigger` (one execution per event).
- `auditlogs.List` / `Trigger` (batch: one execution per poll with all new events) and `healthchecks.List` / `Run` / `Trigger` (batch, one fire per failure streak keyed on `first_started_at` + instance).
- `teams.List`, `members.List`: read-only lookups.
- `publicincidents.*`: Public Monitoring twin of `incidents` (path `/v1/public-incidents/secrets`; ignore/resolve take comma-separated reasons; severity and custom tags are separate `set_*` POSTs). IDs are not interchangeable with internal incidents.
- `webhooks.Receive`: pairs with the core `Webhook` trigger; HMAC-SHA256 keyed `Timestamp` header + signature token over the raw JSON. Kestra 2.0.9 hands the body parsed, so verification tries Python `json.dumps` formatting and compact JSON; `rawBody` enables a strict check.

## Why

- What user problem does this solve? Kestra flows move data, configuration and code between systems, so a leaked credential in a flow output or artifact propagates downstream; and security teams triage GitGuardian incidents by hand across ticketing and chat tools.
- Why would a team adopt this plugin in a workflow? `Scan` stops a flow before secrets leave it, and the incident, honeytoken, audit-log and health-check triggers and tasks let Kestra drive triage (notify, ticket, assign, resolve, revoke) instead of custom scripts against the GitGuardian API.
- What operational/business outcome does it enable? Fewer leaked secrets reaching downstream systems, faster and consistent remediation, and an auditable record of every automated incident action.

## How

### Architecture

Single-module plugin. Source packages under `io.kestra.plugin.gitguardian`:

- root: `GitGuardianConnectionInterface` (shared property wording), `AbstractGitGuardianTask` / `AbstractGitGuardianTrigger` (connection properties, client factory; the trigger base also owns the KV `Watermark` = newest delivered timestamp + boundary IDs), `GitGuardianClient` (Kestra `HttpClient` wrapper: `Authorization: Token`, `Link`-header cursor pagination, 429 retry, error mapping), `GitGuardianApiException`, `GitGuardianPage`.
- `scan`: `Scan` task and the `ScanResult` / `PolicyBreak` / `PolicyBreakMatch` response models.
- `incidents`: `Trigger`, `List`, `Get`, and the write tasks sharing `AbstractIncidentAction` (`incidentId`, `incidents:write`); `Incident` / `Detector` / `CustomTag` / `IncidentNote` models; `Severity` / `IncidentStatus` / `Validity` / `IgnoreReason` enums.
- `AbstractListTask` holds `maxResults` / `perPage` / `fetchType` and `list(...)` for every list task; `ListRunner` implements the `fetchType` contract (FETCH / FETCH_ONE / STORE / NONE + `maxResults`) once for every list task; each task keeps its own typed `Output` so generated docs stay typed.
- Property names `type` and `description` are reserved by `Task`; use `integrationType`, `sourceType`, `honeytokenType`, `sourceDescription`, `honeytokenDescription`.
- Watermark IDs are strings (`Watermark.boundaryIds`) so incident IDs (long), event UUIDs and `type:instanceId` keys all fit.
- All sub-groups use `PluginSubGroup.PluginCategory.BUSINESS`.

Response models use `@JsonAlias("snake_case")` on camelCase fields so task outputs stay camelCase for Pebble expressions. Every model has `@JsonIgnoreProperties(ignoreUnknown = true)`. The `match` field of a policy break (the secret itself) is deliberately not mapped.

Infrastructure dependencies (Docker Compose services):

- `app`: local Kestra `v2.0.8` with `build/libs` mounted as `/app/plugins`.

### Key Plugin Classes

- `io.kestra.plugin.gitguardian.scan.Scan`, `io.kestra.plugin.gitguardian.scan.CreateIncidents`
- `io.kestra.plugin.gitguardian.incidents.Trigger`, `List`, `Get`, `Assign`, `Update`, `AddNote`, `Ignore`, `Reopen`, `Resolve`
- `io.kestra.plugin.gitguardian.publicincidents.Trigger`, `List`, `Get`, `Assign`, `Update`, `AddNote`, `Ignore`, `Reopen`, `Resolve`
- `io.kestra.plugin.gitguardian.sources.CreateCustomSource`, `List`, `Get`, `Scan`
- `io.kestra.plugin.gitguardian.honeytokens.Trigger`, `Create`, `Get`, `List`, `Revoke`, `Reset`
- `io.kestra.plugin.gitguardian.auditlogs.Trigger`, `List`
- `io.kestra.plugin.gitguardian.healthchecks.Trigger`, `List`, `Run`
- `io.kestra.plugin.gitguardian.teams.List`, `io.kestra.plugin.gitguardian.members.List`
- `io.kestra.plugin.gitguardian.webhooks.Receive`

### Build and test

- JDK 25 (Kestra 2.0 baseline); `kestraVersion` in `gradle.properties`.
- Tests use WireMock (`@WireMockTest`) with `@KestraTest`; `RunnerTest` runs the sanity-check flows in `src/test/resources/flows/sanity-checks` against WireMock on port 18099; `TriggerTest` drives `eval()` through `TestsUtils.mockTrigger(...).getValue().context()`.
- `LiveApiTest` runs only when `GITGUARDIAN_API_KEY` is set and is read-only against the real API (scan of a doc example, list then get). `LiveWriteApiTest` additionally needs `GITGUARDIAN_LIVE_WRITE=true` and creates a custom source, an incident and a revoked honeytoken named `kestra-plugin-live-test-*` in the workspace.
- `src/test/resources/application.yml` disables the gRPC server and randomizes the controller port, mirroring Kestra's own test configuration.

### Project Structure

```
plugin-gitguardian/
├── src/main/java/io/kestra/plugin/gitguardian/
│   ├── scan/  incidents/  publicincidents/  sources/  honeytokens/
│   ├── auditlogs/  healthchecks/  teams/  members/  webhooks/
├── src/main/resources/{metadata,icons,doc}/
├── src/test/java/io/kestra/plugin/gitguardian/
├── src/test/resources/flows/sanity-checks/
├── build.gradle
└── README.md
```

## Local rules

- Follow the Kestra plugin contribution guidelines: `Property<T>` everywhere, `@PluginProperty(group = ...)` on every property, `secret = true` plus `@ToString.Exclude` / `@EqualsAndHashCode.Exclude` on secrets, one unconditional WireMock happy-path test per task.
- Never output or log a secret value returned by the GitGuardian API.
- Package names follow the GitGuardian API resource (`scan`, `incidents`, `honeytokens`, `sources`); never create a package named `tasks`.

## References

- https://kestra.io/docs/plugin-developer-guide
- https://kestra.io/docs/plugin-developer-guide/contribution-guidelines
- https://api.gitguardian.com/docs

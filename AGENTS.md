# Kestra GitGuardian Plugin

## What

- Provides plugin components under `io.kestra.plugin.gitguardian`.
- `scan.Scan` scans inline content and internal storage files for secrets via `POST /v1/scan` and `POST /v1/multiscan`.
- `incidents.Trigger` polls `GET /v1/incidents/secrets` and fires one execution per new incident (KV watermark); `incidents.List` / `Get` read incidents; `Assign`, `Update`, `AddNote`, `Ignore`, `Reopen`, `Resolve` write them.
- `scan.CreateIncidents` + `sources.CreateCustomSource` register incidents for non-VCS data; `sources.List` / `Get` / `Scan` manage the perimeter.
- `honeytokens.Create` (value returned as `EncryptedString`) / `Get` / `List` / `Revoke` and `honeytokens.Trigger` (one execution per event).
- `auditlogs.List` / `Trigger` (batch: one execution per poll with all new events) and `healthchecks.List` / `Run` / `Trigger` (batch, one fire per failure streak keyed on `first_started_at` + instance).
- `teams.List`, `members.List`: read-only lookups.
- `publicincidents.*`: Public Monitoring twin of `incidents` (path `/v1/public-incidents/secrets`; ignore/resolve take comma-separated reasons; severity and custom tags are separate `set_*` POSTs). IDs are not interchangeable with internal incidents.
- `webhooks.Receive`: pairs with the core `Webhook` trigger; HMAC-SHA256 keyed `Timestamp` header + signature token over the raw JSON. Kestra 2.0.9 hands the body parsed, so verification tries Python `json.dumps` formatting and compact JSON; `rawBody` enables a strict check.

## Why

- Kestra flows move data, configuration and code between systems; a leaked credential in a flow output or artifact propagates downstream. `Scan` stops the flow before that happens.
- Security teams orchestrate incident triage (notify, ticket, revoke) from Kestra; the incident tasks feed those flows with GitGuardian data.

## How

### Architecture

Single-module plugin. Source packages under `io.kestra.plugin.gitguardian`:

- root: `GitGuardianConnectionInterface` (shared property wording), `AbstractGitGuardianTask` / `AbstractGitGuardianTrigger` (connection properties, client factory; the trigger base also owns the KV `Watermark` = newest delivered timestamp + boundary IDs), `GitGuardianClient` (Kestra `HttpClient` wrapper: `Authorization: Token`, `Link`-header cursor pagination, 429 retry, error mapping), `GitGuardianApiException`, `GitGuardianPage`.
- `scan`: `Scan` task and the `ScanResult` / `PolicyBreak` / `PolicyBreakMatch` response models.
- `incidents`: `Trigger`, `List`, `Get`, and the write tasks sharing `AbstractIncidentAction` (`incidentId`, `incidents:write`); `Incident` / `Detector` / `CustomTag` / `IncidentNote` models; `Severity` / `IncidentStatus` / `Validity` / `IgnoreReason` enums.
- `AbstractListTask` holds `maxResults` / `perPage` / `fetchType` and `list(...)` for every list task; `ListRunner` implements the `fetchType` contract (FETCH / FETCH_ONE / STORE / NONE + `maxResults`) once for every list task; each task keeps its own typed `Output` so generated docs stay typed.
- Property names `type` and `description` are reserved by `Task`; use `integrationType`, `sourceType`, `honeytokenType`, `sourceDescription`, `honeytokenDescription`.
- Watermark IDs are strings (`Watermark.boundaryIds`) so incident IDs (long), event UUIDs and `type:instanceId` keys all fit.

Response models use `@JsonAlias("snake_case")` on camelCase fields so task outputs stay camelCase for Pebble expressions. Every model has `@JsonIgnoreProperties(ignoreUnknown = true)`. The `match` field of a policy break (the secret itself) is deliberately not mapped.

Infrastructure dependencies (Docker Compose services):

- `app`: local Kestra `v2.0.8` with `build/libs` mounted as `/app/plugins`.

- All sub-groups use `PluginSubGroup.PluginCategory.BUSINESS`.
- `LiveApiTest` (read-only) runs with `GITGUARDIAN_API_KEY`; `LiveWriteApiTest` additionally needs `GITGUARDIAN_LIVE_WRITE=true` and creates a custom source, an incident and a revoked honeytoken named `kestra-plugin-live-test-*` in the workspace.

### Build and test

- JDK 25 (Kestra 2.0 baseline); `kestraVersion` in `gradle.properties`.
- Tests use WireMock (`@WireMockTest`) with `@KestraTest`; `RunnerTest` runs the sanity-check flows in `src/test/resources/flows/sanity-checks` against WireMock on port 18099; `TriggerTest` drives `eval()` through `TestsUtils.mockTrigger(...).getValue().context()`.
- `LiveApiTest` runs only when `GITGUARDIAN_API_KEY` is set and is read-only against the real API (scan of a doc example, list then get).
- `src/test/resources/application.yml` disables the gRPC server and randomizes the controller port, mirroring Kestra's own test configuration.

### Project Structure

```
plugin-gitguardian/
├── src/main/java/io/kestra/plugin/gitguardian/{scan,incidents}/
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

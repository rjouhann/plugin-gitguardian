package io.kestra.plugin.gitguardian.auditlogs;

import io.kestra.core.models.annotations.Example;
import io.kestra.core.models.annotations.Plugin;
import io.kestra.core.models.annotations.PluginProperty;
import io.kestra.core.models.property.Property;
import io.kestra.core.models.tasks.RunnableTask;
import io.kestra.core.runners.RunContext;
import io.kestra.plugin.gitguardian.AbstractListTask;
import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Builder;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.ToString;
import lombok.experimental.SuperBuilder;

import java.net.URI;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;

@SuperBuilder
@ToString
@EqualsAndHashCode
@Getter
@NoArgsConstructor
@Schema(
    title = "List GitGuardian audit logs",
    description = """
        Lists workspace audit log entries from `GET /v1/audit_logs` with server-side filters and cursor pagination. \
        Use `fetchType: STORE` to export a period to internal storage for a SIEM, a warehouse, or compliance evidence. \
        Requires the `audit_logs:read` scope.
        """
)
@Plugin(
    examples = {
        @Example(
            title = "Export yesterday's audit logs to internal storage every night",
            full = true,
            code = """
                id: gitguardian_audit_export
                namespace: company.security

                tasks:
                  - id: export
                    type: io.kestra.plugin.gitguardian.auditlogs.List
                    apiKey: "{{ secret('GITGUARDIAN_API_KEY') }}"
                    dateAfter: "{{ trigger.date | dateAdd(-1, 'DAYS') }}"
                    dateBefore: "{{ trigger.date }}"
                    fetchType: STORE

                  - id: to_s3
                    type: io.kestra.plugin.aws.s3.Upload
                    from: "{{ outputs.export.uri }}"
                    bucket: security-audit-logs
                    key: "gitguardian/{{ trigger.date | date('yyyy-MM-dd') }}.ion"

                triggers:
                  - id: nightly
                    type: io.kestra.plugin.core.trigger.Schedule
                    cron: "0 2 * * *"
                """
        )
    }
)
public class List extends AbstractListTask implements RunnableTask<List.Output> {
    private static final String SCOPE = "audit_logs:read";

    @Schema(title = "Only events with this name", description = "For example `incident.ignored`.")
    @PluginProperty(group = "processing")
    private Property<String> eventName;

    @Schema(title = "Only events by this member email")
    @PluginProperty(group = "processing")
    private Property<String> memberEmail;

    @Schema(title = "Only events by this member ID")
    @PluginProperty(group = "processing")
    private Property<Long> memberId;

    @Schema(title = "Only events made with this API token ID", description = "The token's UUID as shown in the dashboard, not the token value.")
    @PluginProperty(group = "processing")
    private Property<String> tokenId;

    @Schema(title = "Only events from this IP address")
    @PluginProperty(group = "processing")
    private Property<String> ipAddress;

    @Schema(title = "Only events after this date")
    @PluginProperty(group = "processing")
    private Property<Instant> dateAfter;

    @Schema(title = "Only events before this date")
    @PluginProperty(group = "processing")
    private Property<Instant> dateBefore;




    @Override
    public Output run(RunContext runContext) throws Exception {
        var query = new LinkedHashMap<String, Object>();
        query.put("event_name", runContext.render(eventName).as(String.class).orElse(null));
        query.put("member_email", runContext.render(memberEmail).as(String.class).orElse(null));
        query.put("member_id", runContext.render(memberId).as(Long.class).orElse(null));
        query.put("api_token_id", runContext.render(tokenId).as(String.class).orElse(null));
        query.put("ip_address", runContext.render(ipAddress).as(String.class).orElse(null));
        query.put("date_after", runContext.render(dateAfter).as(Instant.class).map(Instant::toString).orElse(null));
        query.put("date_before", runContext.render(dateBefore).as(Instant.class).map(Instant::toString).orElse(null));

        try (var client = client(runContext)) {
            var result = list(runContext, client, "/audit_logs", query, SCOPE, AuditLog.class);
            return Output.builder().row(result.row()).rows(result.rows()).uri(result.uri()).size(result.size()).build();
        }
    }

    @Builder
    @Getter
    public static class Output implements io.kestra.core.models.tasks.Output {
        @Schema(title = "The first matching entry", description = "Only with `fetchType: FETCH_ONE`.")
        private final AuditLog row;

        @Schema(title = "All matching entries", description = "Only with `fetchType: FETCH`.")
        private final java.util.List<AuditLog> rows;

        @Schema(title = "Internal storage URI of the entries as an Amazon Ion file", description = "Only with `fetchType: STORE`.")
        private final URI uri;

        @Schema(title = "Number of entries fetched")
        private final Long size;
    }
}

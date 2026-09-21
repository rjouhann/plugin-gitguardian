package io.kestra.plugin.gitguardian.incidents;

import io.kestra.core.models.annotations.Example;
import io.kestra.core.models.annotations.Plugin;
import io.kestra.core.models.annotations.PluginProperty;
import io.kestra.core.models.property.Property;
import io.kestra.core.models.tasks.RunnableTask;
import io.kestra.core.runners.RunContext;
import io.kestra.plugin.gitguardian.AbstractListTask;
import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
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
    title = "List GitGuardian secret incidents",
    description = """
        Lists secret incidents from `GET /v1/incidents/secrets`, following cursor pagination until every matching \
        incident is fetched or `maxResults` is reached. Filters are applied server-side. Use `fetchType: STORE` for \
        large result sets: rows stream to internal storage instead of the execution output. Requires the \
        `incidents:read` scope.
        """
)
@Plugin(
    examples = {
        @Example(
            title = "List open critical incidents with a valid secret",
            full = true,
            code = """
                id: gitguardian_critical_incidents
                namespace: company.security

                tasks:
                  - id: list
                    type: io.kestra.plugin.gitguardian.incidents.List
                    apiKey: "{{ secret('GITGUARDIAN_API_KEY') }}"
                    status: TRIGGERED
                    severity: CRITICAL
                    validity: VALID
                    ordering: "-date"
                    maxResults: 50

                  - id: report
                    type: io.kestra.plugin.core.log.Log
                    message: "{{ outputs.list.size }} critical incident(s) need attention"
                """
        ),
        @Example(
            title = "Export every incident resolved this week to internal storage",
            full = true,
            code = """
                id: gitguardian_weekly_resolved
                namespace: company.security

                tasks:
                  - id: list
                    type: io.kestra.plugin.gitguardian.incidents.List
                    apiKey: "{{ secret('GITGUARDIAN_API_KEY') }}"
                    status: RESOLVED
                    dateAfter: "{{ now() | dateAdd(-7, 'DAYS') }}"
                    fetchType: STORE

                triggers:
                  - id: weekly
                    type: io.kestra.plugin.core.trigger.Schedule
                    cron: "0 8 * * MON"
                """
        )
    }
)
public class List extends AbstractListTask implements RunnableTask<List.Output> {
    private static final String SCOPE = "incidents:read";

    @Schema(title = "Filter by status", description = "`TRIGGERED`, `ASSIGNED`, `RESOLVED`, or `IGNORED`.")
    @PluginProperty(group = "processing")
    private Property<IncidentStatus> status;

    @Schema(title = "Filter by severity", description = "`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`, or `UNKNOWN`.")
    @PluginProperty(group = "processing")
    private Property<Severity> severity;

    @Schema(title = "Filter by secret validity", description = "`VALID`, `INVALID`, `FAILED_TO_CHECK`, `NO_CHECKER`, or `UNKNOWN`.")
    @PluginProperty(group = "processing")
    private Property<Validity> validity;

    @Schema(title = "Only incidents last triggered after this date")
    @PluginProperty(group = "processing")
    private Property<Instant> dateAfter;

    @Schema(title = "Only incidents last triggered before this date")
    @PluginProperty(group = "processing")
    private Property<Instant> dateBefore;

    @Schema(title = "Filter by detector group name", description = "For example `aws_iam` or `slackbot_token`.")
    @PluginProperty(group = "processing")
    private Property<String> detectorGroupName;

    @Schema(title = "Filter by assignee email")
    @PluginProperty(group = "processing")
    private Property<String> assigneeEmail;

    @Schema(title = "Only incidents carrying all of these GitGuardian tags", description = "For example `PUBLICLY_EXPOSED` or `FROM_HISTORICAL_SCAN`.")
    @PluginProperty(group = "processing")
    private Property<java.util.List<String>> tags;

    @Schema(title = "Minimum risk score, from 0 to 100")
    @PluginProperty(group = "processing")
    private Property<@Min(0) @Max(100) Integer> riskScoreMin;

    @Schema(title = "Ordering", description = "`date`, `resolved_at`, `ignored_at`, or `risk_score`; prefix with `-` for descending. Defaults to GitGuardian's ordering (`date` ascending).")
    @PluginProperty(group = "processing")
    private Property<String> ordering;




    @Override
    public Output run(RunContext runContext) throws Exception {
        var query = query(runContext);

        try (var client = client(runContext)) {
            var result = list(runContext, client, "/incidents/secrets", query, SCOPE, Incident.class);
            return Output.builder().row(result.row()).rows(result.rows()).uri(result.uri()).size(result.size()).build();
        }
    }

    private Map<String, Object> query(RunContext runContext) throws Exception {
        var query = new LinkedHashMap<String, Object>();
        query.put("status", runContext.render(status).as(IncidentStatus.class).map(IncidentStatus::apiValue).orElse(null));
        query.put("severity", runContext.render(severity).as(Severity.class).map(Severity::apiValue).orElse(null));
        query.put("validity", runContext.render(validity).as(Validity.class).map(Validity::apiValue).orElse(null));
        query.put("date_after", runContext.render(dateAfter).as(Instant.class).map(Instant::toString).orElse(null));
        query.put("date_before", runContext.render(dateBefore).as(Instant.class).map(Instant::toString).orElse(null));
        query.put("detector_group_name", runContext.render(detectorGroupName).as(String.class).orElse(null));
        query.put("assignee_email", runContext.render(assigneeEmail).as(String.class).orElse(null));
        var rTags = runContext.render(tags).asList(String.class);
        query.put("tags", rTags.isEmpty() ? null : rTags);
        query.put("risk_score_min", runContext.render(riskScoreMin).as(Integer.class).orElse(null));
        query.put("ordering", runContext.render(ordering).as(String.class).orElse(null));
        return query;
    }

    @Builder
    @Getter
    public static class Output implements io.kestra.core.models.tasks.Output {
        @Schema(title = "The first matching incident", description = "Only populated with `fetchType: FETCH_ONE`.")
        private final Incident row;

        @Schema(title = "All matching incidents", description = "Only populated with `fetchType: FETCH`.")
        private final java.util.List<Incident> rows;

        @Schema(title = "Internal storage URI of the incidents as an Amazon Ion file", description = "Only populated with `fetchType: STORE`.")
        private final URI uri;

        @Schema(title = "Number of incidents fetched")
        private final Long size;
    }
}

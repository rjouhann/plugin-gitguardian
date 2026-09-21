package io.kestra.plugin.gitguardian.healthchecks;

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

@SuperBuilder
@ToString
@EqualsAndHashCode
@Getter
@NoArgsConstructor
@Schema(
    title = "List GitGuardian integration health checks",
    description = "Lists the latest health check run per integration instance (VCS, ticketing, messaging, registries) from `GET /v1/health-checks`, optionally filtered by `integrationType` and `status`. Requires the `health_checks:read` scope."
)
@Plugin(
    examples = {
        @Example(
            title = "Fail a daily flow if any integration is failing",
            full = true,
            code = """
                id: gitguardian_integrations_health
                namespace: company.security

                tasks:
                  - id: failing
                    type: io.kestra.plugin.gitguardian.healthchecks.List
                    apiKey: "{{ secret('GITGUARDIAN_API_KEY') }}"
                    status: FAIL

                  - id: assert_healthy
                    type: io.kestra.plugin.core.execution.Assert
                    conditions:
                      - "{{ outputs.failing.size == 0 }}"
                    errorMessage: "{{ outputs.failing.size }} GitGuardian integration(s) failing"

                triggers:
                  - id: daily
                    type: io.kestra.plugin.core.trigger.Schedule
                    cron: "0 7 * * *"
                """
        )
    }
)
public class List extends AbstractListTask implements RunnableTask<List.Output> {
    private static final String SCOPE = "health_checks:read";

    @Schema(title = "Only this integration type", description = "For example `github-installation` or `slack-workspace`.")
    @PluginProperty(group = "processing")
    private Property<String> integrationType;

    @Schema(title = "Only this aggregate status", description = "`PASS`, `WARN`, or `FAIL`.")
    @PluginProperty(group = "processing")
    private Property<HealthCheckStatus> status;

    @Schema(title = "Only runs started after this date")
    @PluginProperty(group = "processing")
    private Property<Instant> startedAfter;

    @Schema(title = "Only runs started before this date")
    @PluginProperty(group = "processing")
    private Property<Instant> startedBefore;




    @Override
    public Output run(RunContext runContext) throws Exception {
        var query = new LinkedHashMap<String, Object>();
        query.put("type", runContext.render(integrationType).as(String.class).orElse(null));
        query.put("status", runContext.render(status).as(HealthCheckStatus.class).map(HealthCheckStatus::apiValue).orElse(null));
        query.put("started_at_after", runContext.render(startedAfter).as(Instant.class).map(Instant::toString).orElse(null));
        query.put("started_at_before", runContext.render(startedBefore).as(Instant.class).map(Instant::toString).orElse(null));

        try (var client = client(runContext)) {
            var result = list(runContext, client, "/health-checks", query, SCOPE, HealthCheck.class);
            return Output.builder().row(result.row()).rows(result.rows()).uri(result.uri()).size(result.size()).build();
        }
    }

    @Builder
    @Getter
    public static class Output implements io.kestra.core.models.tasks.Output {
        @Schema(title = "The first matching health check", description = "Only with `fetchType: FETCH_ONE`.")
        private final HealthCheck row;

        @Schema(title = "All matching health checks", description = "Only with `fetchType: FETCH`.")
        private final java.util.List<HealthCheck> rows;

        @Schema(title = "Internal storage URI of the health checks as an Amazon Ion file", description = "Only with `fetchType: STORE`.")
        private final URI uri;

        @Schema(title = "Number of health checks fetched")
        private final Long size;
    }
}

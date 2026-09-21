package io.kestra.plugin.gitguardian.sources;

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
import java.util.LinkedHashMap;

@SuperBuilder
@ToString
@EqualsAndHashCode
@Getter
@NoArgsConstructor
@Schema(
    title = "List GitGuardian monitored sources",
    description = "Lists the sources (repositories, projects, buckets, channels) known to GitGuardian from `GET /v1/sources`, with server-side filters and cursor pagination. Requires the `sources:read` scope."
)
@Plugin(
    examples = {
        @Example(
            title = "Find at-risk critical repositories and launch a historical scan on them",
            full = true,
            code = """
                id: gitguardian_rescan_at_risk
                namespace: company.security

                tasks:
                  - id: at_risk
                    type: io.kestra.plugin.gitguardian.sources.List
                    apiKey: "{{ secret('GITGUARDIAN_API_KEY') }}"
                    health: at_risk
                    sourceCriticality: critical

                  - id: rescan
                    type: io.kestra.plugin.gitguardian.sources.Scan
                    runIf: "{{ outputs.at_risk.size > 0 }}"
                    apiKey: "{{ secret('GITGUARDIAN_API_KEY') }}"
                    sourceIds: "{{ outputs.at_risk.rows | jq('[.[].id]') | first }}"
                """
        )
    }
)
public class List extends AbstractListTask implements RunnableTask<List.Output> {
    private static final String SCOPE = "sources:read";

    @Schema(title = "Search in source names")
    @PluginProperty(group = "processing")
    private Property<String> search;

    @Schema(title = "Only this source type", description = "For example `github`, `gitlab`, `bitbucket`, `azure_devops`, `slack`, or `custom`.")
    @PluginProperty(group = "processing")
    private Property<String> sourceType;

    @Schema(title = "Only this health", description = "`safe`, `unknown`, or `at_risk`.")
    @PluginProperty(group = "processing")
    private Property<String> health;

    @Schema(title = "Only this visibility", description = "`public`, `private`, or `internal`.")
    @PluginProperty(group = "processing")
    private Property<String> visibility;

    @Schema(title = "Only this criticality", description = "`critical`, `high`, `medium`, `low`, or `unknown`.")
    @PluginProperty(group = "processing")
    private Property<String> sourceCriticality;

    @Schema(title = "Only sources with these monitoring statuses", description = "Any of `active`, `disabled`, `unreachable`, `archived`, `deleted_on_remote`.")
    @PluginProperty(group = "processing")
    private Property<java.util.List<String>> monitoringStatuses;

    @Schema(title = "Only sources owned by this team ID")
    @PluginProperty(group = "processing")
    private Property<Long> teamId;

    @Schema(title = "Ordering", description = "`last_scan_date` or `-last_scan_date`.")
    @PluginProperty(group = "processing")
    private Property<String> ordering;




    @Override
    public Output run(RunContext runContext) throws Exception {
        var query = new LinkedHashMap<String, Object>();
        query.put("search", runContext.render(search).as(String.class).orElse(null));
        query.put("type", runContext.render(sourceType).as(String.class).orElse(null));
        query.put("health", runContext.render(health).as(String.class).orElse(null));
        query.put("visibility", runContext.render(visibility).as(String.class).orElse(null));
        query.put("source_criticality", runContext.render(sourceCriticality).as(String.class).orElse(null));
        var rStatuses = runContext.render(monitoringStatuses).asList(String.class);
        query.put("monitoring_status__in", rStatuses.isEmpty() ? null : rStatuses);
        query.put("team_id", runContext.render(teamId).as(Long.class).orElse(null));
        query.put("ordering", runContext.render(ordering).as(String.class).orElse(null));

        try (var client = client(runContext)) {
            var result = list(runContext, client, "/sources", query, SCOPE, Source.class);
            return Output.builder().row(result.row()).rows(result.rows()).uri(result.uri()).size(result.size()).build();
        }
    }

    @Builder
    @Getter
    public static class Output implements io.kestra.core.models.tasks.Output {
        @Schema(title = "The first matching source", description = "Only with `fetchType: FETCH_ONE`.")
        private final Source row;

        @Schema(title = "All matching sources", description = "Only with `fetchType: FETCH`.")
        private final java.util.List<Source> rows;

        @Schema(title = "Internal storage URI of the sources as an Amazon Ion file", description = "Only with `fetchType: STORE`.")
        private final URI uri;

        @Schema(title = "Number of sources fetched")
        private final Long size;
    }
}

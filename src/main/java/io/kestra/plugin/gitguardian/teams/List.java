package io.kestra.plugin.gitguardian.teams;

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
    title = "List GitGuardian teams",
    description = "Lists workspace teams from `GET /v1/teams`, for example to resolve a team ID before filtering sources or routing incidents. Requires the `teams:read` scope."
)
@Plugin(
    examples = {
        @Example(
            title = "Resolve the platform team's ID and list its sources",
            full = true,
            code = """
                id: gitguardian_team_sources
                namespace: company.security

                tasks:
                  - id: team
                    type: io.kestra.plugin.gitguardian.teams.List
                    apiKey: "{{ secret('GITGUARDIAN_API_KEY') }}"
                    search: platform
                    fetchType: FETCH_ONE

                  - id: sources
                    type: io.kestra.plugin.gitguardian.sources.List
                    apiKey: "{{ secret('GITGUARDIAN_API_KEY') }}"
                    teamId: "{{ outputs.team.row.id }}"
                """
        )
    }
)
public class List extends AbstractListTask implements RunnableTask<List.Output> {
    private static final String SCOPE = "teams:read";

    @Schema(title = "Search in team names")
    @PluginProperty(group = "processing")
    private Property<String> search;

    @Schema(title = "Only the global team (`true`) or only regular teams (`false`)")
    @PluginProperty(group = "processing")
    private Property<Boolean> global;




    @Override
    public Output run(RunContext runContext) throws Exception {
        var query = new LinkedHashMap<String, Object>();
        query.put("search", runContext.render(search).as(String.class).orElse(null));
        query.put("is_global", runContext.render(global).as(Boolean.class).orElse(null));

        try (var client = client(runContext)) {
            var result = list(runContext, client, "/teams", query, SCOPE, Team.class);
            return Output.builder().row(result.row()).rows(result.rows()).uri(result.uri()).size(result.size()).build();
        }
    }

    @Builder
    @Getter
    public static class Output implements io.kestra.core.models.tasks.Output {
        @Schema(title = "The first matching team", description = "Only with `fetchType: FETCH_ONE`.")
        private final Team row;

        @Schema(title = "All matching teams", description = "Only with `fetchType: FETCH`.")
        private final java.util.List<Team> rows;

        @Schema(title = "Internal storage URI of the teams as an Amazon Ion file", description = "Only with `fetchType: STORE`.")
        private final URI uri;

        @Schema(title = "Number of teams fetched")
        private final Long size;
    }
}

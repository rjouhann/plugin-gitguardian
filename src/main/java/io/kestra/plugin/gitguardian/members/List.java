package io.kestra.plugin.gitguardian.members;

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
    title = "List GitGuardian workspace members",
    description = "Lists members from `GET /v1/members`, for example to validate an assignee email before `incidents.Assign` or to audit inactive accounts. Requires the `members:read` scope."
)
@Plugin(
    examples = {
        @Example(
            title = "Report members who never logged in",
            full = true,
            code = """
                id: gitguardian_inactive_members
                namespace: company.security

                tasks:
                  - id: members
                    type: io.kestra.plugin.gitguardian.members.List
                    apiKey: "{{ secret('GITGUARDIAN_API_KEY') }}"
                    active: true

                  - id: report
                    type: io.kestra.plugin.core.log.Log
                    message: "Never logged in: {{ outputs.members.rows | jq('[.[] | select(.lastLogin == null) | .email]') | first }}"
                """
        )
    }
)
public class List extends AbstractListTask implements RunnableTask<List.Output> {
    private static final String SCOPE = "members:read";

    @Schema(title = "Search in names and emails")
    @PluginProperty(group = "processing")
    private Property<String> search;

    @Schema(title = "Only this role", description = "`owner`, `manager`, `member`, or `restricted`.")
    @PluginProperty(group = "processing")
    private Property<String> role;

    @Schema(title = "Only active (`true`) or deactivated (`false`) members")
    @PluginProperty(group = "processing")
    private Property<Boolean> active;

    @Schema(title = "Ordering", description = "`created_at` or `last_login`; prefix with `-` for descending.")
    @PluginProperty(group = "processing")
    private Property<String> ordering;




    @Override
    public Output run(RunContext runContext) throws Exception {
        var query = new LinkedHashMap<String, Object>();
        query.put("search", runContext.render(search).as(String.class).orElse(null));
        query.put("role", runContext.render(role).as(String.class).orElse(null));
        query.put("active", runContext.render(active).as(Boolean.class).orElse(null));
        query.put("ordering", runContext.render(ordering).as(String.class).orElse(null));

        try (var client = client(runContext)) {
            var result = list(runContext, client, "/members", query, SCOPE, Member.class);
            return Output.builder().row(result.row()).rows(result.rows()).uri(result.uri()).size(result.size()).build();
        }
    }

    @Builder
    @Getter
    public static class Output implements io.kestra.core.models.tasks.Output {
        @Schema(title = "The first matching member", description = "Only with `fetchType: FETCH_ONE`.")
        private final Member row;

        @Schema(title = "All matching members", description = "Only with `fetchType: FETCH`.")
        private final java.util.List<Member> rows;

        @Schema(title = "Internal storage URI of the members as an Amazon Ion file", description = "Only with `fetchType: STORE`.")
        private final URI uri;

        @Schema(title = "Number of members fetched")
        private final Long size;
    }
}

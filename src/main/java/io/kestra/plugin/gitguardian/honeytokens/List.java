package io.kestra.plugin.gitguardian.honeytokens;

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
    title = "List GitGuardian honeytokens",
    description = "Lists honeytokens from `GET /v1/honeytokens` with status, type, search and tag filters, never including their values. Requires the `honeytokens:read` scope."
)
@Plugin(
    examples = {
        @Example(
            title = "List triggered honeytokens",
            full = true,
            code = """
                id: gitguardian_triggered_honeytokens
                namespace: company.security

                tasks:
                  - id: list
                    type: io.kestra.plugin.gitguardian.honeytokens.List
                    apiKey: "{{ secret('GITGUARDIAN_API_KEY') }}"
                    status: triggered
                    ordering: "-triggered_at"
                """
        )
    }
)
public class List extends AbstractListTask implements RunnableTask<List.Output> {
    private static final String SCOPE = "honeytokens:read";

    @Schema(title = "Only this status", description = "`active`, `triggered`, or `revoked`.")
    @PluginProperty(group = "processing")
    private Property<String> status;

    @Schema(title = "Only this type", description = "Currently `AWS`.")
    @PluginProperty(group = "processing")
    private Property<String> honeytokenType;

    @Schema(title = "Search in names and descriptions")
    @PluginProperty(group = "processing")
    private Property<String> search;

    @Schema(title = "Only honeytokens carrying all of these tags")
    @PluginProperty(group = "processing")
    private Property<java.util.List<String>> tags;

    @Schema(title = "Ordering", description = "`created_at`, `triggered_at`, `revoked_at`, or `name`; prefix with `-` for descending.")
    @PluginProperty(group = "processing")
    private Property<String> ordering;




    @Override
    public Output run(RunContext runContext) throws Exception {
        var query = new LinkedHashMap<String, Object>();
        query.put("status", runContext.render(status).as(String.class).orElse(null));
        query.put("type", runContext.render(honeytokenType).as(String.class).orElse(null));
        query.put("search", runContext.render(search).as(String.class).orElse(null));
        var rTags = runContext.render(tags).asList(String.class);
        query.put("tags", rTags.isEmpty() ? null : rTags);
        query.put("ordering", runContext.render(ordering).as(String.class).orElse(null));
        query.put("show_token", false);

        try (var client = client(runContext)) {
            var result = list(runContext, client, "/honeytokens", query, SCOPE, Honeytoken.class);
            return Output.builder().row(result.row()).rows(result.rows()).uri(result.uri()).size(result.size()).build();
        }
    }

    @Builder
    @Getter
    public static class Output implements io.kestra.core.models.tasks.Output {
        @Schema(title = "The first matching honeytoken", description = "Only with `fetchType: FETCH_ONE`.")
        private final Honeytoken row;

        @Schema(title = "All matching honeytokens", description = "Only with `fetchType: FETCH`.")
        private final java.util.List<Honeytoken> rows;

        @Schema(title = "Internal storage URI of the honeytokens as an Amazon Ion file", description = "Only with `fetchType: STORE`.")
        private final URI uri;

        @Schema(title = "Number of honeytokens fetched")
        private final Long size;
    }
}

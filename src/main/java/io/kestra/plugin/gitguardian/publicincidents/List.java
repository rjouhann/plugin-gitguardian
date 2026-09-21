package io.kestra.plugin.gitguardian.publicincidents;

import io.kestra.core.models.annotations.Example;
import io.kestra.core.models.annotations.Plugin;
import io.kestra.core.models.annotations.PluginProperty;
import io.kestra.core.models.property.Property;
import io.kestra.core.models.tasks.RunnableTask;
import io.kestra.core.runners.RunContext;
import io.kestra.plugin.gitguardian.AbstractListTask;
import io.kestra.plugin.gitguardian.incidents.IncidentStatus;
import io.kestra.plugin.gitguardian.incidents.Severity;
import io.kestra.plugin.gitguardian.incidents.Validity;
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
    title = "List GitGuardian Public Monitoring incidents",
    description = """
        Lists secrets of yours found on the public perimeter (public GitHub repositories and gists, Docker Hub, ...) \
        from `GET /v1/public-incidents/secrets`, with server-side filters and cursor pagination. These are distinct \
        from internal incidents and their IDs are not interchangeable. Requires the `incidents:read` scope and a \
        GitGuardian Public Monitoring subscription.
        """
)
@Plugin(
    examples = {
        @Example(
            title = "List valid public leaks not yet triaged",
            full = true,
            code = """
                id: gitguardian_public_leaks
                namespace: company.security

                tasks:
                  - id: list
                    type: io.kestra.plugin.gitguardian.publicincidents.List
                    apiKey: "{{ secret('GITGUARDIAN_API_KEY') }}"
                    status: TRIGGERED
                    validity: VALID
                    ordering: "-date"
                """
        )
    }
)
public class List extends AbstractListTask implements RunnableTask<List.Output> {
    private static final String SCOPE = "incidents:read";

    @Schema(title = "Filter by status", description = "`TRIGGERED`, `ASSIGNED`, `RESOLVED`, or `IGNORED`.")
    @PluginProperty(group = "processing")
    private Property<IncidentStatus> status;

    @Schema(title = "Filter by severity")
    @PluginProperty(group = "processing")
    private Property<Severity> severity;

    @Schema(title = "Filter by secret validity")
    @PluginProperty(group = "processing")
    private Property<Validity> validity;

    @Schema(title = "Filter by declarative secret status", description = "For example `not_declared`, `mine`, or `not_mine`.")
    @PluginProperty(group = "processing")
    private Property<String> declarativeSecretStatus;

    @Schema(title = "Only incidents last triggered after this date")
    @PluginProperty(group = "processing")
    private Property<Instant> dateAfter;

    @Schema(title = "Only incidents last triggered before this date")
    @PluginProperty(group = "processing")
    private Property<Instant> dateBefore;

    @Schema(title = "Filter by detector group name")
    @PluginProperty(group = "processing")
    private Property<String> detectorGroupName;

    @Schema(title = "Filter by assignee email")
    @PluginProperty(group = "processing")
    private Property<String> assigneeEmail;

    @Schema(title = "Only incidents carrying all of these tags")
    @PluginProperty(group = "processing")
    private Property<java.util.List<String>> tags;

    @Schema(title = "Minimum risk score, from 0 to 100")
    @PluginProperty(group = "processing")
    private Property<@Min(0) @Max(100) Integer> riskScoreMin;

    @Schema(title = "Ordering", description = "`date`, `resolved_at`, `ignored_at`, or `risk_score`; prefix with `-` for descending.")
    @PluginProperty(group = "processing")
    private Property<String> ordering;




    @Override
    public Output run(RunContext runContext) throws Exception {
        var query = new LinkedHashMap<String, Object>();
        query.put("status", runContext.render(status).as(IncidentStatus.class).map(IncidentStatus::apiValue).orElse(null));
        query.put("severity", runContext.render(severity).as(Severity.class).map(Severity::apiValue).orElse(null));
        query.put("validity", runContext.render(validity).as(Validity.class).map(Validity::apiValue).orElse(null));
        query.put("declarative_secret_status", runContext.render(declarativeSecretStatus).as(String.class).orElse(null));
        query.put("date_after", runContext.render(dateAfter).as(Instant.class).map(Instant::toString).orElse(null));
        query.put("date_before", runContext.render(dateBefore).as(Instant.class).map(Instant::toString).orElse(null));
        query.put("detector_group_name", runContext.render(detectorGroupName).as(String.class).orElse(null));
        query.put("assignee_email", runContext.render(assigneeEmail).as(String.class).orElse(null));
        var rTags = runContext.render(tags).asList(String.class);
        query.put("tags", rTags.isEmpty() ? null : rTags);
        query.put("risk_score_min", runContext.render(riskScoreMin).as(Integer.class).orElse(null));
        query.put("ordering", runContext.render(ordering).as(String.class).orElse(null));

        try (var client = client(runContext)) {
            var result = list(runContext, client, "/public-incidents/secrets", query, SCOPE, PublicIncident.class);
            return Output.builder().row(result.row()).rows(result.rows()).uri(result.uri()).size(result.size()).build();
        }
    }

    @Builder
    @Getter
    public static class Output implements io.kestra.core.models.tasks.Output {
        @Schema(title = "The first matching incident", description = "Only with `fetchType: FETCH_ONE`.")
        private final PublicIncident row;

        @Schema(title = "All matching incidents", description = "Only with `fetchType: FETCH`.")
        private final java.util.List<PublicIncident> rows;

        @Schema(title = "Internal storage URI of the incidents as an Amazon Ion file", description = "Only with `fetchType: STORE`.")
        private final URI uri;

        @Schema(title = "Number of incidents fetched")
        private final Long size;
    }
}

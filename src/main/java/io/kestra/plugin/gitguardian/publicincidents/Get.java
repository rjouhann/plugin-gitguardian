package io.kestra.plugin.gitguardian.publicincidents;

import io.kestra.core.models.annotations.Example;
import io.kestra.core.models.annotations.Plugin;
import io.kestra.core.models.tasks.RunnableTask;
import io.kestra.core.runners.RunContext;
import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Builder;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.ToString;
import lombok.experimental.SuperBuilder;

@SuperBuilder
@ToString
@EqualsAndHashCode
@Getter
@NoArgsConstructor
@Schema(
    title = "Get a GitGuardian Public Monitoring incident",
    description = "Fetches one public incident by ID from `GET /v1/public-incidents/secrets/{id}`. Requires the `incidents:read` scope."
)
@Plugin(
    examples = {
        @Example(
            title = "Fetch a public incident",
            full = true,
            code = """
                id: gitguardian_get_public_incident
                namespace: company.security

                inputs:
                  - id: incident_id
                    type: INT

                tasks:
                  - id: get
                    type: io.kestra.plugin.gitguardian.publicincidents.Get
                    apiKey: "{{ secret('GITGUARDIAN_API_KEY') }}"
                    incidentId: "{{ inputs.incident_id }}"
                """
        )
    }
)
public class Get extends AbstractPublicIncidentAction implements RunnableTask<Get.Output> {
    private static final String SCOPE = "incidents:read";

    @Override
    public Output run(RunContext runContext) throws Exception {
        var rIncidentId = renderIncidentId(runContext);

        runContext.logger().info("Fetching GitGuardian public incident {}", rIncidentId);

        try (var client = client(runContext)) {
            var incident = client.get(incidentPath(rIncidentId), null, SCOPE, PublicIncident.class);
            return Output.builder().incident(requireIncident(incident, rIncidentId)).build();
        }
    }

    @Builder
    @Getter
    public static class Output implements io.kestra.core.models.tasks.Output {
        @Schema(title = "The public incident")
        private final PublicIncident incident;
    }
}

package io.kestra.plugin.gitguardian.incidents;

import io.kestra.core.models.annotations.Example;
import io.kestra.core.models.annotations.Plugin;
import io.kestra.core.models.annotations.PluginProperty;
import io.kestra.core.models.property.Property;
import io.kestra.core.models.tasks.RunnableTask;
import io.kestra.core.runners.RunContext;
import io.kestra.plugin.gitguardian.AbstractGitGuardianTask;
import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotNull;
import lombok.Builder;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.ToString;
import lombok.experimental.SuperBuilder;

import java.util.Map;

@SuperBuilder
@ToString
@EqualsAndHashCode
@Getter
@NoArgsConstructor
@Schema(
    title = "Get a GitGuardian secret incident",
    description = "Fetches one secret incident by ID from `GET /v1/incidents/secrets/{id}`. Requires the `incidents:read` scope."
)
@Plugin(
    examples = {
        @Example(
            title = "Fetch an incident and log its severity",
            full = true,
            code = """
                id: gitguardian_get_incident
                namespace: company.security

                inputs:
                  - id: incident_id
                    type: INT

                tasks:
                  - id: get
                    type: io.kestra.plugin.gitguardian.incidents.Get
                    apiKey: "{{ secret('GITGUARDIAN_API_KEY') }}"
                    incidentId: "{{ inputs.incident_id }}"

                  - id: log
                    type: io.kestra.plugin.core.log.Log
                    message: "{{ outputs.get.incident.incidentName }} is {{ outputs.get.incident.severity }} ({{ outputs.get.incident.gitguardianUrl }})"
                """
        )
    }
)
public class Get extends AbstractGitGuardianTask implements RunnableTask<Get.Output> {
    private static final String SCOPE = "incidents:read";

    @Schema(title = "Incident ID")
    @NotNull
    @PluginProperty(group = "main")
    private Property<Long> incidentId;

    @Override
    public Output run(RunContext runContext) throws Exception {
        var rIncidentId = runContext.render(incidentId).as(Long.class)
            .orElseThrow(() -> new IllegalArgumentException("incidentId is required to fetch a GitGuardian incident."));

        runContext.logger().info("Fetching GitGuardian secret incident {}", rIncidentId);

        try (var client = client(runContext)) {
            var incident = client.get("/incidents/secrets/" + rIncidentId, Map.of("with_occurrences", 0), SCOPE, Incident.class);
            if (incident == null) {
                throw new IllegalStateException("Empty response from the GitGuardian API for incident %d.".formatted(rIncidentId));
            }
            return Output.builder().incident(incident).build();
        }
    }

    @Builder
    @Getter
    public static class Output implements io.kestra.core.models.tasks.Output {
        @Schema(title = "The incident")
        private final Incident incident;
    }
}

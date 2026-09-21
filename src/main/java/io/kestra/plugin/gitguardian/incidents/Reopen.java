package io.kestra.plugin.gitguardian.incidents;

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
    title = "Reopen a GitGuardian secret incident",
    description = "Reopens a resolved or ignored secret incident via `POST /v1/incidents/secrets/{id}/reopen`. Requires the `incidents:write` scope."
)
@Plugin(
    examples = {
        @Example(
            title = "Reopen an incident whose secret is still valid",
            full = true,
            code = """
                id: gitguardian_reopen
                namespace: company.security

                inputs:
                  - id: incident_id
                    type: INT

                tasks:
                  - id: reopen
                    type: io.kestra.plugin.gitguardian.incidents.Reopen
                    apiKey: "{{ secret('GITGUARDIAN_API_KEY') }}"
                    incidentId: "{{ inputs.incident_id }}"
                """
        )
    }
)
public class Reopen extends AbstractIncidentAction implements RunnableTask<Reopen.Output> {
    @Override
    public Output run(RunContext runContext) throws Exception {
        var rIncidentId = renderIncidentId(runContext);

        runContext.logger().info("Reopening GitGuardian incident {}", rIncidentId);

        try (var client = client(runContext)) {
            var incident = client.post(incidentPath(rIncidentId) + "/reopen", null, WRITE_SCOPE, Incident.class);
            return Output.builder().incident(requireIncident(incident, rIncidentId)).build();
        }
    }

    @Builder
    @Getter
    public static class Output implements io.kestra.core.models.tasks.Output {
        @Schema(title = "The updated incident")
        private final Incident incident;
    }
}

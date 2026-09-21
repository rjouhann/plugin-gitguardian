package io.kestra.plugin.gitguardian.incidents;

import io.kestra.core.models.annotations.Example;
import io.kestra.core.models.annotations.Plugin;
import io.kestra.core.models.annotations.PluginProperty;
import io.kestra.core.models.property.Property;
import io.kestra.core.models.tasks.RunnableTask;
import io.kestra.core.runners.RunContext;
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
    title = "Resolve a GitGuardian secret incident",
    description = "Marks a secret incident as resolved via `POST /v1/incidents/secrets/{id}/resolve`, recording whether the secret was revoked. Typically the last step of an automated rotation flow. Requires the `incidents:write` scope."
)
@Plugin(
    examples = {
        @Example(
            title = "Resolve an incident after rotating the secret",
            full = true,
            code = """
                id: gitguardian_resolve_after_rotation
                namespace: company.security

                inputs:
                  - id: incident_id
                    type: INT

                tasks:
                  - id: rotate
                    type: io.kestra.plugin.core.log.Log
                    message: "Rotating the leaked credential..."

                  - id: resolve
                    type: io.kestra.plugin.gitguardian.incidents.Resolve
                    apiKey: "{{ secret('GITGUARDIAN_API_KEY') }}"
                    incidentId: "{{ inputs.incident_id }}"
                    secretRevoked: true
                """
        )
    }
)
public class Resolve extends AbstractIncidentAction implements RunnableTask<Resolve.Output> {
    @Schema(title = "Whether the secret was revoked", description = "Set `true` after rotating or revoking the credential, `false` when resolving without revocation (for example a secret that only had access to a decommissioned system).")
    @NotNull
    @PluginProperty(group = "main")
    private Property<Boolean> secretRevoked;

    @Override
    public Output run(RunContext runContext) throws Exception {
        var rIncidentId = renderIncidentId(runContext);
        var rSecretRevoked = runContext.render(secretRevoked).as(Boolean.class)
            .orElseThrow(() -> new IllegalArgumentException("secretRevoked is required to resolve a GitGuardian incident."));

        runContext.logger().info("Resolving GitGuardian incident {} (secret revoked: {})", rIncidentId, rSecretRevoked);

        try (var client = client(runContext)) {
            var incident = client.post(incidentPath(rIncidentId) + "/resolve", Map.of("secret_revoked", rSecretRevoked), WRITE_SCOPE, Incident.class);
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

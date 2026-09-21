package io.kestra.plugin.gitguardian.publicincidents;

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
    title = "Resolve a GitGuardian Public Monitoring incident",
    description = "Resolves a public incident with one or more reasons via `POST /v1/public-incidents/secrets/{id}/resolve`. Requires the `incidents:write` scope."
)
@Plugin(
    examples = {
        @Example(
            title = "Resolve a public leak after revoking the secret",
            full = true,
            code = """
                id: gitguardian_resolve_public
                namespace: company.security

                inputs:
                  - id: incident_id
                    type: INT

                tasks:
                  - id: resolve
                    type: io.kestra.plugin.gitguardian.publicincidents.Resolve
                    apiKey: "{{ secret('GITGUARDIAN_API_KEY') }}"
                    incidentId: "{{ inputs.incident_id }}"
                    resolveReasons:
                      - revoked
                """
        )
    }
)
public class Resolve extends AbstractPublicIncidentAction implements RunnableTask<Resolve.Output> {
    @Schema(title = "Resolve reasons", description = "One or more reasons, for example `revoked` or `removed`; sent comma-separated as GitGuardian expects.")
    @NotNull
    @PluginProperty(group = "main")
    private Property<java.util.List<String>> resolveReasons;

    @Override
    public Output run(RunContext runContext) throws Exception {
        var rIncidentId = renderIncidentId(runContext);
        var rReasons = runContext.render(resolveReasons).asList(String.class);
        if (rReasons.isEmpty()) {
            throw new IllegalArgumentException("resolveReasons must contain at least one reason to resolve a GitGuardian public incident.");
        }

        runContext.logger().info("Resolving GitGuardian public incident {} as {}", rIncidentId, rReasons);

        try (var client = client(runContext)) {
            var incident = client.post(incidentPath(rIncidentId) + "/resolve", Map.of("resolve_reason", String.join(",", rReasons)), WRITE_SCOPE, PublicIncident.class);
            return Output.builder().incident(requireIncident(incident, rIncidentId)).build();
        }
    }

    @Builder
    @Getter
    public static class Output implements io.kestra.core.models.tasks.Output {
        @Schema(title = "The updated public incident")
        private final PublicIncident incident;
    }
}

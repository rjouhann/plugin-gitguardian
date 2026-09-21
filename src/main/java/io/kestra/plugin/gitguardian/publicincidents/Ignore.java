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
    title = "Ignore a GitGuardian Public Monitoring incident",
    description = "Ignores a public incident with one or more reasons via `POST /v1/public-incidents/secrets/{id}/ignore`. Requires the `incidents:write` scope."
)
@Plugin(
    examples = {
        @Example(
            title = "Ignore a public leak that is not ours",
            full = true,
            code = """
                id: gitguardian_ignore_public
                namespace: company.security

                inputs:
                  - id: incident_id
                    type: INT

                tasks:
                  - id: ignore
                    type: io.kestra.plugin.gitguardian.publicincidents.Ignore
                    apiKey: "{{ secret('GITGUARDIAN_API_KEY') }}"
                    incidentId: "{{ inputs.incident_id }}"
                    ignoreReasons:
                      - false_positive
                """
        )
    }
)
public class Ignore extends AbstractPublicIncidentAction implements RunnableTask<Ignore.Output> {
    @Schema(title = "Ignore reasons", description = "One or more reasons, for example `false_positive`, `test_credential`, `low_risk`, or `invalid`; sent comma-separated as GitGuardian expects.")
    @NotNull
    @PluginProperty(group = "main")
    private Property<java.util.List<String>> ignoreReasons;

    @Override
    public Output run(RunContext runContext) throws Exception {
        var rIncidentId = renderIncidentId(runContext);
        var rReasons = runContext.render(ignoreReasons).asList(String.class);
        if (rReasons.isEmpty()) {
            throw new IllegalArgumentException("ignoreReasons must contain at least one reason to ignore a GitGuardian public incident.");
        }

        runContext.logger().info("Ignoring GitGuardian public incident {} as {}", rIncidentId, rReasons);

        try (var client = client(runContext)) {
            var incident = client.post(incidentPath(rIncidentId) + "/ignore", Map.of("ignore_reason", String.join(",", rReasons)), WRITE_SCOPE, PublicIncident.class);
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

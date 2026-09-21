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
    title = "Ignore a GitGuardian secret incident",
    description = "Ignores a secret incident with a reason via `POST /v1/incidents/secrets/{id}/ignore`. Requires the `incidents:write` scope."
)
@Plugin(
    examples = {
        @Example(
            title = "Ignore incidents found in test files with an invalid secret",
            full = true,
            code = """
                id: gitguardian_ignore_test_credentials
                namespace: company.security

                tasks:
                  - id: ignore
                    type: io.kestra.plugin.gitguardian.incidents.Ignore
                    apiKey: "{{ secret('GITGUARDIAN_API_KEY') }}"
                    incidentId: "{{ trigger.incident.id }}"
                    ignoreReason: TEST_CREDENTIAL

                triggers:
                  - id: on_incident
                    type: io.kestra.plugin.gitguardian.incidents.Trigger
                    apiKey: "{{ secret('GITGUARDIAN_API_KEY') }}"
                    validity: INVALID
                    conditions:
                      - type: io.kestra.plugin.core.condition.Expression
                        expression: "{{ 'TEST_FILE' in trigger.incident.tags }}"
                """
        )
    }
)
public class Ignore extends AbstractIncidentAction implements RunnableTask<Ignore.Output> {
    @Schema(title = "Ignore reason", description = "`TEST_CREDENTIAL`, `FALSE_POSITIVE`, `LOW_RISK`, or `INVALID`.")
    @NotNull
    @PluginProperty(group = "main")
    private Property<IgnoreReason> ignoreReason;

    @Override
    public Output run(RunContext runContext) throws Exception {
        var rIncidentId = renderIncidentId(runContext);
        var rReason = runContext.render(ignoreReason).as(IgnoreReason.class)
            .orElseThrow(() -> new IllegalArgumentException("ignoreReason is required to ignore a GitGuardian incident."));

        runContext.logger().info("Ignoring GitGuardian incident {} as {}", rIncidentId, rReason.apiValue());

        try (var client = client(runContext)) {
            var incident = client.post(incidentPath(rIncidentId) + "/ignore", Map.of("ignore_reason", rReason.apiValue()), WRITE_SCOPE, Incident.class);
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

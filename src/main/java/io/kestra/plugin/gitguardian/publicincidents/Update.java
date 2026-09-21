package io.kestra.plugin.gitguardian.publicincidents;

import io.kestra.core.models.annotations.Example;
import io.kestra.core.models.annotations.Plugin;
import io.kestra.core.models.annotations.PluginProperty;
import io.kestra.core.models.property.Property;
import io.kestra.core.models.tasks.RunnableTask;
import io.kestra.core.runners.RunContext;
import io.kestra.plugin.gitguardian.incidents.Severity;
import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Builder;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.ToString;
import lombok.experimental.SuperBuilder;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.Map;

@SuperBuilder
@ToString
@EqualsAndHashCode
@Getter
@NoArgsConstructor
@Schema(
    title = "Update a GitGuardian Public Monitoring incident",
    description = "Sets the severity (`POST .../set_severity`) and/or replaces the custom tags (`POST .../set_custom_tags`) of a public incident. Requires the `incidents:write` scope."
)
@Plugin(
    examples = {
        @Example(
            title = "Mark a public leak critical and tag the owning team",
            full = true,
            code = """
                id: gitguardian_update_public
                namespace: company.security

                tasks:
                  - id: update
                    type: io.kestra.plugin.gitguardian.publicincidents.Update
                    apiKey: "{{ secret('GITGUARDIAN_API_KEY') }}"
                    incidentId: "{{ trigger.incident.id }}"
                    severity: CRITICAL
                    customTags:
                      team: platform

                triggers:
                  - id: on_public_leak
                    type: io.kestra.plugin.gitguardian.publicincidents.Trigger
                    apiKey: "{{ secret('GITGUARDIAN_API_KEY') }}"
                    validity: VALID
                """
        )
    }
)
public class Update extends AbstractPublicIncidentAction implements RunnableTask<Update.Output> {
    @Schema(title = "New severity", description = "`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, or `INFO`. Unchanged when omitted.")
    @PluginProperty(group = "main")
    private Property<Severity> severity;

    @Schema(title = "Custom tags to set", description = "Map of key to value; empty value for a key-only tag. Replaces the current custom tags. Unchanged when omitted.")
    @PluginProperty(group = "main")
    private Property<Map<String, String>> customTags;

    @Override
    public Output run(RunContext runContext) throws Exception {
        var rIncidentId = renderIncidentId(runContext);
        var rSeverity = runContext.render(severity).as(Severity.class).orElse(null);
        var rCustomTags = runContext.render(customTags).asMap(String.class, String.class);
        if (rSeverity == null && rCustomTags.isEmpty()) {
            throw new IllegalArgumentException("Set severity, customTags, or both to update a GitGuardian public incident.");
        }

        runContext.logger().info("Updating GitGuardian public incident {}", rIncidentId);

        try (var client = client(runContext)) {
            PublicIncident incident = null;
            if (rSeverity != null) {
                incident = client.post(incidentPath(rIncidentId) + "/set_severity", Map.of("severity", rSeverity.apiValue()), WRITE_SCOPE, PublicIncident.class);
            }
            if (!rCustomTags.isEmpty()) {
                var tags = new ArrayList<Map<String, String>>();
                rCustomTags.forEach((key, value) -> {
                    var tag = new LinkedHashMap<String, String>();
                    tag.put("key", key);
                    tag.put("value", value == null || value.isBlank() ? null : value);
                    tags.add(tag);
                });
                incident = client.post(incidentPath(rIncidentId) + "/set_custom_tags", Map.of("custom_tags", tags), WRITE_SCOPE, PublicIncident.class);
            }
            if (incident == null) {
                incident = client.get(incidentPath(rIncidentId), null, "incidents:read", PublicIncident.class);
            }
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

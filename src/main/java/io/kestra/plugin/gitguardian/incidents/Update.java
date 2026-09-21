package io.kestra.plugin.gitguardian.incidents;

import io.kestra.core.models.annotations.Example;
import io.kestra.core.models.annotations.Plugin;
import io.kestra.core.models.annotations.PluginProperty;
import io.kestra.core.models.property.Property;
import io.kestra.core.models.tasks.RunnableTask;
import io.kestra.core.runners.RunContext;
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
    title = "Update a GitGuardian secret incident",
    description = "Sets the severity and/or custom tags of a secret incident via `PATCH /v1/incidents/secrets/{id}`. Custom tags replace the incident's current custom tags; missing tags are created in the workspace. Requires the `incidents:write` scope."
)
@Plugin(
    examples = {
        @Example(
            title = "Escalate severity and tag the owning team when the secret is publicly exposed",
            full = true,
            code = """
                id: gitguardian_escalate_public
                namespace: company.security

                tasks:
                  - id: update
                    type: io.kestra.plugin.gitguardian.incidents.Update
                    apiKey: "{{ secret('GITGUARDIAN_API_KEY') }}"
                    incidentId: "{{ trigger.incident.id }}"
                    severity: CRITICAL
                    customTags:
                      team: platform
                      source: kestra

                triggers:
                  - id: on_incident
                    type: io.kestra.plugin.gitguardian.incidents.Trigger
                    apiKey: "{{ secret('GITGUARDIAN_API_KEY') }}"
                    tags:
                      - PUBLICLY_EXPOSED
                """
        )
    }
)
public class Update extends AbstractIncidentAction implements RunnableTask<Update.Output> {
    @Schema(title = "New severity", description = "`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`, or `UNKNOWN`. Unchanged when omitted.")
    @PluginProperty(group = "main")
    private Property<Severity> severity;

    @Schema(title = "Custom tags to set", description = "Map of tag key to value; use an empty value for a key-only tag. Replaces the incident's current custom tags. Unchanged when omitted.")
    @PluginProperty(group = "main")
    private Property<Map<String, String>> customTags;

    @Override
    public Output run(RunContext runContext) throws Exception {
        var rIncidentId = renderIncidentId(runContext);
        var rSeverity = runContext.render(severity).as(Severity.class).orElse(null);
        var rCustomTags = runContext.render(customTags).asMap(String.class, String.class);
        if (rSeverity == null && rCustomTags.isEmpty()) {
            throw new IllegalArgumentException("Set severity, customTags, or both to update a GitGuardian incident.");
        }

        var body = new LinkedHashMap<String, Object>();
        if (rSeverity != null) {
            body.put("severity", rSeverity.apiValue());
        }
        if (!rCustomTags.isEmpty()) {
            var tags = new ArrayList<Map<String, String>>();
            rCustomTags.forEach((key, value) -> {
                var tag = new LinkedHashMap<String, String>();
                tag.put("key", key);
                tag.put("value", value == null || value.isBlank() ? null : value);
                tags.add(tag);
            });
            body.put("custom_tags", tags);
        }

        runContext.logger().info("Updating GitGuardian incident {} with {}", rIncidentId, body.keySet());

        try (var client = client(runContext)) {
            var incident = client.patch(incidentPath(rIncidentId), body, WRITE_SCOPE, Incident.class);
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

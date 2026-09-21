package io.kestra.plugin.gitguardian.publicincidents;

import io.kestra.core.models.annotations.Example;
import io.kestra.core.models.annotations.Plugin;
import io.kestra.core.models.annotations.PluginProperty;
import io.kestra.core.models.property.Property;
import io.kestra.core.models.tasks.RunnableTask;
import io.kestra.core.runners.RunContext;
import io.kestra.plugin.gitguardian.incidents.IncidentNote;
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
    title = "Add a note to a GitGuardian Public Monitoring incident",
    description = "Posts a comment on a public incident via `POST /v1/public-incidents/secrets/{id}/notes`. Requires the `incidents:write` scope."
)
@Plugin(
    examples = {
        @Example(
            title = "Record the Kestra execution on the incident",
            full = true,
            code = """
                id: gitguardian_public_note
                namespace: company.security

                tasks:
                  - id: note
                    type: io.kestra.plugin.gitguardian.publicincidents.AddNote
                    apiKey: "{{ secret('GITGUARDIAN_API_KEY') }}"
                    incidentId: "{{ trigger.incident.id }}"
                    comment: "Handled by Kestra execution {{ execution.id }}"

                triggers:
                  - id: on_public_leak
                    type: io.kestra.plugin.gitguardian.publicincidents.Trigger
                    apiKey: "{{ secret('GITGUARDIAN_API_KEY') }}"
                """
        )
    }
)
public class AddNote extends AbstractPublicIncidentAction implements RunnableTask<AddNote.Output> {
    @Schema(title = "Note content", description = "Up to 10 000 characters.")
    @NotNull
    @PluginProperty(group = "main")
    private Property<String> comment;

    @Override
    public Output run(RunContext runContext) throws Exception {
        var rIncidentId = renderIncidentId(runContext);
        var rComment = runContext.render(comment).as(String.class)
            .filter(value -> !value.isBlank())
            .orElseThrow(() -> new IllegalArgumentException("comment is required to add a note to a GitGuardian public incident."));

        runContext.logger().info("Adding a note to GitGuardian public incident {}", rIncidentId);

        try (var client = client(runContext)) {
            var note = client.post(incidentPath(rIncidentId) + "/notes", Map.of("comment", rComment), WRITE_SCOPE, IncidentNote.class);
            if (note == null) {
                throw new IllegalStateException("Empty response from the GitGuardian API when adding a note to public incident %d.".formatted(rIncidentId));
            }
            return Output.builder().note(note).build();
        }
    }

    @Builder
    @Getter
    public static class Output implements io.kestra.core.models.tasks.Output {
        @Schema(title = "The created note")
        private final IncidentNote note;
    }
}

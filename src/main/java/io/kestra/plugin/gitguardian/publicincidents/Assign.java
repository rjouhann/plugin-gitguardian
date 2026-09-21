package io.kestra.plugin.gitguardian.publicincidents;

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

import java.util.LinkedHashMap;

@SuperBuilder
@ToString
@EqualsAndHashCode
@Getter
@NoArgsConstructor
@Schema(
    title = "Assign a GitGuardian Public Monitoring incident",
    description = "Assigns a public incident to a member by email or ID via `POST /v1/public-incidents/secrets/{id}/assign`. Requires the `incidents:write` scope."
)
@Plugin(
    examples = {
        @Example(
            title = "Assign public leaks to the on-call",
            full = true,
            code = """
                id: gitguardian_assign_public
                namespace: company.security

                tasks:
                  - id: assign
                    type: io.kestra.plugin.gitguardian.publicincidents.Assign
                    apiKey: "{{ secret('GITGUARDIAN_API_KEY') }}"
                    incidentId: "{{ trigger.incident.id }}"
                    assigneeEmail: security-oncall@company.com

                triggers:
                  - id: on_public_leak
                    type: io.kestra.plugin.gitguardian.publicincidents.Trigger
                    apiKey: "{{ secret('GITGUARDIAN_API_KEY') }}"
                """
        )
    }
)
public class Assign extends AbstractPublicIncidentAction implements RunnableTask<Assign.Output> {
    @Schema(title = "Email of the member to assign", description = "Mutually exclusive with `assigneeMemberId`.")
    @PluginProperty(group = "main")
    private Property<String> assigneeEmail;

    @Schema(title = "ID of the member to assign", description = "Mutually exclusive with `assigneeEmail`.")
    @PluginProperty(group = "main")
    private Property<Long> assigneeMemberId;

    @Schema(title = "Notify the assignee by email", description = "Defaults to `true`.")
    @Builder.Default
    @PluginProperty(group = "advanced")
    private Property<Boolean> sendEmail = Property.ofValue(true);

    @Override
    public Output run(RunContext runContext) throws Exception {
        var rIncidentId = renderIncidentId(runContext);
        var rEmail = runContext.render(assigneeEmail).as(String.class).orElse(null);
        var rMemberId = runContext.render(assigneeMemberId).as(Long.class).orElse(null);
        if ((rEmail == null) == (rMemberId == null)) {
            throw new IllegalArgumentException("Set exactly one of assigneeEmail or assigneeMemberId to assign a GitGuardian public incident.");
        }
        var body = new LinkedHashMap<String, Object>();
        if (rEmail != null) {
            body.put("email", rEmail);
        } else {
            body.put("member_id", rMemberId);
        }

        runContext.logger().info("Assigning GitGuardian public incident {}", rIncidentId);

        try (var client = client(runContext)) {
            var incident = client.post(incidentPath(rIncidentId) + "/assign?send_email=" + runContext.render(sendEmail).as(Boolean.class).orElse(true), body, WRITE_SCOPE, PublicIncident.class);
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

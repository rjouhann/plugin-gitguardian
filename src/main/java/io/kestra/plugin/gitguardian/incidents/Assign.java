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

import java.util.LinkedHashMap;
import java.util.Map;

@SuperBuilder
@ToString
@EqualsAndHashCode
@Getter
@NoArgsConstructor
@Schema(
    title = "Assign a GitGuardian secret incident",
    description = "Assigns a secret incident to a workspace member by email or member ID via `POST /v1/incidents/secrets/{id}/assign`. Requires the `incidents:write` scope."
)
@Plugin(
    examples = {
        @Example(
            title = "Assign every new critical incident to the security on-call",
            full = true,
            code = """
                id: gitguardian_assign_oncall
                namespace: company.security

                tasks:
                  - id: assign
                    type: io.kestra.plugin.gitguardian.incidents.Assign
                    apiKey: "{{ secret('GITGUARDIAN_API_KEY') }}"
                    incidentId: "{{ trigger.incident.id }}"
                    assigneeEmail: security-oncall@company.com

                triggers:
                  - id: on_incident
                    type: io.kestra.plugin.gitguardian.incidents.Trigger
                    apiKey: "{{ secret('GITGUARDIAN_API_KEY') }}"
                    severity: CRITICAL
                """
        )
    }
)
public class Assign extends AbstractIncidentAction implements RunnableTask<Assign.Output> {
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
            throw new IllegalArgumentException("Set exactly one of assigneeEmail or assigneeMemberId to assign a GitGuardian incident.");
        }
        var rSendEmail = runContext.render(sendEmail).as(Boolean.class).orElse(true);

        var body = new LinkedHashMap<String, Object>();
        if (rEmail != null) {
            body.put("email", rEmail);
        } else {
            body.put("member_id", rMemberId);
        }

        runContext.logger().info("Assigning GitGuardian incident {} to {}", rIncidentId, rEmail != null ? rEmail : "member " + rMemberId);

        try (var client = client(runContext)) {
            var incident = client.post(incidentPath(rIncidentId) + "/assign?send_email=" + rSendEmail, body, WRITE_SCOPE, Incident.class);
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

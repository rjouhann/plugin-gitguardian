package io.kestra.plugin.gitguardian.incidents;

import io.kestra.core.models.annotations.PluginProperty;
import io.kestra.core.models.property.Property;
import io.kestra.core.runners.RunContext;
import io.kestra.plugin.gitguardian.AbstractGitGuardianTask;
import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotNull;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.ToString;
import lombok.experimental.SuperBuilder;

/** Base for every task that acts on one secret incident: holds the `incidentId` and the `incidents:write` scope. */
@SuperBuilder
@ToString
@EqualsAndHashCode
@Getter
@NoArgsConstructor
public abstract class AbstractIncidentAction extends AbstractGitGuardianTask {
    protected static final String WRITE_SCOPE = "incidents:write";

    @Schema(title = "Incident ID", description = "Typically `{{ trigger.incident.id }}` in a flow started by the incidents trigger.")
    @NotNull
    @PluginProperty(group = "main")
    protected Property<Long> incidentId;

    protected long renderIncidentId(RunContext runContext) throws Exception {
        return runContext.render(incidentId).as(Long.class)
            .orElseThrow(() -> new IllegalArgumentException("incidentId is required to act on a GitGuardian incident."));
    }

    protected String incidentPath(long rIncidentId) {
        return "/incidents/secrets/" + rIncidentId;
    }

    protected static Incident requireIncident(Incident incident, long rIncidentId) {
        if (incident == null) {
            throw new IllegalStateException("Empty response from the GitGuardian API for incident %d.".formatted(rIncidentId));
        }
        return incident;
    }
}

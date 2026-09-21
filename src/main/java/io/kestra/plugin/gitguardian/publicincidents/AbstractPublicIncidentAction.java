package io.kestra.plugin.gitguardian.publicincidents;

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

/** Base for every task acting on one public incident. */
@SuperBuilder
@ToString
@EqualsAndHashCode
@Getter
@NoArgsConstructor
public abstract class AbstractPublicIncidentAction extends AbstractGitGuardianTask {
    protected static final String WRITE_SCOPE = "incidents:write";

    @Schema(title = "Public incident ID", description = "Typically `{{ trigger.incident.id }}` in a flow started by the public incidents trigger. Not interchangeable with internal incident IDs.")
    @NotNull
    @PluginProperty(group = "main")
    protected Property<Long> incidentId;

    protected long renderIncidentId(RunContext runContext) throws Exception {
        return runContext.render(incidentId).as(Long.class)
            .orElseThrow(() -> new IllegalArgumentException("incidentId is required to act on a GitGuardian public incident."));
    }

    protected String incidentPath(long rIncidentId) {
        return "/public-incidents/secrets/" + rIncidentId;
    }

    protected static PublicIncident requireIncident(PublicIncident incident, long rIncidentId) {
        if (incident == null) {
            throw new IllegalStateException("Empty response from the GitGuardian API for public incident %d.".formatted(rIncidentId));
        }
        return incident;
    }
}

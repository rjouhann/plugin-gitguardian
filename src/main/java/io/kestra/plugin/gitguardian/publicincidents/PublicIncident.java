package io.kestra.plugin.gitguardian.publicincidents;

import com.fasterxml.jackson.annotation.JsonAlias;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import io.kestra.plugin.gitguardian.incidents.CustomTag;
import io.kestra.plugin.gitguardian.incidents.Detector;
import io.kestra.plugin.gitguardian.incidents.IncidentStatus;
import io.kestra.plugin.gitguardian.incidents.Severity;
import io.kestra.plugin.gitguardian.incidents.Validity;
import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.time.Instant;
import java.util.List;

/**
 * A Public Monitoring secret incident (a secret of yours leaked on public GitHub, gists, Docker Hub, ...) as
 * returned by `GET /v1/public-incidents/secrets`. Distinct from internal incidents: IDs are not interchangeable.
 */
@Getter
@Setter
@NoArgsConstructor
@JsonIgnoreProperties(ignoreUnknown = true)
public class PublicIncident {
    @Schema(title = "Incident ID")
    private Long id;

    @Schema(title = "Human-readable incident name")
    @JsonAlias("incident_name")
    private String incidentName;

    @Schema(title = "Date the incident was last triggered")
    private Instant date;

    @Schema(title = "Date the incident was first triggered")
    @JsonAlias("triggered_at")
    private Instant triggeredAt;

    @Schema(title = "Detector that found the secret")
    private Detector detector;

    @Schema(title = "Incident URL on the GitGuardian dashboard")
    @JsonAlias("gitguardian_url")
    private String gitguardianUrl;

    @Schema(title = "Public share URL, if shared")
    @JsonAlias("share_url")
    private String shareUrl;

    @Schema(title = "Incident status", description = "`TRIGGERED`, `ASSIGNED`, `RESOLVED`, or `IGNORED`.")
    private IncidentStatus status;

    @Schema(title = "Incident severity")
    private Severity severity;

    @Schema(title = "Validity of the secret")
    private Validity validity;

    @Schema(title = "Whether the secret was declared as yours", description = "Public Monitoring only: the declarative status set by the workspace, for example `not_declared`, `mine`, or `not_mine`.")
    @JsonAlias("declarative_secret_status")
    private String declarativeSecretStatus;

    @Schema(title = "Risk score from 0 to 100")
    @JsonAlias("risk_score")
    private Integer riskScore;

    @Schema(title = "Number of public occurrences")
    @JsonAlias("occurrences_count")
    private Integer occurrencesCount;

    @Schema(title = "ID of the assigned member")
    @JsonAlias("assignee_id")
    private Long assigneeId;

    @Schema(title = "Email of the assigned member")
    @JsonAlias("assignee_email")
    private String assigneeEmail;

    @Schema(title = "Comma-separated reasons the incident was ignored")
    @JsonAlias("ignore_reason")
    private String ignoreReason;

    @Schema(title = "Comma-separated reasons the incident was resolved")
    @JsonAlias("resolve_reason")
    private String resolveReason;

    @Schema(title = "Date the incident was ignored")
    @JsonAlias("ignored_at")
    private Instant ignoredAt;

    @Schema(title = "Date the incident was resolved")
    @JsonAlias("resolved_at")
    private Instant resolvedAt;

    @Schema(title = "Whether the secret was revoked")
    @JsonAlias("secret_revoked")
    private Boolean secretRevoked;

    @Schema(title = "Whether the secret is stored in a vault")
    @JsonAlias("is_vaulted")
    private Boolean vaulted;

    @Schema(title = "GitGuardian tags")
    private List<String> tags;

    @Schema(title = "Custom tags")
    @JsonAlias("custom_tags")
    private List<CustomTag> customTags;
}

package io.kestra.plugin.gitguardian.incidents;

import com.fasterxml.jackson.annotation.JsonAlias;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.time.Instant;
import java.util.List;

/**
 * A GitGuardian secret incident as returned by `GET /v1/incidents/secrets` and
 * `GET /v1/incidents/secrets/{id}`. Occurrences are deliberately not mapped: they carry code
 * context and belong in a dedicated task rather than in every list output.
 */
@Getter
@Setter
@NoArgsConstructor
@JsonIgnoreProperties(ignoreUnknown = true)
public class Incident {
    @Schema(title = "Incident ID")
    private Long id;

    @Schema(title = "Human-readable incident name", description = "Combines the detector and a short identifier, for example `AWS Keys - 7f3a`.")
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

    @Schema(title = "Public share URL, if the incident was shared")
    @JsonAlias("share_url")
    private String shareUrl;

    @Schema(title = "Incident status", description = "`TRIGGERED`, `ASSIGNED`, `RESOLVED`, or `IGNORED`.")
    private IncidentStatus status;

    @Schema(title = "Incident severity", description = "`critical`, `high`, `medium`, `low`, `info`, or `unknown`.")
    private Severity severity;

    @Schema(title = "Validity of the secret", description = "`valid`, `invalid`, `failed_to_check`, `no_checker`, or `unknown`.")
    private Validity validity;

    @Schema(title = "Risk score from 0 (low) to 100 (critical)")
    @JsonAlias("risk_score")
    private Integer riskScore;

    @Schema(title = "Whether the incident was re-triggered after being resolved or ignored")
    private Boolean regression;

    @Schema(title = "Number of occurrences of the secret across monitored sources")
    @JsonAlias({"occurrences_count", "occurrence_count"})
    private Integer occurrencesCount;

    @Schema(title = "Declarative secret status", description = "Only set on Public Monitoring incidents delivered by webhook, for example `active` or `not_declared`.")
    @JsonAlias("declarative_secret_status")
    private String declarativeSecretStatus;

    @Schema(title = "ID of the assigned member")
    @JsonAlias("assignee_id")
    private Long assigneeId;

    @Schema(title = "Email of the assigned member")
    @JsonAlias("assignee_email")
    private String assigneeEmail;

    @Schema(title = "Reason given when the incident was ignored", description = "`test_credential`, `false_positive`, `low_risk`, or `invalid`.")
    @JsonAlias("ignore_reason")
    private String ignoreReason;

    @Schema(title = "Date the incident was ignored")
    @JsonAlias("ignored_at")
    private Instant ignoredAt;

    @Schema(title = "Date the incident was resolved")
    @JsonAlias("resolved_at")
    private Instant resolvedAt;

    @Schema(title = "Whether the secret was reported as revoked on resolution")
    @JsonAlias("secret_revoked")
    private Boolean secretRevoked;

    @Schema(title = "Whether the secret is stored in a vault")
    @JsonAlias("is_vaulted")
    private Boolean vaulted;

    @Schema(title = "GitGuardian tags", description = "For example `FROM_HISTORICAL_SCAN`, `PUBLICLY_EXPOSED`, or `TEST_FILE`.")
    private List<String> tags;

    @Schema(title = "Custom tags set on the incident")
    @JsonAlias("custom_tags")
    private List<CustomTag> customTags;
}

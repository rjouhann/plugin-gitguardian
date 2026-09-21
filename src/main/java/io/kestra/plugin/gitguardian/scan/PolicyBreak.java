package io.kestra.plugin.gitguardian.scan;

import com.fasterxml.jackson.annotation.JsonAlias;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import io.kestra.plugin.gitguardian.incidents.Validity;
import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.util.List;

/** One policy break (a detected secret) reported by `POST /v1/scan` or `POST /v1/multiscan`. */
@Getter
@Setter
@NoArgsConstructor
@JsonIgnoreProperties(ignoreUnknown = true)
public class PolicyBreak {
    @Schema(title = "Detector that matched", description = "For example `AWS Keys` or `Generic High Entropy Secret`.")
    private String type;

    @Schema(title = "Policy that was broken", description = "Currently always `Secrets detection`.")
    private String policy;

    @Schema(title = "Validity of the secret", description = "`valid`, `invalid`, `failed_to_check`, `no_checker`, or `unknown`.")
    private Validity validity;

    @Schema(title = "Whether GitGuardian already knows this secret from a monitored source")
    @JsonAlias("known_secret")
    private Boolean knownSecret;

    @Schema(title = "URL of the existing incident on the GitGuardian dashboard, when the secret is known")
    @JsonAlias("incident_url")
    private String incidentUrl;

    @Schema(title = "Locations of the secret in the document")
    private List<PolicyBreakMatch> matches;
}

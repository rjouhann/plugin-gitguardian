package io.kestra.plugin.gitguardian.healthchecks;

import com.fasterxml.jackson.annotation.JsonAlias;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.time.Instant;
import java.util.List;

/** The latest health check run of one integration instance, as returned by `GET /v1/health-checks`. */
@Getter
@Setter
@NoArgsConstructor
@JsonIgnoreProperties(ignoreUnknown = true)
public class HealthCheck {
    @Schema(title = "Health check run ID")
    private Long id;

    @Schema(title = "Aggregate status", description = "`pass`, `warn`, or `fail`.")
    private HealthCheckStatus status;

    @Schema(title = "Integration type", description = "For example `github-installation`, `slack-workspace`, or `jira-cloud-installation`.")
    private String type;

    @Schema(title = "When this run started")
    @JsonAlias("started_at")
    private Instant startedAt;

    @Schema(title = "When the current uninterrupted streak of identical results started")
    @JsonAlias("first_started_at")
    private Instant firstStartedAt;

    @Schema(title = "Date of the last passing check for this instance")
    @JsonAlias("last_successful_check_date")
    private Instant lastSuccessfulCheckDate;

    @Schema(title = "The integration instance")
    private Instance instance;

    @Schema(title = "Individual check results")
    private List<Result> results;

    @Getter
    @Setter
    @NoArgsConstructor
    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class Instance {
        @Schema(title = "Instance ID")
        private Long id;

        @Schema(title = "Instance display name")
        private String name;

        @Schema(title = "Instance URL")
        private String url;

        @Schema(title = "Operational status", description = "`active`, `revoked`, `suspended`, or `deleted`.")
        private String status;
    }

    @Getter
    @Setter
    @NoArgsConstructor
    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class Result {
        @Schema(title = "Check category", description = "`api_network`, `webhook_network`, `api_access_rights`, or `webhook_access_rights`.")
        private String kind;

        @Schema(title = "Check result", description = "`pass`, `warn`, or `fail`.")
        private HealthCheckStatus status;

        @Schema(title = "Error code, 0 when there is no error")
        @JsonAlias("error_code")
        private Integer errorCode;

        @Schema(title = "Human-readable error message")
        @JsonAlias("error_message")
        private String errorMessage;
    }
}
